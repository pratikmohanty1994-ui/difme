package acs

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Verdict is Tazama's evaluation mapped as in the payment hub (ADR-023).
type Verdict string

const (
	NoAlert   Verdict = "NO_ALERT"
	Alert     Verdict = "ALERT"
	Interdict Verdict = "INTERDICT"
	Unknown   Verdict = "UNKNOWN"
)

// FRM is fraud and risk management: Tazama in DIFME.
type FRM interface {
	Evaluate(ctx context.Context, id, payer, merchant string, amountMinor int64, currency string) (Verdict, string)
}

//go:embed tazama/pacs008.json
var pacs008 []byte

//go:embed tazama/pacs002.json
var pacs002 []byte

// Tazama reports the authentication attempt to Tazama's TMS as a credit transfer and its status, then polls the
// admin service for the evaluation, exactly as the payment hub's Tazama client does (same templates, same verdict
// mapping). Card numbers are never sent: payer is an opaque card reference.
type Tazama struct {
	TMS, Admin string
	Budget     time.Duration
	HTTP       *http.Client
}

func NewTazama(tms, admin string, budget time.Duration) *Tazama {
	return &Tazama{TMS: strings.TrimSuffix(tms, "/"), Admin: strings.TrimSuffix(admin, "/"), Budget: budget, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

func msgID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type obj = map[string]any

func at(m obj, path ...string) obj {
	for _, p := range path {
		switch v := m[p].(type) {
		case obj:
			m = v
		case []any:
			m = v[0].(obj)
		}
	}
	return m
}

func (t *Tazama) post(ctx context.Context, path string, body obj) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, t.TMS+path, bytes.NewReader(b))
	req.Header.Set("content-type", "application/json")
	r, err := t.HTTP.Do(req)
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, r.StatusCode)
	}
	return nil
}

func (t *Tazama) Evaluate(ctx context.Context, id, payer, merchant string, amountMinor int64, currency string) (Verdict, string) {
	ctx, cancel := context.WithTimeout(ctx, t.Budget)
	defer cancel()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var p8, p2 obj
	_ = json.Unmarshal(pacs008, &p8)
	_ = json.Unmarshal(pacs002, &p2)
	cd := at(p8, "FIToFICstmrCdtTrf")
	grp, tx := at(cd, "GrpHdr"), at(cd, "CdtTrfTxInf")
	grp["MsgId"], grp["CreDtTm"] = msgID(), now
	pid := at(tx, "PmtId")
	pid["InstrId"], pid["EndToEndId"] = id, id
	amt := float64(amountMinor) / 100
	for _, f := range []string{"IntrBkSttlmAmt", "InstdAmt"} {
		a := at(tx, f, "Amt")
		a["Amt"], a["Ccy"] = amt, currency
	}
	for _, pa := range [][2]string{{"Dbtr", "DbtrAcct"}, {"Cdtr", "CdtrAcct"}} {
		who := payer
		if pa[0] == "Cdtr" {
			who = merchant
		}
		at(tx, pa[0], "Id", "PrvtId", "Othr")["Id"] = who
		at(tx, pa[1], "Id", "Othr")["Id"] = who
		at(tx, pa[0])["Nm"], at(tx, pa[1])["Nm"] = who, who
	}
	at(tx, "InitgPty", "Id", "PrvtId", "Othr")["Id"] = payer
	statusID := msgID()
	st := at(p2, "FIToFIPmtSts")
	at(st, "GrpHdr")["MsgId"], at(st, "GrpHdr")["CreDtTm"] = statusID, now
	ts := at(st, "TxInfAndSts")
	ts["OrgnlInstrId"], ts["OrgnlEndToEndId"], ts["TxSts"], ts["AccptncDtTm"] = id, id, "ACCC", now
	if err := t.post(ctx, "/v1/evaluate/iso20022/pacs.008.001.10", p8); err != nil {
		return Unknown, "TMS: " + err.Error()
	}
	if err := t.post(ctx, "/v1/evaluate/iso20022/pacs.002.001.12", p2); err != nil {
		return Unknown, "TMS: " + err.Error()
	}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.Admin+"/v1/admin/reports/getreportbymsgid?msgid="+statusID, nil)
		r, err := t.HTTP.Do(req)
		if err != nil {
			return Unknown, "admin service: " + err.Error()
		}
		if r.StatusCode == http.StatusOK {
			var body struct{ Data json.RawMessage }
			err := json.NewDecoder(r.Body).Decode(&body)
			r.Body.Close()
			if err != nil {
				return Unknown, "admin service: " + err.Error()
			}
			return ParseEvaluation(body.Data)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			return Unknown, fmt.Sprintf("admin service: HTTP %d", r.StatusCode)
		}
		select {
		case <-ctx.Done():
			return Unknown, fmt.Sprintf("no evaluation within %s", t.Budget)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ParseEvaluation: INTERDICT when a typology reached its interdiction threshold, ALERT on ALRT, NO_ALERT on NALT.
func ParseEvaluation(data []byte) (Verdict, string) {
	var e struct {
		Report     *report `json:"report"`
		Evaluation struct {
			Report *report `json:"report"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return Unknown, "evaluation: " + err.Error()
	}
	rep := e.Report
	if rep == nil {
		rep = e.Evaluation.Report
	}
	if rep == nil {
		return Unknown, "evaluation without report"
	}
	var scores []string
	interdict := false
	for _, t := range rep.TadpResult.TypologyResult {
		scores = append(scores, fmt.Sprintf("%s=%v", t.Cfg, t.Result))
		if t.Workflow.InterdictionThreshold != nil && t.Result >= *t.Workflow.InterdictionThreshold {
			interdict = true
		}
	}
	detail := rep.Status
	if len(scores) > 0 {
		detail += " (" + strings.Join(scores, ", ") + ")"
	}
	switch {
	case interdict:
		return Interdict, detail
	case rep.Status == "ALRT":
		return Alert, detail
	case rep.Status == "NALT":
		return NoAlert, detail
	}
	return Unknown, "unrecognised report status: " + detail
}

type report struct {
	Status     string `json:"status"`
	TadpResult struct {
		TypologyResult []struct {
			Cfg      string  `json:"cfg"`
			Result   float64 `json:"result"`
			Workflow struct {
				InterdictionThreshold *float64 `json:"interdictionThreshold"`
			} `json:"workflow"`
		} `json:"typologyResult"`
	} `json:"tadpResult"`
}
