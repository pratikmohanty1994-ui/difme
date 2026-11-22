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

//go:embed tazama/pain001.json
var pain001 []byte

// Tazama reports the authentication attempt to Tazama's TMS as a payment initiation (pain.001) and polls the admin
// service for its evaluation (same verdict mapping as the payment hub). Only pain.001: the velocity rules count
// pacs.002 and D02 counts pacs.008, so an authentication is not counted again when the payment itself (pacs.008 +
// pacs.002 from the payment hub) is evaluated. The network map routes pain.001 to typology difme-3ds-risk (rule D01,
// the fraud model). Card numbers are never sent: payer is an opaque card reference.
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
	var p1 obj
	_ = json.Unmarshal(pain001, &p1)
	ci := at(p1, "CstmrCdtTrfInitn")
	statusID := msgID()
	grp := at(ci, "GrpHdr")
	grp["MsgId"], grp["CreDtTm"] = statusID, now
	at(grp, "InitgPty", "Id", "PrvtId", "Othr")["Id"] = payer
	pmt := at(ci, "PmtInf")
	pmt["PmtInfId"] = msgID()
	at(pmt, "Dbtr", "Id", "PrvtId", "Othr")["Id"] = payer
	at(pmt, "DbtrAcct", "Id", "Othr")["Id"] = payer
	at(pmt, "Dbtr")["Nm"], at(pmt, "DbtrAcct")["Nm"] = payer, payer
	tx := at(pmt, "CdtTrfTxInf")
	at(tx, "PmtId")["EndToEndId"] = id
	amt := float64(amountMinor) / 100
	for _, f := range []string{"InstdAmt", "EqvtAmt"} {
		a := at(tx, "Amt", f, "Amt")
		a["Amt"], a["Ccy"] = amt, currency
	}
	at(tx, "Amt", "EqvtAmt")["CcyOfTrf"] = currency
	at(tx, "Cdtr", "Id", "PrvtId", "Othr")["Id"] = merchant
	at(tx, "CdtrAcct", "Id", "Othr")["Id"] = merchant
	at(tx, "Cdtr")["Nm"], at(tx, "CdtrAcct")["Nm"] = merchant, merchant
	if err := t.post(ctx, "/v1/evaluate/iso20022/pain.001.001.11", p1); err != nil {
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
