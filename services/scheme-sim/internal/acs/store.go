package acs

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"
)

// ChallengeState is the durable form of a pending challenge (one per acsTransID). It never holds app-channel key
// material: the AppSession content key stays in the process that ran the key agreement (ACS.apps). If that process
// restarts during an app-channel challenge, the challenge ends with transStatus U (reason 09) — see ACS.Recover and
// ACS.AppChallenge.
//
// Step is "select" (choose the passcode channel), "otp", "oob", "decoupled", "fido" (WebAuthn/SPC in the browser
// challenge page) or "spc" (merchant-initiated SPC: ARes S sent, waiting for AReq #2).
type ChallengeState struct {
	AReq       AReq         `json:"areq"`
	Card       Card         `json:"card"`
	Version    string       `json:"messageVersion"`
	ACSTransID string       `json:"acsTransID"`
	Step       string       `json:"step"`
	OTPMAC     []byte       `json:"otpMAC,omitempty"` // HMAC of the passcode (security module); never the passcode
	Expires    time.Time    `json:"expires"`
	Attempts   int          `json:"attempts"`
	OOB        string       `json:"oob,omitempty"`     // "", "approved", "declined"
	App        bool         `json:"app,omitempty"`     // app channel: the session key lives only in Owner's memory
	Owner      string       `json:"owner,omitempty"`   // ACS instance that holds the app-channel session key
	CardRef    string       `json:"cardRef,omitempty"` // HMAC card reference (FIDO credentials are filed under it)
	FIDO       *FIDOPending `json:"fido,omitempty"`    // steps "fido" (browser WebAuthn/SPC) and "spc" (merchant-initiated SPC)
	Device     string       `json:"device,omitempty"`  // 3DS Method device hash, remembered for the card when the challenge succeeds
	// Rev is the store revision (optimistic concurrency between ACS replicas); kept outside the document.
	Rev int64 `json:"-"`
}

func (c *ChallengeState) clone() *ChallengeState {
	cp := *c
	cp.OTPMAC = slices.Clone(c.OTPMAC)
	cp.Card.Channels = slices.Clone(c.Card.Channels)
	cp.FIDO = c.FIDO.clone()
	if c.AReq.ReqAuthInfo != nil {
		v := *c.AReq.ReqAuthInfo
		cp.AReq.ReqAuthInfo = &v
	}
	if c.AReq.PriorAuthInfo != nil {
		v := *c.AReq.PriorAuthInfo
		cp.AReq.PriorAuthInfo = &v
	}
	if c.AReq.SDKEphemPubKey != nil {
		k := *c.AReq.SDKEphemPubKey
		cp.AReq.SDKEphemPubKey = &k
	}
	return &cp
}

var (
	// ErrNoChallenge: no pending challenge with that acsTransID.
	ErrNoChallenge = errors.New("no such challenge")
	// ErrConflict: the challenge changed since it was read (another ACS replica, or it already finished).
	ErrConflict = errors.New("challenge changed concurrently")
)

// ChallengeStore keeps pending challenges. Create sets Rev to 1; Update and Delete succeed only when the stored
// revision equals the given one (Update then increments ch.Rev).
type ChallengeStore interface {
	Create(ctx context.Context, ch *ChallengeState) error
	Get(ctx context.Context, acsTransID string) (*ChallengeState, error)
	Update(ctx context.Context, ch *ChallengeState) error
	Delete(ctx context.Context, acsTransID string, rev int64) error
	List(ctx context.Context) ([]*ChallengeState, error)
}

// MemoryStore is the in-process challenge store (a restart loses pending challenges).
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]*ChallengeState
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]*ChallengeState{}} }

func (s *MemoryStore) Create(_ context.Context, ch *ChallengeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[ch.ACSTransID]; ok {
		return ErrConflict
	}
	ch.Rev = 1
	s.m[ch.ACSTransID] = ch.clone()
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (*ChallengeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok {
		return nil, ErrNoChallenge
	}
	return ch.clone(), nil
}

func (s *MemoryStore) Update(_ context.Context, ch *ChallengeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[ch.ACSTransID]
	switch {
	case !ok:
		return ErrNoChallenge
	case cur.Rev != ch.Rev:
		return ErrConflict
	}
	ch.Rev++
	s.m[ch.ACSTransID] = ch.clone()
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, id string, rev int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[id]
	switch {
	case !ok:
		return ErrNoChallenge
	case cur.Rev != rev:
		return ErrConflict
	}
	delete(s.m, id)
	return nil
}

func (s *MemoryStore) List(_ context.Context) ([]*ChallengeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ChallengeState, 0, len(s.m))
	for _, k := range slices.Sorted(maps.Keys(s.m)) {
		out = append(out, s.m[k].clone())
	}
	return out, nil
}
