package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Vault protects card numbers at rest (card vault, ADR-024): the database holds only an HMAC index of the PAN (for
// lookups) and the PAN encrypted with AES-GCM bound to the card id; both keys stay in the security module.
type Vault interface {
	Index(ctx context.Context, pan string) (string, error)
	Seal(ctx context.Context, cardID, pan string) (string, error)
	Open(ctx context.Context, cardID, sealed string) (string, error)
}

// PGStore keeps cards and authorisations on the shared Postgres (ADR-019).
type PGStore struct {
	db    *pgxpool.Pool
	vault Vault
}

const schema = `
CREATE TABLE IF NOT EXISTS cards (
  id text PRIMARY KEY,
  pan_index text UNIQUE NOT NULL,      -- HMAC of the PAN (security module key card-index)
  pan_sealed text NOT NULL,            -- AES-GCM(PAN), associated data = id (security module key card-vault)
  doc jsonb NOT NULL                   -- the card without its PAN
);
CREATE TABLE IF NOT EXISTS authorisations (
  id text PRIMARY KEY,
  card_id text NOT NULL,
  state text NOT NULL,
  amount_minor bigint NOT NULL,
  doc jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS statements (
  card_id text NOT NULL,
  period_end timestamptz NOT NULL,
  doc jsonb NOT NULL,
  PRIMARY KEY (card_id, period_end)
);
CREATE INDEX IF NOT EXISTS authorisations_held ON authorisations (card_id) WHERE state = 'HELD';`

func NewPGStore(ctx context.Context, dsn string, v Vault) (*PGStore, error) {
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &PGStore{db: db, vault: v}, nil
}

type storedCard struct {
	Card
	PVV        string `json:"pvv,omitempty"`
	PendingPIN string `json:"pendingPin,omitempty"` // ISO 4 block under the security module's PIN key (opaque here)
}

func (s *PGStore) PutCard(ctx context.Context, c Card) error {
	idx, err := s.vault.Index(ctx, c.PAN)
	if err != nil {
		return err
	}
	sealed, err := s.vault.Seal(ctx, c.ID, c.PAN)
	if err != nil {
		return err
	}
	doc, _ := json.Marshal(storedCard{Card: c, PVV: c.PVV, PendingPIN: c.PendingPIN})
	_, err = s.db.Exec(ctx, `INSERT INTO cards (id, pan_index, pan_sealed, doc) VALUES ($1,$2,$3,$4)
ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc`, c.ID, idx, sealed, doc)
	return err
}

func (s *PGStore) load(ctx context.Context, where string, arg string) (Card, error) {
	var id, sealed string
	var doc []byte
	err := s.db.QueryRow(ctx, `SELECT id, pan_sealed, doc FROM cards WHERE `+where+` = $1`, arg).Scan(&id, &sealed, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return Card{}, ErrNotFound
	} else if err != nil {
		return Card{}, err
	}
	var sc storedCard
	if err := json.Unmarshal(doc, &sc); err != nil {
		return Card{}, err
	}
	c := sc.Card
	c.PVV, c.PendingPIN = sc.PVV, sc.PendingPIN
	if c.PAN, err = s.vault.Open(ctx, id, sealed); err != nil {
		return Card{}, err
	}
	return c, nil
}

func (s *PGStore) Card(ctx context.Context, id string) (Card, error) { return s.load(ctx, "id", id) }

func (s *PGStore) CardByPAN(ctx context.Context, pan string) (Card, error) {
	idx, err := s.vault.Index(ctx, pan)
	if err != nil {
		return Card{}, err
	}
	return s.load(ctx, "pan_index", idx)
}

func (s *PGStore) PutAuth(ctx context.Context, a Auth) error {
	doc, _ := json.Marshal(a)
	_, err := s.db.Exec(ctx, `INSERT INTO authorisations (id, card_id, state, amount_minor, doc) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, amount_minor = EXCLUDED.amount_minor, doc = EXCLUDED.doc`, a.ID, a.CardID, a.State, a.AmountMinor, doc)
	return err
}

func (s *PGStore) Auth(ctx context.Context, id string) (Auth, error) {
	var doc []byte
	err := s.db.QueryRow(ctx, `SELECT doc FROM authorisations WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return Auth{}, ErrNotFound
	} else if err != nil {
		return Auth{}, err
	}
	var a Auth
	return a, json.Unmarshal(doc, &a)
}

func (s *PGStore) HeldTotal(ctx context.Context, cardID string) (int64, error) {
	var t int64
	err := s.db.QueryRow(ctx, `SELECT COALESCE(SUM(amount_minor),0) FROM authorisations WHERE card_id = $1 AND state = 'HELD'`, cardID).Scan(&t)
	return t, err
}

func (s *PGStore) PutStatement(ctx context.Context, st Statement) error {
	doc, _ := json.Marshal(st)
	_, err := s.db.Exec(ctx, `INSERT INTO statements (card_id, period_end, doc) VALUES ($1,$2,$3)
ON CONFLICT (card_id, period_end) DO UPDATE SET doc = EXCLUDED.doc`, st.CardID, st.PeriodEnd, doc)
	return err
}

func (s *PGStore) LastStatement(ctx context.Context, cardID string) (Statement, error) {
	var doc []byte
	err := s.db.QueryRow(ctx, `SELECT doc FROM statements WHERE card_id = $1 ORDER BY period_end DESC LIMIT 1`, cardID).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return Statement{}, ErrNotFound
	} else if err != nil {
		return Statement{}, err
	}
	var st Statement
	return st, json.Unmarshal(doc, &st)
}

func (s *PGStore) CreditCards(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT id FROM cards WHERE doc->>'product' = 'CREDIT'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
