package acs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore keeps pending challenges in PostgreSQL (table acs_challenge, created if missing): one JSON document
// per acsTransID (ChallengeState: AReq, card, step, attempts, expiry, passcode HMAC) plus a revision for optimistic
// concurrency between ACS replicas. App-channel session keys are never written (they are not part of the document).
//
// The document holds the AReq, which carries the card number: the database belongs to the cardholder-data
// environment (encrypted storage, restricted access), like card management's.
type PostgresStore struct {
	db     *pgxpool.Pool
	sealer Sealer
}

const pgSchema = `CREATE TABLE IF NOT EXISTS acs_challenge (
	acs_trans_id text PRIMARY KEY,
	doc          jsonb       NOT NULL,
	rev          bigint      NOT NULL,
	expires      timestamptz NOT NULL,
	updated      timestamptz NOT NULL DEFAULT now()
)`

// Sealer encrypts challenge documents at rest: they carry the AReq, card number included. The security module's
// card-vault key (AES-GCM, associated data = acsTransID) does it, so the database never holds a card number in clear.
type Sealer interface {
	Seal(ctx context.Context, id string, plain []byte) (string, error)
	Open(ctx context.Context, id, sealed string) ([]byte, error)
}

// Seal makes the store keep only ciphertext (required for real use; tests may run without).
func (s *PostgresStore) Seal(x Sealer) *PostgresStore { s.sealer = x; return s }

func (s *PostgresStore) encode(ctx context.Context, ch *ChallengeState) ([]byte, error) {
	doc, err := json.Marshal(ch)
	if err != nil || s.sealer == nil {
		return doc, err
	}
	sealed, err := s.sealer.Seal(ctx, ch.ACSTransID, doc)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"sealed": sealed})
}

func (s *PostgresStore) decode(ctx context.Context, id string, doc []byte, rev int64) (*ChallengeState, error) {
	var env struct{ Sealed string }
	if json.Unmarshal(doc, &env) == nil && env.Sealed != "" {
		if s.sealer == nil {
			return nil, errors.New("sealed challenge document and no sealer")
		}
		plain, err := s.sealer.Open(ctx, id, env.Sealed)
		if err != nil {
			return nil, err
		}
		doc = plain
	}
	return decodeState(doc, rev)
}

// acs_fido_credential holds registered WebAuthn credentials (CredentialStore, fido.go): one row per credential,
// keyed by the SHA-256 of the credential id, filed under the ACS's HMAC card reference (never the PAN). The document
// (credential id, COSE public key) is sealed like challenge documents (card-vault key, associated data
// "fido|<card_ref>|<cred_key>"); the signature counter is a plain column so replicas can compare-and-set it.
var pgCredSchema = []string{`CREATE TABLE IF NOT EXISTS acs_fido_credential (
	cred_key   text        PRIMARY KEY,
	card_ref   text        NOT NULL,
	doc        jsonb       NOT NULL,
	sign_count bigint      NOT NULL,
	created    timestamptz NOT NULL DEFAULT now()
)`, `CREATE INDEX IF NOT EXISTS acs_fido_credential_card ON acs_fido_credential (card_ref)`}

func credKey(id []byte) string { return hex.EncodeToString(sha256Sum(id)) }

func (s *PostgresStore) AddCredential(ctx context.Context, ref string, c FIDOCredential) error {
	key := credKey(c.ID)
	doc, err := json.Marshal(FIDOCredential{ID: c.ID, PublicKey: c.PublicKey, SPC: c.SPC, Created: c.Created})
	if err != nil {
		return err
	}
	if s.sealer != nil {
		sealed, err := s.sealer.Seal(ctx, "fido|"+ref+"|"+key, doc)
		if err != nil {
			return err
		}
		doc, _ = json.Marshal(map[string]string{"sealed": sealed})
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO acs_fido_credential (cred_key, card_ref, doc, sign_count) VALUES ($1, $2, $3, $4)
		ON CONFLICT (cred_key) DO NOTHING`, key, ref, doc, int64(c.SignCount))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialExists
	}
	return nil
}

func (s *PostgresStore) Credentials(ctx context.Context, ref string) ([]FIDOCredential, error) {
	rows, err := s.db.Query(ctx, `SELECT cred_key, doc, sign_count FROM acs_fido_credential WHERE card_ref = $1 ORDER BY created, cred_key`, ref)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FIDOCredential
	for rows.Next() {
		var key string
		var doc []byte
		var n int64
		if err := rows.Scan(&key, &doc, &n); err != nil {
			return nil, err
		}
		var env struct{ Sealed string }
		if json.Unmarshal(doc, &env) == nil && env.Sealed != "" {
			if s.sealer == nil {
				return nil, errors.New("sealed credential document and no sealer")
			}
			if doc, err = s.sealer.Open(ctx, "fido|"+ref+"|"+key, env.Sealed); err != nil {
				return nil, err
			}
		}
		var c FIDOCredential
		if err := json.Unmarshal(doc, &c); err != nil {
			return nil, fmt.Errorf("acs_fido_credential document: %w", err)
		}
		c.SignCount = uint32(n)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateSignCount(ctx context.Context, ref string, id []byte, old, new uint32) error {
	key := credKey(id)
	tag, err := s.db.Exec(ctx, `UPDATE acs_fido_credential SET sign_count = $4 WHERE cred_key = $1 AND card_ref = $2 AND sign_count = $3`,
		key, ref, int64(old), int64(new))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var one int
		err := s.db.QueryRow(ctx, `SELECT 1 FROM acs_fido_credential WHERE cred_key = $1 AND card_ref = $2`, key, ref).Scan(&one)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNoCredential
		case err != nil:
			return err
		}
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) DeleteCredential(ctx context.Context, ref string, id []byte) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM acs_fido_credential WHERE cred_key = $1 AND card_ref = $2`, credKey(id), ref)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoCredential
	}
	return nil
}

// NewPostgresStore connects (a pgx connection string, e.g. ACS_DATABASE_URL) and creates the tables if missing.
func NewPostgresStore(ctx context.Context, url string) (*PostgresStore, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, pgSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("acs_challenge table: %w", err)
	}
	for _, q := range pgCredSchema {
		if _, err := db.Exec(ctx, q); err != nil {
			db.Close()
			return nil, fmt.Errorf("acs_fido_credential table: %w", err)
		}
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() { s.db.Close() }

func (s *PostgresStore) Create(ctx context.Context, ch *ChallengeState) error {
	doc, err := s.encode(ctx, ch)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO acs_challenge (acs_trans_id, doc, rev, expires) VALUES ($1, $2, 1, $3)
		ON CONFLICT (acs_trans_id) DO NOTHING`, ch.ACSTransID, doc, ch.Expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	ch.Rev = 1
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*ChallengeState, error) {
	var doc []byte
	var rev int64
	err := s.db.QueryRow(ctx, `SELECT doc, rev FROM acs_challenge WHERE acs_trans_id = $1`, id).Scan(&doc, &rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoChallenge
	}
	if err != nil {
		return nil, err
	}
	return s.decode(ctx, id, doc, rev)
}

func decodeState(doc []byte, rev int64) (*ChallengeState, error) {
	var ch ChallengeState
	if err := json.Unmarshal(doc, &ch); err != nil {
		return nil, fmt.Errorf("acs_challenge document: %w", err)
	}
	ch.Rev = rev
	return &ch, nil
}

// missingOrConflict tells a vanished row from a changed one after a conditional write touched nothing.
func (s *PostgresStore) missingOrConflict(ctx context.Context, id string) error {
	var one int
	err := s.db.QueryRow(ctx, `SELECT 1 FROM acs_challenge WHERE acs_trans_id = $1`, id).Scan(&one)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNoChallenge
	case err != nil:
		return err
	}
	return ErrConflict
}

func (s *PostgresStore) Update(ctx context.Context, ch *ChallengeState) error {
	doc, err := s.encode(ctx, ch)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `UPDATE acs_challenge SET doc = $2, rev = rev + 1, expires = $3, updated = now()
		WHERE acs_trans_id = $1 AND rev = $4`, ch.ACSTransID, doc, ch.Expires, ch.Rev)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.missingOrConflict(ctx, ch.ACSTransID)
	}
	ch.Rev++
	return nil
}

func (s *PostgresStore) Delete(ctx context.Context, id string, rev int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM acs_challenge WHERE acs_trans_id = $1 AND rev = $2`, id, rev)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.missingOrConflict(ctx, id)
	}
	return nil
}

func (s *PostgresStore) List(ctx context.Context) ([]*ChallengeState, error) {
	rows, err := s.db.Query(ctx, `SELECT acs_trans_id, doc, rev FROM acs_challenge ORDER BY acs_trans_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ChallengeState
	for rows.Next() {
		var id string
		var doc []byte
		var rev int64
		if err := rows.Scan(&id, &doc, &rev); err != nil {
			return nil, err
		}
		ch, err := s.decode(ctx, id, doc, rev)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}
