package issuer

import (
	"context"
	"sync"
)

// Store keeps cards and authorisations. MemStore is used in tests and single-replica dev; PGStore (pgstore.go) on the
// shared Postgres in the cluster.
type Store interface {
	PutCard(ctx context.Context, c Card) error
	Card(ctx context.Context, id string) (Card, error)
	CardByPAN(ctx context.Context, pan string) (Card, error)
	PutAuth(ctx context.Context, a Auth) error
	Auth(ctx context.Context, id string) (Auth, error)
	HeldTotal(ctx context.Context, cardID string) (int64, error)
}

type MemStore struct {
	mu    sync.Mutex
	cards map[string]Card
	byPAN map[string]string
	auths map[string]Auth
}

func NewMemStore() *MemStore {
	return &MemStore{cards: map[string]Card{}, byPAN: map[string]string{}, auths: map[string]Auth{}}
}

func (m *MemStore) PutCard(_ context.Context, c Card) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cards[c.ID], m.byPAN[c.PAN] = c, c.ID
	return nil
}

func (m *MemStore) Card(_ context.Context, id string) (Card, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cards[id]
	if !ok {
		return Card{}, ErrNotFound
	}
	return c, nil
}

func (m *MemStore) CardByPAN(ctx context.Context, pan string) (Card, error) {
	m.mu.Lock()
	id, ok := m.byPAN[pan]
	m.mu.Unlock()
	if !ok {
		return Card{}, ErrNotFound
	}
	return m.Card(ctx, id)
}

func (m *MemStore) PutAuth(_ context.Context, a Auth) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auths[a.ID] = a
	return nil
}

func (m *MemStore) Auth(_ context.Context, id string) (Auth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auths[id]
	if !ok {
		return Auth{}, ErrNotFound
	}
	return a, nil
}

func (m *MemStore) HeldTotal(_ context.Context, cardID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var t int64
	for _, a := range m.auths {
		if a.CardID == cardID && a.State == "HELD" {
			t += a.AmountMinor
		}
	}
	return t, nil
}
