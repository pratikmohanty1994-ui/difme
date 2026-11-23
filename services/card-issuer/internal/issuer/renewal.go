package issuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Card renewal and reissue (card management).
//
//   - RENEWAL (expiry due) and REPLACEMENT (damaged card): the PAN is kept or a new one issued by product setting
//     (Issuer.NewPANOnRenewal). LOST_STOLEN: always a new PAN, the old card blocked at once.
//   - Same PAN: new expiry, so a new CVV2 (same CVK; the dCVV2 key is per PAN and unchanged); the PIN (PVV) stays. The
//     previous expiry and its CVV2 stay valid until the grace date or the first use of the new expiry.
//   - New PAN: a new card record on the same account (the vault seals the new PAN and indexes it; the old record is
//     kept), CVV2 and dCVV2 follow the new PAN; the PIN cannot carry over (the PVV is bound to the PAN), so the new
//     card needs a PIN (GeneratePIN / SetPIN). The old card stays valid until the grace date or the new card's first
//     use, then is REPLACED. A credit line's open authorisations count on both cards, statements move to the new one.
//   - Both cards are found by PAN (scheme-sim routes the BIN's cards to card-issuer; the ACS looks them up here).

// Renewal reasons.
const (
	Renewal     = "RENEWAL"
	Replacement = "REPLACEMENT"
	LostStolen  = "LOST_STOLEN"
)

// DefaultGraceDays: how long the old card (or the old expiry) stays usable after a renewal or replacement.
const DefaultGraceDays = 45

// RenewRequest asks for a renewed or reissued card.
type RenewRequest struct {
	Reason    string `json:"reason"`              // RENEWAL, REPLACEMENT or LOST_STOLEN
	GraceDays int    `json:"graceDays,omitempty"` // default Issuer.GraceDays (DefaultGraceDays)
}

// Renewed is returned once: the (new) card with its PAN and CVV2 for the card bureau / the app's secure display.
type Renewed struct {
	Issued
	SamePAN     bool `json:"samePan"`
	PINRequired bool `json:"pinRequired"` // new PAN: no PIN yet
}

// Renew renews or reissues card id.
func (i *Issuer) Renew(ctx context.Context, id string, r RenewRequest) (Renewed, error) {
	if r.Reason != Renewal && r.Reason != Replacement && r.Reason != LostStolen {
		return Renewed{}, fmt.Errorf("%w: reason RENEWAL|REPLACEMENT|LOST_STOLEN", ErrInvalid)
	}
	if r.GraceDays < 0 || r.GraceDays > 180 {
		return Renewed{}, fmt.Errorf("%w: graceDays 0..180", ErrInvalid)
	}
	grace := r.GraceDays
	if grace == 0 {
		grace = i.GraceDays
	}
	if grace == 0 {
		grace = DefaultGraceDays
	}
	c, err := i.store.Card(ctx, id)
	if err != nil {
		return Renewed{}, err
	}
	switch {
	case c.Status == "REPLACED" || c.ReplacedBy != "":
		return Renewed{}, fmt.Errorf("%w: card already replaced by %s", ErrInvalid, c.ReplacedBy)
	case c.Status == "BLOCKED" && r.Reason != LostStolen:
		return Renewed{}, fmt.Errorf("%w: blocked card: only LOST_STOLEN reissue", ErrInvalid)
	}
	until := i.now().AddDate(0, 0, grace)
	expiry := i.newExpiry()
	newPAN := r.Reason == LostStolen || i.NewPANOnRenewal[c.Product]
	defer func() {
		i.Audit(ctx, "card_renewal", "card", c.ID, "pan", c.MaskedPAN, "reason", r.Reason, "newPan", fmt.Sprint(newPAN))
	}()
	if !newPAN {
		if expiry == c.Expiry {
			return Renewed{}, fmt.Errorf("%w: the card already has the renewal expiry %s", ErrInvalid, expiry)
		}
		cvv2, err := i.hsm.CVV2(ctx, c.PAN, expiry)
		if err != nil {
			return Renewed{}, fmt.Errorf("security module: %w", err)
		}
		c.PrevExpiry, c.PrevValidUntil, c.Expiry, c.FirstUsedAt = c.Expiry, &until, expiry, nil
		if err := i.store.PutCard(ctx, c); err != nil {
			return Renewed{}, err
		}
		return Renewed{Issued: Issued{Card: c, PANFull: c.PAN, CVV2: cvv2}, SamePAN: true}, nil
	}
	pan := i.newPAN(ctx)
	cvv2, err := i.hsm.CVV2(ctx, pan, expiry)
	if err != nil {
		return Renewed{}, fmt.Errorf("security module: %w", err)
	}
	n := Card{ID: "card-" + randomDigits(12), PAN: pan, MaskedPAN: Mask(pan), Expiry: expiry, Product: c.Product, Account: c.Account,
		LimitMinor: c.LimitMinor, Status: "ACTIVE", Holder: c.Holder, Channels: c.Channels, Email: c.Email, Mobile: c.Mobile, CreatedAt: i.now(), Replaces: c.ID}
	if err := i.store.PutCard(ctx, n); err != nil {
		return Renewed{}, err
	}
	if c.Product == Credit { // the billing cycle continues on the new card
		if st, err := i.store.LastStatement(ctx, c.ID); err == nil {
			st.CardID = n.ID
			if err := i.store.PutStatement(ctx, st); err != nil {
				return Renewed{}, err
			}
		} else if !errors.Is(err, ErrNotFound) {
			return Renewed{}, err
		}
	}
	c.ReplacedBy = n.ID
	if r.Reason == LostStolen {
		c.Status = "BLOCKED"
	} else {
		c.ValidUntil = &until
	}
	if err := i.store.PutCard(ctx, c); err != nil {
		return Renewed{}, err
	}
	return Renewed{Issued: Issued{Card: n, PANFull: pan, CVV2: cvv2}, PINRequired: true}, nil
}

// firstUse records a card's first approved use and ends the grace of what it replaced: the card it replaces becomes
// REPLACED; with the same PAN, presenting the new expiry ends the previous one's validity. Caller holds i.mu.
func (i *Issuer) firstUse(ctx context.Context, id string, newExpiryPresented bool) {
	c, err := i.store.Card(ctx, id) // re-read under the lock
	if err != nil {
		return
	}
	changed := false
	if c.FirstUsedAt == nil {
		t := i.now()
		c.FirstUsedAt, changed = &t, true
		if c.Replaces != "" {
			if old, err := i.store.Card(ctx, c.Replaces); err == nil && old.Status == "ACTIVE" && old.ReplacedBy == c.ID {
				old.Status = "REPLACED"
				if err := i.store.PutCard(ctx, old); err != nil {
					slog.Error("renewal: retiring the replaced card", "card", old.ID, "err", err)
				}
			}
		}
	}
	if newExpiryPresented && c.PrevExpiry != "" {
		c.PrevExpiry, c.PrevValidUntil, changed = "", nil, true
	}
	if changed {
		if err := i.store.PutCard(ctx, c); err != nil {
			slog.Error("renewal: recording first use", "card", c.ID, "err", err)
		}
	}
}
