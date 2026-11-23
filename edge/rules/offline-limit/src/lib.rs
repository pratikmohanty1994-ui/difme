//! Offline limit rule. Limits follow the RBI framework for small-value offline payments: at most ₹500 per payment
//! and ₹2,000 cumulative before the device must go online again. The escrow rights the device holds
//! (specs/tla/CrdtMerge.tla) are a second, hard ceiling: a device can never sign more than it was granted.

wit_bindgen::generate!({ world: "offline-rule", path: "../../wit" });

use exports::difme::rules::limit::{Decision, Guest, Payment};

/// ₹500 in paise.
pub const PER_PAYMENT_MAX: i64 = 50_000;
/// ₹2,000 in paise, cumulative since the last sync.
pub const CUMULATIVE_MAX: i64 = 200_000;

struct OfflineLimit;

impl Guest for OfflineLimit {
    fn check(p: Payment) -> Decision {
        if p.currency != "INR" {
            return Decision::Deny(format!("offline payments are INR only, got {}", p.currency));
        }
        if p.amount_minor <= 0 {
            return Decision::Deny("amount must be positive".into());
        }
        if p.amount_minor > PER_PAYMENT_MAX {
            return Decision::Deny(format!("amount {} exceeds the per-payment offline limit {PER_PAYMENT_MAX}", p.amount_minor));
        }
        match p.offline_spent.checked_add(p.amount_minor) {
            Some(total) if total <= CUMULATIVE_MAX => {}
            _ => return Decision::Deny(format!("cumulative offline spend would exceed {CUMULATIVE_MAX}; sync first")),
        }
        if p.amount_minor > p.rights_available {
            return Decision::Deny(format!("amount {} exceeds the {} of escrow rights held", p.amount_minor, p.rights_available));
        }
        Decision::Allow
    }

    fn describe() -> String {
        format!("offline-limit/{} per-payment={PER_PAYMENT_MAX} cumulative={CUMULATIVE_MAX}", env!("CARGO_PKG_VERSION"))
    }
}

export!(OfflineLimit);
