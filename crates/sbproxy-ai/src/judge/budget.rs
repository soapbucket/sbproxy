//! Hard-fail token budget tracker for the judge backend.
//!
//! The tracker exposes a single [`BudgetTracker::charge`] entry
//! point. Each call atomically subtracts the requested token-equivalent
//! amount from a remaining balance backed by an [`AtomicU64`].
//! When the balance is insufficient, `charge` returns
//! [`BudgetExhausted`] and the caller is expected to surface
//! [`JudgeError::BudgetExhausted`] which the proxy converts to
//! `PolicyDecision::Deny`. The tracker never silently allows after
//! the budget runs dry; that would defeat the security purpose of
//! calling the judge.
//!
//! The tracker is concurrency-safe: many simultaneous `charge`
//! calls race on the same atomic and the loser sees the same
//! shortfall the winner would have seen on a serialised path.
//!
//! Budget reset is intentionally out of scope for this file.
//! A scheduled task elsewhere in the runtime can call
//! [`BudgetTracker::reset_to`] (or rebuild the tracker) at the start
//! of each window. Keeping reset off the hot path keeps the contract
//! between caller and enforcer obvious.
//!
//! [`JudgeError::BudgetExhausted`]: super::JudgeError::BudgetExhausted

use std::sync::atomic::{AtomicU64, Ordering};

/// Sentinel returned by [`BudgetTracker::charge`] when the remaining
/// balance is less than the requested amount. Mapped by the caller
/// to [`super::JudgeError::BudgetExhausted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExhausted;

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("judge budget exhausted")
    }
}

impl std::error::Error for BudgetExhausted {}

/// Atomic-backed remaining-token tracker.
///
/// `remaining` is the live balance; `initial` is preserved for
/// observability (utilisation ratios, dashboards, debug logs).
#[derive(Debug)]
pub struct BudgetTracker {
    remaining: AtomicU64,
    initial: u64,
}

impl BudgetTracker {
    /// Build a tracker initialised to `total_tokens`. A `total` of
    /// zero is allowed and means every `charge` call fails immediately
    /// (useful in tests and as a kill switch).
    pub fn new(total_tokens: u64) -> Self {
        Self {
            remaining: AtomicU64::new(total_tokens),
            initial: total_tokens,
        }
    }

    /// Charge `tokens` against the budget.
    ///
    /// On success the balance has been decremented by `tokens`; on
    /// failure the balance is unchanged. The implementation uses a
    /// CAS loop so a racing `charge` from another thread cannot
    /// observe a torn intermediate value.
    ///
    /// `charge(0)` always succeeds and is a no-op; this matches the
    /// expectation that cache hits charge zero tokens.
    pub fn charge(&self, tokens: u64) -> Result<(), BudgetExhausted> {
        if tokens == 0 {
            return Ok(());
        }
        loop {
            let current = self.remaining.load(Ordering::Acquire);
            if current < tokens {
                return Err(BudgetExhausted);
            }
            let next = current - tokens;
            // CAS so a concurrent charger cannot push us into
            // negative territory by tearing the load above.
            match self.remaining.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
    }

    /// Current remaining balance. Snapshot value; concurrent charges
    /// may have moved on by the time the caller reads it.
    pub fn remaining(&self) -> u64 {
        self.remaining.load(Ordering::Acquire)
    }

    /// Original capacity the tracker was constructed with. Useful
    /// for utilisation ratios and dashboard math.
    pub fn initial(&self) -> u64 {
        self.initial
    }

    /// Reset the balance to a fresh value. Used by the window-reset
    /// task (e.g. once per minute). Not on the hot path.
    pub fn reset_to(&self, new_total: u64) {
        self.remaining.store(new_total, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn charge_succeeds_until_budget_exhausted() {
        let tracker = BudgetTracker::new(100);
        assert!(tracker.charge(40).is_ok());
        assert_eq!(tracker.remaining(), 60);
        assert!(tracker.charge(50).is_ok());
        assert_eq!(tracker.remaining(), 10);
        assert!(tracker.charge(11).is_err());
        // Failed charge does not mutate the balance.
        assert_eq!(tracker.remaining(), 10);
        assert!(tracker.charge(10).is_ok());
        assert_eq!(tracker.remaining(), 0);
        assert_eq!(tracker.charge(1), Err(BudgetExhausted));
    }

    #[test]
    fn charge_zero_is_noop_even_when_empty() {
        let tracker = BudgetTracker::new(0);
        // Cache hits charge zero; that path must not fail just
        // because the budget happens to be empty.
        assert!(tracker.charge(0).is_ok());
        assert_eq!(tracker.remaining(), 0);
        // But any non-zero charge against an empty budget fails.
        assert_eq!(tracker.charge(1), Err(BudgetExhausted));
    }

    #[test]
    fn reset_to_restores_balance() {
        let tracker = BudgetTracker::new(50);
        assert!(tracker.charge(30).is_ok());
        assert_eq!(tracker.remaining(), 20);
        tracker.reset_to(100);
        assert_eq!(tracker.remaining(), 100);
        assert_eq!(tracker.initial(), 50);
    }

    #[test]
    fn concurrent_charges_do_not_panic_or_oversubscribe() {
        // 32 threads each try to charge 1 token from a 16-token
        // budget. Exactly 16 must succeed and 16 must fail; the
        // remaining balance must land at zero. If the CAS were
        // wrong we would either oversubscribe (negative balance,
        // checked by the type system) or undersubscribe (residual
        // balance with failures still reported).
        let tracker = Arc::new(BudgetTracker::new(16));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let t = Arc::clone(&tracker);
            handles.push(std::thread::spawn(move || t.charge(1).is_ok()));
        }
        let successes: u32 = handles.into_iter().map(|h| h.join().unwrap() as u32).sum();
        assert_eq!(successes, 16, "exactly 16 of 32 racers should succeed");
        assert_eq!(tracker.remaining(), 0);
    }
}
