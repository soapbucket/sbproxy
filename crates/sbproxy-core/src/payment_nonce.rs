//! The durable single-serve ledger settlement burns quote nonces against.
//!
//! WOR-2317. Double *charge* protection was durable from the first release:
//! `consumed_payment_proofs` and `payment_intents.reserved_proof_digest` are
//! rows in SQLite, so a credential that already paid cannot pay again across
//! any number of restarts. Double *serve* protection was not. The request
//! path burned its nonce into an in-process set, which meant a client
//! re-presenting an already-settled quote token was served again after a
//! restart, once per restart, having paid exactly once. For a content paywall
//! that is a rounding error. For a metered expensive API it is a leak.
//!
//! [`DurableNonceStore`] closes it by putting the burn in the same database
//! as the settlement it authorizes. Not a second database beside it: the same
//! [`SqliteSettlementStore`] handle, so the two facts cannot end up in
//! different files, and a backup, a moved `state_path`, or a lost volume
//! takes both or neither.
//!
//! # Why the burn is synchronous
//!
//! [`NonceStore`] is a synchronous trait, because the crawl-pricing path that
//! defined it runs on the proxy's sync hot path. The burn therefore takes the
//! store's connection directly instead of going through the async blocking
//! pool the rest of the store uses. That is one indexed insert on an open
//! WAL connection, taken once per settled redemption, immediately after a
//! network round trip to a payment provider. Nothing awaits while the
//! connection is held, so it cannot deadlock against the pooled path; the
//! worst case is a short wait behind another writer, bounded by the store's
//! configured busy timeout.
//!
//! # Fail closed, and unmistakably
//!
//! Every storage failure comes back as [`NonceError`]. There is no `Ok`
//! value on this path that means "the burn may or may not have landed":
//! [`NonceCheck::Fresh`] is returned only after a committed insert this call
//! performed. A caller that cannot reach the database refuses service, which
//! is the correct trade for a subsystem where the alternative is serving a
//! paid response an unknown number of times.

use std::sync::Arc;

use sbproxy_billing::sqlite::{QuoteNonceBurn, SqliteSettlementStore};
use sbproxy_modules::policy::quote_token::{NonceCheck, NonceError, NonceStore};

/// Milliseconds per second, for turning a token `exp` into a stored bound.
const MILLIS_PER_SECOND: u64 = 1_000;

/// The largest `exp`, in unix seconds, that still fits the stored bound.
///
/// Past this the bound saturates at [`i64::MAX`], which is "keep forever".
/// Saturating upward is the fail-closed direction: a nonce kept too long
/// refuses a replay that was never going to be valid anyway, where one
/// forgotten too early would serve a paid response twice.
const MAX_BOUNDED_SECONDS: u64 = (i64::MAX as u64) / MILLIS_PER_SECOND;

/// Single-serve quote nonces, durable in the settlement database.
///
/// Holds the settlement store rather than a connection of its own, which is
/// the property that matters: there is exactly one settlement database per
/// runtime and this writes to it.
pub struct DurableNonceStore {
    store: Arc<SqliteSettlementStore>,
}

impl DurableNonceStore {
    /// Wraps the runtime's settlement store as a nonce ledger.
    #[must_use]
    pub const fn new(store: Arc<SqliteSettlementStore>) -> Self {
        Self { store }
    }

    /// Turns a token `exp` in unix seconds into a stored millisecond bound.
    const fn bound_ms(expires_at_unix_secs: u64) -> i64 {
        if expires_at_unix_secs >= MAX_BOUNDED_SECONDS {
            i64::MAX
        } else {
            // Bounded by the branch above, so the multiply and the narrowing
            // are both exact.
            (expires_at_unix_secs * MILLIS_PER_SECOND) as i64
        }
    }

    /// Burns one nonce and translates the outcome onto the trait's vocabulary.
    fn burn(&self, nonce: &str, expires_at_ms: Option<i64>) -> Result<NonceCheck, NonceError> {
        match self.store.burn_quote_nonce(nonce, expires_at_ms) {
            Ok(QuoteNonceBurn::Fresh) => Ok(NonceCheck::Fresh),
            Ok(QuoteNonceBurn::AlreadyServed) => Ok(NonceCheck::AlreadyConsumed),
            // The billing error is already redacted by construction: its
            // variants name a storage step, never a row, an identifier, or a
            // payer. Carrying the text through gives an operator the step
            // that failed without putting settlement data in a log line.
            Err(error) => Err(NonceError::new(error.to_string())),
        }
    }
}

impl std::fmt::Debug for DurableNonceStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No path, no row counts, nothing about what has been burned. The
        // trait requires `Debug` and the seam prints itself on reload.
        formatter.debug_struct("DurableNonceStore").finish()
    }
}

impl NonceStore for DurableNonceStore {
    /// Burns without a retention bound, which means the row is kept forever.
    ///
    /// Reachable only from a caller that has no token expiry to offer.
    /// Settlement always has one and calls
    /// [`NonceStore::check_and_consume_with_expiry`] instead. Keeping the row
    /// rather than inventing a lifetime is the fail-closed answer: an
    /// unbounded row refuses replays for as long as the database lives, where
    /// a guessed bound could forget a burn while its token was still valid.
    fn check_and_consume(&self, nonce: &str) -> Result<NonceCheck, NonceError> {
        self.burn(nonce, None)
    }

    fn check_and_consume_with_expiry(
        &self,
        nonce: &str,
        expires_at_unix_secs: u64,
    ) -> Result<NonceCheck, NonceError> {
        self.burn(nonce, Some(Self::bound_ms(expires_at_unix_secs)))
    }

    /// A no-op, because the burn is the insert.
    ///
    /// There is nothing to pre-register. A nonce is either being spent for
    /// the first time or it was spent before, and the primary key decides
    /// which without anything having made it known in advance. That is also
    /// why this store never answers [`NonceCheck::Unknown`]: the window a
    /// pre-registration step exists to close does not exist here.
    fn register(&self, _nonce: &str) -> Result<(), NonceError> {
        Ok(())
    }
}

/// A nonce ledger that refuses every burn.
///
/// Wired where a [`NonceStore`] is structurally required but must never be
/// reached. [`sbproxy_modules::policy::quote_token::QuoteTokenVerifier`] takes
/// one in its constructor because its legacy `verify` path consumes, and the
/// settlement path deliberately does not use that path: it authenticates with
/// `verify_authenticity` and lets the durable intent and proof transaction own
/// single use, because burning a quote while parsing a signature would make an
/// interrupted payment unresumable.
///
/// The previous wiring passed an in-memory store there. It was unreachable,
/// but "unreachable" is a claim about today's call graph. This makes it a
/// property of the value: if a future caller ever routes a consume through
/// that verifier, it fails closed and says so, instead of quietly burning
/// into a set that no restart survives and nothing prunes.
#[derive(Debug, Default)]
pub struct RefusingNonceStore;

impl RefusingNonceStore {
    /// Builds the refusing ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NonceStore for RefusingNonceStore {
    fn check_and_consume(&self, _nonce: &str) -> Result<NonceCheck, NonceError> {
        Err(NonceError::new(
            "settlement quote tokens are not consumed at verification; \
             single use belongs to the durable settlement ledger",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sbproxy_modules::policy::quote_token::InMemoryNonceStore;

    /// A quote expiry far enough out that nothing here prunes.
    const FAR_FUTURE_UNIX_SECS: u64 = 4_102_444_800;

    /// Builds a ledger over a fresh handle on `path`, the way a restart does.
    fn ledger(path: &std::path::Path) -> DurableNonceStore {
        DurableNonceStore::new(Arc::new(
            SqliteSettlementStore::open(path).expect("open settlement store"),
        ))
    }

    #[test]
    fn a_burned_nonce_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settlement.sqlite3");

        let before = ledger(&path);
        assert_eq!(
            before
                .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
                .expect("first burn"),
            NonceCheck::Fresh,
        );
        drop(before);

        // A second handle on the same file is what a restarted process gets.
        let after = ledger(&path);
        assert_eq!(
            after
                .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
                .expect("burn after restart"),
            NonceCheck::AlreadyConsumed,
            "a settled quote must not buy a second response after a restart",
        );
    }

    #[test]
    fn the_in_memory_ledger_forgets_a_burn_that_the_durable_one_keeps() {
        // The defect WOR-2317 closes, written as a comparison so the two
        // behaviours sit next to each other. The in-memory ledger is still
        // the right answer for the crawl-pricing path, where a forgotten
        // nonce costs a re-quote rather than an unpaid response.
        let before = InMemoryNonceStore::new();
        assert_eq!(
            before
                .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
                .expect("first burn"),
            NonceCheck::Fresh,
        );
        drop(before);

        let after = InMemoryNonceStore::new();
        assert_eq!(
            after
                .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
                .expect("burn after restart"),
            NonceCheck::Fresh,
            "an in-process set cannot carry a burn across a restart, which is \
             why the settlement seam does not wire one",
        );
    }

    #[test]
    fn a_burn_without_an_expiry_is_still_durable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settlement.sqlite3");

        assert_eq!(
            ledger(&path)
                .check_and_consume("requirement-1")
                .expect("first burn"),
            NonceCheck::Fresh,
        );
        assert_eq!(
            ledger(&path)
                .check_and_consume("requirement-1")
                .expect("burn after restart"),
            NonceCheck::AlreadyConsumed,
        );
    }

    #[test]
    fn registering_is_a_no_op_and_never_answers_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settlement.sqlite3");
        let store = ledger(&path);

        store.register("requirement-1").expect("register");
        assert_eq!(
            store
                .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
                .expect("burn"),
            NonceCheck::Fresh,
            "a registration must not consume the nonce it announces",
        );
        assert_eq!(
            store
                .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
                .expect("second burn"),
            NonceCheck::AlreadyConsumed,
        );
    }

    #[test]
    fn a_saturating_expiry_does_not_wrap_into_an_immediate_prune() {
        // A token claiming an `exp` beyond what milliseconds can hold must
        // saturate upward. Wrapping would put the bound in the past and prune
        // the burn on the very next request.
        assert_eq!(DurableNonceStore::bound_ms(u64::MAX), i64::MAX);
        assert_eq!(DurableNonceStore::bound_ms(0), 0);
        assert_eq!(DurableNonceStore::bound_ms(1), 1_000);
    }

    #[test]
    fn the_refusing_ledger_never_reports_a_burn() {
        let store = RefusingNonceStore::new();
        let outcome = store.check_and_consume("requirement-1");
        assert!(
            outcome.is_err(),
            "a ledger that must never be reached cannot answer Fresh",
        );
        // The defaulted expiry-carrying method routes to the same refusal, so
        // there is no second door into it.
        assert!(store
            .check_and_consume_with_expiry("requirement-1", FAR_FUTURE_UNIX_SECS)
            .is_err());
    }
}
