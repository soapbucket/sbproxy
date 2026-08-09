//! Durable single-serve quote nonces, across restarts and across handles.
//!
//! WOR-2317. Double charge protection was already durable; double serve was
//! not, because the request path burned its nonce into an in-process set.
//! Every test here uses an on-disk database, and the ones that matter open a
//! second [`SqliteSettlementStore`] handle on the same file, because the
//! guarantee being made is about a process that died and came back rather
//! than about two tasks in one process.

#![cfg(feature = "runtime")]

use std::sync::Arc;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::sqlite::{QuoteNonceBurn, SqliteSettlementStore};
use sbproxy_billing::store::BillingClock;

mod common;

use common::TestClock;

/// A fixed instant every test starts from.
const START_MS: i64 = 1_700_000_000_000;

/// A quote expiry comfortably after the start instant.
const EXPIRY_MS: i64 = 1_700_000_600_000;

/// Opens a store handle on `path` driven by `clock`.
///
/// Deliberately returns the concrete type rather than the shared trait
/// object. The nonce burn is a synchronous method on the store, because the
/// nonce-ledger trait the request path calls it through is synchronous.
fn handle(path: &std::path::Path, clock: &Arc<TestClock>) -> SqliteSettlementStore {
    SqliteSettlementStore::open(path)
        .expect("open settlement store")
        .with_clock(Arc::clone(clock) as Arc<dyn BillingClock>)
}

#[test]
fn a_burned_nonce_is_still_burned_after_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);

    // First process.
    let first = handle(&path, &clock);
    assert_eq!(
        first
            .burn_quote_nonce("requirement-1", Some(EXPIRY_MS))
            .expect("first burn"),
        QuoteNonceBurn::Fresh,
        "the first presentation of a settled quote serves",
    );
    drop(first);

    // Restart: a new handle on the same file, exactly as a fresh process
    // would open it. This is the case that used to serve a second response
    // for one payment, once per restart.
    let second = handle(&path, &clock);
    assert_eq!(
        second
            .burn_quote_nonce("requirement-1", Some(EXPIRY_MS))
            .expect("burn after restart"),
        QuoteNonceBurn::AlreadyServed,
        "a restart must not un-burn a nonce",
    );
}

#[test]
fn two_handles_on_one_file_see_the_same_burn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);

    let first = handle(&path, &clock);
    let second = handle(&path, &clock);

    assert_eq!(
        first
            .burn_quote_nonce("requirement-1", Some(EXPIRY_MS))
            .expect("burn on the first handle"),
        QuoteNonceBurn::Fresh,
    );
    assert_eq!(
        second
            .burn_quote_nonce("requirement-1", Some(EXPIRY_MS))
            .expect("burn on the second handle"),
        QuoteNonceBurn::AlreadyServed,
        "the burn is in the file, not in a handle",
    );
}

#[test]
fn concurrent_burns_of_one_nonce_produce_exactly_one_winner() {
    /// How many threads race for the same nonce.
    const RACERS: usize = 16;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);

    // Two handles, so the race is decided by SQLite's write lock and the
    // primary key rather than by one process's mutex. A read-then-write
    // would let two racers both observe "not burned" and both serve.
    let handles: Vec<Arc<SqliteSettlementStore>> =
        (0..2).map(|_| Arc::new(handle(&path, &clock))).collect();

    let barrier = Arc::new(std::sync::Barrier::new(RACERS));
    let mut threads = Vec::with_capacity(RACERS);
    for racer in 0..RACERS {
        let store = Arc::clone(&handles[racer % handles.len()]);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.burn_quote_nonce("requirement-1", Some(EXPIRY_MS))
        }));
    }

    let mut fresh = 0_usize;
    let mut already = 0_usize;
    for thread in threads {
        match thread.join().expect("racer thread") {
            Ok(QuoteNonceBurn::Fresh) => fresh += 1,
            Ok(QuoteNonceBurn::AlreadyServed) => already += 1,
            Err(error) => panic!("a racer could not reach the ledger: {error}"),
        }
    }

    assert_eq!(fresh, 1, "exactly one racer may serve");
    assert_eq!(
        already,
        RACERS - 1,
        "every other racer is refused as a replay"
    );
}

#[test]
fn a_nonce_whose_token_expired_is_pruned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    assert_eq!(
        store
            .burn_quote_nonce("short-lived", Some(START_MS + 1_000))
            .expect("burn the short-lived nonce"),
        QuoteNonceBurn::Fresh,
    );
    assert_eq!(
        store
            .burn_quote_nonce("long-lived", Some(EXPIRY_MS))
            .expect("burn the long-lived nonce"),
        QuoteNonceBurn::Fresh,
    );

    // Past the short-lived token's expiry, but well inside the other one's.
    clock.advance(2_000);

    // Any burn prunes, which is what keeps the table bounded without a
    // scheduler: rows can only accumulate while burns are happening.
    assert_eq!(
        store
            .burn_quote_nonce("unrelated", Some(EXPIRY_MS))
            .expect("burn an unrelated nonce"),
        QuoteNonceBurn::Fresh,
    );

    assert_eq!(
        store
            .burn_quote_nonce("short-lived", Some(EXPIRY_MS))
            .expect("re-burn the pruned nonce"),
        QuoteNonceBurn::Fresh,
        "an expired token's nonce is forgotten; it can never be presented again anyway",
    );
    assert_eq!(
        store
            .burn_quote_nonce("long-lived", Some(EXPIRY_MS))
            .expect("re-burn the live nonce"),
        QuoteNonceBurn::AlreadyServed,
        "pruning must not touch a nonce whose token is still presentable",
    );
}

#[test]
fn a_nonce_with_no_retention_bound_is_never_pruned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    assert_eq!(
        store
            .burn_quote_nonce("unbounded", None)
            .expect("burn without a bound"),
        QuoteNonceBurn::Fresh,
    );

    // Far past any plausible token lifetime.
    clock.advance(365 * 24 * 60 * 60 * 1_000);
    assert_eq!(
        store
            .burn_quote_nonce("unrelated", Some(i64::MAX))
            .expect("burn an unrelated nonce"),
        QuoteNonceBurn::Fresh,
    );

    assert_eq!(
        store
            .burn_quote_nonce("unbounded", None)
            .expect("re-burn the unbounded nonce"),
        QuoteNonceBurn::AlreadyServed,
        "a bound nobody stated must never cause a row to be forgotten",
    );
}

#[test]
fn a_database_failure_at_burn_time_refuses_rather_than_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    assert_eq!(
        store
            .burn_quote_nonce("requirement-1", Some(EXPIRY_MS))
            .expect("burn while the ledger is healthy"),
        QuoteNonceBurn::Fresh,
    );

    // Break the ledger underneath the open handle. Any storage failure would
    // do; this one is deterministic and does not depend on filesystem
    // permissions or on how the platform handles a revoked mount.
    {
        let saboteur = rusqlite::Connection::open(&path).expect("open a second connection");
        saboteur
            .execute_batch("DROP TABLE served_quote_nonces;")
            .expect("drop the nonce table");
    }

    let outcome = store.burn_quote_nonce("requirement-2", Some(EXPIRY_MS));
    assert!(
        matches!(outcome, Err(BillingError::Storage(_))),
        "an unreachable ledger is an error, never a burn: {outcome:?}",
    );

    // The point of the assertion above, stated the other way round: there is
    // no success value on this path that a caller could mistake for a burn.
    assert!(
        !matches!(outcome, Ok(QuoteNonceBurn::Fresh)),
        "a failed burn must never report that the nonce was spent",
    );
}
