// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-tenant gapless sequence numbers for evidence records (WOR-2384).
//!
//! A SIEM ingesting `mcp_governance_decision` events over a lossy
//! transport (a webhook that drops a batch, a queue that overran) has
//! no way to tell "nothing happened" from "something happened and we
//! never heard about it" unless the records themselves carry a counter
//! it can check for holes. [`next_seq`] is that counter: strictly
//! monotonic per tenant, starting at 1, with no gaps under concurrent
//! callers, so a receiver that sees `1, 2, 4` for a tenant knows exactly
//! one record is missing without cross-referencing anything else.
//!
//! # Bounded, mirroring the egress sightings inventory
//!
//! `tenant_id` is caller-controlled (it comes off the resolved request
//! principal, ultimately from a header or a token an untrusted caller
//! presented), so a process-lifetime map keyed by it is a
//! memory-exhaustion knob if left unbounded. This registry caps itself
//! at [`MAX_TRACKED_TENANTS`] distinct tenants, the same bounded-map
//! hygiene `crates/sbproxy-security/src/egress.rs`'s sightings inventory
//! already applies to a different caller-controlled key space.
//!
//! The two hygienes differ in one respect. The sightings inventory can
//! simply refuse a new key once full, because a sighting nobody records
//! is still visible everywhere else that call site already logs.
//! [`next_seq`] cannot do that: it has to return *a* value, because the
//! call site building the evidence record has no other slot to put in
//! `sbproxy.evidence.seq`. So a tenant past the cap does not get
//! refused; it gets routed to a single shared overflow counter (see
//! [`OVERFLOW_TENANT`]) instead of a dedicated one, and every one of
//! those lookups ticks
//! [`crate::metrics::record_evidence_seq_tenant_cap`] so the loss of
//! per-tenant gaplessness past the cap is itself an observable signal
//! rather than a silent downgrade.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

/// Ceiling on the number of tenants this process tracks a dedicated
/// sequence counter for.
///
/// 4096 mirrors `EGRESS_INVENTORY_MAX_ENTRIES`'s order of magnitude:
/// generous for any real multi-tenant deployment's active tenant count,
/// small enough that filling it costs kilobytes, not a resource
/// exhaustion.
pub const MAX_TRACKED_TENANTS: usize = 4096;

/// The bucket every tenant past [`MAX_TRACKED_TENANTS`] shares.
///
/// A NUL prefix keeps this out of the space of tenant ids the rest of
/// the proxy actually mints (an empty string is already the
/// single-tenant sentinel elsewhere; this is deliberately not that
/// either), so a real tenant can never collide with the overflow bucket
/// by having the bad luck to be named the same thing.
const OVERFLOW_TENANT: &str = "\u{0}sbproxy-evidence-seq-overflow";

/// Registry state: one atomic counter per tracked tenant, guarded by a
/// single lock. The lock is held only for the lookup-or-insert; the
/// values are atomics so a caller that only needs the increment (every
/// caller, today) pays one `fetch_add` under the lock rather than a
/// read-modify-write race a plain `u64` would need the lock to prevent
/// anyway.
struct SeqRegistry {
    counters: HashMap<String, AtomicU64>,
}

fn registry() -> &'static Mutex<SeqRegistry> {
    static REGISTRY: std::sync::OnceLock<Mutex<SeqRegistry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(SeqRegistry {
            counters: HashMap::new(),
        })
    })
}

/// Latches true the first time the registry refuses a new tenant its
/// own counter, so the saturation warning logs once per process rather
/// than once per overflowing call, mirroring
/// `egress_inventory_saturated` in `sbproxy-security`.
fn registry_saturated() -> &'static std::sync::atomic::AtomicBool {
    static SATURATED: std::sync::OnceLock<std::sync::atomic::AtomicBool> =
        std::sync::OnceLock::new();
    SATURATED.get_or_init(|| std::sync::atomic::AtomicBool::new(false))
}

/// Hand out the next sequence value for `tenant_id`.
///
/// Starts at 1. Strictly monotonic and gapless per tenant under
/// concurrent callers: the increment is one atomic `fetch_add` on that
/// tenant's own counter, so two threads calling this for the same
/// tenant at once still hand out two distinct, consecutive values
/// rather than racing a read-modify-write and losing one.
///
/// Distinct tenants have fully independent sequences; tenant `"acme"`
/// reaching 40 says nothing about where tenant `"globex"` is.
///
/// Once this process has seen [`MAX_TRACKED_TENANTS`] distinct tenants,
/// the next new one does not get a dedicated counter: it draws from a
/// single shared fallback shared by every tenant past the cap (see the
/// module docs), and [`crate::metrics::record_evidence_seq_tenant_cap`]
/// ticks on every such call so the condition is observable rather than
/// a silent loss of the per-tenant guarantee.
pub fn next_seq(tenant_id: &str) -> u64 {
    let mut guard = registry().lock();
    next_seq_capped(&mut guard.counters, tenant_id, MAX_TRACKED_TENANTS)
}

/// The actual lookup-or-insert-or-overflow logic, parameterized on the
/// map and the cap rather than reaching for the process-global registry
/// directly.
///
/// Split out so the overflow branch is unit-testable against a small,
/// throwaway `cap` and a local map: filling the real
/// [`MAX_TRACKED_TENANTS`] (4096) against the actual process-global
/// registry inside a test would permanently saturate it for every other
/// test sharing this test binary's process, which is exactly the kind
/// of cross-test global-state pollution this crate's own tests
/// elsewhere go out of their way to avoid.
fn next_seq_capped(counters: &mut HashMap<String, AtomicU64>, tenant_id: &str, cap: usize) -> u64 {
    if let Some(counter) = counters.get(tenant_id) {
        return counter.fetch_add(1, Ordering::SeqCst);
    }
    if counters.len() >= cap {
        if !registry_saturated().swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "sbproxy::evidence",
                max_tenants = cap,
                "evidence sequence registry is full; new tenants share a fallback counter"
            );
        }
        crate::metrics::record_evidence_seq_tenant_cap();
        let counter = counters
            .entry(OVERFLOW_TENANT.to_string())
            .or_insert_with(|| AtomicU64::new(1));
        return counter.fetch_add(1, Ordering::SeqCst);
    }
    let counter = counters
        .entry(tenant_id.to_string())
        .or_insert_with(|| AtomicU64::new(1));
    counter.fetch_add(1, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// A fresh tenant id per test, so tests running in the same binary
    /// (this registry is process-global) never share a counter and
    /// never see each other's cap-overflow state.
    fn unique_tenant(label: &str) -> String {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("sbproxy-test-{label}-{n}")
    }

    #[test]
    fn starts_at_one_and_is_strictly_monotonic_for_one_tenant() {
        let tenant = unique_tenant("monotonic");
        assert_eq!(next_seq(&tenant), 1);
        assert_eq!(next_seq(&tenant), 2);
        assert_eq!(next_seq(&tenant), 3);
    }

    #[test]
    fn distinct_tenants_have_independent_sequences() {
        let a = unique_tenant("a");
        let b = unique_tenant("b");
        assert_eq!(next_seq(&a), 1);
        assert_eq!(next_seq(&a), 2);
        // `b`'s first call is still 1: it has never been seen before,
        // and `a` having already reached 2 must not leak into it.
        assert_eq!(next_seq(&b), 1);
        assert_eq!(next_seq(&a), 3);
        assert_eq!(next_seq(&b), 2);
    }

    #[test]
    fn two_tenants_interleaved_under_concurrency_each_produce_a_gapless_run() {
        // WOR-2384 test (a): spawn threads for two tenants and confirm
        // each tenant's collected values are exactly `1..=N` with no
        // duplicate and no gap, which a plain (non-atomic) counter
        // could fail under exactly this interleaving.
        const CALLS_PER_TENANT: usize = 200;
        const THREADS_PER_TENANT: usize = 8;

        let tenant_a = Arc::new(unique_tenant("interleaved-a"));
        let tenant_b = Arc::new(unique_tenant("interleaved-b"));

        // Two tenants' worth of threads, spawned interleaved (a, b, a,
        // b, ...) so the two tenants' calls actually race each other
        // rather than running as two back-to-back serial batches.
        let mut handles: Vec<(&'static str, std::thread::JoinHandle<Vec<u64>>)> = Vec::new();
        for _ in 0..THREADS_PER_TENANT {
            let a = tenant_a.clone();
            handles.push((
                "a",
                std::thread::spawn(move || {
                    (0..(CALLS_PER_TENANT / THREADS_PER_TENANT))
                        .map(|_| next_seq(&a))
                        .collect()
                }),
            ));
            let b = tenant_b.clone();
            handles.push((
                "b",
                std::thread::spawn(move || {
                    (0..(CALLS_PER_TENANT / THREADS_PER_TENANT))
                        .map(|_| next_seq(&b))
                        .collect()
                }),
            ));
        }

        let mut results_a = Vec::new();
        let mut results_b = Vec::new();
        for (which, handle) in handles {
            let seen = handle.join().expect("worker thread panicked");
            if which == "a" {
                results_a.extend(seen);
            } else {
                results_b.extend(seen);
            }
        }

        for (label, mut results) in [("a", results_a), ("b", results_b)] {
            results.sort_unstable();
            let expected: Vec<u64> = (1..=results.len() as u64).collect();
            let unique: HashSet<u64> = results.iter().copied().collect();
            assert_eq!(
                unique.len(),
                results.len(),
                "tenant {label} produced a duplicate sequence value: {results:?}"
            );
            assert_eq!(
                results, expected,
                "tenant {label} has a gap: got {results:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn tenants_past_the_cap_share_the_overflow_counter_instead_of_stalling_or_panicking() {
        // Exercises `next_seq_capped` directly against a local,
        // throwaway map and a cap of 2, rather than filling the real
        // 4096-entry process-global registry (see that function's doc
        // comment for why doing this against the real registry inside
        // a test would be its own bug).
        let mut counters: HashMap<String, AtomicU64> = HashMap::new();
        let cap = 2;

        assert_eq!(next_seq_capped(&mut counters, "t1", cap), 1);
        assert_eq!(next_seq_capped(&mut counters, "t2", cap), 1);
        // The map is now at the cap. A tenant never seen before does
        // not get a dedicated counter, but it still gets a real,
        // monotonically increasing value rather than panicking,
        // hanging, or silently returning the same number twice.
        let third = next_seq_capped(&mut counters, "t3", cap);
        let fourth = next_seq_capped(&mut counters, "t4", cap);
        assert!(third >= 1);
        assert!(
            fourth > third,
            "overflow tenants must still advance monotonically: {third} then {fourth}"
        );
        // A tenant that already had a dedicated counter before the cap
        // was hit is unaffected: its own sequence keeps going exactly
        // where it left off.
        assert_eq!(next_seq_capped(&mut counters, "t1", cap), 2);
    }
}
