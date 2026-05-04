//! SLO burn-rate regression (Wave 1 / Q1.13).
//!
//! Per `docs/adr-slo-alert-taxonomy.md` (A1.6), every SLO has a
//! multi-window multi-burn-rate alert pair. This test replays a fixture
//! traffic profile and asserts the right alerts fire (and only the
//! right ones fire) when the error rate or latency cross thresholds.
//!
//! Window pairs and thresholds from the ADR (page tier):
//!
//! | Window pair  | Burn rate | Time to budget burn |
//! |--------------|-----------|---------------------|
//! | 5m AND 1h    | 14.4×     | 2% of monthly in 1h |
//! | 30m AND 6h   | 6×        | 5% of monthly in 6h |
//! | 2h AND 24h   | 3×        | 10% of monthly in 24h |
//!
//! Fixture profile: configure SLO at 99% (1% error budget), drive
//! 100 successes and 5 errors over a simulated 1h window. Burn rate
//! at 1h is `0.05 / 0.01 = 5×`, which crosses the 30m/6h pair (6×
//! threshold trips on a tighter window) but NOT the 5m/1h 14.4× pair.
//!
//! Then add another 100 errors over a simulated additional hour.
//! Cumulative error rate crosses 14.4× and the page-tier alert fires.
//!
//! The test uses `golden_signals.rs` as the in-memory SLI source. The
//! burn-rate evaluator (`sbproxy_observe::alerting::burn_rate`) is
//! NEW in R1.1 / A1.6 implementation; until it lands the assertions
//! that depend on it are `#[ignore]`d. The fixture-shape test runs
//! today as a contract floor.

use std::time::Duration;

/// One synthetic minute of traffic. Every fixture is built out of
/// these so the test is self-contained and replay is deterministic.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // p99_ms is read by the latency-side test once R1.1 lands.
struct MinuteSample {
    requests: u64,
    errors: u64,
    /// p99 latency observed in this minute, ms.
    p99_ms: f64,
}

/// Fixture profile A: 105 requests over 60 minutes with 5 errors all
/// concentrated in the last 15 minutes. Hits the 30m/6h burn pair but
/// stays under the 5m/1h 14.4× threshold because the per-5m error
/// rate never spikes high enough.
fn profile_5_errors_over_one_hour() -> Vec<MinuteSample> {
    let mut out = Vec::with_capacity(60);
    // Minutes 0..=44: 2 requests/minute, 0 errors.
    for _ in 0..45 {
        out.push(MinuteSample {
            requests: 2,
            errors: 0,
            p99_ms: 18.0,
        });
    }
    // Minutes 45..=59: 1 request/minute with one error every 3 minutes.
    for i in 45..60 {
        out.push(MinuteSample {
            requests: 1,
            errors: if i % 3 == 0 { 1 } else { 0 },
            p99_ms: 22.0,
        });
    }
    debug_assert_eq!(
        out.iter().map(|m| m.requests).sum::<u64>(),
        105,
        "profile A request total"
    );
    debug_assert_eq!(
        out.iter().map(|m| m.errors).sum::<u64>(),
        5,
        "profile A error total"
    );
    out
}

/// Fixture profile B: profile A with 100 additional errors stacked
/// across the second hour. Cumulative error rate crosses the 14.4×
/// threshold; the page-tier alert MUST fire.
fn profile_full_burn() -> Vec<MinuteSample> {
    let mut out = profile_5_errors_over_one_hour();
    for _ in 60..120 {
        out.push(MinuteSample {
            requests: 2,
            errors: 2, // every request errors out
            p99_ms: 110.0,
        });
    }
    debug_assert_eq!(out.len(), 120);
    out
}

/// Compute the simple ratio used by the SLO computation. The real
/// burn-rate engine in R1.1 keeps a sliding window per metric family
/// and emits per-(window, burn-rate) alerts; this helper is a sanity
/// check the fixture matches the expected shape.
fn error_rate(samples: &[MinuteSample]) -> f64 {
    let total: u64 = samples.iter().map(|s| s.requests).sum();
    let err: u64 = samples.iter().map(|s| s.errors).sum();
    if total == 0 {
        0.0
    } else {
        err as f64 / total as f64
    }
}

#[test]
fn fixture_profile_a_under_threshold_for_short_window() {
    let prof = profile_5_errors_over_one_hour();
    let er = error_rate(&prof);
    // 5/105 = ~4.76% which is 4.76× the 1% budget; under 14.4×, over 3×.
    assert!(er > 0.04 && er < 0.06, "profile A error rate: {er}");
}

#[test]
fn fixture_profile_b_above_threshold_for_short_window() {
    let prof = profile_full_burn();
    let er = error_rate(&prof);
    // 105 errors out of 225 = ~46.6% which is 46× the 1% budget.
    assert!(er > 0.4, "profile B error rate: {er}");
}

/// Replay profile A through the SLO engine and assert the right alerts
/// fire. Per the ADR:
/// - SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H (5m/1h, 14.4×): MUST NOT fire.
/// - SBPROXY-SUBSTRATE-AVAIL-INBOUND-6H (30m/6h, 6×): MUST fire.
/// - SBPROXY-SUBSTRATE-AVAIL-INBOUND-24H (2h/24h, 3×): would fire on
///   sustained burn but the 24h window is not yet full; expected not
///   to fire on a 1h replay.
#[test]
#[ignore = "TODO(wave3): R1.1 alerting module landed in sbproxy-observe but the burn-rate (multiwindow) engine is not implemented; only `check_slo_violation(p99)` exists. `replay_and_evaluate` is still a no-op stub returning an empty AlertSnapshot."]
fn slo_burn_rate_partial_burn_fires_six_hour_alert_only() {
    let prof = profile_5_errors_over_one_hour();
    let alerts = replay_and_evaluate(&prof, slo_target(0.99));

    assert!(
        !alerts.fired("SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H"),
        "5m/1h 14.4× alert must not fire on partial burn; alerts={:?}",
        alerts.fired_names()
    );
    assert!(
        alerts.fired("SBPROXY-SUBSTRATE-AVAIL-INBOUND-6H"),
        "30m/6h 6× alert MUST fire on partial burn; alerts={:?}",
        alerts.fired_names()
    );
    assert!(
        !alerts.fired("SBPROXY-SUBSTRATE-AVAIL-INBOUND-24H"),
        "2h/24h 3× alert must not fire when 24h window is unfilled"
    );
}

/// Replay profile B (full burn) and assert the page-tier alert fires.
#[test]
#[ignore = "TODO(wave3): R1.1 alerting module landed in sbproxy-observe but the burn-rate (multiwindow) engine is not implemented; only `check_slo_violation(p99)` exists. `replay_and_evaluate` is still a no-op stub returning an empty AlertSnapshot."]
fn slo_burn_rate_full_burn_fires_one_hour_page_alert() {
    let prof = profile_full_burn();
    let alerts = replay_and_evaluate(&prof, slo_target(0.99));

    assert!(
        alerts.fired("SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H"),
        "5m/1h 14.4× alert MUST fire on full burn; alerts={:?}",
        alerts.fired_names()
    );
    // The 6h alert from the partial-burn case MUST also fire (an
    // upgrade from ticket to page is fine; a regression from page back
    // to ticket would be a serious bug).
    assert!(
        alerts.fired("SBPROXY-SUBSTRATE-AVAIL-INBOUND-6H"),
        "30m/6h 6× alert MUST also fire on full burn"
    );
}

/// Latency-side coverage: drive a profile where p99 latency crosses
/// the SLO-LATENCY-P99 threshold (50 ms per ADR) for a sustained 5
/// minutes. SBPROXY-SUBSTRATE-LATENCY-P99 page tier MUST fire.
#[test]
#[ignore = "TODO(wave3): R1.1 latency SLO check exists (`check_slo_violation`) but the multiwindow burn-rate engine + replay harness is not yet wired."]
fn slo_latency_p99_breach_fires_page_alert() {
    let mut prof = vec![
        MinuteSample {
            requests: 100,
            errors: 0,
            p99_ms: 22.0,
        };
        55
    ];
    // 200 ms is 4x the 50 ms threshold so the burn rate is high enough
    // to trip the 5m / 1h pair quickly.
    prof.extend(std::iter::repeat_n(
        MinuteSample {
            requests: 100,
            errors: 0,
            p99_ms: 200.0,
        },
        5,
    ));

    let alerts = replay_and_evaluate(&prof, slo_target(0.99));
    assert!(
        alerts.fired("SBPROXY-SUBSTRATE-LATENCY-P99"),
        "p99 latency breach MUST fire page-tier alert; alerts={:?}",
        alerts.fired_names()
    );
}

// --- Test-only stubs ---
//
// These wrap a future `sbproxy-observe::alerting::burn_rate` engine
// the implementation lands in R1.1. The shape locked here:
//
//     pub struct AlertSnapshot { /* ... */ }
//     impl AlertSnapshot {
//         pub fn fired(&self, name: &str) -> bool;
//         pub fn fired_names(&self) -> Vec<String>;
//     }
//     pub fn replay_and_evaluate(samples: &[MinuteSample], target: f64) -> AlertSnapshot;
//     pub fn slo_target(s: f64) -> f64;
//
// Until then, the ignored tests above prove the contract review
// surface; ungated tests assert fixture shape only.

struct AlertSnapshot {
    fired: Vec<String>,
}

impl AlertSnapshot {
    fn fired(&self, name: &str) -> bool {
        self.fired.iter().any(|n| n == name)
    }
    fn fired_names(&self) -> Vec<String> {
        self.fired.clone()
    }
}

fn slo_target(s: f64) -> f64 {
    s
}

fn replay_and_evaluate(_samples: &[MinuteSample], _target: f64) -> AlertSnapshot {
    // Stub: a real implementation drives a virtual clock at 1 minute
    // tick over the samples, feeds them into a burn-rate evaluator,
    // and returns the set of alerts that fired during the replay.
    let _ = Duration::from_secs(60);
    AlertSnapshot { fired: Vec::new() }
}
