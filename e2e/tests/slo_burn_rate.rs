//! SLO burn-rate regression for the in-process evaluator.
//!
//! These fixtures replay minute-resolution traffic through
//! `sbproxy_observe::alerting::burn_rate` and assert which objectives fire.
//! They spawn no proxy: the evaluator is a pure function of a sample slice,
//! and the samples the live engine feeds it come from a ring this test can
//! build directly.
//!
//! # What the in-process evaluator is for
//!
//! It publishes exactly one availability objective,
//! `SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H`: the last 60 minutes against the
//! configured target, firing at 14.4x. That is the fast-burn page tier and
//! nothing else.
//!
//! The other two tiers an operator pages on live in
//! `deploy/alerts/alerting-rules.yml` and are evaluated by Prometheus
//! against retained series:
//!
//! | Objective | Windows | Burn rate | Tier |
//! |---|---|---|---|
//! | `SBPROXY-SUBSTRATE-AVAIL-1H` | 5m AND 1h | 14.4x | page |
//! | `SBPROXY-SUBSTRATE-AVAIL-6H` | 30m AND 6h | 6x | page |
//! | `SBPROXY-SUBSTRATE-AVAIL-24H` | 1h AND 24h | 3x | ticket |
//!
//! Both 6h and 24h need history that outlives the process. The in-process
//! ring is 1,440 minutes, holds nothing across a restart, and reads healthy
//! for as long as it is refilling, so it is the wrong place to answer them
//! from. What it can answer, and the reason it exists, is a fast burn in a
//! deployment that has no scrape target pointed at it.
//!
//! This file previously asserted the opposite of all of that, because it
//! was written against a version of the evaluator whose 1H tier summed
//! every sample it was given and whose 6H tier read a 30-minute tail.

use sbproxy_observe::alerting::burn_rate::{replay_and_evaluate, slo_target, MinuteSample};

/// The one objective the in-process evaluator publishes.
const ONE_HOUR: &str = "SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H";
/// Objectives this evaluator used to publish and no longer does. Prometheus
/// owns both; nothing in process may emit either name again.
const RETIRED: [&str; 2] = [
    "SBPROXY-SUBSTRATE-AVAIL-INBOUND-6H",
    "SBPROXY-SUBSTRATE-AVAIL-INBOUND-24H",
];
/// The 99% availability target every fixture here runs against, so one
/// percent of requests is the whole error budget and a burn rate is just
/// the error percentage.
const TARGET: f64 = 0.99;

/// `count` identical minutes of traffic. `p99_ms` sits far below the 50 ms
/// latency threshold so availability fixtures cannot trip the latency
/// objective by accident.
fn minutes(count: usize, requests: u64, errors: u64) -> Vec<MinuteSample> {
    vec![
        MinuteSample {
            requests,
            errors,
            p99_ms: 18.0,
        };
        count
    ]
}

/// A full ring: `head` minutes of one shape followed by `tail` of another.
fn profile(head: Vec<MinuteSample>, tail: Vec<MinuteSample>) -> Vec<MinuteSample> {
    let mut out = head;
    out.extend(tail);
    out
}

#[test]
fn an_hour_of_burn_above_the_page_threshold_fires_the_one_hour_objective() {
    // Twenty-three hours of clean traffic, then the last hour fails 20% of
    // requests. That is 20x the budget over the window the objective names.
    let prof = profile(minutes(23 * 60, 100, 0), minutes(60, 100, 20));
    let alerts = replay_and_evaluate(&prof, slo_target(TARGET));

    assert!(
        alerts.fired(ONE_HOUR),
        "a 20x hour must page; alerts={:?}",
        alerts.fired_names()
    );
}

#[test]
fn a_burn_that_ended_an_hour_ago_no_longer_fires() {
    // The mirror image: a day-long outage that recovered an hour ago. The
    // ring still holds every failing minute and the objective must not,
    // because the hour it reads is clean.
    let prof = profile(minutes(23 * 60, 100, 50), minutes(60, 100, 0));
    let alerts = replay_and_evaluate(&prof, slo_target(TARGET));

    assert_eq!(
        alerts.fired_names(),
        Vec::<String>::new(),
        "a recovered hour must be quiet even with a ring full of failures"
    );
}

#[test]
fn a_thirty_minute_burn_under_the_hourly_threshold_no_longer_fires() {
    // 15% failure for half an hour inside an otherwise clean hour. Over the
    // hour that averages 7.5x, under the page threshold. The retired 6H
    // tier fired here, off a 30-minute tail it called six hours; the
    // Prometheus 6x rule is the one that owns this shape now.
    let prof = profile(minutes(30, 100, 0), minutes(30, 100, 15));
    let alerts = replay_and_evaluate(&prof, slo_target(TARGET));

    assert_eq!(
        alerts.fired_names(),
        Vec::<String>::new(),
        "7.5x over the hour is under the 14.4x page threshold"
    );
}

#[test]
fn a_full_day_of_slow_burn_is_left_to_the_prometheus_ticket_tier() {
    // 3.1x sustained for 24 hours: real budget loss, and a ticket rather
    // than a page. deploy/alerts/alerting-rules.yml carries it as
    // SBPROXY-SUBSTRATE-AVAIL-24H against series that survive a restart.
    let prof = minutes(24 * 60, 1_000, 31);
    let alerts = replay_and_evaluate(&prof, slo_target(TARGET));

    assert_eq!(
        alerts.fired_names(),
        Vec::<String>::new(),
        "the slow-burn ticket tier is a Prometheus rule, not an in-process one"
    );
}

#[test]
fn less_than_an_hour_of_history_fires_nothing() {
    // Fifty-nine minutes in which every single request failed. The
    // objective is an hour, this is not an hour, and a partial window is
    // the state every process is in for an hour after it starts.
    let prof = minutes(59, 1, 1);
    let alerts = replay_and_evaluate(&prof, slo_target(TARGET));

    assert_eq!(
        alerts.fired_names(),
        Vec::<String>::new(),
        "a partial window must not answer for a full one"
    );
}

#[test]
fn the_retired_six_and_twenty_four_hour_objectives_are_never_published() {
    // Every shape that used to reach one of the retired tiers, replayed
    // together. Whatever else fires, neither name may appear.
    let shapes = [
        profile(minutes(30, 100, 0), minutes(30, 100, 50)),
        profile(minutes(23 * 60, 100, 50), minutes(60, 100, 0)),
        minutes(24 * 60, 1_000, 31),
        minutes(24 * 60, 100, 50),
    ];

    for prof in shapes {
        let alerts = replay_and_evaluate(&prof, slo_target(TARGET));
        for retired in RETIRED {
            assert!(
                !alerts.fired(retired),
                "{retired} is a Prometheus rule now; alerts={:?}",
                alerts.fired_names()
            );
        }
    }
}

#[test]
fn slo_latency_p99_breach_fires_page_alert() {
    // Latency is unchanged and was never part of the window defect: five
    // consecutive minutes above 50 ms fires the page tier, matching the
    // `for: 5m` on the Prometheus rule of the same name.
    let mut prof = minutes(55, 100, 0);
    prof.extend(std::iter::repeat_n(
        MinuteSample {
            requests: 100,
            errors: 0,
            p99_ms: 200.0,
        },
        5,
    ));

    let alerts = replay_and_evaluate(&prof, slo_target(TARGET));
    assert!(
        alerts.fired("SBPROXY-SUBSTRATE-LATENCY-P99"),
        "p99 latency breach MUST fire page-tier alert; alerts={:?}",
        alerts.fired_names()
    );
    assert!(
        !alerts.fired(ONE_HOUR),
        "a latency breach with no errors must not open an availability incident"
    );
}
