// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! What the meter says about itself, and the seam it says it through.
//!
//! # Metrics are not the billing record
//!
//! Say it before anything else, because everything below reads like an
//! invoice if you skip this paragraph. The signed chain in
//! [`crate::ledger`] is the authoritative record of what was consumed.
//! These observations are operational telemetry and they are lossy by
//! construction: an OTLP `PeriodicReader` drops a batch when export fails,
//! cumulative counters reset to zero when the process restarts, and every
//! aggregation window destroys the individual events that went into it. A
//! number read off a dashboard is therefore a number that may be missing a
//! restart's worth of traffic, a failed export's worth of traffic, or both,
//! with nothing anywhere saying so.
//!
//! An invoice built from a Grafana panel is quietly wrong, and quietly is
//! the problem: it will agree with the chain most months. Reconcile against
//! the chain, and use these to find out whether the meter is healthy.
//!
//! # Why a seam rather than a metrics dependency
//!
//! This crate depends on no other crate in the workspace and pulls in no
//! metrics library, so it cannot name a Prometheus family or an
//! OpenTelemetry instrument. It also should not have to: an operator
//! metering a plain REST API gets the hash chain either way, and what they
//! graph it with is their business.
//!
//! So the meter reports through [`MeterObserver`] and somebody else decides
//! what that means. `sbproxy-observe` installs the implementation that
//! turns these calls into the `sbproxy_meter_*` families; a process that
//! installs nothing pays one relaxed atomic load per observation and emits
//! nothing at all.
//!
//! # Divergence is an alert, not enforcement
//!
//! Two independent numbers are reported for the same traffic:
//! [`MeterObserver::units`] carries what the meter counted, and
//! [`MeterObserver::chained`] carries what actually reached the signed
//! chain. They should agree. When they do not, either receipts were dropped
//! or something is writing units outside the chain, and both are worth
//! knowing.
//!
//! Neither is worth failing traffic over, so divergence never reaches
//! [`FailurePosture`] and never refuses a request. It is a counter and a
//! documented alert. The posture stays reserved for the case where the
//! meter genuinely could not write what it owed, which
//! [`MeterObserver::chain_gap`] reports and which is the marker that says
//! revenue went unbilled.

use std::sync::OnceLock;

use crate::event::{MeteredEvent, Unit, UnitSource};
use crate::outcome::{Billable, BillableOutcome};

/// The posture in force when the meter could not write what it owed.
///
/// Mirrors the four postures the proxy's configuration surface offers, as a
/// local enum rather than a shared type: this crate cannot see
/// `sbproxy-config`, and the label value on a metric is a wire string
/// anyway. The spellings [`FailurePosture::as_str`] returns are the ones an
/// operator reads in their own YAML, so a `failure_mode` label matches the
/// key that produced it without a translation table in the middle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailurePosture {
    /// The request was refused rather than served unmetered.
    Closed,
    /// The request was served and nothing was claimed.
    Open,
    /// The request was served, the guarantee was marked as not made, and
    /// the hole is countable. This is what a best-effort append that failed
    /// leaves behind, and the default posture for metering, because billing
    /// is not a security boundary and a full disk should not take an API
    /// down.
    Degraded,
    /// The request was served and the decision the meter would have taken
    /// was recorded instead of applied.
    Observe,
}

impl FailurePosture {
    /// Stable snake-case name, used as the `failure_mode` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::Degraded => "degraded",
            Self::Observe => "observe",
        }
    }
}

/// What one chained entry contributes to the meter's own reconciliation.
///
/// Returned by [`crate::ledger::LedgerPayload::chain_contribution`]. A
/// payload that returns `None` is invisible to the divergence check, which
/// is the honest answer for a payload that carries no unit counts: counting
/// it on one side of a comparison and not the other would manufacture a
/// disagreement rather than detect one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainContribution<'a> {
    /// The billing account this entry is charged to.
    pub tenant_id: &'a str,
    /// How many units the entry carries.
    pub units: u64,
}

/// Where the meter's self-observation goes.
///
/// Six methods, five of which map one-to-one onto a metric family. The
/// exception is [`MeterObserver::chained`], which has no family of its own
/// and exists to feed the counter-versus-chain comparison; publishing it
/// would put a second authoritative-looking unit total on a dashboard next
/// to the first, which is the confusion this module opens by warning
/// against.
///
/// Implementations are called on the metering path and must not block, must
/// not panic, and must not fail a request. Nothing here returns a `Result`
/// for exactly that reason: there is no answer an observer could give that
/// the meter would be right to act on.
pub trait MeterObserver: Send + Sync {
    /// Units the meter counted for a tenant, by unit name and provenance.
    ///
    /// `unit` is operator-chosen and therefore unbounded; an implementation
    /// is responsible for keeping it inside a cardinality budget.
    fn units(&self, tenant_id: &str, unit: &str, source: UnitSource, count: u64);

    /// One attempt classified by the outcome table: what happened, and what
    /// the operator's answer for it was.
    fn receipt(&self, tenant_id: &str, outcome: BillableOutcome, billable: Billable);

    /// Units that reached the signed chain. The other half of the
    /// divergence comparison; see the module documentation.
    fn chained(&self, tenant_id: &str, units: u64);

    /// The meter owed a record and could not write it. Nonzero means
    /// revenue went unbilled, which is the thing worth alerting on.
    fn chain_gap(&self, tenant_id: &str, failure_mode: FailurePosture);

    /// The chain head after a successful append. Flat under traffic means a
    /// stalled meter, which no counter can show on its own.
    fn chain_head(&self, seq: u64);

    /// How long an append took. Appends hold a mutex and flush, so this is
    /// where backpressure on the metering path becomes visible.
    fn append_duration(&self, seconds: f64);
}

/// Installed once per process, by whoever owns the metrics surface.
static OBSERVER: OnceLock<&'static dyn MeterObserver> = OnceLock::new();

/// Route the meter's self-observation to `observer`.
///
/// Returns `false` when an observer was already installed, and leaves the
/// first one in place. Idempotent rather than last-write-wins because two
/// observers would double-count every unit, and a silently doubled billing
/// counter is worse than a second install that quietly did nothing.
pub fn set_observer(observer: &'static dyn MeterObserver) -> bool {
    OBSERVER.set(observer).is_ok()
}

/// The installed observer, or `None` in a process that installed none.
fn observer() -> Option<&'static dyn MeterObserver> {
    OBSERVER.get().copied()
}

/// Report one settled attempt: the operator's answer for its outcome, and
/// every unit that survived it.
///
/// `billed` is the already-computed result of
/// [`crate::outcome::OutcomeTable::billable_units`] rather than something
/// recomputed here, so observation costs a walk of a slice the caller was
/// holding anyway.
///
/// The receipt is reported even when nothing bills. An attempt that billed
/// zero still happened, and a `receipts_total` that counted only the
/// billable ones would make "we served you and charged you nothing" and "we
/// never saw your call" the same picture.
pub fn observe_settled_event(event: &MeteredEvent, billable: Billable, billed: &[Unit]) {
    let Some(observer) = observer() else {
        return;
    };
    let tenant_id = event.subject.tenant.as_str();
    observer.receipt(tenant_id, event.outcome, billable);
    for unit in billed {
        observer.units(tenant_id, &unit.name, unit.source, unit.count);
    }
}

/// Report that the meter owed a record and could not write it.
///
/// `tenant_id` may be empty when the failure happened somewhere that does
/// not know who was being charged; the observer is expected to substitute a
/// bounded placeholder rather than emit an empty label.
pub fn observe_chain_gap(tenant_id: &str, failure_mode: FailurePosture) {
    if let Some(observer) = observer() {
        observer.chain_gap(tenant_id, failure_mode);
    }
}

/// Report a successful append: the new chain head, how long it took, and
/// what the entry contributes to the divergence comparison.
pub fn observe_chain_append(seq: u64, seconds: f64, contribution: Option<ChainContribution<'_>>) {
    let Some(observer) = observer() else {
        return;
    };
    observer.chain_head(seq);
    observer.append_duration(seconds);
    if let Some(contribution) = contribution {
        observer.chained(contribution.tenant_id, contribution.units);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Evidence, Subject};
    use crate::outcome::OutcomeTable;
    use std::sync::Mutex;

    /// A recording observer. Installed by exactly one test in this module,
    /// because [`set_observer`] is process-wide and first-write-wins.
    #[derive(Default)]
    struct Recorder {
        lines: Mutex<Vec<String>>,
    }

    static RECORDER: OnceLock<Recorder> = OnceLock::new();

    fn recorder() -> &'static Recorder {
        RECORDER.get_or_init(Recorder::default)
    }

    impl MeterObserver for Recorder {
        fn units(&self, tenant_id: &str, unit: &str, source: UnitSource, count: u64) {
            self.push(format!(
                "units {tenant_id} {unit} {} {count}",
                source.as_str()
            ));
        }
        fn receipt(&self, tenant_id: &str, outcome: BillableOutcome, billable: Billable) {
            self.push(format!(
                "receipt {tenant_id} {} {}",
                outcome.as_str(),
                billable.as_str()
            ));
        }
        fn chained(&self, tenant_id: &str, units: u64) {
            self.push(format!("chained {tenant_id} {units}"));
        }
        fn chain_gap(&self, tenant_id: &str, failure_mode: FailurePosture) {
            self.push(format!("gap {tenant_id} {}", failure_mode.as_str()));
        }
        fn chain_head(&self, seq: u64) {
            self.push(format!("head {seq}"));
        }
        fn append_duration(&self, _seconds: f64) {
            self.push("append".to_string());
        }
    }

    impl Recorder {
        fn push(&self, line: String) {
            self.lines.lock().expect("recorder mutex").push(line);
        }
        fn drain(&self) -> Vec<String> {
            std::mem::take(&mut *self.lines.lock().expect("recorder mutex"))
        }
    }

    fn table() -> OutcomeTable {
        OutcomeTable::from_entries(&[
            (BillableOutcome::Delivered, Billable::Yes),
            (BillableOutcome::ClientDisconnected, Billable::Partial),
            (BillableOutcome::Origin4xx, Billable::No),
            (BillableOutcome::Origin5xx, Billable::No),
            (BillableOutcome::PolicyBlocked, Billable::No),
            (BillableOutcome::RateLimited, Billable::No),
            (BillableOutcome::CacheHit, Billable::Yes),
            (BillableOutcome::Retry, Billable::Collapse),
        ])
        .expect("a complete table builds")
    }

    fn event(outcome: BillableOutcome) -> MeteredEvent {
        MeteredEvent {
            subject: Subject {
                tenant: "acme".to_string(),
                key_id: None,
                agent: None,
            },
            route: "search".to_string(),
            request_digest: String::new(),
            response_digest: Some("sha-256=:x:".to_string()),
            outcome,
            units: vec![Unit::new(
                "api_call",
                1,
                Evidence::RouteWeight {
                    config_revision: "a3f19c8b2d04".to_string(),
                },
            )],
            claim_id: "claim_1".to_string(),
        }
    }

    #[test]
    fn every_observation_reaches_the_installed_observer() {
        // Ignored on purpose. `recorder()` is the only observer this module
        // ever installs, so whether this call or a sibling test's call won
        // the race changes nothing: the drains below fail if anything else
        // is installed, because nothing else would record into it.
        let _ = set_observer(recorder());
        let table = table();

        let delivered = event(BillableOutcome::Delivered);
        let billed = table.billable_units(&delivered);
        observe_settled_event(&delivered, table.billable(delivered.outcome), &billed);
        assert_eq!(
            recorder().drain(),
            vec![
                "receipt acme delivered yes".to_string(),
                "units acme api_call route_weight 1".to_string(),
            ]
        );

        // An outcome that bills nothing still reports its receipt, so a
        // free call and an unseen call do not look the same.
        let blocked = event(BillableOutcome::PolicyBlocked);
        let billed = table.billable_units(&blocked);
        observe_settled_event(&blocked, table.billable(blocked.outcome), &billed);
        assert_eq!(
            recorder().drain(),
            vec!["receipt acme policy_blocked no".to_string()]
        );

        observe_chain_gap("acme", FailurePosture::Degraded);
        observe_chain_append(
            12,
            0.0004,
            Some(ChainContribution {
                tenant_id: "acme",
                units: 1,
            }),
        );
        assert_eq!(
            recorder().drain(),
            vec![
                "gap acme degraded".to_string(),
                "head 12".to_string(),
                "append".to_string(),
                "chained acme 1".to_string(),
            ]
        );
    }

    #[test]
    fn a_second_install_is_refused_rather_than_doubling_every_counter() {
        // Whichever of the two tests in this file runs second sees the
        // first one's observer already installed. Both orders are asserted
        // by the same call, because the meaningful claim is that installing
        // twice never yields two live observers.
        let first = set_observer(recorder());
        let second = set_observer(recorder());
        assert!(!(first && second), "at most one install may succeed");
    }

    #[test]
    fn every_posture_has_a_distinct_wire_spelling() {
        let spellings: Vec<&str> = [
            FailurePosture::Closed,
            FailurePosture::Open,
            FailurePosture::Degraded,
            FailurePosture::Observe,
        ]
        .into_iter()
        .map(FailurePosture::as_str)
        .collect();
        assert_eq!(spellings, ["closed", "open", "degraded", "observe"]);
    }
}
