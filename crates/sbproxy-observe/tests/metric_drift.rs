// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The metric drift guard.
//!
//! Replaces `dashboard_metrics_match.rs`, which scanned `dashboards/grafana/`
//! only and asserted that each referenced name appeared *somewhere* in the
//! source tree as a substring. Both halves of that were too weak to catch
//! anything. It never looked at `dashboards/prometheus/` or `deploy/alerts/`,
//! which is where the broken SLO lived, and a substring match is satisfied by
//! the metric's own declaration, so a family that was declared and never
//! incremented passed forever.
//!
//! What it missed, all of it live on `main` until this test landed:
//!
//! - `sbproxy_requests_total{status_class!="5xx"}` selected on a label that has
//!   never existed. An absent label is the empty string in PromQL, `"" != "5xx"`
//!   is true, so the matcher took every series, numerator equalled denominator,
//!   and the availability SLO read exactly 1.0 forever. Three alerts, two of
//!   them page-tier, could not fire.
//! - Six metrics named by alert rules are not declared by any crate.
//! - Fifteen metrics are declared, registered, and scraped while nothing
//!   increments them.

use sbproxy_capability::scan::{self, ReferenceExemption};
use sbproxy_capability::{
    validate_metrics, CompatTier, MetricCapability, MetricKind, Registry, RegistryError,
    SupportLevel, Writer,
};
use sbproxy_observe::metric_registry::{
    run_scoped_label_gaps, tenant_label_gaps, METRICS, REFERENCE_EXEMPTIONS,
    RUN_SCOPED_LABEL_EXEMPTIONS, TENANT_LABEL_EXEMPTIONS, TENANT_SCOPED_METRICS,
};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-observe -> crates -> repo root")
        .to_path_buf()
}

fn report(what: &str, errors: &[RegistryError]) {
    assert!(
        errors.is_empty(),
        "{what}\n\n{}\n",
        errors
            .iter()
            .map(|error| format!("  - {error}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_registry_is_internally_consistent() {
    report(
        "The metric registry violates its own invariants.",
        &validate_metrics(METRICS),
    );
}

#[test]
fn every_declared_metric_is_classified() {
    report(
        "A metric is declared in code but missing from the registry. Every family \
         has to say what writes it and what we promise about its name, the same way \
         a new `serve:` schema field must be classified before it compiles.",
        &scan::verify_coverage(METRICS, &repo_root()),
    );
}

#[test]
fn every_stable_metric_has_a_production_writer() {
    report(
        "A metric claims a live writer that no production code calls. This is the \
         defect the registry exists to catch: the declaration is intact, the \
         recorder compiles, the scrape succeeds, and the value is always zero.",
        &scan::verify_writers(METRICS, &repo_root()),
    );
}

#[test]
fn every_dashboard_and_alert_rule_reads_a_live_metric_with_labels_that_exist() {
    let root = repo_root();
    let references = scan::query_references(&root);

    assert!(
        references.len() > 40,
        "the scanner found only {} metric references across dashboards/ and deploy/; \
         it is not reading the files it thinks it is",
        references.len()
    );

    report(
        "A dashboard or alert rule queries a metric that does not exist, is never \
         incremented, or carries a label the metric does not have. Any of the three \
         produces a panel that cannot draw and an alert that cannot fire.",
        &scan::verify_references(METRICS, &references, REFERENCE_EXEMPTIONS),
    );
}

#[test]
fn a_dead_metric_reference_needs_a_reason_and_a_ticket() {
    // The allow-list is the escape hatch, so it is the thing most likely to be
    // abused. An entry has to explain itself and name the ticket that removes
    // it; otherwise "known dead" decays back into "nobody noticed".
    for exemption in REFERENCE_EXEMPTIONS {
        let ReferenceExemption { metric, reason } = exemption;

        assert!(
            reason.len() > 40,
            "exemption for {metric} needs a real reason, not '{reason}'"
        );
        assert!(
            reason.contains("WOR-"),
            "exemption for {metric} must name the ticket that removes it: '{reason}'"
        );
        assert!(
            METRICS.iter().any(|m| m.name == *metric),
            "exemption for {metric} names a metric that is not in the registry"
        );
    }
}

#[test]
fn every_tenant_scoped_metric_carries_a_tenant_label() {
    // Multi-tenant enforcement, metrics half. A metric can have a live
    // writer and a truthful support level and still merge every tenant's
    // spend, tokens, or security verdicts into one series if nothing on it
    // says whose data it is. That failure is quieter than a dead metric:
    // the numbers are real, the panel draws, and the answer it gives is to
    // a question nobody asked. WOR-1896 was one instance of this shape of
    // bug (attribution declared but not reachable through
    // `snapshot_named`); this guard is the label-set half of the same
    // concern.
    report(
        "A metric is marked tenant-scoped in TENANT_SCOPED_METRICS but its label set \
         carries none of TENANT_LABEL_NAMES (tenant_id, api_key_id, tenant, workspace), \
         and TENANT_LABEL_EXEMPTIONS does not cover it. Add the label, or add a reviewed, \
         ticketed exemption.",
        &tenant_label_gaps(METRICS, TENANT_SCOPED_METRICS, TENANT_LABEL_EXEMPTIONS),
    );
}

#[test]
fn no_metric_carries_a_run_scoped_identifier_label() {
    // Cardinality enforcement, and the inverse of the tenant guard above:
    // that one requires a label, this one forbids a family of them. A run
    // id, task id, context id, session id, or trace id takes one distinct
    // value per run, forever. On a span or a ledger row that is exactly
    // right and is how a single run is reconstructed. On a metric it mints
    // one time series per run, and the series outlive the run by the whole
    // retention window, so the monitoring system pays for a dimension
    // nobody can usefully group by.
    //
    // Unlike `every_tenant_scoped_metric_carries_a_tenant_label`, this one
    // has no opt-in list to be forgotten: it scans every entry in METRICS.
    // The failure mode is somebody adding a label without thinking about
    // it, and that person is not going to register it for a check either.
    report(
        "A metric carries a run-scoped identifier label. The rule was stated in \
         docs/observability.md, on A2AContext::task_id, and in a2a_body_phase.rs, and \
         enforced nowhere until this guard. Drop the label and put the identifier on the \
         span and in the ledger, or add a reviewed, ticketed RUN_SCOPED_LABEL_EXEMPTIONS \
         entry. Giving the label a cardinality budget is not a fix.",
        &run_scoped_label_gaps(METRICS, RUN_SCOPED_LABEL_EXEMPTIONS),
    );
}

#[test]
fn the_run_scoped_label_guard_catches_a_run_id_label() {
    // A guard with no proof it can fail is not a guard. The table passes
    // today, so the assertion above is satisfied by an empty table, a
    // broken matcher, or a real absence of violations, and it cannot tell
    // you which. This fixture pins it to the third.
    let planted = MetricCapability {
        name: "sbproxy_run_scoped_fixture_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_fixture"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        // `route` is bounded and fine. `run_id` is the bomb, and
        // `a2a_task_id` is the qualified spelling that an exact-match-only
        // list would have missed.
        labels: &["route", "run_id", "a2a_task_id"],
        description: "A fixture that must never exist in METRICS.",
        dead_reason: None,
    };

    let errors = run_scoped_label_gaps(&[planted], RUN_SCOPED_LABEL_EXEMPTIONS);

    assert_eq!(errors.len(), 1, "the guard did not fire: {errors:?}");
    assert!(
        errors[0].message.contains("run_id") && errors[0].message.contains("a2a_task_id"),
        "both offending labels must be named so one run fixes all of them: {:?}",
        errors[0]
    );
    assert!(
        !errors[0].message.contains("\"route\""),
        "a bounded label must not be blamed: {:?}",
        errors[0]
    );
}

#[test]
fn a_run_scoped_label_exemption_needs_a_reason_and_a_ticket() {
    // Same rule as the dead-reference allow-list above, for the same
    // reason: the escape hatch is the thing most likely to be abused, and
    // an exemption here is a series count that grows with traffic for as
    // long as the entry survives.
    for exemption in RUN_SCOPED_LABEL_EXEMPTIONS {
        let ReferenceExemption { metric, reason } = exemption;

        assert!(
            reason.len() > 40,
            "exemption for {metric} needs a real reason, not '{reason}'"
        );
        assert!(
            reason.contains("WOR-"),
            "exemption for {metric} must name the ticket that removes it: '{reason}'"
        );
        assert!(
            METRICS.iter().any(|m| m.name == *metric),
            "exemption for {metric} names a metric that is not in the registry"
        );
    }
}

#[test]
fn no_family_is_registered_on_both_registries() {
    // `ProxyMetrics::render()` gathers the private registry and the process
    // default and concatenates them. A family on both is emitted twice, the
    // Prometheus text format forbids a repeated `# TYPE`, and the scrape is
    // rejected wholesale. `record_channel_drop` did exactly this, and it comes
    // into existence only under backpressure, so `/metrics` broke at the
    // moment it was most needed.
    //
    // A const table cannot express "registered twice" by construction, which is
    // the point: the registry has one `registry` field per metric, so the only
    // way back into that bug is to edit the code and not the table, and the
    // writer scan catches that.
    let mut seen: Vec<&str> = METRICS.iter().map(|m| m.name).collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "a metric name is declared twice");
}

#[test]
fn the_published_catalogue_matches_the_registry() {
    let rendered = sbproxy_observe::metric_registry::render_markdown();

    assert_eq!(
        rendered,
        sbproxy_observe::metric_registry::render_markdown(),
        "the generated catalogue is not deterministic"
    );

    for metric in METRICS {
        assert!(
            rendered.contains(&format!("| `{}` |", metric.name)),
            "{} is missing from the generated catalogue",
            metric.name
        );
    }

    assert!(
        !rendered.contains('\u{2014}'),
        "generated docs must not use em dashes"
    );
    // Public docs never cite the internal tracker. The dead_reason strings do,
    // because they are code; the rendered catalogue must not leak them.
    assert!(
        !rendered.contains("WOR-"),
        "the published catalogue must not cite internal ticket numbers"
    );
}

#[test]
fn the_committed_catalogue_is_current() {
    let path = repo_root().join("docs/metrics-stability.md");
    let committed = std::fs::read_to_string(&path).expect("read docs/metrics-stability.md");

    assert_eq!(
        committed,
        sbproxy_observe::metric_registry::render_markdown(),
        "docs/metrics-stability.md is stale. Regenerate it:\n\n    \
         cargo run -q -p sbproxy-observe --bin generate-metrics-stability > \
         docs/metrics-stability.md\n"
    );
}
