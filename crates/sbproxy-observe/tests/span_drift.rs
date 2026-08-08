// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The span drift guard.
//!
//! `metric_drift.rs` covers the metrics vocabulary. Nothing covered the
//! traces one, and three separate drifts were live on `main` when this
//! landed:
//!
//! - `docs/observability.md` published eight fully-qualified span names
//!   (`sbproxy.intake.accept`, `sbproxy.policy.enforce`,
//!   `sbproxy.action.challenge`, `sbproxy.action.redeem`,
//!   `sbproxy.ledger.redeem`, `sbproxy.rail.settle`,
//!   `sbproxy.transform.shape`, `sbproxy.audit.emit`) as the span-naming
//!   convention. Zero of the eight are emitted by any production code, and
//!   a trace query filtered on one of them is indistinguishable from a
//!   quiet system.
//! - The one pillar span production really opens is
//!   `sbproxy.rail.reconcile`, a background worker, and it was not on the
//!   published list.
//! - Three AI span constructors (`provider_selection_span`,
//!   `guardrail_eval_span`, `streaming_span`) exist, compile, carry full
//!   attribute sets, and have never been called from anything but their own
//!   unit tests.
//!
//! A fourth was in the pillar enum itself: its doc comment said "one of the
//! eight standard pillars" over seven variants, while the traces dashboard
//! hardcoded the eighth, `notify`, as a filter value operators could pick.

use sbproxy_capability::scan;
use sbproxy_capability::{
    validate_spans, CompatTier, RegistryError, SpanCapability, SpanEmitter, SupportLevel,
};
use sbproxy_observe::span_registry::{self, SPANS};
use sbproxy_observe::telemetry::Pillar;
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

/// The canonical pillar vocabulary, as the tracing helpers define it.
///
/// `validate_spans` takes this rather than knowing it, because
/// `sbproxy-capability` is a leaf and `Pillar` lives with the helpers that
/// build span names from it. Passing it here is what binds the registry's
/// pillar slugs to the enum.
fn pillar_slugs() -> Vec<&'static str> {
    Pillar::ALL.iter().map(|pillar| pillar.as_str()).collect()
}

#[test]
fn the_registry_is_internally_consistent() {
    report(
        "The span registry violates its own invariants.",
        &validate_spans(SPANS, &pillar_slugs()),
    );
}

#[test]
fn every_span_opened_in_code_is_classified() {
    report(
        "A span is opened in code but missing from the registry. Every span name has \
         to say what emits it and what we promise about the name, the same way a new \
         metric family must be classified before it compiles.",
        &scan::verify_span_coverage(SPANS, &repo_root()),
    );
}

#[test]
fn every_live_span_has_a_production_emitter() {
    // This is the defect the registry exists to catch, and it runs in both
    // directions. A span the table calls live whose constructor lost its
    // last caller looks exactly like one that was never wired: the
    // constructor still typechecks, its unit test still passes, and the
    // span is simply never opened. A span the table calls dead after
    // somebody wired it is the same rot in the flattering direction.
    report(
        "A span claims a live emitter that no production code opens, or claims to be \
         dead while production opens it.",
        &scan::verify_span_emitters(SPANS, &repo_root()),
    );
}

#[test]
fn the_scanner_sees_the_spans_it_thinks_it_does() {
    // `verify_span_emitters` is satisfied by an empty declared set for
    // every `SpanEmitter::Nothing` entry, so a scanner that silently read
    // no files would pass the test above. Pin the floor.
    let declared = scan::declared_spans(&repo_root());

    assert!(
        declared.len() >= 6,
        "the scanner found only {} span names under crates/; it is not reading the \
         files it thinks it is: {declared:?}",
        declared.len()
    );
    for expected in ["ai.request", "mcp.execute_tool"] {
        assert!(
            declared.contains(expected),
            "{expected} is opened in production and the scanner missed it: {declared:?}"
        );
    }
}

#[test]
fn no_span_name_is_declared_twice() {
    let mut seen: Vec<&str> = SPANS.iter().map(|span| span.name).collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "a span name is declared twice");
}

#[test]
fn the_pillar_enum_and_the_traces_dashboard_agree() {
    // The drift this pins: `Pillar` documented itself as eight pillars over
    // seven variants, and the dashboard's filter offered the missing
    // `notify` as a value nothing could produce. Three lists, and the two
    // that could be compared mechanically never were.
    let path = repo_root().join("deploy/dashboards/traces-overview.json");
    let dashboard = std::fs::read_to_string(&path).expect("read the traces dashboard");

    let expected = Pillar::ALL
        .iter()
        .map(|pillar| pillar.as_str())
        .collect::<Vec<_>>()
        .join(",");

    assert!(
        dashboard.contains(&format!("\"query\": \"{expected}\"")),
        "the dashboard's pillar variable does not list exactly the Pillar variants, in \
         order. Expected the query to be:\n\n    {expected}\n\nIf the dashboard is \
         right, the enum is missing a variant."
    );

    for pillar in Pillar::ALL {
        let slug = pillar.as_str();
        assert!(
            dashboard.contains(&format!("\"value\": \"{slug}\"")),
            "pillar '{slug}' has no option entry in the dashboard's pillar variable"
        );
    }
}

#[test]
fn a_dead_span_names_the_ticket_that_resolves_it() {
    // Same rule the metric registry's allow-lists carry, for the same
    // reason: an admission with no tracking decays back into "nobody
    // noticed". Eleven of the seventeen entries here are admissions.
    for span in SPANS {
        if span.emitter.is_live() {
            continue;
        }
        let reason = span
            .dead_reason
            .unwrap_or_else(|| panic!("{} is dead and carries no dead_reason", span.name));

        assert!(
            reason.len() > 40,
            "{} needs a real dead_reason, not '{reason}'",
            span.name
        );
        assert!(
            reason.contains("WOR-"),
            "{} must name the ticket that emits or deletes it: '{reason}'",
            span.name
        );
    }
}

#[test]
fn the_committed_span_vocabulary_is_current() {
    let path = repo_root().join("docs/observability.md");
    let committed = std::fs::read_to_string(&path).expect("read docs/observability.md");

    let spliced = span_registry::splice(&committed).unwrap_or_else(|| {
        panic!(
            "docs/observability.md carries no generated span block. It must contain \
             both markers:\n  {}\n  {}",
            span_registry::BLOCK_BEGIN,
            span_registry::BLOCK_END,
        )
    });

    assert_eq!(
        committed, spliced,
        "docs/observability.md is stale. Regenerate it:\n\n    \
         cargo run -q -p sbproxy-observe --bin generate-span-vocabulary\n"
    );
}

#[test]
fn the_published_vocabulary_says_which_spans_are_not_emitted() {
    // The point of regenerating the table is not tidiness. It is that a
    // reader of the doc can tell an emitted span from a reserved name, and
    // before this guard the doc's only span table listed eight names that
    // were all reserved and said nothing about it.
    let rendered = span_registry::render_markdown();

    for span in SPANS {
        assert!(
            rendered.contains(&format!("| `{}` |", span.name)),
            "{} is missing from the published vocabulary",
            span.name
        );
    }

    let not_yet = SPANS.iter().filter(|span| !span.emitter.is_live()).count();
    assert_eq!(
        rendered.matches("| not yet |").count(),
        not_yet,
        "every span nothing emits must be marked as such in the published table"
    );
}

#[test]
fn the_emitter_guard_catches_an_unwired_constructor() {
    // A guard with no proof it can fail is not a guard. The table passes
    // today, so `every_live_span_has_a_production_emitter` is satisfied by
    // an empty table, a broken resolver, or a real absence of violations,
    // and it cannot tell you which. These fixtures pin it to the third.
    //
    // `guardrail_eval_span` is real and really has no production caller,
    // which is what makes it the right fixture: a constructor that does not
    // exist would fail for the wrong reason, and the resolver would look
    // healthy while being unable to distinguish "no callers" from "no
    // symbol".
    let root = repo_root();

    let planted_live = SpanCapability {
        name: "ai.guardrail_eval",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Constructor("guardrail_eval_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        description: "A fixture that must never exist in SPANS.",
        dead_reason: None,
    };

    let errors = scan::verify_span_emitters(&[planted_live], &root);

    assert_eq!(errors.len(), 1, "the guard did not fire: {errors:?}");
    assert!(
        errors[0].message.contains("no call site outside tests"),
        "the failure has to name the reason, not just fail: {:?}",
        errors[0]
    );

    // The other direction: a constructor the table still calls dead after
    // somebody wired it. `ai_request_span` has a production caller, so
    // recording it as unwired must fail.
    let planted_dead = SpanCapability {
        name: "ai.request",
        emitter: SpanEmitter::Unwired("ai_request_span"),
        support: SupportLevel::ConfigOnly,
        dead_reason: Some("a fixture (WOR-2318)"),
        ..planted_live
    };

    let errors = scan::verify_span_emitters(&[planted_dead], &root);

    assert_eq!(
        errors.len(),
        1,
        "the reverse guard did not fire: {errors:?}"
    );
    assert!(
        errors[0].message.contains("production call site"),
        "the failure has to say the span went live: {:?}",
        errors[0]
    );
}

#[test]
fn the_emitter_guard_catches_a_published_span_that_became_real() {
    // The third fixture, for the state the eight pillar names are in. An
    // entry recorded as emitted by nothing must fail the moment the name
    // shows up in a span macro, or the registry's own admissions rot into
    // the stale table it replaced.
    let planted = SpanCapability {
        name: "ai.request",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "A fixture that must never exist in SPANS.",
        dead_reason: Some("a fixture (WOR-2318)"),
    };

    let errors = scan::verify_span_emitters(&[planted], &repo_root());

    assert_eq!(errors.len(), 1, "the guard did not fire: {errors:?}");
    assert!(
        errors[0].message.contains("tracing span macro"),
        "the failure has to point at the emission that now exists: {:?}",
        errors[0]
    );
}

#[test]
fn the_coverage_guard_catches_an_unregistered_span() {
    // And the fourth: the direction that keeps the table from going stale
    // as the code grows. An empty registry must report every span the
    // workspace opens, including the two the original audit of this area
    // missed.
    let errors = scan::verify_span_coverage(&[], &repo_root());

    let subjects: Vec<&str> = errors.iter().map(|error| error.subject.as_str()).collect();

    // The last two are the ones a read-only audit of this area missed:
    // neither goes through a constructor, so both are easy to overlook by
    // grepping for `*_span` helpers. This is the check that finds them.
    for expected in [
        "ai.request",
        "mcp.execute_tool",
        "ai.provider.attempt",
        "sbproxy.ai.usage_sink",
    ] {
        assert!(
            subjects.contains(&expected),
            "the coverage scan reported nothing for {expected}, which is plainly \
             opened in production: {subjects:?}"
        );
    }
    assert!(
        errors
            .iter()
            .all(|error| error.message.contains("missing from the span registry")),
        "every coverage failure should say what to do about it: {errors:?}"
    );
}
