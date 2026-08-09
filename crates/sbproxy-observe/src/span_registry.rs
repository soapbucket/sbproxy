// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Every span name SBproxy publishes, and what we are willing to promise
//! about it.
//!
//! The traces half of the executable capability registry, and it exists for
//! the reason the metrics half does: `docs/observability.md` was
//! hand-maintained, and a hand-maintained catalog drifts in exactly one
//! direction. Three separate drifts were live on `main` when this table
//! landed, and none of them was visible to review:
//!
//! - The doc published eight fully-qualified `sbproxy.<pillar>.<verb>` span
//!   names as the span-naming convention. Nothing in the proxy emitted any
//!   of the eight. An operator who filtered a trace query on
//!   `sbproxy.policy.enforce` got an empty result and no way to tell that
//!   from a quiet system. Three of the eight are live now on the ordinary
//!   proxied request path, along with a fourth name the published eight
//!   did not have, `sbproxy.intake.authenticate`. The rest are reserved.
//! - The one pillar span production really opened,
//!   `sbproxy.rail.reconcile`, was not on the published list. It is also a
//!   background worker rather than a request-path span, which is worth
//!   knowing before anyone reads a latency panel built from it.
//! - Three AI span constructors exist, compile, carry full attribute sets,
//!   and are called by nothing outside their own tests.
//!
//! Two fields carry the weight, and they are the same two the metric
//! registry leans on:
//!
//! - `SpanCapability::emitter` names the production code that opens the
//!   span. The drift guard resolves it against the source tree and requires
//!   a call site outside `#[cfg(test)]`. A constructor that exists,
//!   compiles, and is called by nobody is the failure mode this catches,
//!   and it is invisible to review because the constructor still typechecks
//!   and its unit test still passes.
//! - `SpanCapability::support` is that liveness, made declarable. `Stable`
//!   means something emits it. `ConfigOnly` means nothing does, and is an
//!   honest and permitted state so long as it is *declared*, carries a
//!   `dead_reason`, and the published vocabulary says so where a reader
//!   will see it.
//!
//! `SpanCapability::compat` is the other axis: the promise about the
//! *name*, which is what a saved trace query or a dashboard variable
//! depends on. A span nothing emits cannot carry a `stable` compat tier.
//!
//! Opening a span in code without adding it here fails the build, through
//! `scan::verify_span_coverage`.
//!
//! # Scope
//!
//! This table describes the vocabulary. It does not emit anything, and
//! adding an entry does not make a span appear. The entries still recorded
//! as not emitted are the payment, ledger, and audit names, and they stay
//! that way until something opens them.
//!
//! Four phases of a proxied request are covered: inbound acceptance,
//! which is the parent of the rest, then authentication, policy
//! evaluation, and response-body shaping. Three of those had a pillar name
//! reserved and waiting. Authentication did not, and took a new verb under
//! the pillar that already owns inbound admission rather than a pillar of
//! its own.
//!
//! The phases that are still uncovered are worth stating, because a reader
//! will go looking for them: the upstream connect and send, and the
//! response header filter. Neither has a pillar in this vocabulary at all.
//! The eight are a domain taxonomy rather than an HTTP-phase one, so
//! covering those two means adding a pillar, which moves the enum,
//! `deploy/dashboards/traces-overview.json`, and the published convention
//! together. That is a vocabulary change rather than a wiring change, so
//! it is not folded in here.

use sbproxy_capability::{CompatTier, SpanCapability, SpanEmitter, SupportLevel};

/// The literal that opens the generated block in `docs/observability.md`.
pub const BLOCK_BEGIN: &str = "<!-- BEGIN GENERATED SPAN VOCABULARY -->";

/// The literal that closes the generated block in `docs/observability.md`.
pub const BLOCK_END: &str = "<!-- END GENERATED SPAN VOCABULARY -->";

/// Every span name that exists in this workspace's code or its docs.
///
/// Ordered the way the published table reads: the pillar vocabulary first,
/// in the order `docs/observability.md` has always listed it, then the
/// spans that follow a foreign naming convention.
pub const SPANS: &[SpanCapability] = &[
    // --- The pillar vocabulary: sbproxy.<pillar>.<verb> ---
    SpanCapability {
        name: "sbproxy.intake.accept",
        pillar: Some("intake"),
        verb: Some("accept"),
        emitter: SpanEmitter::Constructor("intake_accept_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        description: "The inbound phase of one request, and the parent of every other \
                      span the proxy opens while handling it: origin resolution, \
                      authentication, the policy chain, the response-cache probe, and \
                      non-proxy action dispatch. It closes before the upstream is \
                      dialed, so its duration is admission cost rather than origin \
                      latency. Carries `http.request.method`.",
        dead_reason: None,
    },
    SpanCapability {
        name: "sbproxy.intake.authenticate",
        pillar: Some("intake"),
        verb: Some("authenticate"),
        emitter: SpanEmitter::Constructor("intake_authenticate_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        description: "One authentication check against the origin's configured \
                      provider, which is what makes a slow forward-auth subrequest \
                      visible instead of folded into the inbound phase. Carries the \
                      provider type and nothing about the caller: no subject, no \
                      token, no header.",
        dead_reason: None,
    },
    SpanCapability {
        name: "sbproxy.policy.enforce",
        pillar: Some("policy"),
        verb: Some("enforce"),
        emitter: SpanEmitter::Constructor("policy_enforce_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        description: "One policy evaluation: rate limit, WAF, AI crawl, and the rest \
                      of the enforcer chain. Opened per enforcer rather than per \
                      chain, so the trace says which policy spent the time, and the \
                      spans render in configured order under the inbound phase.",
        dead_reason: None,
    },
    SpanCapability {
        name: "sbproxy.action.challenge",
        pillar: Some("action"),
        verb: Some("challenge"),
        emitter: SpanEmitter::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover issuing a 402 payment challenge.",
        dead_reason: Some(
            "published as the span-naming convention and emitted by nothing; the \
             challenge path opens no span (WOR-2318)",
        ),
    },
    SpanCapability {
        name: "sbproxy.action.redeem",
        pillar: Some("action"),
        verb: Some("redeem"),
        emitter: SpanEmitter::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover verifying a presented token or receipt.",
        dead_reason: Some(
            "published as the span-naming convention and emitted by nothing; the \
             redeem path opens no span (WOR-2318)",
        ),
    },
    SpanCapability {
        name: "sbproxy.ledger.redeem",
        pillar: Some("ledger"),
        verb: Some("redeem"),
        emitter: SpanEmitter::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover the outbound HTTP call to the ledger.",
        dead_reason: Some(
            "published as the span-naming convention and emitted by nothing; the \
             ledger client does not open a span and does not inject trace context \
             either (WOR-2318)",
        ),
    },
    SpanCapability {
        name: "sbproxy.rail.settle",
        pillar: Some("rail"),
        verb: Some("settle"),
        emitter: SpanEmitter::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover an outbound payment-rail settlement. The rail \
                      pillar is live, but only for reconciliation.",
        dead_reason: Some(
            "the rail span constructor is called with the verb 'reconcile' and no \
             other; nothing passes 'settle' (WOR-2318)",
        ),
    },
    SpanCapability {
        name: "sbproxy.rail.reconcile",
        pillar: Some("rail"),
        verb: Some("reconcile"),
        emitter: SpanEmitter::Constructor("settlement_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        description: "One settlement reconciliation attempt. Opened by the background \
                      sweep and by an operator-triggered sweep, never on the request \
                      path, so it has no parent span and its latency is not a user's \
                      latency.",
        dead_reason: None,
    },
    SpanCapability {
        name: "sbproxy.transform.shape",
        pillar: Some("transform"),
        verb: Some("shape"),
        emitter: SpanEmitter::Constructor("transform_shape_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        description: "One response-body transform, opened per transform in the \
                      origin's chain over the buffered body. This is the proxy's own \
                      CPU rather than the upstream's latency, which is the point of \
                      separating it. The body never reaches an attribute.",
        dead_reason: None,
    },
    SpanCapability {
        name: "sbproxy.audit.emit",
        pillar: Some("audit"),
        verb: Some("emit"),
        emitter: SpanEmitter::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover appending one audit-log entry.",
        dead_reason: Some(
            "published as the span-naming convention and emitted by nothing; the \
             audit writer opens no span (WOR-2318)",
        ),
    },
    // --- The AI gateway vocabulary: gen_ai / OpenInference names ---
    SpanCapability {
        name: "ai.request",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Constructor("ai_request_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        description: "One AI gateway request, from dispatch entry to the last byte of \
                      the completion. Carries the gen_ai and OpenInference attribute \
                      sets, the token split, the derived cost, and the run identity.",
        dead_reason: None,
    },
    SpanCapability {
        name: "mcp.execute_tool",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Constructor("execute_tool_span"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        description: "One MCP tool dispatch: the tool name, the server it went to, the \
                      outcome, and the per-tool cost when the price map resolves it.",
        dead_reason: None,
    },
    SpanCapability {
        name: "ai.provider.attempt",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Literal {
            site: "handle_ai_proxy",
        },
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        description: "One attempt against one provider. Opened per try, so a fallback \
                      chain renders as sibling spans under the request and a retry is \
                      visible rather than folded into one long call.",
        dead_reason: None,
    },
    SpanCapability {
        name: "sbproxy.ai.usage_sink",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Literal { site: "record" },
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        description: "The usage record emitted after a completion settles, so a trace \
                      backend can read spend without also being the metrics backend.",
        dead_reason: None,
    },
    SpanCapability {
        name: "ai.provider_selection",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Unwired("provider_selection_span"),
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover the routing decision: which provider and model the \
                      strategy picked.",
        dead_reason: Some(
            "provider_selection_span exists, compiles, and is called by nothing but \
             its own unit test, so the routing decision is on no trace (WOR-2318)",
        ),
    },
    SpanCapability {
        name: "ai.guardrail_eval",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Unwired("guardrail_eval_span"),
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover one guardrail rule set being evaluated against a \
                      request or a completion.",
        dead_reason: Some(
            "guardrail_eval_span exists, compiles, and is called by nothing but its \
             own unit test, so a blocked request shows no evaluation span (WOR-2318)",
        ),
    },
    SpanCapability {
        name: "ai.streaming",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Unwired("streaming_span"),
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        description: "Would cover the window from the first SSE chunk to the close of \
                      a streamed completion.",
        dead_reason: Some(
            "streaming_span exists, compiles, and is called by nothing but its own \
             unit test, so a streamed completion has no span over accumulation \
             (WOR-2318)",
        ),
    },
    // --- Implementation detail, visible only without an OTLP layer ---
    SpanCapability {
        name: "sbproxy.span",
        pillar: None,
        verb: None,
        emitter: SpanEmitter::Literal { site: "span" },
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        description: "The tracing metadata name every pillar span is created under. \
                      The OpenTelemetry layer replaces it with the value of the span's \
                      `otel.name` field, so an OTLP backend sees the pillar name and \
                      never this one. A local console subscriber with no OTLP layer \
                      configured sees this name instead.",
        dead_reason: None,
    },
];

/// Render the span vocabulary block published inside
/// `docs/observability.md`.
///
/// Deterministic and byte-stable: the drift guard regenerates it and
/// compares, so the committed doc cannot drift from the code. Hand-editing
/// the block between the markers is not so much forbidden as pointless.
pub fn render_markdown() -> String {
    let mut out = String::from(BLOCK_BEGIN);
    out.push('\n');
    out.push_str(
        "<!-- Generated from crates/sbproxy-observe/src/span_registry.rs. Do not \
         hand-edit this block; run\n     cargo run -q -p sbproxy-observe --bin \
         generate-span-vocabulary -->\n\n",
    );

    out.push_str(
        "Span names follow one of two conventions. SBproxy's own pillars are \
         `sbproxy.<pillar>.<verb>`, with eight pillars: `intake`, `policy`, \
         `action`, `transform`, `ledger`, `rail`, `audit`, and `notify`. The AI \
         gateway spans instead follow the OpenTelemetry GenAI and OpenInference \
         vocabularies, so LLM-native trace backends render them without \
         remapping.\n\n",
    );

    out.push_str(
        "The `Emitted` column is the one to read first. `yes` means production \
         code opens the span and a drift guard proves it, by resolving the \
         emitter against the source tree and requiring a call site outside \
         tests. `not yet` means the name is reserved and published here and \
         nothing opens it, so a trace query filtered on that name returns \
         nothing. Four pillar spans cover an ordinary proxied request: the \
         inbound phase, one per authentication check, one per policy \
         evaluation, and one per response-body transform. The reserved names \
         that remain are the payment, ledger, and audit ones, plus the \
         settlement rail's second verb.\n\n",
    );

    out.push_str(
        "`Name` is the compatibility promise about the span name itself, on the \
         same three tiers the metric catalog uses. `stable` will not be renamed \
         without a deprecation period, `beta` may be renamed in a minor release \
         with a changelog entry, and `alpha` may be renamed or removed in any \
         release. A name nothing emits cannot be better than `alpha`.\n\n",
    );

    out.push_str("| Span | Pillar | Emitted | Name | What it covers |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for span in SPANS {
        let pillar = match span.pillar {
            Some(pillar) => format!("`{pillar}`"),
            None => "not pillar-shaped".to_string(),
        };
        let emitted = if span.emitter.is_live() {
            "yes"
        } else {
            "not yet"
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | `{}` | {} |\n",
            span.name,
            pillar,
            emitted,
            span.compat.as_str(),
            span.description,
        ));
    }

    out.push('\n');
    out.push_str(BLOCK_END);
    out.push('\n');
    out
}

/// Replace the generated block in `doc` with the current rendering.
///
/// Returns `None` when the markers are missing or out of order, which is a
/// failure rather than a no-op: silently returning the document unchanged
/// would let the guard pass against a doc that no longer carries the block
/// at all.
pub fn splice(doc: &str) -> Option<String> {
    let begin = doc.find(BLOCK_BEGIN)?;
    let end = doc.find(BLOCK_END)?;
    if end < begin {
        return None;
    }
    // Consume the newline that terminates the end marker's line, if any, so
    // the rendered block (which supplies its own) does not double it.
    let mut after = end + BLOCK_END.len();
    if doc[after..].starts_with('\n') {
        after += 1;
    }

    let mut out = String::with_capacity(doc.len());
    out.push_str(&doc[..begin]);
    out.push_str(&render_markdown());
    out.push_str(&doc[after..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rendering_is_deterministic() {
        assert_eq!(render_markdown(), render_markdown());
    }

    #[test]
    fn every_span_reaches_the_rendered_table() {
        let rendered = render_markdown();
        for span in SPANS {
            assert!(
                rendered.contains(&format!("| `{}` |", span.name)),
                "{} is missing from the generated vocabulary",
                span.name
            );
        }
    }

    #[test]
    fn the_rendering_leaks_neither_em_dashes_nor_ticket_numbers() {
        let rendered = render_markdown();
        assert!(
            !rendered.contains('\u{2014}'),
            "generated docs must not use em dashes"
        );
        // The dead_reason strings cite the tracker because they are code.
        // The published block must not.
        assert!(
            !rendered.contains("WOR-"),
            "the published vocabulary must not cite internal ticket numbers"
        );
    }

    #[test]
    fn the_request_path_constructors_name_registered_spans() {
        // The request path opens its spans by a `&'static str` constant
        // instead of formatting `sbproxy.<pillar>.<verb>` per request, so
        // the name is written down twice: once where the span is opened
        // and once here. This is the join. Without it a rename lands on
        // one side, the published table keeps describing a name nothing
        // emits, and the drift guard stays green because its own
        // emitter check only asks whether the constructor has a caller.
        //
        // In-crate rather than in `tests/span_drift.rs` because the
        // constants are `pub(crate)`: an out-of-crate reader would be the
        // only reason they were `pub`, and a `pub` item whose only
        // consumer is a test is what the pub-item ratchet refuses.
        for name in [
            crate::telemetry::SPAN_INTAKE_ACCEPT,
            crate::telemetry::SPAN_INTAKE_AUTHENTICATE,
            crate::telemetry::SPAN_POLICY_ENFORCE,
            crate::telemetry::SPAN_TRANSFORM_SHAPE,
        ] {
            let span = SPANS
                .iter()
                .find(|span| span.name == name)
                .unwrap_or_else(|| panic!("the request path opens {name}, which is unregistered"));
            assert!(
                span.emitter.is_live(),
                "{name} is opened on the request path but recorded as emitted by nothing"
            );
        }
    }

    #[test]
    fn splicing_is_idempotent_and_needs_both_markers() {
        let doc = format!("before\n\n{BLOCK_BEGIN}\nstale\n{BLOCK_END}\n\nafter\n");
        let once = splice(&doc).expect("markers are present");
        let twice = splice(&once).expect("markers survive a splice");

        assert_eq!(once, twice);
        assert!(once.starts_with("before\n\n"));
        assert!(once.ends_with("\nafter\n"));
        assert!(!once.contains("stale"));
        assert!(splice("no markers here").is_none());
    }
}
