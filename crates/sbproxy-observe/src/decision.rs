// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The decision-event vocabulary: what the proxy decides, who decided it,
//! and what came out.
//!
//! Two axes were tangled before this module existed: **which decision
//! points exist** and **which engines can answer them**. Adding a
//! capability meant picking an engine first and inheriting whatever seam
//! that engine happened to have, which is how CEL ended up compiled at
//! six operator-facing sites with six different namespace vocabularies
//! and how twenty-one decision points ended up with one audit record
//! between them.
//!
//! The position is **define the event, not the engine**. A decision event
//! is a named pipeline point. An engine implements events, and the
//! operator picks which engine answers which event. `CustomLogFieldConfig`
//! already ships that shape, a `source:` plus an `engine:` of `cel | lua |
//! js`, refusing `wasm` because a compiled module is not inline source.
//! This generalizes it rather than inventing a second mechanism.
//!
//! ## What lives here
//!
//! - [`crate::decision::DecisionEvent`], the pipeline points, each with a stable label.
//! - [`crate::decision::DecisionEngine`], who answered.
//! - [`crate::decision::DecisionOutcome`], what came back, including the two outcomes every
//!   event carries whether or not it declares them: `error` and `timeout`.
//! - [`crate::decision::record_decision`] and friends, the one metric family all of the
//!   above dimension rather than duplicate.
//! - [`crate::decision::DecisionAudit`], the SIEM-shaped record, normalized to OCSF.
//!
//! ## Why one family instead of one metric per feature
//!
//! `record_policy`, `record_policy_evaluation_duration`,
//! `record_policy_decision_latency`, `record_mcp_policy_hook_invocation`,
//! `record_rate_limit_decision`, `record_cache`, and
//! `record_semantic_cache` all exist with different label vocabularies,
//! because each arrived with its feature. Twenty-one events hand-rolled
//! the same way is how the surface got inconsistent; adding the routing,
//! cache, and AI-failure events the same way would make it worse.
//!
//! Existing per-feature metrics stay. This is the family new events use
//! and the one existing events migrate toward, not a flag day.
//!
//! ## Fail-open is a counter, not an outcome
//!
//! A fail-open is not an error. It is a request that proceeded *without
//! the decision being made*, which is a different operational fact and
//! wants a different alert. Burying it in an `outcome` label is how it
//! stops being alarmable, so it gets
//! [`crate::decision::record_decision_fail_open`] and its own family.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::metrics::{metrics, sanitize_label_budget, sanitize_label_budget_tenant};

/// Tenant label used when a deployment has no tenancy configured.
///
/// Single-tenant deployments fall through to the proxy-wide path so
/// their series stay byte-identical to what they had before this family
/// existed. Adding multi-tenancy to a metric must not change what a
/// single-tenant operator's dashboards draw.
pub const DEFAULT_TENANT: &str = "__default__";

/// A named decision point in the request pipeline.
///
/// The label is the wire contract: it appears in the `event` metric
/// label, in the audit record, and in operator config that scopes audit
/// emission. Renaming a variant's label is a breaking change for
/// dashboards and SIEM rules both.
///
/// `#[non_exhaustive]` because the set grows: routing and cache are the
/// events with no competitor equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DecisionEvent {
    /// Authentication resolved a principal, or refused to.
    Auth,
    /// A policy rendered a verdict on the request.
    Policy,
    /// A rate limiter admitted or refused the request.
    RateLimit,
    /// The WAF matched, or did not.
    Waf,
    /// Cache key derivation, request-side.
    ///
    /// Split from [`Self::CacheAdmit`] by a hard ordering constraint: a
    /// key must exist before the lookup, so this event runs with no
    /// response in scope.
    CacheKey,
    /// Cache admission and TTL, response-side.
    ///
    /// Whether a response is worth storing depends on status, size,
    /// content, and cost, none of which exist at request time.
    CacheAdmit,
    /// Routing chose a candidate plan.
    RouteDecide,
    /// An AI guardrail inspected the prompt.
    AiGuardrailInput,
    /// An AI guardrail inspected the completion.
    AiGuardrailOutput,
    /// A tool call was inspected before dispatch.
    AiToolCall,
    /// One streamed chunk was inspected.
    ///
    /// Fires per chunk, so it never publishes an audit record whatever
    /// the operator configures. `ai.close` carries the stream's summary
    /// once instead; a per-chunk SIEM feed is an ingest bill rather than
    /// a control.
    AiStreamEvent,
    /// A streamed response finished and its aggregates were reported.
    AiClose,
    /// An upstream AI call failed.
    AiFailure,
    /// The AI gateway refused a request before any provider saw it.
    ///
    /// Distinct from [`Self::AiFailure`], which is an upstream fact.
    /// This one is the proxy's own decision, taken at the inbound
    /// native-format shim or the stored-prompt resolver: an MCP tool
    /// block that would have asked the provider to contact an MCP
    /// server behind the gateway's back, a stateful-join reference the
    /// gateway cannot honor, a stored-prompt reference nothing holds, a
    /// body that is not JSON. Without it the only trace of a
    /// governance-bypass attempt was a bare 400, which is metrically
    /// indistinguishable from a typo.
    AiAdmission,
    /// A transform rewrote a response.
    Transform,
    /// An action served a response.
    Action,
    /// A custom access-log field was computed.
    LogCustomField,
    /// An MCP tool invocation was gated.
    McpTool,
    /// A payment moved through its lifecycle.
    PaymentLifecycle,
}

/// Whether a decision event's records reach the audit bus.
///
/// [`DecisionEvent::coverage`] is the only producer. The three states
/// exist because "wired or not" could not describe `waf` and
/// `rate_limit`, whose decisions do reach the bus, just under a
/// different event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCoverage {
    /// Publishes its own decision-audit records.
    Emitted,
    /// Runs in the policy chain, so its decisions publish as `policy`
    /// records carrying a `policy_id` that names which module decided.
    /// Selecting on that field is the supported query; a separate
    /// emitter would double-record.
    SupersededByPolicy,
    /// The decision is recorded, on a durable store rather than this
    /// bus, and deliberately not published here.
    ///
    /// This feed is lossy by contract: the queue holds 10 000 records,
    /// overflow drops and counts, and the request continues. That is the
    /// right trade for a security decision, where the drop counter is a
    /// paging signal and a missed record is recoverable context.
    ///
    /// It is the wrong trade for money. A payment record that can be
    /// dropped under load is not an audit trail, and the settlement
    /// store already exists so that no fund movement is ever forgotten:
    /// an attempt that may have dispatched can only move to
    /// `NeedsReconciliation`, never silently to a terminal state.
    /// Publishing the same event onto a lossy queue beside it would
    /// offer a second, weaker answer to a question that already has an
    /// authoritative one.
    DurableElsewhere,
    /// Publishes on this feed only under a specific configuration.
    ///
    /// `policy` is the only one. It has always reached the audit bus,
    /// but arrives as a `PolicyVerdictEvent` on its own prefix until
    /// `policy_record_format: decision` moves it onto this feed. Calling
    /// that "unwired" tells an operator nothing publishes it, which is
    /// false in both formats; calling it "emitted" tells them it is on
    /// this feed, which is false in one.
    ConfigDependent,
    /// Cannot publish, whatever the operator configures.
    ///
    /// `ai.stream.event` fires once per streamed chunk, so a per-event
    /// audit record is an ingest bill rather than a control. It is
    /// refused ahead of both the per-event map and the master switch,
    /// which makes an emitter for it unreachable. Reporting it as "not
    /// yet" would promise a feed that is never coming; `ai.close`
    /// carries the same stream's summary once.
    NeverPublishes,
    /// No emitter yet. Enabling it publishes nothing.
    Unwired,
}

impl DecisionEvent {
    /// Stable label. Used as a Prometheus label value, an audit record
    /// field, and the key operators scope audit emission by.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Policy => "policy",
            Self::RateLimit => "rate_limit",
            Self::Waf => "waf",
            Self::CacheKey => "cache.key",
            Self::CacheAdmit => "cache.admit",
            Self::RouteDecide => "route.decide",
            Self::AiGuardrailInput => "ai.guardrail.input",
            Self::AiGuardrailOutput => "ai.guardrail.output",
            Self::AiToolCall => "ai.tool_call",
            Self::AiStreamEvent => "ai.stream.event",
            Self::AiClose => "ai.close",
            Self::AiFailure => "ai.failure",
            Self::AiAdmission => "ai.admission",
            Self::Transform => "transform",
            Self::Action => "action",
            Self::LogCustomField => "log.custom_field",
            Self::McpTool => "mcp.tool",
            Self::PaymentLifecycle => "payment.lifecycle",
        }
    }

    /// Every event, in declaration order. The cardinality budget in
    /// `docs/observability.md` is computed from this length, so a new
    /// variant has to be added here too.
    pub const ALL: &'static [Self] = &[
        Self::Auth,
        Self::Policy,
        Self::RateLimit,
        Self::Waf,
        Self::CacheKey,
        Self::CacheAdmit,
        Self::RouteDecide,
        Self::AiGuardrailInput,
        Self::AiGuardrailOutput,
        Self::AiToolCall,
        Self::AiStreamEvent,
        Self::AiClose,
        Self::AiFailure,
        Self::AiAdmission,
        Self::Transform,
        Self::Action,
        Self::LogCustomField,
        Self::McpTool,
        Self::PaymentLifecycle,
    ];

    /// Resolve a label back to its event. Used by config parsing, where
    /// an operator names events to scope audit emission.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.as_label() == label)
    }

    /// Whether this event has a production call site that publishes an
    /// audit record today.
    ///
    /// An operator can enable any event in
    /// `observability.log.decision_audit`, and the config accepts every
    /// known label because refusing one would block pre-configuring an
    /// event a later release wires. That leaves a gap the config cannot
    /// close: an event enabled here but unwired publishes nothing, and
    /// silence from an audit feed is indistinguishable from a feed with
    /// nothing to report. Boot reads this to warn instead (WOR-2446).
    ///
    /// **Hand-maintained, and it will drift if you let it.** Wiring a
    /// new emitter means flipping its arm here in the same change.
    /// `every_wired_event_is_listed_here` pins the three that exist so a
    /// removed emitter is caught; nothing yet catches an *added* emitter
    /// whose arm was not flipped, which is the direction a scanner
    /// guard would need to cover.
    pub const fn has_emitter(self) -> bool {
        matches!(self.coverage(), EventCoverage::Emitted)
    }

    /// Whether this event's decisions reach the audit bus, and under
    /// which event they arrive.
    ///
    /// Three states rather than two, because "no emitter" was wrong for
    /// `waf` and `rate_limit` and wrong in a way that would have made
    /// the surface worse if acted on. Both are **policy modules**:
    /// `waf` compiles to a `Policy::Waf` enforcer, and the rate-limit
    /// family to `Policy::RateLimit` and friends. They run in the
    /// policy chain, so `emit_policy_verdict` already publishes each
    /// decision with `policy_id` naming which one fired. Writing a
    /// `record_decision(Waf, ..)` call site would emit a *second*
    /// record for one decision, which is the two-shapes incoherence
    /// WOR-2448 exists to remove.
    ///
    /// The labels stay, and deliberately. `validate_decision_audit`
    /// fails config load on an `events:` key naming no known event, so
    /// deleting these variants would turn a working `events: {waf:
    /// true}` into a startup failure on upgrade. A superseded label
    /// parses, warns, and points at where its records actually are.
    ///
    /// **Hand-maintained, and it will drift if you let it.** Wiring a
    /// new emitter means flipping its arm here in the same change.
    /// `every_wired_event_is_listed_here` pins the set so a removed
    /// emitter is caught; nothing yet catches an *added* emitter whose
    /// arm was not flipped.
    pub const fn coverage(self) -> EventCoverage {
        match self {
            // cache.admit: proxy_http.rs, the response-side plan arm.
            // cache.key: request_phase.rs, the request-side plan arm.
            // route.decide: ai_dispatch.rs, the accepted-plan arm.
            // auth: server.rs `record_auth_decision`, the single seam
            // every one of the fourteen auth call sites goes through.
            // ai.guardrail.*: ai_dispatch.rs, the input and output
            // guardrail funnels.
            // mcp.tool: action_dispatch.rs `emit_mcp_tool_attribution`.
            // ai.tool_call: ai_dispatch.rs `handle_verdicts`, one record
            // per judged streamed tool call. Bounded by tool calls
            // rather than chunks, which is what separates it from
            // ai.stream.event.
            // ai.failure: `record_ai_provider_response_failure` in
            // ai_dispatch.rs, the one funnel every provider-response
            // failure classification already ran through (WOR-2486).
            // ai.admission: `record_ai_admission_refusal` in
            // ai_dispatch.rs, the funnel behind the three refusal arms
            // of the inbound native-format shim (the Anthropic Messages
            // translate, the Responses prompt-object bridge, and the
            // Responses translate) and the two of the shared
            // stored-prompt resolver. Narrower than "every pre-provider
            // refusal": a request refused by the model gate, a
            // guardrail, a budget, or a policy is recorded by that
            // plane's own event and never reaches this one. See
            // `docs/events.md`.
            // ai.close: `AiRequestExtensions::close()` in
            // ai_extensions.rs, called once per stream regardless of
            // whether any bundle hook subscribed to `ai.close` itself
            // (WOR-2486). Scoped to a request whose AI extension chain
            // is non-empty: a deployment with zero configured AI
            // extension bundles builds no `AiRequestExtensions` at all,
            // so `close()` never runs for it. That is narrower than
            // "every streamed AI response" and is a real, documented
            // gap (see `docs/events.md`), not the funnel-per-event
            // shape the other `Emitted` arms guarantee.
            // ai.guardrail.output: `ai_output_guardrail_block` in
            // ai_dispatch.rs, on the live provider response, the
            // idempotency replay, and the semantic-cache hit, for the
            // allow as well as the block. Until WOR-2649 the live
            // response did not route through it and published nothing,
            // so the feed carried replays only. Still narrower than
            // "every AI response": a streamed response is never
            // materialized, and a live multipart response runs its own
            // external-adapter path. See `docs/events.md`.
            // Each of the others is a funnel rather than a scattering of
            // call sites, which is what makes those arms honest: wiring
            // some sites and not others would silence the startup
            // warning while the feed still missed decisions (WOR-2446).
            Self::CacheAdmit
            | Self::CacheKey
            | Self::RouteDecide
            | Self::Auth
            | Self::AiGuardrailInput
            | Self::AiGuardrailOutput
            | Self::AiFailure
            | Self::AiAdmission
            | Self::AiClose
            | Self::McpTool => EventCoverage::Emitted,
            // Published as `policy` records already; see the doc above.
            Self::Waf | Self::RateLimit => EventCoverage::SupersededByPolicy,
            // Money is recorded by the durable settlement store, not
            // here. See `EventCoverage::DurableElsewhere`.
            Self::PaymentLifecycle => EventCoverage::DurableElsewhere,
            Self::AiToolCall => EventCoverage::Emitted,
            Self::Policy => EventCoverage::ConfigDependent,
            Self::AiStreamEvent => EventCoverage::NeverPublishes,
            Self::Transform | Self::Action | Self::LogCustomField => EventCoverage::Unwired,
        }
    }

    /// OCSF `activity_id` for this event on the API Activity class.
    ///
    /// OCSF models API Activity (6003) with CRUD-shaped activities. A
    /// proxy decision is a read of the request plus a control action, so
    /// everything that inspects maps to Read (2) and the two events that
    /// create state, a cache store and a payment, map to Create (1).
    const fn ocsf_activity_id(self) -> u8 {
        match self {
            Self::CacheAdmit | Self::PaymentLifecycle => 1,
            _ => 2,
        }
    }
}

impl fmt::Display for DecisionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

/// Which engine answered a decision event.
///
/// This is the axis that was tangled with [`DecisionEvent`]. An event is
/// a place; an engine is an implementation the operator chooses for that
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DecisionEngine {
    /// A compiled-in module, dispatched through its enum arm.
    BuiltIn,
    /// A link-time Rust plugin.
    Plugin,
    /// A CEL expression.
    ///
    /// CEL returns a scalar, not a document, which is exactly why
    /// `route_to:gpt-4o-mini` became a string mini-language. Events that
    /// return documents support CEL and document its ceiling rather than
    /// stretching it a third time.
    Cel,
    /// A Luau script.
    Lua,
    /// A JavaScript or TypeScript bundle hook.
    JavaScript,
    /// Rego, evaluated in process on the Regorus interpreter.
    Rego,
    /// An envelope-ABI WebAssembly bundle hook.
    Wasm,
    /// A Proxy-Wasm filter.
    ProxyWasm,
}

impl DecisionEngine {
    /// Stable Prometheus label value.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::Plugin => "plugin",
            Self::Cel => "cel",
            Self::Lua => "lua",
            Self::JavaScript => "js",
            Self::Rego => "rego",
            Self::Wasm => "wasm",
            Self::ProxyWasm => "proxy_wasm",
        }
    }

    /// Every engine, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::BuiltIn,
        Self::Plugin,
        Self::Cel,
        Self::Lua,
        Self::JavaScript,
        Self::Rego,
        Self::Wasm,
        Self::ProxyWasm,
    ];

    /// Whether this engine returns a document rather than a scalar.
    ///
    /// The ranking criterion for which engines can serve which events.
    /// An event whose output is `{store, ttl_secs, reason}` is native to
    /// a document engine and needs a token mini-language on a scalar
    /// one, which is the mistake `route_to:` already made.
    pub const fn returns_documents(self) -> bool {
        match self {
            Self::Cel => false,
            // Rego sits here rather than beside CEL: a rule may
            // return any value, and `policy: rego` narrowing that to a
            // boolean is this surface's choice rather than the
            // language's limit.
            Self::BuiltIn
            | Self::Plugin
            | Self::Rego
            | Self::Lua
            | Self::JavaScript
            | Self::Wasm
            | Self::ProxyWasm => true,
        }
    }
}

impl fmt::Display for DecisionEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

/// What a decision event produced.
///
/// `Error` and `Timeout` are carried by every event whether or not it
/// declares them, so a failing hook is alertable without knowing in
/// advance which hook it was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// The event permitted the operation.
    Allow,
    /// The event refused the operation.
    Deny,
    /// The event recorded a match without refusing.
    Flag,
    /// The event returned a modified payload.
    Mutate,
    /// The event chose not to decide, and the built-in default applies.
    ///
    /// The common path for routing and cache policies: a rule for a few
    /// cases and the configured strategy for everything else. Declining
    /// must stay the cheapest thing to write, and it is not a failure.
    Decline,
    /// The engine faulted.
    Error,
    /// The engine did not finish inside its deadline.
    Timeout,
}

impl DecisionOutcome {
    /// Stable Prometheus label value.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Flag => "flag",
            Self::Mutate => "mutate",
            Self::Decline => "decline",
            Self::Error => "error",
            Self::Timeout => "timeout",
        }
    }

    /// Every outcome, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Allow,
        Self::Deny,
        Self::Flag,
        Self::Mutate,
        Self::Decline,
        Self::Error,
        Self::Timeout,
    ];

    /// OCSF Security Control `disposition_id` for this outcome.
    ///
    /// The Security Control profile is what makes an OCSF record say
    /// what a control *did*, as opposed to what merely happened, which
    /// is the whole point of auditing a proxy decision.
    const fn ocsf_disposition_id(self) -> u8 {
        match self {
            // Allowed (1)
            Self::Allow | Self::Decline => 1,
            // Blocked (2)
            Self::Deny => 2,
            // Detected (12): observed and recorded, not acted on.
            Self::Flag => 12,
            // Corrected (13): the control changed the payload.
            Self::Mutate => 13,
            // Error (99) / Other (99) for the two failure outcomes.
            Self::Error | Self::Timeout => 99,
        }
    }

    /// Whether the record should be flagged to an analyst.
    const fn is_alert(self) -> bool {
        matches!(self, Self::Deny | Self::Flag)
    }
}

impl fmt::Display for DecisionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

/// Record one decision event on the shared counter.
///
/// `origin` is required rather than optional: a decision is meaningless
/// without knowing whose traffic it was made on, and `origin` is bounded
/// by config, which makes it the safer multi-tenant dimension.
///
/// **Pass the configured origin id, never the request `Host`.** Every
/// label value goes through the global cardinality limiter, which
/// demotes overflow to `__other__`, and the budgets are per label name
/// and shared across every metric using that name: `origin` is 200,
/// `tenant` is 1000. A `Host` is attacker-chosen, so under a wildcard
/// origin it would let an unauthenticated caller exhaust a budget that
/// every other origin-labelled family draws on. Several older recorders
/// do pass the `Host`; they predate that reasoning and are not the
/// pattern to copy here.
pub fn record_decision(
    event: DecisionEvent,
    engine: DecisionEngine,
    outcome: DecisionOutcome,
    origin: &str,
    tenant: &str,
) {
    let origin =
        sanitize_label_budget_tenant("sbproxy_decision_event_total", "origin", origin, tenant);
    let tenant = sanitize_label_budget("sbproxy_decision_event_total", "tenant", tenant);
    metrics()
        .decision_event_total
        .with_label_values(&[
            event.as_label(),
            engine.as_label(),
            outcome.as_label(),
            origin.as_str(),
            tenant.as_str(),
        ])
        .inc();
}

/// Record how long a decision event took.
///
/// `tenant` is deliberately absent. A histogram multiplies its label set
/// by its bucket count, so an unbounded-ish dimension costs ten to
/// fifteen times there what it costs on a counter, and per-tenant
/// latency is rarely the actionable cut. Latency per origin and per
/// engine is: that is what answers "is this hook slow" and "is this
/// engine's marshalling too expensive". If per-tenant latency turns out
/// to be needed it should arrive as a separate opt-in histogram rather
/// than by widening this one.
pub fn record_decision_duration(
    event: DecisionEvent,
    engine: DecisionEngine,
    origin: &str,
    duration_secs: f64,
) {
    let origin = sanitize_label_budget("sbproxy_decision_event_duration_seconds", "origin", origin);
    metrics()
        .decision_event_duration
        .with_label_values(&[event.as_label(), engine.as_label(), origin.as_str()])
        .observe(duration_secs);
}

/// Record that a decision event failed open.
///
/// Its own family, not an `outcome` label, because a fail-open is not an
/// error: it is a request that proceeded without the decision being
/// made. Every fail-open posture in the codebase needs this to be honest
/// about what it is doing, and an operator needs to alert on it
/// separately from engine faults.
pub fn record_decision_fail_open(
    event: DecisionEvent,
    engine: DecisionEngine,
    origin: &str,
    tenant: &str,
) {
    let origin = sanitize_label_budget_tenant(
        "sbproxy_decision_event_fail_open_total",
        "origin",
        origin,
        tenant,
    );
    let tenant = sanitize_label_budget("sbproxy_decision_event_fail_open_total", "tenant", tenant);
    metrics()
        .decision_event_fail_open
        .with_label_values(&[
            event.as_label(),
            engine.as_label(),
            origin.as_str(),
            tenant.as_str(),
        ])
        .inc();
}

/// A decision rationale that has already been through the scrub.
///
/// [`DecisionAudit::reason`] is this type rather than a `String` so
/// "already redacted" is something the compiler checks instead of
/// something a doc comment asks for. There is exactly one way to build
/// one, [`RedactedReason::redact`], and it runs the scrub. There is
/// deliberately no `new` and no `From<String>`: either would be a second
/// door into the type with none of the guarantee behind it, and the
/// guarantee is the only reason the type exists.
///
/// The text is untrusted. A `reason` comes back from an operator-authored
/// Lua, JS, or CEL hook, and a hook is free to explain itself with
/// `"prompt looked like " + prompt[:100]`. Wiring the audit record is
/// therefore also the first opportunity to put prompt bodies and live
/// credentials into a customer's SIEM, which is why the scrub is a
/// property of the type rather than a step a call site can forget.
///
/// ## What the scrub does not catch
///
/// The floor is a regex pass over known credential shapes, plus the
/// operator's optional `redact.patterns:` masks and PII rules. None of
/// them sees free-form prose: "the user asked about their divorce"
/// survives every rule in [`crate::redact`], every rule in
/// `sbproxy_security::pii`, and any pattern an operator did not think to
/// write. This type bounds the credential and structured-PII hazard. It
/// does not make an arbitrary rationale safe to ship, and nothing here
/// enforces that a hook declines to paste model output into its
/// `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RedactedReason(String);

impl RedactedReason {
    /// Upper bound in bytes.
    ///
    /// Matches `MAX_ROUTE_REASON_BYTES` and `MAX_CACHE_REASON_BYTES`, the
    /// bounds the routing and cache events already apply at decode, so a
    /// reason that survived decode passes through here unchanged rather
    /// than being cut a second time to a different length.
    pub const MAX_BYTES: usize = 512;

    /// Scrub a raw rationale, then bound it.
    ///
    /// Four passes, in this order:
    ///
    /// 1. [`crate::redact::redact_secrets`], the config-free floor. Runs
    ///    on every record whatever the operator configured, because a
    ///    credential in a SIEM is a credential in a SIEM.
    /// 2. The operator's `redact.patterns:` regex masks for `(tenant,
    ///    route)`, when `state` is supplied.
    /// 3. The operator's composed PII rules for the same scope.
    /// 4. Truncation to [`Self::MAX_BYTES`], last.
    ///
    /// Passes 1 through 3 are exactly
    /// [`crate::logging::OpRedactState::redact_free_text`], which is the
    /// same code the access, audit, and trace sinks run, so a mask an
    /// operator writes once covers every feed rather than every feed but
    /// this one. It was every feed but this one until WOR-2405: the audit
    /// reason ran the floor and the PII rules and skipped `patterns:`
    /// entirely, so `patterns: [{name: acct, regex: 'ACCT-[0-9]{10}'}]`
    /// masked an account number in the access log and published it
    /// verbatim in the OCSF record going to the customer's SIEM.
    ///
    /// The field-key denylist (`redact.fields:`) is the one pass that
    /// does not run, because a bare reason string has no field key to
    /// match. See `redact_free_text` for why.
    ///
    /// **Scrubbing must precede truncation.** Every detection pattern
    /// needs a minimum body length: `Bearer [a-zA-Z0-9._\-]{20,}` needs
    /// twenty characters after the keyword. Bound first and a token
    /// sitting near the boundary gets cut to nineteen, the pattern stops
    /// matching, and the surviving prefix of a live credential ships as
    /// ordinary text. An operator pattern is no different: an
    /// `ACCT-[0-9]{10}` mask stops firing on `ACCT-12345`. Bounding a
    /// string that is already scrubbed can only ever shorten a
    /// `[REDACTED]` marker, which costs nothing.
    ///
    /// ## The caller supplies the redaction state
    ///
    /// `state` is a parameter rather than a lookup performed here
    /// because it lives in a process-wide slot whose accessor is
    /// [`crate::logging::operator_redact_state`], and reading it per
    /// reason would pin a snapshot per call rather than per request.
    /// Take one handle at the emit site, pass a borrow of it here, and
    /// every reason in that request is scrubbed by the same policy even
    /// if a reload lands mid-request.
    ///
    /// `tenant` and `route` are the scope the operator's rules are keyed
    /// by. One trap: `route` is the route string the log emitter stamps,
    /// which is the origin's hostname, while [`DecisionAudit::origin`] is
    /// the configured origin id. The two hold the same bytes today and
    /// the two fields exist precisely so they can stop doing so, so pass
    /// the route, not the origin id, or the origin-scope rules are
    /// silently skipped. `None` for either falls through to the next
    /// scope up.
    ///
    /// `state: None` is the honest config-free floor: pass 1 and the
    /// bound, nothing else. It is the right value only where no scope is
    /// knowable, which in this crate means the [`Deserialize`] impl. It
    /// is not a shortcut to skip the lookup.
    pub fn redact(
        raw: &str,
        state: Option<&crate::logging::OpRedactState>,
        tenant: Option<&str>,
        route: Option<&str>,
    ) -> Self {
        // Passes 1 through 3. With a state in hand they are the log
        // path's own code, so this cannot drift from what the access log
        // does to the same string. Without one, the floor alone: it is
        // unconditional and first, so a deployment with no redaction
        // config still cannot ship a Bearer token.
        let scrubbed = match state {
            Some(state) => state.redact_free_text(tenant, route, raw),
            None => crate::redact::redact_secrets(raw),
        };
        // The bound, LAST. Doing this first would cut a token below the
        // body length its detection pattern needs, so the pattern would
        // stop matching and the prefix would survive as plain text. See
        // the ordering note in this function's rustdoc.
        Self(sbproxy_util::truncate_utf8(&scrubbed, Self::MAX_BYTES).to_owned())
    }

    /// The scrubbed text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parsing cannot bypass the scrub.
///
/// A record read back off the wire came from somewhere this process
/// cannot vouch for: a replayed stderr line, a queue, a fixture. Deriving
/// `Deserialize` on the newtype would hand that text straight into a type
/// whose entire contract is that it carries none, so the impl routes
/// through [`RedactedReason::redact`] like every other producer.
///
/// It passes `None` for the redaction state deliberately, and that is a
/// strictly weaker scrub than a constructed value gets. Precisely: a
/// deserialized reason gets [`crate::redact::redact_secrets`] and the
/// 512-byte bound. It does **not** get the operator's
/// `redact.patterns:` masks and does **not** get their PII rules,
/// because both are keyed by a `(tenant, route)` scope and this impl has
/// neither. Serde hands the field values over one at a time with no
/// access to the record's siblings, so even the tenant sitting next to
/// this field in the same JSON object is not readable from here, and
/// guessing a scope would apply some other tenant's rules.
///
/// In practice that gap is narrow. A value that was scrubbed with
/// operator rules before it was serialized stays scrubbed, because every
/// pass is idempotent over text it has already replaced, and this crate
/// serializes reasons only from values that already went through
/// [`RedactedReason::redact`] with a scope. The uncovered case is a
/// reason that entered this process from outside having never been
/// scrubbed with the local operator's rules: a replayed stderr line, a
/// queue, a fixture. Such a value is bounded and credential-free but may
/// still carry something only a local `patterns:` mask would have
/// caught, so do not treat a deserialized record as equivalent to one
/// this process built.
impl<'de> Deserialize<'de> for RedactedReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::redact(&raw, None, None, None))
    }
}

/// A decision event, shaped for a SIEM.
///
/// Normalized to [OCSF] rather than to field names of our own, because
/// emitting our own guarantees every customer writes a mapping layer and
/// that layer becomes the thing they blame when a rule misfires. OCSF
/// has neutral governance and cross-vendor backing; ECS is the
/// Elastic-native alternative and would tie the record to one stack.
///
/// The class is **API Activity (6003)** under Application Activity,
/// carrying the **Security Control** profile, which is the pairing that
/// lets a record say both what was requested and what the control did
/// about it.
///
/// [OCSF]: https://schema.ocsf.io/
///
/// ## Origin and tenant are mandatory
///
/// Stronger than the metrics requirement, where a demoted `__other__`
/// label is acceptable degradation. A record an analyst cannot filter to
/// a customer is not evidence, so these are plain fields rather than
/// `Option`s and they carry the real identity.
///
/// ## The reason is the payload
///
/// A record saying a request was denied is nearly useless. One naming
/// the rule and why is an investigation. It is the same `reason` the
/// routing and cache events already return, so it is one concept across
/// the whole surface rather than three.
///
/// It also has to live here rather than only in a log line:
/// `release_max_level_info` compiles `debug!` and `trace!` out of
/// release builds, so a reason that exists only in a debug line does not
/// exist in production, which is exactly where an operator needs it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecisionAudit {
    /// Idempotency key for the consumer. One per decision.
    pub event_id: uuid::Uuid,
    /// Correlates to the access log entry and any traces.
    pub request_id: String,
    /// Which pipeline point decided.
    pub event: DecisionEvent,
    /// Which engine answered.
    pub engine: DecisionEngine,
    /// What came back.
    pub outcome: DecisionOutcome,
    /// Origin the decision was made on. Never empty.
    pub origin: String,
    /// Tenant the decision is attributed to. [`DEFAULT_TENANT`] in a
    /// single-tenant deployment.
    pub tenant: String,
    /// Wall-clock instant the decision was rendered.
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Why. A [`RedactedReason`] rather than a `String` because the
    /// previous version of this line said "redacted before it reaches
    /// this struct" and nothing anywhere enforced it. The type does.
    pub reason: RedactedReason,
    /// Stable identifier for the rule or hook that decided, when the
    /// engine exposes one.
    pub rule_id: Option<String>,
    /// Structured detail about what the decision did.
    ///
    /// The `reason` says why in the operator's words; this says what, in
    /// fields a SIEM rule can select on. Both matter and neither
    /// replaces the other: prose does not aggregate, and a field set
    /// does not explain itself.
    ///
    /// Empty for a decision with nothing structured to add.
    ///
    /// `default` on purpose: a record serialized before this field
    /// existed, or by a producer that has nothing to add, still has to
    /// parse. Absence means "no detail", never "malformed".
    #[serde(default, skip_serializing_if = "DecisionDetails::is_empty")]
    pub details: DecisionDetails,
}

/// Structured, filterable detail about one decision.
///
/// Every value here is proxy-authored, not operator-authored, which is
/// what separates it from [`RedactedReason`]. A model id, a provider id,
/// and a tier count come from the routing plan the proxy resolved, so
/// they are not free text and do not carry the leak risk the reason
/// does. They are rendered into the OCSF record as plain fields.
///
/// This exists so an analyst does not have to grep prose. "Show me every
/// routing decision that moved a request off its requested model" is a
/// field comparison here and a regex over English without it, and a
/// regex over English is how a SIEM rule quietly stops matching when
/// someone rewords a script.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionDetails {
    /// The model the request asked for, when the decision concerns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    /// The model the decision selected, when it selected one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_model: Option<String>,
    /// The provider the decision selected, when it selected one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_provider: Option<String>,
    /// How many tiers the resolved plan carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_count: Option<usize>,
    /// How many entries the host dropped from the plan before running
    /// it. Non-zero means this is not the plan the operator wrote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped: Option<usize>,
    /// Whether a cache decision stored the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    /// TTL the decision settled on, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Stale-while-revalidate window the decision settled on, in
    /// seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swr_secs: Option<u64>,
    /// Whether a cache-key decision skipped the lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_lookup: Option<bool>,
    /// How many extra dimensions a cache-key decision folded into the
    /// key. Zero means the policy ran and added nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vary_count: Option<usize>,
    /// The MCP tool a dispatch decision concerns.
    ///
    /// The name the agent asked for, as advertised by the gateway, so
    /// it matches what `tools/list` returned and what
    /// `sbproxy_mcp_tool_dispatch_total` is labelled by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The federated server the tool resolved to.
    ///
    /// Carried beside the tool because a name can be served by
    /// different upstreams across a config change, and "which server
    /// answered" is the question an incident asks first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    /// Which guardrail decided, by its configured name.
    ///
    /// The selector for "every block by the jailbreak guardrail". Empty
    /// on an allow, because no single guardrail owns the decision when
    /// they all passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrail: Option<String>,
    /// How many detectors flagged without reaching the block threshold.
    ///
    /// The signal that a request was close to the line. A rule watching
    /// this climb across a tenant sees pressure that no individual
    /// allow record shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flagged_count: Option<usize>,
    /// Bounded detection spans (WOR-2492 item 6): entity type, byte
    /// offset, and byte length for every match the deciding guardrail
    /// found, over the SCANNED (pre-redaction) text. Never the matched
    /// value -- a span is a position, not the PII or secret it flagged,
    /// so this field cannot become a second place the value leaks from.
    /// Absent when the deciding guardrail carries no positional
    /// detail. Capped at
    /// [`sbproxy_security::span::MAX_DETECTION_SPANS`]; see
    /// `guardrail_spans_dropped` for the count past the cap.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub guardrail_spans: Vec<sbproxy_security::span::DetectionSpan>,
    /// Count of matches past the span cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrail_spans_dropped: Option<usize>,
    /// Which authentication method decided.
    ///
    /// The closed-ish set the `sbproxy_auth_results_total` metric
    /// already labels by (`virtual_key`, `forward_auth`, `api_key`,
    /// `bearer`, and the rest), so a rule can select "every forward-auth
    /// refusal" as a term query and correlate it with the metric that
    /// alerted.
    ///
    /// Deliberately the method and not the subject. A resolved principal
    /// is the one field on this path that is attacker-influenced and
    /// frequently personal, and `DecisionDetails` is the half of the
    /// record that ships unredacted. Anything about who authenticated
    /// belongs in the reason, which is scrubbed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// Which policy decided, by its stable config identity.
    ///
    /// The field an analyst pivots on first: "every deny by the waf
    /// policy" has to be a term query, not a substring match against
    /// prose that whoever wrote the rule can reword.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Whether a built-in arm or a dynamic-dispatch plugin decided.
    ///
    /// Carried beside `engine` rather than derived from it, because a
    /// surface cannot tell a CEL expression from a rate limiter and an
    /// engine cannot tell a linked plugin from a built-in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_surface: Option<String>,
    /// The coarse verdict tag the policy returned.
    ///
    /// Not the same as the record's `outcome`, and both are carried on
    /// purpose. A policy whose `enforce()` faulted still produces a
    /// verdict, because the posture decides what happens to the request,
    /// while the decision itself was an engine error. An analyst asking
    /// "what happened to this request" reads the verdict; one asking
    /// "is the control plane healthy" reads the outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// How long the decision took, in milliseconds.
    ///
    /// Coarse on purpose, matching the field it replaces. The histogram
    /// is where latency analysis belongs; this is here so one record is
    /// self-contained when an analyst is looking at a single decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_latency_ms: Option<u32>,
    /// Which inbound AI surface the decision was taken on.
    ///
    /// The same closed vocabulary
    /// `sbproxy_ai_surface_requests_total` is labelled by (`messages`,
    /// `responses`, `chat_completions`, ...), so a rule can join a
    /// refusal record to the surface's own request rate.
    /// Proxy-authored: it is classified from the request path, never
    /// read out of the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
}

impl DecisionDetails {
    /// Detail for an authentication decision.
    ///
    /// One field today, and that is the whole contract: the method.
    /// Adding a second later is a breaking change for every rule
    /// selecting on this record, so the bar for what goes in is whether
    /// a rule can be written against it that stays true, not whether the
    /// value happens to be available at the call site.
    pub fn auth(auth_type: &str) -> Self {
        Self {
            auth_type: (!auth_type.is_empty()).then(|| auth_type.to_owned()),
            ..Self::default()
        }
    }

    /// Detail for an MCP tool dispatch.
    ///
    /// `result` is the dispatch label, not the record's outcome. They
    /// differ on purpose: `tool_error` and `tool_not_found` both map to
    /// a non-allow outcome, and only this field says whether the
    /// upstream failed or the gateway never found the tool.
    pub fn mcp_tool(tool: &str, server: &str, result: &str) -> Self {
        Self {
            tool: (!tool.is_empty()).then(|| tool.to_owned()),
            tool_server: (!server.is_empty()).then(|| server.to_owned()),
            verdict: (!result.is_empty()).then(|| result.to_owned()),
            ..Self::default()
        }
    }

    /// Detail for one judged streamed tool call.
    ///
    /// `verdict` is the guard's own word (`clean`, `blocked`,
    /// `flagged`) rather than the record outcome, because flag mode
    /// leaves the stream untouched while still recording a judgement an
    /// analyst wants to count. Collapsing it into the outcome would
    /// make "the guard disagreed but we shipped it anyway" unreadable.
    pub fn ai_tool_call(tool: &str, verdict: &str) -> Self {
        Self {
            tool: (!tool.is_empty()).then(|| tool.to_owned()),
            verdict: (!verdict.is_empty()).then(|| verdict.to_owned()),
            ..Self::default()
        }
    }

    /// Detail for an AI guardrail decision.
    ///
    /// `guardrail` names the one that blocked, and is absent on an
    /// allow because no single guardrail owns a decision they all
    /// passed. `flagged_count` carries the near-miss signal either way,
    /// which is what makes an allow record worth storing at all.
    ///
    /// `spans`/`spans_dropped` (WOR-2492 item 6) are the deciding
    /// guardrail's bounded detection positions, when it has any --
    /// today only the `pii` guardrail does. Empty for every other
    /// guardrail and for an allow with no positional guardrail behind
    /// it, which is why this takes the already-capped pair rather than
    /// an uncapped source: the cap is enforced once, at the detector,
    /// not re-derived here.
    pub fn guardrail(
        guardrail: Option<&str>,
        flagged_count: usize,
        spans: &[sbproxy_security::span::DetectionSpan],
        spans_dropped: usize,
    ) -> Self {
        Self {
            guardrail: guardrail
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned),
            flagged_count: Some(flagged_count),
            guardrail_spans: spans.to_vec(),
            guardrail_spans_dropped: (spans_dropped > 0).then_some(spans_dropped),
            ..Self::default()
        }
    }

    /// Detail for a policy decision.
    ///
    /// The field set that lets `policy` records answer the questions
    /// `PolicyVerdictEvent` answered, so converging the two shapes does
    /// not cost a consumer anything it had. Every value is
    /// proxy-authored: a policy id comes from the compiled config, a
    /// surface and a verdict are closed enums here, and the latency is a
    /// measurement. None of them is operator prose, which is what keeps
    /// them out of [`RedactedReason`] and lets them ship as plain
    /// selectable fields.
    pub fn policy(policy_id: &str, surface: &str, verdict: &str, decision_latency_ms: u32) -> Self {
        Self {
            policy_id: (!policy_id.is_empty()).then(|| policy_id.to_owned()),
            policy_surface: (!surface.is_empty()).then(|| surface.to_owned()),
            verdict: (!verdict.is_empty()).then(|| verdict.to_owned()),
            decision_latency_ms: Some(decision_latency_ms),
            ..Self::default()
        }
    }

    /// Detail for a routing decision.
    ///
    /// `selected_model` and `selected_provider` are `Option` because a
    /// plan can resolve to an empty tier list; a record that claimed a
    /// selection in that case would be inventing one.
    pub fn routing(
        requested_model: &str,
        selected_model: Option<&str>,
        selected_provider: Option<&str>,
        tier_count: usize,
        dropped: usize,
    ) -> Self {
        Self {
            requested_model: (!requested_model.is_empty()).then(|| requested_model.to_owned()),
            selected_model: selected_model.map(ToOwned::to_owned),
            selected_provider: selected_provider.map(ToOwned::to_owned),
            tier_count: Some(tier_count),
            dropped: Some(dropped),
            ..Self::default()
        }
    }

    /// Detail for a cache-admission decision.
    ///
    /// `ttl_secs` and `swr_secs` are the values the decision settled on
    /// rather than what the script asked for, so a record shows what the
    /// cache will actually do. `None` on either means the origin's
    /// configured value applies.
    pub fn cache_admit(stored: bool, ttl_secs: Option<u64>, swr_secs: Option<u64>) -> Self {
        Self {
            stored: Some(stored),
            ttl_secs,
            swr_secs,
            ..Self::default()
        }
    }

    /// Detail for a cache-key decision.
    ///
    /// `vary_count` rather than the dimension names: the names can carry
    /// header values an operator chose to key on, and this object is not
    /// scrubbed the way `reason` is. A count answers "did the policy
    /// narrow this key" without carrying what it narrowed on.
    pub fn cache_key(skip_lookup: bool, vary_count: usize) -> Self {
        Self {
            skip_lookup: Some(skip_lookup),
            vary_count: Some(vary_count),
            ..Self::default()
        }
    }

    /// Detail for an upstream AI provider failure (WOR-2486).
    ///
    /// Reuses the routing and policy fields rather than adding a new
    /// pair: `selected_provider` names the provider whose response
    /// failed, and `verdict` carries the classified failure kind
    /// (`rate_limited`, `content_filter`, `upstream_5xx`,
    /// `provider_error`), a closed vocabulary rather than the raw
    /// upstream status text, which can carry a prompt fragment back.
    pub fn ai_failure(provider: &str, kind: &str) -> Self {
        Self {
            selected_provider: (!provider.is_empty()).then(|| provider.to_owned()),
            verdict: (!kind.is_empty()).then(|| kind.to_owned()),
            ..Self::default()
        }
    }

    /// Detail for a streamed response's close (WOR-2486).
    ///
    /// `verdict` carries the terminal `finish_reason` (`stop`,
    /// `length`, `tool_calls`, `content_filter`, ...). Token counts and
    /// cost are not duplicated here: they already have an authoritative
    /// home in the access log and the usage ledger, and this record's
    /// job is marking that the stream reached its end, not re-billing
    /// it.
    pub fn ai_close(finish_reason: Option<&str>) -> Self {
        Self {
            verdict: finish_reason
                .filter(|reason| !reason.is_empty())
                .map(ToOwned::to_owned),
            ..Self::default()
        }
    }

    /// Detail for a pre-provider AI gateway refusal.
    ///
    /// `surface` is the inbound AI surface the request arrived on:
    /// `messages` or `responses` for a refusal at the native-format
    /// shim, and whatever surface the request came in on for a refusal
    /// at the shared stored-prompt resolver, which the canonical
    /// `chat_completions` path reaches too. `verdict` is the refusal's
    /// bounded reason code
    /// (`tools_mcp_unsupported`, `store_unsupported`, `malformed_json`,
    /// ...). Both are `&'static str` at every call site on purpose:
    /// details ship unredacted, and the refusal messages these records
    /// accompany interpolate caller bytes (a JSON parse error, an
    /// unrecognized role name), so the message never becomes a field
    /// here.
    pub fn ai_admission(surface: &str, reason: &str) -> Self {
        Self {
            surface: (!surface.is_empty()).then(|| surface.to_owned()),
            verdict: (!reason.is_empty()).then(|| reason.to_owned()),
            ..Self::default()
        }
    }

    /// Whether every field is absent, so the OCSF render can leave the
    /// object out rather than emit an empty one.
    ///
    /// Destructures without `..` on purpose (WOR-2486): the nine
    /// fields added after the first ten (`tool`, `tool_server`,
    /// `guardrail`, `flagged_count`, `auth_type`, `policy_id`,
    /// `policy_surface`, `verdict`, `decision_latency_ms`) were never
    /// added here, so a `guardrail()`, `mcp_tool()`, `auth()`, or
    /// `policy()` detail reported empty and `to_ocsf` never emitted
    /// `unmapped` for it: every `AiGuardrailInput`/`AiGuardrailOutput`,
    /// `McpTool`, `Auth`, and `policy_record_format: decision` `Policy`
    /// record shipped with its structured detail silently dropped. A
    /// destructure with no `..` fails to compile the moment a field is
    /// added and not listed here, which is what an exhaustive
    /// enumeration is for.
    pub fn is_empty(&self) -> bool {
        let Self {
            requested_model,
            selected_model,
            selected_provider,
            tier_count,
            dropped,
            stored,
            ttl_secs,
            swr_secs,
            skip_lookup,
            vary_count,
            tool,
            tool_server,
            guardrail,
            flagged_count,
            guardrail_spans,
            guardrail_spans_dropped,
            auth_type,
            policy_id,
            policy_surface,
            verdict,
            decision_latency_ms,
            surface,
        } = self;
        requested_model.is_none()
            && selected_model.is_none()
            && selected_provider.is_none()
            && tier_count.is_none()
            && dropped.is_none()
            && stored.is_none()
            && ttl_secs.is_none()
            && swr_secs.is_none()
            && skip_lookup.is_none()
            && vary_count.is_none()
            && tool.is_none()
            && tool_server.is_none()
            && guardrail.is_none()
            && flagged_count.is_none()
            && guardrail_spans.is_empty()
            && guardrail_spans_dropped.is_none()
            && auth_type.is_none()
            && policy_id.is_none()
            && policy_surface.is_none()
            && verdict.is_none()
            && decision_latency_ms.is_none()
            && surface.is_none()
    }

    /// Whether the decision moved the request off what it asked for, or
    /// ran a plan the host had to degrade.
    ///
    /// Not a filter the proxy applies. It is here so the same question a
    /// SIEM rule asks has one answer in this codebase too, for tests and
    /// for anything that later wants to log it.
    pub fn changed_route(&self) -> bool {
        self.dropped.is_some_and(|d| d > 0)
            || match (&self.requested_model, &self.selected_model) {
                (Some(requested), Some(selected)) => requested != selected,
                _ => false,
            }
    }
}

impl DecisionAudit {
    /// Build a record, scrubbing `reason` on the way in.
    ///
    /// Ten arguments, and every one is load bearing on a SIEM record:
    /// dropping any of `event_id`, `request_id`, `origin`, `tenant`, or
    /// `occurred_at` makes the record unfilterable or uncorrelatable,
    /// which is the failure this whole family exists to avoid. A
    /// builder would let a caller omit one and find out in production.
    ///
    /// `reason` is a `&str` and not a [`RedactedReason`] on purpose. A
    /// caller that could hand in a finished newtype is a caller that
    /// decides for itself what "redacted" means, and every emit site
    /// would then have to decide it the same way. The constructor owns
    /// the scrub instead, so the only way to build a record is to have
    /// it run.
    ///
    /// `redact_state` is the operator's installed redaction state, taken
    /// once at the emit site with
    /// [`crate::logging::operator_redact_state`]. See
    /// [`RedactedReason::redact`] for the passes it drives and what
    /// `None` costs.
    ///
    /// `route` is the origin **hostname** the operator's per-origin rules
    /// are keyed by, which is not necessarily `origin`, the configured
    /// origin id this record carries. Pass the route or the origin-scope
    /// rules are silently skipped. The tenant half of that scope is not a
    /// parameter: it is this record's own `tenant`, so the scrub cannot
    /// run under one tenant's rules while the record is filed under
    /// another. An empty `tenant` resolves as no tenant scope rather than
    /// as the [`DEFAULT_TENANT`] sentinel, because the sentinel is a
    /// display value for a single-tenant deployment and not a key an
    /// operator can write a rule against.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: uuid::Uuid,
        request_id: impl Into<String>,
        event: DecisionEvent,
        engine: DecisionEngine,
        outcome: DecisionOutcome,
        origin: impl Into<String>,
        tenant: impl Into<String>,
        occurred_at: chrono::DateTime<chrono::Utc>,
        reason: &str,
        redact_state: Option<&crate::logging::OpRedactState>,
        route: Option<&str>,
    ) -> Self {
        let tenant = tenant.into();
        let scope_tenant = if tenant.is_empty() {
            None
        } else {
            Some(tenant.as_str())
        };
        let reason = RedactedReason::redact(reason, redact_state, scope_tenant, route);
        Self {
            event_id,
            request_id: request_id.into(),
            event,
            engine,
            outcome,
            origin: origin.into(),
            tenant: if tenant.is_empty() {
                DEFAULT_TENANT.to_owned()
            } else {
                tenant
            },
            occurred_at,
            reason,
            rule_id: None,
            details: DecisionDetails::default(),
        }
    }

    /// Attach structured detail about what the decision did.
    #[must_use]
    pub fn with_details(mut self, details: DecisionDetails) -> Self {
        self.details = details;
        self
    }

    /// Attach the rule or hook identifier that produced the decision.
    #[must_use]
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Render as an OCSF API Activity (6003) event with the Security
    /// Control profile.
    ///
    /// `class_uid * 100 + activity_id` is OCSF's `type_uid`, and it is
    /// what most consumers actually route on, so it is computed here
    /// rather than left for the customer to derive.
    pub fn to_ocsf(&self) -> serde_json::Value {
        const CLASS_UID: u32 = 6003;
        let activity_id = self.event.ocsf_activity_id();
        let mut record = serde_json::json!({
            "class_uid": CLASS_UID,
            "class_name": "API Activity",
            "category_uid": 6,
            "category_name": "Application Activity",
            "activity_id": activity_id,
            "type_uid": CLASS_UID * 100 + u32::from(activity_id),
            "severity_id": if self.outcome.is_alert() { 3 } else { 1 },
            "time": self.occurred_at.timestamp_millis(),
            "metadata": {
                "version": "1.6.0",
                "product": {
                    "name": "SBproxy",
                    "vendor_name": "Soap Bucket LLC",
                },
                "profiles": ["security_control"],
                "uid": self.event_id.to_string(),
                "correlation_uid": self.request_id,
            },
            // Security Control profile.
            "disposition_id": self.outcome.ocsf_disposition_id(),
            "is_alert": self.outcome.is_alert(),
            "policy": {
                "name": self.event.as_label(),
                "uid": self.rule_id,
                "desc": self.reason.as_str(),
            },
            // Tenancy. Mandatory: a record an analyst cannot filter to a
            // customer is not evidence.
            "cloud": { "org": { "name": self.tenant } },
            "api": {
                "service": { "name": self.origin },
                "operation": self.event.as_label(),
            },
            "actor": { "process": { "name": self.engine.as_label() } },
            "status_id": match self.outcome {
                DecisionOutcome::Error | DecisionOutcome::Timeout => 2,
                _ => 1,
            },
            "message": self.reason.as_str(),
        });
        // Structured detail rides under `unmapped`, which is OCSF's
        // sanctioned home for attributes the class does not define. A
        // SIEM rule selecting on `unmapped.selected_provider` keeps
        // working when someone rewords the script that produced the
        // reason; one selecting on a regex over `message` does not.
        //
        // Left out entirely when empty rather than emitted as `{}`, so a
        // consumer can test for presence.
        if !self.details.is_empty() {
            if let Ok(detail) = serde_json::to_value(&self.details) {
                record["unmapped"] = detail;
            }
        }
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_detail_reaches_the_ocsf_record() {
        // The point of the type. A SIEM rule selecting on a field keeps
        // working when someone rewords the script that produced the
        // reason; one selecting on a regex over `message` does not.
        let audit = DecisionAudit::new(
            uuid::Uuid::new_v4(),
            "req-detail",
            DecisionEvent::RouteDecide,
            DecisionEngine::Cel,
            DecisionOutcome::Allow,
            "api.example.test",
            "acme-corp",
            chrono::Utc::now(),
            "cheaper tier available",
            None,
            None,
        )
        .with_details(DecisionDetails::routing(
            "gpt-4o",
            Some("claude-haiku"),
            Some("anthropic"),
            2,
            1,
        ));
        let ocsf = audit.to_ocsf();
        let unmapped = ocsf
            .get("unmapped")
            .expect("structured detail has to reach the record, not just the struct");
        assert_eq!(unmapped["requested_model"], "gpt-4o");
        assert_eq!(unmapped["selected_model"], "claude-haiku");
        assert_eq!(unmapped["selected_provider"], "anthropic");
        assert_eq!(unmapped["tier_count"], 2);
        assert_eq!(unmapped["dropped"], 1);
    }

    #[test]
    fn a_record_with_no_detail_omits_the_object_entirely() {
        // Emitted as `{}` a consumer cannot tell "no detail" from "the
        // producer forgot", so absence is spelled as absence.
        let audit = DecisionAudit::new(
            uuid::Uuid::new_v4(),
            "req-plain",
            DecisionEvent::CacheAdmit,
            DecisionEngine::Lua,
            DecisionOutcome::Deny,
            "api.example.test",
            "acme-corp",
            chrono::Utc::now(),
            "set-cookie present",
            None,
            None,
        );
        assert!(audit.details.is_empty());
        assert!(audit.to_ocsf().get("unmapped").is_none());
    }

    /// WOR-2486 regression: `is_empty()` used to check only the first
    /// ten fields, so a `guardrail()` detail (which sets only
    /// `guardrail` and `flagged_count`, both added later) reported
    /// empty and `to_ocsf` never attached `unmapped` at all. Every
    /// `AiGuardrailInput`/`AiGuardrailOutput` record shipped with its
    /// structured detail silently dropped until this test's fix. Picks
    /// `guardrail()` specifically because it is the constructor whose
    /// only two fields both post-date the original ten-field check.
    #[test]
    fn a_guardrail_detail_reaches_the_ocsf_record() {
        let audit = DecisionAudit::new(
            uuid::Uuid::new_v4(),
            "req-guardrail",
            DecisionEvent::AiGuardrailOutput,
            DecisionEngine::BuiltIn,
            DecisionOutcome::Deny,
            "api.example.test",
            "acme-corp",
            chrono::Utc::now(),
            "jailbreak guardrail blocked the request",
            None,
            None,
        )
        .with_details(DecisionDetails::guardrail(Some("jailbreak"), 0, &[], 0));
        assert!(
            !audit.details.is_empty(),
            "a guardrail name is real detail, not absence"
        );
        let ocsf = audit.to_ocsf();
        let unmapped = ocsf
            .get("unmapped")
            .expect("guardrail detail has to reach the record, not just the struct");
        assert_eq!(unmapped["guardrail"], "jailbreak");
    }

    /// WOR-2492 item 6: a PII guardrail's detection spans carry
    /// `{entity_type, offset, len}` through to the OCSF record, and
    /// never the matched value.
    #[test]
    fn a_guardrail_span_detail_reaches_the_ocsf_record_without_the_matched_text() {
        let planted = "definitely-not-a-real-address@example.test";
        let spans = vec![sbproxy_security::span::DetectionSpan::new("email", 12, 5)];
        let audit = DecisionAudit::new(
            uuid::Uuid::new_v4(),
            "req-guardrail-spans",
            DecisionEvent::AiGuardrailInput,
            DecisionEngine::BuiltIn,
            DecisionOutcome::Deny,
            "api.example.test",
            "acme-corp",
            chrono::Utc::now(),
            "initial guardrail pii blocked the request",
            None,
            None,
        )
        .with_details(DecisionDetails::guardrail(Some("pii"), 0, &spans, 3));
        let ocsf = audit.to_ocsf();
        let unmapped = ocsf
            .get("unmapped")
            .expect("guardrail span detail has to reach the record");
        assert_eq!(unmapped["guardrail_spans"][0]["entity_type"], "email");
        assert_eq!(unmapped["guardrail_spans"][0]["offset"], 12);
        assert_eq!(unmapped["guardrail_spans"][0]["len"], 5);
        assert_eq!(unmapped["guardrail_spans_dropped"], 3);
        let rendered = serde_json::to_string(&ocsf).expect("ocsf serializes");
        assert!(
            !rendered.contains(planted),
            "a decision record must never carry the matched value, got: {rendered}"
        );
    }

    /// Red-first: an allow with no positional guardrail behind it
    /// carries no spans field at all, not an empty array -- consistent
    /// with every other optional detail on this type.
    #[test]
    fn guardrail_detail_with_no_spans_omits_the_field() {
        let details = DecisionDetails::guardrail(None, 2, &[], 0);
        let wire = serde_json::to_value(&details).expect("serializes");
        assert!(wire.get("guardrail_spans").is_none());
        assert!(wire.get("guardrail_spans_dropped").is_none());
    }

    /// Same regression, for `ai_failure()` and `ai_close()` specifically,
    /// since both are new in this change and both use only
    /// post-original-ten fields (`selected_provider`/`verdict` and
    /// `verdict` respectively).
    #[test]
    fn ai_failure_and_ai_close_details_reach_the_ocsf_record() {
        let failure = DecisionAudit::new(
            uuid::Uuid::new_v4(),
            "req-ai-failure",
            DecisionEvent::AiFailure,
            DecisionEngine::BuiltIn,
            DecisionOutcome::Error,
            "api.example.test",
            "acme-corp",
            chrono::Utc::now(),
            "provider openai returned upstream_5xx (status 503)",
            None,
            None,
        )
        .with_details(DecisionDetails::ai_failure("openai", "upstream_5xx"));
        let unmapped = failure
            .to_ocsf()
            .get("unmapped")
            .cloned()
            .expect("ai.failure detail must reach the record");
        assert_eq!(unmapped["selected_provider"], "openai");
        assert_eq!(unmapped["verdict"], "upstream_5xx");

        let close = DecisionAudit::new(
            uuid::Uuid::new_v4(),
            "req-ai-close",
            DecisionEvent::AiClose,
            DecisionEngine::BuiltIn,
            DecisionOutcome::Allow,
            "api.example.test",
            "acme-corp",
            chrono::Utc::now(),
            "stream closed",
            None,
            None,
        )
        .with_details(DecisionDetails::ai_close(Some("tool_calls")));
        let unmapped = close
            .to_ocsf()
            .get("unmapped")
            .cloned()
            .expect("ai.close detail must reach the record");
        assert_eq!(unmapped["verdict"], "tool_calls");
    }

    #[test]
    fn changed_route_reads_the_same_question_a_siem_rule_would() {
        // Kept in the codebase so the definition has one home, even
        // though the proxy does not filter on it.
        let moved = DecisionDetails::routing("gpt-4o", Some("claude-haiku"), None, 1, 0);
        assert!(moved.changed_route());

        let same = DecisionDetails::routing("gpt-4o", Some("gpt-4o"), None, 1, 0);
        assert!(!same.changed_route(), "a plan that changed nothing did not");

        let degraded = DecisionDetails::routing("gpt-4o", Some("gpt-4o"), None, 2, 1);
        assert!(
            degraded.changed_route(),
            "a degraded plan is not the plan the operator wrote, so it counts"
        );
    }

    #[test]
    fn every_wired_event_carries_structured_detail() {
        // WOR-2448: detail existed on exactly one event, so a SIEM rule
        // could select on routing decisions and had only prose for the
        // cache ones. All three wired events carry fields now.
        let admit = DecisionDetails::cache_admit(false, Some(300), Some(30));
        assert!(!admit.is_empty());
        assert_eq!(admit.stored, Some(false));
        assert_eq!(admit.ttl_secs, Some(300));
        assert_eq!(admit.swr_secs, Some(30));

        let key = DecisionDetails::cache_key(true, 2);
        assert!(!key.is_empty());
        assert_eq!(key.skip_lookup, Some(true));
        assert_eq!(key.vary_count, Some(2));
    }

    #[test]
    fn a_cache_key_record_carries_a_count_not_the_dimension_names() {
        // The names can carry header values an operator chose to key on,
        // and this object is not scrubbed the way `reason` is. A count
        // answers "did the policy narrow this key" without carrying
        // what it narrowed on.
        let key = DecisionDetails::cache_key(false, 3);
        let rendered = serde_json::to_string(&key).expect("serializes");
        assert!(rendered.contains("\"vary_count\":3"), "{rendered}");
        assert!(
            !rendered.contains("vary\":["),
            "dimension names must not ride along: {rendered}"
        );
    }

    #[test]
    fn cache_detail_omits_what_the_decision_did_not_settle() {
        // `None` means the origin's configured value applies. Emitting
        // a zero would read as "this decision chose no TTL", which is a
        // different and false claim.
        let admit = DecisionDetails::cache_admit(true, None, None);
        let rendered = serde_json::to_string(&admit).expect("serializes");
        assert!(rendered.contains("\"stored\":true"), "{rendered}");
        assert!(!rendered.contains("ttl_secs"), "{rendered}");
        assert!(!rendered.contains("swr_secs"), "{rendered}");
    }

    #[test]
    fn ai_failure_detail_carries_provider_and_kind() {
        let detail = DecisionDetails::ai_failure("openai", "upstream_5xx");
        let rendered = serde_json::to_string(&detail).expect("serializes");
        assert!(
            rendered.contains("\"selected_provider\":\"openai\""),
            "{rendered}"
        );
        assert!(
            rendered.contains("\"verdict\":\"upstream_5xx\""),
            "{rendered}"
        );
    }

    #[test]
    fn ai_close_detail_carries_the_finish_reason() {
        let detail = DecisionDetails::ai_close(Some("tool_calls"));
        let rendered = serde_json::to_string(&detail).expect("serializes");
        assert!(
            rendered.contains("\"verdict\":\"tool_calls\""),
            "{rendered}"
        );

        // No finish reason (a stream that never delivered one) omits
        // the field entirely rather than emitting an empty string,
        // matching every other Option field on this struct.
        let empty = DecisionDetails::ai_close(None);
        assert!(empty.is_empty());
    }

    #[test]
    fn every_wired_event_is_listed_here() {
        // Pins the emitters that exist. A removed call site whose arm
        // was not flipped shows up here; an *added* one still needs a
        // human to flip its arm, which is the drift this cannot see.
        //
        // `auth` is wired through a single seam in `sbproxy-core`
        // (`record_auth_decision`) rather than at its fourteen
        // individual decision points, and a test over there greps for
        // anyone bypassing it. That pairing is what makes this entry
        // honest: this list claims the feed is complete, and only a
        // funnel can keep that claim true as arms are added.
        let wired: Vec<&str> = DecisionEvent::ALL
            .iter()
            .filter(|e| e.has_emitter())
            .map(|e| e.as_label())
            .collect();
        assert_eq!(
            wired,
            vec![
                "auth",
                "cache.key",
                "cache.admit",
                "route.decide",
                "ai.guardrail.input",
                "ai.guardrail.output",
                "ai.tool_call",
                "ai.close",
                "ai.failure",
                "ai.admission",
                "mcp.tool"
            ],
            "the wired set changed; update has_emitter and the docs that state coverage"
        );
    }

    #[test]
    fn the_policy_backed_events_are_superseded_rather_than_unwired() {
        // `waf` and `rate_limit` compile to policy modules, so their
        // decisions already publish as `policy` records carrying a
        // `policy_id`. Classifying them as unwired invited an emitter
        // that would have double-recorded one decision, which is the
        // incoherence WOR-2448 exists to remove.
        for event in [DecisionEvent::Waf, DecisionEvent::RateLimit] {
            assert_eq!(
                event.coverage(),
                EventCoverage::SupersededByPolicy,
                "{event} runs in the policy chain; a separate emitter would emit a second \
                 record for one decision"
            );
            assert!(
                !event.has_emitter(),
                "{event} must not report an emitter of its own: it publishes under `policy`"
            );
        }
    }

    #[test]
    fn money_is_not_routed_onto_a_lossy_feed() {
        // `payment.lifecycle` is not an unwired event waiting for an
        // emitter. This queue drops records under load by design, which
        // is a sound trade for a security decision and the wrong one for
        // a financial record. The settlement store already answers this
        // authoritatively, so a second lossy copy would be a weaker
        // answer to a question that already has one.
        assert_eq!(
            DecisionEvent::PaymentLifecycle.coverage(),
            EventCoverage::DurableElsewhere,
            "a payment record that can be dropped under load is not an audit trail"
        );
        assert!(
            !DecisionEvent::PaymentLifecycle.has_emitter(),
            "it must not claim an emitter on this feed"
        );
        // Still parses, so an operator who configured it does not fail
        // their load on upgrade; the boot warning tells them where the
        // records actually are.
        assert!(DecisionEvent::from_label("payment.lifecycle").is_some());
    }

    #[test]
    fn a_superseded_label_still_parses() {
        // Retiring these by deleting the variants would fail config
        // load for anyone who wrote `events: {waf: true}`, because an
        // unknown label is refused. The label has to survive its
        // emitter never existing.
        for label in ["waf", "rate_limit"] {
            assert!(
                DecisionEvent::from_label(label).is_some(),
                "`{label}` must keep parsing; deleting it turns a working config into a \
                 startup failure on upgrade"
            );
        }
    }

    #[test]
    fn the_per_chunk_event_is_never_wired() {
        // It cannot be: it is refused before the config map or the
        // master switch is consulted, so an emitter for it would be
        // unreachable and claiming one would be a lie.
        assert!(!DecisionEvent::AiStreamEvent.has_emitter());
    }

    #[test]
    fn every_event_label_round_trips() {
        for event in DecisionEvent::ALL {
            assert_eq!(
                DecisionEvent::from_label(event.as_label()),
                Some(*event),
                "{event} must parse back from its own label"
            );
        }
    }

    #[test]
    fn event_labels_are_unique() {
        // The label is the wire contract for metrics, audit records, and
        // operator config all at once. Two events sharing one would
        // silently merge three different things.
        let mut seen = std::collections::BTreeSet::new();
        for event in DecisionEvent::ALL {
            assert!(
                seen.insert(event.as_label()),
                "duplicate event label: {}",
                event.as_label()
            );
        }
        assert_eq!(seen.len(), DecisionEvent::ALL.len());
    }

    #[test]
    fn engine_and_outcome_labels_are_unique() {
        let engines: std::collections::BTreeSet<_> =
            DecisionEngine::ALL.iter().map(|e| e.as_label()).collect();
        assert_eq!(engines.len(), DecisionEngine::ALL.len());
        let outcomes: std::collections::BTreeSet<_> =
            DecisionOutcome::ALL.iter().map(|o| o.as_label()).collect();
        assert_eq!(outcomes.len(), DecisionOutcome::ALL.len());
    }

    #[test]
    fn cel_is_the_only_scalar_engine() {
        // The ranking criterion for which engines can serve which
        // events. If a second scalar engine ever appears, the events
        // that return documents need to refuse it explicitly.
        let scalar: Vec<_> = DecisionEngine::ALL
            .iter()
            .filter(|e| !e.returns_documents())
            .collect();
        assert_eq!(scalar, vec![&DecisionEngine::Cel]);
    }

    #[test]
    fn an_empty_tenant_becomes_the_single_tenant_sentinel() {
        // Single-tenant deployments must not produce records with a
        // blank tenancy field; an analyst filtering on tenant would drop
        // them entirely.
        let audit = DecisionAudit::new(
            uuid::Uuid::nil(),
            "req-1",
            DecisionEvent::Policy,
            DecisionEngine::Cel,
            DecisionOutcome::Deny,
            "api.local",
            "",
            chrono::DateTime::from_timestamp(0, 0).unwrap(),
            "rule 7 refused an unsigned agent",
            None,
            None,
        );
        assert_eq!(audit.tenant, DEFAULT_TENANT);
    }

    #[test]
    fn ocsf_render_carries_the_class_profile_and_identity() {
        let audit = DecisionAudit::new(
            uuid::Uuid::nil(),
            "req-1",
            DecisionEvent::Policy,
            DecisionEngine::Cel,
            DecisionOutcome::Deny,
            "api.local",
            "tenant-a",
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            "rule 7 refused an unsigned agent",
            None,
            None,
        )
        .with_rule_id("no-unsigned-agents");
        let json = audit.to_ocsf();

        assert_eq!(json["class_uid"], 6003);
        assert_eq!(json["category_uid"], 6);
        assert_eq!(json["activity_id"], 2);
        assert_eq!(json["type_uid"], 600302, "type_uid is class*100 + activity");
        assert_eq!(json["metadata"]["profiles"][0], "security_control");
        assert_eq!(json["disposition_id"], 2, "a deny is Blocked");
        assert_eq!(json["is_alert"], true);

        // Identity is what an analyst filters on first.
        assert_eq!(json["cloud"]["org"]["name"], "tenant-a");
        assert_eq!(json["api"]["service"]["name"], "api.local");
        assert_eq!(json["metadata"]["correlation_uid"], "req-1");

        // The reason is the payload, and it must survive into the record
        // rather than living only in a debug line that release builds
        // compile out.
        assert_eq!(json["policy"]["desc"], "rule 7 refused an unsigned agent");
        assert_eq!(json["policy"]["uid"], "no-unsigned-agents");
    }

    #[test]
    fn a_cache_store_is_an_ocsf_create_and_a_gate_is_a_read() {
        let store = DecisionAudit::new(
            uuid::Uuid::nil(),
            "req-1",
            DecisionEvent::CacheAdmit,
            DecisionEngine::BuiltIn,
            DecisionOutcome::Allow,
            "api.local",
            "t",
            chrono::DateTime::from_timestamp(0, 0).unwrap(),
            "deterministic completion",
            None,
            None,
        );
        assert_eq!(store.to_ocsf()["activity_id"], 1);
        assert_eq!(store.to_ocsf()["type_uid"], 600301);
    }

    #[test]
    fn declining_is_not_a_failure() {
        // Declining is the common path for routing and cache policies.
        // If it rendered as an error the dashboards would show a
        // permanent fault on a correctly configured proxy.
        let audit = DecisionAudit::new(
            uuid::Uuid::nil(),
            "req-1",
            DecisionEvent::RouteDecide,
            DecisionEngine::Wasm,
            DecisionOutcome::Decline,
            "api.local",
            "t",
            chrono::DateTime::from_timestamp(0, 0).unwrap(),
            "no rule matched; built-in strategy applies",
            None,
            None,
        );
        let json = audit.to_ocsf();
        assert_eq!(json["status_id"], 1);
        assert_eq!(json["disposition_id"], 1);
        assert_eq!(json["is_alert"], false);
    }

    #[test]
    fn a_credential_in_a_raw_reason_never_reaches_the_record() {
        // A `reason` comes back from an operator-authored hook, and a
        // hook is free to explain itself by quoting what it saw. The
        // audit record is the first thing that carries a rationale off
        // the box, so it is the first chance to put a live credential in
        // a customer's SIEM. Assert on the OCSF render rather than on
        // the field, because the render is what actually ships.
        let audit = DecisionAudit::new(
            uuid::Uuid::nil(),
            "req-1",
            DecisionEvent::CacheAdmit,
            DecisionEngine::Lua,
            DecisionOutcome::Deny,
            "api.local",
            "t",
            chrono::DateTime::from_timestamp(0, 0).unwrap(),
            "upstream refused: Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345 \
             using key sk-abcdefghijklmnopqrstuvwxyz1234",
            None,
            None,
        );
        let rendered = audit.to_ocsf().to_string();
        assert!(
            !rendered.contains("abcdefghijklmnopqrstuvwxyz012345"),
            "bearer token survived into the record: {rendered}"
        );
        assert!(
            !rendered.contains("sk-abcdefghijklmnopqrstuvwxyz1234"),
            "api key survived into the record: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        // Both OCSF fields that carry the rationale, not just the one
        // that happened to be checked first.
        let json = audit.to_ocsf();
        assert_eq!(json["policy"]["desc"], json["message"]);
    }

    #[test]
    fn the_scrub_runs_before_the_bound_and_not_after() {
        // The ordering is load bearing, so prove both directions.
        //
        // Every detection pattern needs a minimum body length; the
        // Bearer pattern needs twenty characters after the keyword.
        // Place a 24-character token so a 512-byte cut lands ten
        // characters into it, which is below what the pattern needs.
        // Bound first and the pattern stops matching, so ten characters
        // of a live token ship as ordinary text. Scrub first and the
        // whole token is gone before anything is measured.
        const TOKEN: &str = "AbCdEfGh0123456789ijKLmn";
        // 495 filler + "Bearer " (7) = 502, so the bound falls at
        // TOKEN[10].
        let filler = "a".repeat(495);
        let raw = format!("{filler}Bearer {TOKEN}");
        assert_eq!(TOKEN.len(), 24);
        assert_eq!(raw.len(), 526, "the arithmetic this test rests on");

        // The counterfactual. If this assertion ever fails the test has
        // stopped proving anything, because truncate-then-scrub would no
        // longer be the leak it is being contrasted with.
        let cut_first = sbproxy_util::truncate_utf8(&raw, RedactedReason::MAX_BYTES);
        let bound_first = crate::redact::redact_secrets(cut_first);
        assert!(
            bound_first.contains("AbCdEfGh01"),
            "bounding first is expected to leak the token prefix: {bound_first}"
        );

        // The implementation, in the other order.
        let reason = RedactedReason::redact(&raw, None, None, None);
        assert!(
            !reason.as_str().contains("AbCdEfGh"),
            "token prefix survived: {}",
            reason.as_str()
        );
        assert!(reason.as_str().ends_with("Bearer [REDACTED]"));
        assert!(reason.as_str().len() <= RedactedReason::MAX_BYTES);
    }

    #[test]
    fn a_reason_cannot_be_smuggled_in_through_deserialization() {
        // A record read back off the wire came from somewhere this
        // process cannot vouch for. Deriving `Deserialize` on the
        // newtype would hand that text straight into a type whose whole
        // contract is that it carries none.
        let wire = serde_json::json!({
            "event_id": "00000000-0000-0000-0000-000000000000",
            "request_id": "req-1",
            "event": "cache_admit",
            "engine": "lua",
            "outcome": "deny",
            "origin": "api.local",
            "tenant": "t",
            "occurred_at": "2026-08-12T00:00:00Z",
            "reason": "hook said Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
            "rule_id": null,
        });
        let audit: DecisionAudit = serde_json::from_value(wire).expect("record parses");
        assert_eq!(
            audit.reason.as_str(),
            "hook said Authorization: Bearer [REDACTED]"
        );

        // The newtype on its own, so the guarantee is pinned to the type
        // rather than only to the record that happens to hold one today.
        let bare: RedactedReason =
            serde_json::from_str("\"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"")
                .expect("string parses");
        assert_eq!(bare.as_str(), "sk-ant-[REDACTED]");
    }

    #[test]
    fn an_overlong_clean_reason_is_bounded_on_a_character_boundary() {
        // One ASCII byte then 300 two-byte characters, so every boundary
        // past the first sits at an odd offset and the 512-byte bound
        // cannot land on one. A naive slice panics here; a naive byte
        // copy emits invalid UTF-8 into a SIEM that is entitled to
        // assume the field is a string.
        let raw = format!("x{}", "é".repeat(300));
        assert_eq!(raw.len(), 601);

        let reason = RedactedReason::redact(&raw, None, None, None);
        assert!(reason.as_str().len() <= RedactedReason::MAX_BYTES);
        assert_eq!(
            reason.as_str().len(),
            511,
            "backed off to the boundary below 512 rather than splitting a character"
        );
        assert!(reason.as_str().ends_with('é'));
        // Clean input stays clean: the bound is the only pass that did
        // anything.
        assert!(!reason.as_str().contains("REDACTED"));
    }

    /// One compiled operator mask, the shape `redact.patterns:` entries
    /// compile to at config load.
    fn pattern_mask(pattern: &str, replacement: &str) -> (regex::Regex, String) {
        (
            regex::Regex::new(pattern).expect("test pattern compiles"),
            replacement.to_owned(),
        )
    }

    /// An [`crate::logging::OpRedactState`] carrying only the slots a
    /// test names.
    ///
    /// Every field is spelled out rather than reached through
    /// `..OpRedactState::empty()`, matching how the logging tests build
    /// one. Struct-update syntax would let a new scope land defaulted to
    /// "no rules" inside tests whose entire subject is that the rules
    /// run, and that failure is invisible: the assertions still pass.
    fn state_with(
        patterns: Vec<(regex::Regex, String)>,
        tenant_patterns: std::collections::HashMap<String, Vec<(regex::Regex, String)>>,
        proxy_pii: Option<sbproxy_security::pii::PiiRedactor>,
    ) -> crate::logging::OpRedactState {
        crate::logging::OpRedactState {
            fields: Vec::new(),
            patterns,
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns,
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
            proxy_pii,
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn the_operators_pii_rules_run_on_the_reason_when_the_caller_resolves_them() {
        // The config-free floor knows credential shapes, not the
        // operator's idea of PII. The redaction state is a parameter
        // rather than a lookup because the composed per-scope rules are
        // keyed by a scope this type cannot derive, so passing `None`
        // where rules exist is the quiet way to lose them. Pin both
        // halves.
        let raw = "hook matched the account for bob@acme.com";
        assert!(
            RedactedReason::redact(raw, None, None, None)
                .as_str()
                .contains("bob@acme.com"),
            "the floor alone does not know about email; that is what the rules are for"
        );

        let state = state_with(
            Vec::new(),
            std::collections::HashMap::new(),
            Some(sbproxy_security::pii::PiiRedactor::defaults()),
        );
        let scrubbed = RedactedReason::redact(raw, Some(&state), None, None);
        assert!(
            !scrubbed.as_str().contains("bob@acme.com"),
            "operator rules did not run: {}",
            scrubbed.as_str()
        );
    }

    #[test]
    fn an_operator_pattern_mask_reaches_the_audit_reason() {
        // The bug this test exists for. `redact.patterns:` is documented
        // as the general extension point for "mask this shape wherever it
        // appears", and it ran on the access log, the error log, and the
        // trace exporter. It did not run here, so an operator who masked
        // an account number saw it masked in their own logs and shipped
        // verbatim in the OCSF record going to their SIEM. The audit feed
        // is the one that leaves the building.
        let state = state_with(
            vec![pattern_mask(r"ACCT-[0-9]{10}", "[ACCT]")],
            std::collections::HashMap::new(),
            None,
        );
        let raw = "no cache for ACCT-1234567890";

        // The counterfactual: nothing but the floor, which is what this
        // path used to run. If this ever starts masking, the assertion
        // below has stopped proving the patterns pass is wired.
        assert!(
            RedactedReason::redact(raw, None, None, None)
                .as_str()
                .contains("ACCT-1234567890"),
            "the credential floor is not expected to know an operator's account shape"
        );

        let scrubbed = RedactedReason::redact(raw, Some(&state), None, None);
        assert_eq!(scrubbed.as_str(), "no cache for [ACCT]");
    }

    #[test]
    fn a_tenant_scope_pattern_applies_to_that_tenant_and_not_another() {
        // Same isolation the log path gives a tenant-scope rule set. A
        // mask written under one tenant must not scrub a sibling's
        // records, or a shared proxy leaks one customer's redaction
        // policy into another's evidence.
        let mut tenant_patterns = std::collections::HashMap::new();
        tenant_patterns.insert(
            "acme".to_owned(),
            vec![pattern_mask(r"ACCT-[0-9]{10}", "[ACCT]")],
        );
        let state = state_with(Vec::new(), tenant_patterns, None);
        let raw = "no cache for ACCT-1234567890";

        let at_acme = RedactedReason::redact(raw, Some(&state), Some("acme"), None);
        assert_eq!(at_acme.as_str(), "no cache for [ACCT]");

        let at_other = RedactedReason::redact(raw, Some(&state), Some("other"), None);
        assert_eq!(
            at_other.as_str(),
            "no cache for ACCT-1234567890",
            "a tenant-scope mask must not fire for a sibling tenant"
        );
    }

    #[test]
    fn an_operator_pattern_runs_before_the_bound_and_not_after() {
        // The ordering argument the credential floor makes applies to
        // operator masks too, and an operator pattern is more brittle
        // than the built-ins: `ACCT-[0-9]{10}` needs all ten digits, so a
        // cut anywhere inside the number stops it matching and the
        // surviving prefix ships as ordinary text.
        let state = state_with(
            vec![pattern_mask(r"ACCT-[0-9]{10}", "[ACCT]")],
            std::collections::HashMap::new(),
            None,
        );
        // 500 filler + the 15-character account number, so a 512-byte cut
        // lands after "ACCT-" plus seven digits.
        let filler = "b".repeat(500);
        let raw = format!("{filler}ACCT-1234567890");
        assert_eq!(raw.len(), 515, "the arithmetic this test rests on");

        // Bound first, then mask: the pattern no longer matches and most
        // of the number survives.
        let cut_first = sbproxy_util::truncate_utf8(&raw, RedactedReason::MAX_BYTES);
        let bound_first = state.redact_free_text(None, None, cut_first);
        assert!(
            bound_first.contains("ACCT-1234567"),
            "bounding first is expected to leak the prefix: {bound_first}"
        );

        // The implementation, in the other order.
        let reason = RedactedReason::redact(&raw, Some(&state), None, None);
        assert!(
            !reason.as_str().contains("ACCT-"),
            "account prefix survived: {}",
            reason.as_str()
        );
        assert!(reason.as_str().ends_with("[ACCT]"));
        assert!(reason.as_str().len() <= RedactedReason::MAX_BYTES);
    }

    #[test]
    fn the_record_scrubs_its_reason_under_its_own_tenants_rules() {
        // The constructor takes the state and the route and derives the
        // tenant half of the scope from the record's own `tenant`, so a
        // record cannot be filed under one tenant and scrubbed under
        // another's rules. Assert on the OCSF render, because that is
        // what ships.
        let mut tenant_patterns = std::collections::HashMap::new();
        tenant_patterns.insert(
            "acme".to_owned(),
            vec![pattern_mask(r"ACCT-[0-9]{10}", "[ACCT]")],
        );
        let state = state_with(Vec::new(), tenant_patterns, None);

        let audit = DecisionAudit::new(
            uuid::Uuid::nil(),
            "req-1",
            DecisionEvent::CacheAdmit,
            DecisionEngine::Lua,
            DecisionOutcome::Decline,
            "api-origin",
            "acme",
            chrono::DateTime::from_timestamp(0, 0).unwrap(),
            "no cache for ACCT-1234567890",
            Some(&state),
            Some("api.acme.example.com"),
        );
        let rendered = audit.to_ocsf().to_string();
        assert!(
            !rendered.contains("ACCT-1234567890"),
            "operator mask never reached the OCSF record: {rendered}"
        );
        assert_eq!(audit.reason.as_str(), "no cache for [ACCT]");
    }

    #[test]
    fn the_metric_family_accepts_every_event_engine_and_outcome() {
        // Prometheus panics on a label-count mismatch, and the recorders
        // build their label arrays by hand. Drive every combination
        // through once so a future variant cannot land without its
        // label.
        for event in DecisionEvent::ALL {
            for engine in DecisionEngine::ALL {
                for outcome in DecisionOutcome::ALL {
                    record_decision(*event, *engine, *outcome, "api.local", "tenant-a");
                }
                record_decision_duration(*event, *engine, "api.local", 0.001);
                record_decision_fail_open(*event, *engine, "api.local", "tenant-a");
            }
        }
    }
}
