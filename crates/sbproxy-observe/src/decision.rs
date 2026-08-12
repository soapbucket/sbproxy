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
/// events with no competitor equivalent, and the AI failure event is
/// still landing.
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
    /// Fires per chunk. Never emits a per-event audit record; see
    /// [`DecisionEvent::emits_audit_by_default`].
    AiStreamEvent,
    /// A streamed response finished and its aggregates were reported.
    AiClose,
    /// An upstream AI call failed.
    AiFailure,
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

    /// Whether this event emits a SIEM audit record when the operator
    /// has not said otherwise.
    ///
    /// Defaulting by security relevance rather than blanket-on, because
    /// an audit feed nobody can afford to ingest gets turned off whole,
    /// and then the security-relevant events go with it.
    ///
    /// [`Self::AiStreamEvent`] is the one event that is never on by
    /// default and cannot usefully be: it fires per chunk, so a
    /// per-event SIEM feed is an ingest bill rather than a control.
    /// Aggregate at [`Self::AiClose`] instead.
    ///
    /// [`Self::RouteDecide`] is the interesting middle case. It is worth
    /// emitting when a decision crosses a provider or data-residency
    /// boundary and is noise otherwise, which is a predicate over the
    /// decision rather than a property of the event. It defaults off and
    /// the routing event config carries the predicate.
    pub const fn emits_audit_by_default(self) -> bool {
        match self {
            Self::Auth
            | Self::Policy
            | Self::RateLimit
            | Self::Waf
            | Self::AiGuardrailInput
            | Self::AiGuardrailOutput
            | Self::AiToolCall
            | Self::CacheKey
            | Self::McpTool
            | Self::PaymentLifecycle => true,
            Self::CacheAdmit
            | Self::RouteDecide
            | Self::AiStreamEvent
            | Self::AiClose
            | Self::AiFailure
            | Self::Transform
            | Self::Action
            | Self::LogCustomField => false,
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
            Self::BuiltIn
            | Self::Plugin
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
/// by config, which makes it the safer multi-tenant dimension. Every
/// label value goes through the global cardinality limiter, which
/// demotes overflow to `__other__`. The budgets are per label name and
/// shared across every metric using that name: `origin` is 200, `tenant`
/// is 1000. Callers pass the request `Host` for `origin`, matching every
/// other origin-labelled recorder in the tree, so a wildcard origin can
/// consume the budget faster than a config origin count suggests.
pub fn record_decision(
    event: DecisionEvent,
    engine: DecisionEngine,
    outcome: DecisionOutcome,
    origin: &str,
    tenant: &str,
) {
    let origin =
        sanitize_label_budget_tenant("sbproxy_extension_event_total", "origin", origin, tenant);
    let tenant = sanitize_label_budget("sbproxy_extension_event_total", "tenant", tenant);
    metrics()
        .extension_event_total
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
    let origin =
        sanitize_label_budget("sbproxy_extension_event_duration_seconds", "origin", origin);
    metrics()
        .extension_event_duration
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
        "sbproxy_extension_event_fail_open_total",
        "origin",
        origin,
        tenant,
    );
    let tenant = sanitize_label_budget("sbproxy_extension_event_fail_open_total", "tenant", tenant);
    metrics()
        .extension_event_fail_open
        .with_label_values(&[
            event.as_label(),
            engine.as_label(),
            origin.as_str(),
            tenant.as_str(),
        ])
        .inc();
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
    /// Why. Redacted before it reaches this struct.
    pub reason: String,
    /// Stable identifier for the rule or hook that decided, when the
    /// engine exposes one.
    pub rule_id: Option<String>,
}

impl DecisionAudit {
    /// Build a record. `reason` must already be redacted.
    ///
    /// Nine arguments, and every one is load bearing on a SIEM record:
    /// dropping any of `event_id`, `request_id`, `origin`, `tenant`, or
    /// `occurred_at` makes the record unfilterable or uncorrelatable,
    /// which is the failure this whole family exists to avoid. A
    /// builder would let a caller omit one and find out in production.
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
        reason: impl Into<String>,
    ) -> Self {
        let tenant = tenant.into();
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
            reason: reason.into(),
            rule_id: None,
        }
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
        serde_json::json!({
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
                "desc": self.reason,
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
            "message": self.reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_per_chunk_event_never_audits_by_default() {
        // A per-chunk SIEM feed is an ingest bill, not a control. This
        // is the one default that must not drift.
        assert!(!DecisionEvent::AiStreamEvent.emits_audit_by_default());
    }

    #[test]
    fn security_relevant_events_audit_by_default() {
        for event in [
            DecisionEvent::Auth,
            DecisionEvent::Policy,
            DecisionEvent::AiGuardrailInput,
            DecisionEvent::AiGuardrailOutput,
            DecisionEvent::AiToolCall,
            DecisionEvent::CacheKey,
            DecisionEvent::PaymentLifecycle,
        ] {
            assert!(
                event.emits_audit_by_default(),
                "{event} is security relevant and must default on"
            );
        }
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
        );
        let json = audit.to_ocsf();
        assert_eq!(json["status_id"], 1);
        assert_eq!(json["disposition_id"], 1);
        assert_eq!(json["is_alert"], false);
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
