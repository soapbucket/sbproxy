// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

// Every item below exists to feed the durable billing queue, and that queue
// only exists in a `payments` build. The mapping rules and the identifier
// derivation are compiled and unit tested unconditionally anyway: they are
// the correctness property this module is here for, and a rule that is only
// checked in a feature-gated lane nobody builds is a rule nobody checks.
#![cfg_attr(not(feature = "payments"), allow(dead_code))]

//! Turning a served request into queued, billable usage (WOR-2169).
//!
//! `proxy.payments.usage_reporters.stripe_meter` shipped with a reporter, a
//! durable queue, and a recovery worker that drains it, and with nothing
//! anywhere that put a row into that queue. An operator could configure the
//! block, pass validation, pass startup, serve a month of paid traffic, and
//! bill nobody. The existing integration tests exercised the reporter
//! contract directly, which is exactly why none of them noticed: they
//! started one step past the missing step.
//!
//! This module is the producer. It is the only place in the request path
//! that calls `sbproxy_billing::store::SettlementStore::enqueue_usage_event`.
//!
//! Every reference to the billing crate in this file's documentation is a
//! plain code span rather than an intra-doc link, on purpose. `payments` is
//! not a default feature, and the docs lane builds with default features, so
//! a link to a feature-gated item resolves on a `payments` build and fails
//! the gate on every other one.
//!
//! # Why the bridge lives here rather than in the meter
//!
//! `sbproxy-meter` depends on no other crate in this workspace, on purpose,
//! so an operator metering a plain REST API can compile it without the
//! gateway or the settlement stack. An edge from the meter to
//! `sbproxy-billing` would end that quietly. `sbproxy-core` already sees the
//! meter, the AI plane, the MCP dispatcher, and the billing crate, so the
//! adapter goes here and the arrow only ever points core to billing.
//!
//! # The hot path enqueues and never dials a provider
//!
//! Everything below writes one durable row and stops. No HTTP call to
//! Stripe happens on a request, ever: the provider call is
//! `sbproxy_billing::worker::SettlementWorker`'s job, behind its own
//! lease, its own idempotency key, and its own dispatch stamp. A meter that
//! called Stripe inline would put a third party's availability on the
//! request path of a proxy whose entire value proposition is not doing that.
//!
//! # The identifier is the whole correctness story
//!
//! [`usage_identifier`] derives the provider deduplication key. Getting it
//! wrong has exactly two outcomes and both are bad: an identifier that
//! collides drops a charge, and one that varies between two reports of the
//! same unit charges the customer twice. So it is derived from the claim,
//! the reporter, the resource, and the unit, by a pure function over
//! length-framed inputs, with no clock, no counter, and no randomness in it.
//! Read [`usage_identifier`]'s own documentation before changing anything
//! about it.
//!
//! # Doing nothing is the common case and costs nothing
//!
//! A deployment with no reporter configured reaches `record_billable_usage`,
//! finds no bridge on the pinned pipeline, and returns. No allocation, no
//! mapping, no lock, no store call.
//! `an_ai_request_with_no_reporter_configured_queues_nothing` in
//! `e2e/tests/usage_bridge.rs` proves it from outside the process, against
//! both the durable queue and the metric.

use sha2::{Digest as _, Sha256};

use sbproxy_config::payments::{
    USAGE_UNIT_COMPLETION_TOKENS, USAGE_UNIT_PROMPT_TOKENS, USAGE_UNIT_TOTAL_TOKENS,
};

/// Prefix on every identifier this module derives.
///
/// Namespaces the proxy's identifiers against anything else an operator
/// reports into the same Stripe meter by hand, and makes an identifier
/// recognisable in a provider dashboard without having to be reversible.
const IDENTIFIER_PREFIX: &str = "sbu";

/// How much of the digest goes into an identifier, in hex characters.
///
/// 128 bits. The readable claim prefix already separates one request's
/// units from another's, so the digest only has to separate units inside
/// one claim; 128 bits is far past the point where that could fail and
/// still leaves the whole identifier comfortably inside Stripe's 200
/// character limit.
const DIGEST_HEX_CHARS: usize = 32;

/// Longest claim fragment carried in the clear inside an identifier.
///
/// The claim is there so an operator reading a provider dashboard can find
/// the request without a lookup table. It is a convenience, not the
/// uniqueness mechanism, which is why truncating it is safe: the digest
/// underneath covers the untruncated value.
const CLAIM_PREFIX_MAX_CHARS: usize = 64;

// --- Resources ---

/// What kind of thing consumed the unit being billed.
///
/// A closed enum with one variant per producer, so an MCP tool call is
/// recorded as an MCP tool call. The AI usage plane already encodes a tool
/// call as `provider: "mcp"` with the server name in the `model` field,
/// which is a reasonable trick for making tool spend filterable next to
/// model spend in one log stream, and a bad thing to put on an invoice: a
/// buyer reading `model: acme-search` on a bill for a tool call has been
/// told something untrue about what they bought.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ResourceKind {
    /// An HTTP route the `proxy.attestation` meter priced.
    HttpRoute,
    /// A model that served an AI request.
    AiModel,
    /// A tool an MCP server dispatched.
    McpTool,
}

impl ResourceKind {
    /// Stable snake-case name, used as the `resource_type` attribute on a
    /// queued usage event and as a metric label value.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HttpRoute => "http_route",
            Self::AiModel => "ai_model",
            Self::McpTool => "mcp_tool",
        }
    }
}

/// One quantity, ready to be queued against one reporter.
///
/// Deliberately plain data with no billing type in it, so the mapping rules
/// and the identifier derivation compile and are tested in every build
/// rather than only in one nobody's CI runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BillableUnit {
    /// What kind of thing consumed it.
    pub(crate) kind: ResourceKind,
    /// Which one, named the way the operator would recognise it: the route
    /// path, `provider/model`, or `server/tool`.
    pub(crate) resource: String,
    /// The unit name that appears on the invoice line.
    pub(crate) unit: String,
    /// How many. Never zero: see [`map_ai`].
    pub(crate) quantity: u64,
}

/// One MCP tool call a request dispatched, recorded for the bridge.
///
/// Held on [`crate::context::RequestContext`] because a tool call happens
/// during dispatch and the queue is written in `logging`, by which point the
/// dispatcher is long gone. Recorded only when a bridge is configured, so a
/// deployment without one allocates nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolCall {
    /// The MCP server that owns the tool.
    pub server: String,
    /// The tool, with any `<server>__` federation prefix already stripped.
    pub tool: String,
}

// --- The identifier ---

/// Derive the provider deduplication identifier for one billable unit.
///
/// # What this has to guarantee
///
/// Two things, and they pull in opposite directions.
///
/// **Stable.** The same unit reported twice, from two processes, on two
/// sides of a restart, has to produce the same string, or the customer is
/// charged twice. So the inputs are all durable facts about the unit and
/// nothing else: no clock, no counter, no process identity, no randomness.
/// The recovery worker replays a queued row verbatim, so a row written
/// before a crash and drained after one carries the identifier this function
/// produced at enqueue time, unchanged.
///
/// **Distinct.** Two different units must not collide, or a charge is
/// silently dropped by the provider's own deduplication and nothing anywhere
/// records that it went missing. The request id alone is not enough and this
/// is the mistake worth naming: one request routinely produces several
/// billable units, a route weight and an egress count and three tool calls,
/// and keying them all on the request would report the first and discard the
/// rest.
///
/// # The framing
///
/// The five inputs are length-framed (`<len>:<bytes>`) rather than joined
/// with a separator. A separator has to be a byte that cannot appear in any
/// input, and `resource` is a route path or a model name, which are
/// operator- and vendor-controlled. Length framing is injective whatever the
/// inputs contain, so `("ab", "c")` and `("a", "bc")` cannot hash alike.
///
/// # The shape
///
/// `sbu-<claim>-<digest>`, where `<claim>` is the claim id reduced to
/// characters a provider will accept and truncated, and `<digest>` is the
/// first [`DIGEST_HEX_CHARS`] of SHA-256 over the framed tuple. The claim is
/// carried in the clear so an operator looking at a Stripe dashboard can
/// find the request; uniqueness rests entirely on the digest, which covers
/// the untruncated inputs.
pub(crate) fn usage_identifier(
    claim_id: &str,
    reporter: &str,
    kind: ResourceKind,
    resource: &str,
    unit: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [claim_id, reporter, kind.as_str(), resource, unit] {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());

    let claim: String = claim_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .take(CLAIM_PREFIX_MAX_CHARS)
        .collect();

    format!(
        "{IDENTIFIER_PREFIX}-{claim}-{}",
        &digest[..DIGEST_HEX_CHARS]
    )
}

// --- Mapping ---

/// The units an HTTP request receipt contributes to one meter event.
///
/// `billed` is what the operator's own
/// [`sbproxy_meter::OutcomeTable::billable_units`] returned, never the raw
/// resolver output. That is the whole point of taking it as a parameter
/// rather than re-deriving it: a cache hit, a policy block, a rate limit, or
/// a client disconnect is charged or not charged according to the table the
/// operator wrote, and this module has no opinion of its own to add. A
/// receipt that billed nothing contributes nothing here, and does so without
/// any rule in this file saying so.
///
/// Only units whose name matches the meter event's configured `unit` are
/// reported. A deployment metering `egress_kib` and `search_call` against
/// one Stripe meter that bills `search_call` reports the search calls and
/// leaves the kibibytes for a meter event that asks for them.
pub(crate) fn map_http(
    unit_name: &str,
    route: &str,
    billed: &[sbproxy_meter::Unit],
) -> Vec<BillableUnit> {
    billed
        .iter()
        .filter(|unit| unit.name == unit_name && unit.count > 0)
        .map(|unit| BillableUnit {
            kind: ResourceKind::HttpRoute,
            resource: route.to_string(),
            unit: unit.name.clone(),
            quantity: unit.count,
        })
        .collect()
}

/// The units an AI request contributes to one meter event.
///
/// At most one, because a meter event carries one quantity. The provider and
/// the model are both on the resource name: two providers serving the same
/// model name are two different costs, and a bill that merged them could not
/// be reconciled against either provider's own invoice.
///
/// A zero quantity yields nothing rather than a zero-quantity row. Stripe
/// refuses a meter event with a zero value, so queueing one would turn a
/// request that legitimately consumed nothing into a durable row that can
/// only ever fail.
pub(crate) fn map_ai(
    unit_name: &str,
    provider: &str,
    model: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Vec<BillableUnit> {
    let quantity = match unit_name {
        USAGE_UNIT_PROMPT_TOKENS => prompt_tokens,
        USAGE_UNIT_COMPLETION_TOKENS => completion_tokens,
        USAGE_UNIT_TOTAL_TOKENS => prompt_tokens.saturating_add(completion_tokens),
        // Unreachable through a validated document: the configuration
        // crate refuses an `ai` unit outside its own vocabulary. It is a
        // fallback rather than a panic because this is a runtime, and a
        // runtime that panics on input it was told had been validated takes
        // a served request down over somebody else's bug.
        _ => 0,
    };
    if quantity == 0 {
        return Vec::new();
    }
    vec![BillableUnit {
        kind: ResourceKind::AiModel,
        resource: format!("{provider}/{model}"),
        unit: unit_name.to_string(),
        quantity,
    }]
}

/// The units a request's MCP tool calls contribute to one meter event.
///
/// One per distinct tool, counted rather than one row per call, because the
/// identifier is derived from the resource and two rows for the same tool in
/// the same request would derive the same identifier and the second would be
/// silently discarded as a duplicate. Counting is the honest encoding: three
/// calls to one tool is a quantity of three, not three events the provider
/// deduplicates back down to one.
///
/// Order follows first dispatch, so two runs of the same traffic queue the
/// same rows in the same order.
pub(crate) fn map_mcp(unit_name: &str, calls: &[McpToolCall]) -> Vec<BillableUnit> {
    let mut units: Vec<BillableUnit> = Vec::new();
    for call in calls {
        let resource = format!("{}/{}", call.server, call.tool);
        match units.iter_mut().find(|unit| unit.resource == resource) {
            Some(existing) => existing.quantity = existing.quantity.saturating_add(1),
            None => units.push(BillableUnit {
                kind: ResourceKind::McpTool,
                resource,
                unit: unit_name.to_string(),
                quantity: 1,
            }),
        }
    }
    units
}

// --- The runtime half ---

#[cfg(feature = "payments")]
mod runtime {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use sbproxy_billing::registry::UsageEvent;
    use sbproxy_billing::store::SettlementStore;
    use sbproxy_config::payments::{PaymentsConfig, UsageSource};
    use sbproxy_config::types::FailureMode;

    use super::{map_ai, map_http, map_mcp, usage_identifier, BillableUnit, ResourceKind};
    use crate::context::RequestContext;
    use crate::meter_runtime::SettledRequest;

    /// Attribute naming the resource kind on a queued usage event.
    pub(crate) const ATTRIBUTE_RESOURCE_TYPE: &str = "resource_type";

    /// Attribute naming the specific resource.
    pub(crate) const ATTRIBUTE_RESOURCE_NAME: &str = "resource_name";

    /// Attribute naming the unit the quantity counts.
    pub(crate) const ATTRIBUTE_UNIT: &str = "unit";

    /// Attribute carrying the claim every attempt at one unit of work
    /// shares, so a queued row joins back to the signed receipt.
    pub(crate) const ATTRIBUTE_CLAIM_ID: &str = "claim_id";

    /// Attribute naming the outcome the operator's table priced.
    ///
    /// Carried so a queued row states, in the vocabulary of the receipt
    /// beside it, *why* it is a charge. "You billed me for a cache hit" is
    /// a complaint an operator answers by pointing at their own table, and
    /// they can only do that if the row says the outcome was `cache_hit`
    /// rather than leaving them to infer it from a timestamp.
    pub(crate) const ATTRIBUTE_OUTCOME: &str = "outcome";

    /// One configured meter event, lowered.
    ///
    /// Crate visible rather than public: nothing outside this crate has a
    /// reason to name one, and a public type here would widen the surface
    /// the pub-item ratchet has to keep honest for no benefit.
    #[derive(Debug)]
    pub(crate) struct UsageBinding {
        /// The reporter this event is drained through.
        pub(crate) reporter: String,
        /// The provider's event name.
        pub(crate) event_name: String,
        /// Principal metadata key holding the provider customer id.
        pub(crate) customer_field: String,
        /// The attribute name the reporter reads that id back from.
        pub(crate) customer_attribute: &'static str,
        /// Which request-path record is authoritative for this event.
        pub(crate) source: UsageSource,
        /// The unit this event bills.
        pub(crate) unit: String,
    }

    /// Every configured meter event, plus the posture that decides what
    /// happens when the queue will not take a row.
    ///
    /// Built once per settlement runtime and then immutable except for the
    /// `writable` flag, so the request path never re-reads YAML. A link
    /// rather than a code span there would be an intra-doc link from a
    /// public type to a private field, which rustdoc refuses.
    #[derive(Debug)]
    pub struct UsageBridgeRuntime {
        bindings: Vec<UsageBinding>,
        failure_posture: FailureMode,
        writable: AtomicBool,
    }

    impl UsageBridgeRuntime {
        /// Lower `proxy.payments.usage_reporters` into a bridge, or return
        /// `None` when nothing is configured.
        ///
        /// `None` rather than an empty bridge on purpose. The request path
        /// tests one `Option` and stops, which is what makes "no reporter
        /// configured does no billing work" a property of the shape rather
        /// than of a length check somebody could later forget.
        // A build with `payments` and no rail feature carries the store,
        // the service, and the worker but no reporter, so it reads neither
        // argument and every configured reporter has already failed the
        // compiled-feature check by name in `billing_runtime`.
        #[cfg_attr(not(feature = "payment-stripe"), allow(unused_variables, unused_mut))]
        #[must_use]
        pub fn from_config(config: &PaymentsConfig) -> Option<Arc<Self>> {
            let mut bindings = Vec::new();
            let mut failure_posture = FailureMode::Degraded;

            #[cfg(feature = "payment-stripe")]
            if let Some(meter) = &config.usage_reporters.stripe_meter {
                bindings.push(UsageBinding {
                    reporter: sbproxy_billing::stripe_meter::STRIPE_METER_REPORTER.to_string(),
                    event_name: meter.event_name.clone(),
                    customer_field: meter.customer_field.clone(),
                    customer_attribute: sbproxy_billing::stripe_meter::ATTRIBUTE_STRIPE_CUSTOMER_ID,
                    source: meter.source,
                    unit: meter.unit.clone(),
                });
                // One posture for the bridge, taken from the reporters that
                // are configured. There is exactly one reporter today; when
                // a second lands it gets its own posture and this becomes a
                // per-binding field rather than a bridge-wide one.
                failure_posture = meter.failure_posture;
            }

            if bindings.is_empty() {
                return None;
            }
            Some(Arc::new(Self {
                bindings,
                failure_posture,
                writable: AtomicBool::new(true),
            }))
        }

        /// The posture in force when a durable enqueue fails.
        #[must_use]
        pub fn failure_posture(&self) -> FailureMode {
            self.failure_posture
        }

        /// Whether a row written now would land.
        ///
        /// One relaxed atomic load, read from `response_filter` on every
        /// response an origin with a bridge serves.
        #[must_use]
        pub fn is_writable(&self) -> bool {
            self.writable.load(Ordering::Relaxed)
        }

        /// Stop admitting rows.
        ///
        /// Called on the `closed` branch so the *next* request is refused
        /// before its body goes out. It does nothing for the request that
        /// just failed: that one has already been served and cannot be
        /// recalled, which is the same constraint the receipt chain works
        /// under and for the same reason.
        fn close(&self) {
            self.writable.store(false, Ordering::Relaxed);
        }
    }

    /// Whether this response must be refused rather than served unbilled.
    ///
    /// Called from `response_filter`, before the body reaches the client.
    /// True only under `closed`, and only once a durable enqueue has
    /// already failed once and shut the bridge. Every other posture admits.
    pub(crate) fn preflight_refuses(ctx: &RequestContext) -> bool {
        let Some(bridge) = bridge(ctx) else {
            return false;
        };
        matches!(bridge.failure_posture(), FailureMode::Closed) && !bridge.is_writable()
    }

    /// The bridge this request's pinned generation runs under.
    fn bridge(ctx: &RequestContext) -> Option<&Arc<UsageBridgeRuntime>> {
        ctx.pipeline.payments.as_ref()?.usage_bridge()
    }

    /// Queue everything this request owes, and do nothing at all when it
    /// owes nothing.
    ///
    /// Called from `logging`, once, after the receipt has been cut. `logging`
    /// runs after the response has been written to the client, so the SQLite
    /// write below is off the latency path a caller can see.
    ///
    /// Never fails, never panics, and never propagates. A billing defect
    /// that took a served request down with it would be a worse bug than the
    /// one it was reporting.
    pub(crate) async fn record_billable_usage(
        ctx: &RequestContext,
        settled: Option<&SettledRequest>,
    ) {
        let Some(bridge) = bridge(ctx) else {
            // The overwhelmingly common path: no reporter configured, so
            // no mapping, no allocation, no store call.
            return;
        };
        let Some(payments) = ctx.pipeline.payments.as_ref() else {
            return;
        };

        let tenant = ctx.tenant_id.as_str();
        for binding in &bridge.bindings {
            let Some(customer) = customer_id(ctx, &binding.customer_field) else {
                // No credential attribute means nobody to bill. Stripe
                // refuses such an event anyway, so queueing one would turn
                // a missing attribute into a row that can only ever fail
                // and would need an operator to delete it by hand.
                tracing::debug!(
                    tenant_id = %tenant,
                    reporter = %binding.reporter,
                    field = %binding.customer_field,
                    "usage-bridge: no customer identifier on this principal, nothing queued"
                );
                continue;
            };
            let units = resolve_units(ctx, binding, settled);
            for unit in units {
                enqueue_one(ctx, payments, bridge, binding, &unit, &customer, settled).await;
            }
        }
    }

    /// The units one binding claims from this request.
    fn resolve_units(
        ctx: &RequestContext,
        binding: &UsageBinding,
        settled: Option<&SettledRequest>,
    ) -> Vec<BillableUnit> {
        match binding.source {
            UsageSource::Http => match settled {
                Some(settled) => map_http(&binding.unit, &settled.route, &settled.billed),
                // No receipt means `proxy.attestation` is absent or this
                // origin's role writes none, so there is no outcome table
                // and therefore no operator answer for whether this
                // request is billable. Charging anyway would be this
                // module inventing the answer.
                None => Vec::new(),
            },
            UsageSource::Ai => {
                let (Some(provider), Some(model)) = (&ctx.ai_provider, &ctx.ai_model) else {
                    return Vec::new();
                };
                map_ai(
                    &binding.unit,
                    provider,
                    model,
                    ctx.ai_tokens_in.unwrap_or(0),
                    ctx.ai_tokens_out.unwrap_or(0),
                )
            }
            UsageSource::Mcp => {
                // The guard is taken and dropped inside this expression.
                // Nothing below it awaits, and the caller has the mapped
                // units by value before it reaches the store.
                let calls = ctx.mcp_billable_calls.lock();
                map_mcp(&binding.unit, calls.as_slice())
            }
        }
    }

    /// Write one durable row, or take the operator's failure branch.
    async fn enqueue_one(
        ctx: &RequestContext,
        payments: &crate::billing_runtime::PaymentsRuntime,
        bridge: &UsageBridgeRuntime,
        binding: &UsageBinding,
        unit: &BillableUnit,
        customer: &str,
        settled: Option<&SettledRequest>,
    ) {
        let tenant = ctx.tenant_id.as_str();
        let claim_id = claim_id(ctx, settled);
        let identifier = usage_identifier(
            &claim_id,
            &binding.reporter,
            unit.kind,
            &unit.resource,
            &unit.unit,
        );

        let mut attributes = BTreeMap::new();
        attributes.insert(binding.customer_attribute.to_string(), customer.to_string());
        attributes.insert(
            ATTRIBUTE_RESOURCE_TYPE.to_string(),
            unit.kind.as_str().to_string(),
        );
        attributes.insert(ATTRIBUTE_RESOURCE_NAME.to_string(), unit.resource.clone());
        attributes.insert(ATTRIBUTE_UNIT.to_string(), unit.unit.clone());
        attributes.insert(ATTRIBUTE_CLAIM_ID.to_string(), claim_id.clone());
        // Only an HTTP unit has a metered outcome. An AI or MCP unit is not
        // priced through the outcome table at all, and stamping one of its
        // values on such a row would put a provenance on an invoice line
        // that nothing produced.
        if let Some(settled) = settled.filter(|_| unit.kind == ResourceKind::HttpRoute) {
            attributes.insert(
                ATTRIBUTE_OUTCOME.to_string(),
                settled.outcome.as_str().to_string(),
            );
        }

        let event = UsageEvent {
            reporter: binding.reporter.clone(),
            usage_identifier: identifier,
            tenant_id: tenant.to_string(),
            origin_id: ctx.hostname.to_string(),
            event_name: binding.event_name.clone(),
            quantity: unit.quantity,
            occurred_at_ms: payments.service().clock().now_ms(),
            attributes,
        };

        match payments.service().store().enqueue_usage_event(&event).await {
            Ok(inserted) => {
                sbproxy_observe::metrics::record_usage_bridge_enqueued(
                    tenant,
                    &binding.reporter,
                    unit.kind.as_str(),
                    inserted,
                );
                tracing::trace!(
                    tenant_id = %tenant,
                    reporter = %binding.reporter,
                    resource_type = unit.kind.as_str(),
                    inserted,
                    "usage-bridge: billable unit queued"
                );
            }
            Err(error) => {
                tracing::warn!(
                    category = %error.failure_category(),
                    tenant_id = %tenant,
                    reporter = %binding.reporter,
                    resource_type = unit.kind.as_str(),
                    "usage-bridge: a billable unit could not be queued"
                );
                take_failure_branch(ctx, bridge, settled);
            }
        }
    }

    /// Do what the operator said to do when a billable unit cannot be
    /// queued.
    ///
    /// Matched exhaustively with no wildcard arm, the same way
    /// `crate::meter_runtime::take_failure_branch` is: a fifth posture is a
    /// fifth answer to "what happens to revenue that went unbilled", and
    /// inheriting one of these would be this module deciding it on the
    /// operator's behalf.
    ///
    /// `Observe` is refused by configuration validation and is therefore
    /// unreachable through a loaded document. It is handled as `Open` here
    /// rather than as a panic, because this is a runtime and a served
    /// request must not die over a posture nobody can reach.
    fn take_failure_branch(
        ctx: &RequestContext,
        bridge: &UsageBridgeRuntime,
        settled: Option<&SettledRequest>,
    ) {
        let tenant = ctx.tenant_id.as_str();
        let posture = bridge.failure_posture();
        match posture {
            FailureMode::Degraded => {
                // Admit, and leave the hole provable. The marker is an
                // ordinary chained, signed receipt, so a later verification
                // walks straight through it and an operator reconciling an
                // invoice can see which unit went unbilled.
                crate::meter_runtime::write_usage_gap_marker(ctx, settled);
            }
            FailureMode::Closed => {
                // This request is already served and cannot be recalled.
                // Closing the bridge buys the next one: `preflight_refuses`
                // reads the flag in `response_filter`, before a body goes
                // out.
                bridge.close();
                crate::meter_runtime::write_usage_gap_marker(ctx, settled);
            }
            FailureMode::Open | FailureMode::Observe => {
                // Admit and claim nothing. Cheapest, and the least
                // recoverable after the fact: the counter is the whole
                // record of this one.
            }
        }
        sbproxy_observe::metrics::record_usage_bridge_gap(tenant, posture.as_label());
    }

    /// The claim every attempt at one unit of work shares.
    ///
    /// The receipt's claim when there is a receipt, so a queued row and a
    /// signed receipt for the same work name the same claim and an operator
    /// can join them. The request id otherwise, which is what the meter
    /// itself uses when it mints a claim.
    fn claim_id(ctx: &RequestContext, settled: Option<&SettledRequest>) -> String {
        settled.map_or_else(
            || ctx.request_id.to_string(),
            |settled| settled.claim_id.clone(),
        )
    }

    /// The provider customer identifier for this request's principal.
    ///
    /// Read from the credential's metadata map rather than from a header,
    /// so a caller cannot nominate the account their usage is billed to by
    /// setting a request header.
    fn customer_id(ctx: &RequestContext, field: &str) -> Option<String> {
        ctx.principal
            .attrs
            .metadata
            .get(field)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
    }
}

#[cfg(feature = "payments")]
pub use runtime::UsageBridgeRuntime;

#[cfg(feature = "payments")]
pub(crate) use runtime::{preflight_refuses, record_billable_usage};

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::payments::USAGE_UNIT_TOOL_CALL;
    use sbproxy_meter::{Evidence, Unit};

    /// The reporter every test derives an identifier under.
    const REPORTER: &str = "stripe_meter";

    fn route_weight(name: &str, count: u64) -> Unit {
        Unit::new(
            name,
            count,
            Evidence::RouteWeight {
                config_revision: "9f2c41a0be77".to_string(),
            },
        )
    }

    #[test]
    fn the_same_unit_derives_the_same_identifier_across_a_restart() {
        // The property the whole module rests on. A row queued before a
        // crash and a row queued after one describe the same sale, and the
        // provider deduplicates on this string: if it moved, the customer
        // would be charged twice.
        //
        // Nothing here stands in for a restart because nothing needs to.
        // The derivation reads no clock, no counter, no process identity,
        // and no random source, so "call it twice" is the whole test: a
        // second process has exactly the same inputs available to it.
        let first = usage_identifier(
            "01J8XQ2R9K",
            REPORTER,
            ResourceKind::HttpRoute,
            "/v1/search",
            "search_call",
        );
        let second = usage_identifier(
            "01J8XQ2R9K",
            REPORTER,
            ResourceKind::HttpRoute,
            "/v1/search",
            "search_call",
        );

        assert_eq!(first, second);
        assert!(first.starts_with("sbu-01J8XQ2R9K-"), "{first}");
        assert!(
            first.len() <= 200,
            "a Stripe identifier is bounded at 200 characters: {first}"
        );
    }

    #[test]
    fn one_request_emitting_several_units_derives_several_identifiers() {
        // The bug this function exists to prevent. Keying on the request
        // alone would report the first unit and let the provider discard
        // every other one as a duplicate, which is a dropped charge that
        // leaves no trace anywhere.
        let claim = "01J8XQ2R9K";
        let identifiers = [
            usage_identifier(
                claim,
                REPORTER,
                ResourceKind::HttpRoute,
                "/v1/search",
                "search_call",
            ),
            usage_identifier(
                claim,
                REPORTER,
                ResourceKind::HttpRoute,
                "/v1/search",
                "egress_kib",
            ),
            usage_identifier(
                claim,
                REPORTER,
                ResourceKind::McpTool,
                "acme/search",
                "tool_call",
            ),
            usage_identifier(
                claim,
                REPORTER,
                ResourceKind::McpTool,
                "acme/fetch",
                "tool_call",
            ),
            usage_identifier(
                claim,
                REPORTER,
                ResourceKind::AiModel,
                "openai/gpt-4o",
                "total_tokens",
            ),
        ];

        let mut unique: Vec<&String> = identifiers.iter().collect();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            identifiers.len(),
            "every billable unit of one request needs its own identifier: {identifiers:?}"
        );
    }

    #[test]
    fn the_reporter_is_part_of_the_identity() {
        // Two reporters against the same unit are two provider accounts
        // and two separate charges, so they must not share a key.
        let one = usage_identifier(
            "claim_1",
            "stripe_meter",
            ResourceKind::HttpRoute,
            "/v1/search",
            "search_call",
        );
        let two = usage_identifier(
            "claim_1",
            "other_meter",
            ResourceKind::HttpRoute,
            "/v1/search",
            "search_call",
        );
        assert_ne!(one, two);
    }

    #[test]
    fn framing_keeps_a_shifted_boundary_from_colliding() {
        // Joining with a separator would need a byte that cannot appear in
        // a route path or a model name, and there is none. Length framing
        // is injective whatever the inputs contain, and this is the pair
        // that catches a naive concatenation.
        let left = usage_identifier(
            "ab",
            REPORTER,
            ResourceKind::HttpRoute,
            "/search",
            "search_call",
        );
        let right = usage_identifier(
            "a",
            REPORTER,
            ResourceKind::HttpRoute,
            "b/search",
            "search_call",
        );
        assert_ne!(left, right);

        // And the same for the two adjacent operator-controlled fields.
        let merged = usage_identifier(
            "claim_1",
            REPORTER,
            ResourceKind::HttpRoute,
            "/searchcall",
            "",
        );
        let split = usage_identifier(
            "claim_1",
            REPORTER,
            ResourceKind::HttpRoute,
            "/search",
            "call",
        );
        assert_ne!(merged, split);
    }

    #[test]
    fn an_awkward_claim_id_still_yields_a_usable_identifier() {
        // A claim id is a ULID today, but nothing on the wire guarantees
        // that forever. The prefix is a convenience and the digest is the
        // uniqueness, so anything a claim can contain has to survive into
        // a string a provider will accept.
        let identifier = usage_identifier(
            "claim/with spaces:and\u{e9}",
            REPORTER,
            ResourceKind::HttpRoute,
            "/v1/search",
            "search_call",
        );
        assert!(
            identifier
                .chars()
                .all(|character| character.is_ascii_alphanumeric()
                    || character == '-'
                    || character == '_'),
            "an identifier has to be provider safe: {identifier}"
        );

        // Truncating the readable prefix must not merge two claims that
        // differ only past the cut, because the digest covers the whole
        // untruncated value.
        let long = "c".repeat(CLAIM_PREFIX_MAX_CHARS + 8);
        let longer = format!("{long}z");
        assert_ne!(
            usage_identifier(&long, REPORTER, ResourceKind::HttpRoute, "/s", "u"),
            usage_identifier(&longer, REPORTER, ResourceKind::HttpRoute, "/s", "u"),
        );
    }

    #[test]
    fn http_mapping_reports_only_the_unit_the_meter_event_asked_for() {
        let billed = vec![
            route_weight("search_call", 5),
            route_weight("egress_kib", 12),
        ];

        let units = map_http("search_call", "/v1/search", &billed);

        assert_eq!(units.len(), 1, "one meter event bills one unit: {units:?}");
        assert_eq!(units[0].quantity, 5);
        assert_eq!(units[0].unit, "search_call");
        assert_eq!(units[0].resource, "/v1/search");
        assert_eq!(units[0].kind, ResourceKind::HttpRoute);
    }

    #[test]
    fn an_outcome_the_table_billed_nothing_for_queues_nothing() {
        // The operator's outcome table is the only thing that decides
        // this, and it decides it before the slice reaches here: a cache
        // hit priced at `no`, a policy block, and a rate limit all arrive
        // as an empty billed list. There is deliberately no rule in the
        // mapping that mentions any of them.
        assert!(map_http("search_call", "/v1/search", &[]).is_empty());

        // A resolver that ran and found nothing is not a billable
        // quantity either, and a zero-quantity meter event is one Stripe
        // refuses.
        assert!(map_http(
            "search_call",
            "/v1/search",
            &[route_weight("search_call", 0)]
        )
        .is_empty());
    }

    #[test]
    fn ai_mapping_names_the_provider_and_the_model_and_never_sums_the_wrong_pair() {
        let prompt = map_ai(USAGE_UNIT_PROMPT_TOKENS, "openai", "gpt-4o", 900, 120);
        assert_eq!(prompt[0].quantity, 900);
        assert_eq!(prompt[0].resource, "openai/gpt-4o");
        assert_eq!(prompt[0].kind, ResourceKind::AiModel);

        let completion = map_ai(USAGE_UNIT_COMPLETION_TOKENS, "openai", "gpt-4o", 900, 120);
        assert_eq!(completion[0].quantity, 120);

        let total = map_ai(USAGE_UNIT_TOTAL_TOKENS, "openai", "gpt-4o", 900, 120);
        assert_eq!(total[0].quantity, 1_020);

        // Two providers serving the same model name are two different
        // costs, and a bill that merged them could not be reconciled
        // against either provider's own invoice.
        let elsewhere = map_ai(USAGE_UNIT_TOTAL_TOKENS, "azure", "gpt-4o", 900, 120);
        assert_ne!(total[0].resource, elsewhere[0].resource);

        // A request that consumed nothing queues nothing.
        assert!(map_ai(USAGE_UNIT_TOTAL_TOKENS, "openai", "gpt-4o", 0, 0).is_empty());
    }

    #[test]
    fn an_mcp_tool_call_is_a_tool_call_and_not_a_model() {
        // The AI usage plane encodes a tool call as `provider: "mcp"` with
        // the server in the `model` field so tool spend is filterable next
        // to model spend. That is a fine trick for a log stream and a bad
        // thing to put on an invoice.
        let units = map_mcp(
            USAGE_UNIT_TOOL_CALL,
            &[McpToolCall {
                server: "acme".to_string(),
                tool: "search".to_string(),
            }],
        );

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, ResourceKind::McpTool);
        assert_eq!(units[0].kind.as_str(), "mcp_tool");
        assert_eq!(units[0].resource, "acme/search");
        assert_eq!(units[0].unit, USAGE_UNIT_TOOL_CALL);
    }

    #[test]
    fn repeat_calls_to_one_tool_become_a_quantity_rather_than_a_dropped_charge() {
        // Two rows for the same tool in the same request would derive the
        // same identifier, and the provider would discard the second. A
        // count is the encoding that survives deduplication.
        let calls = vec![
            McpToolCall {
                server: "acme".to_string(),
                tool: "search".to_string(),
            },
            McpToolCall {
                server: "acme".to_string(),
                tool: "fetch".to_string(),
            },
            McpToolCall {
                server: "acme".to_string(),
                tool: "search".to_string(),
            },
        ];

        let units = map_mcp(USAGE_UNIT_TOOL_CALL, &calls);

        assert_eq!(units.len(), 2, "two tools, two lines: {units:?}");
        assert_eq!(units[0].resource, "acme/search");
        assert_eq!(units[0].quantity, 2);
        assert_eq!(units[1].resource, "acme/fetch");
        assert_eq!(units[1].quantity, 1);

        // Every line still gets its own identifier.
        let first = usage_identifier(
            "claim_1",
            REPORTER,
            units[0].kind,
            &units[0].resource,
            &units[0].unit,
        );
        let second = usage_identifier(
            "claim_1",
            REPORTER,
            units[1].kind,
            &units[1].resource,
            &units[1].unit,
        );
        assert_ne!(first, second);
    }

    #[test]
    fn no_tool_calls_map_to_nothing() {
        assert!(map_mcp(USAGE_UNIT_TOOL_CALL, &[]).is_empty());
    }

    #[test]
    fn every_resource_kind_has_a_distinct_wire_spelling() {
        let names: Vec<&str> = [
            ResourceKind::HttpRoute,
            ResourceKind::AiModel,
            ResourceKind::McpTool,
        ]
        .into_iter()
        .map(ResourceKind::as_str)
        .collect();
        assert_eq!(names, ["http_route", "ai_model", "mcp_tool"]);
    }
}
