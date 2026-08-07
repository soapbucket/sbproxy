//! WOR-2143: the settlement origin gate for `ai_crawl_control`.
//!
//! This module decides whether an unpaid crawl request reaches the origin.
//! It runs at exactly one seam: the `check_policies` call site in the
//! request phase, immediately after the enforcer chain returned its
//! verdict. A 402 the `ai_crawl_control` policy produced is intercepted
//! here and answered from durable settlement state instead of the legacy
//! in-memory ledger.
//!
//! # Why the seam is the call site and not the enforcer
//!
//! [`sbproxy_plugin::PolicyEnforcer::enforce`] returns a boxed future whose
//! lifetime elides to `&self`, so the future cannot borrow the
//! [`RequestContext`]. Settlement has to await the durable store and then
//! mutate the context, which is only possible where an async caller owns
//! `&mut RequestContext`: the call site.
//!
//! # The authorization invariant
//!
//! Exactly one outcome admits a request:
//! [`AuthorizationDecision::Settled`] with a committed receipt, recheck of
//! the stored intent saying `Succeeded`, and a fresh single-serve nonce.
//! Every other state, and every infrastructure failure under the `closed`
//! posture, keeps the request away from the origin. Payment refusals are
//! never subject to `proxy.payments.failure_mode`; only infrastructure
//! failures are.
//!
//! # Challenge and retry, per rail
//!
//! The challenge path compiles the matched price into a
//! [`sbproxy_billing::types::PaymentRequirementDraft`], persists a durable
//! pending intent through
//! [`sbproxy_billing::service::BillingService::prepare_requirement`]
//! before the 402 is written, and renders the challenge in the selected
//! rail's wire shape. The signed quote token always travels in the
//! policy's configured challenge header, and the retry re-presents it
//! there verbatim.
//!
//! One thing stops that path before it prices anything: an intent for the
//! same route already sitting in `NeedsReconciliation`. That payment may
//! have moved a payer's money and nothing expires it, so a fresh invoice
//! for the same content would be a second bill for it. The answer is a 503
//! with `Retry-After`, counted as `operation="challenge"`,
//! `outcome="unresolved_payment"` (WOR-2230).
//!
//! # Whose payment is stuck
//!
//! That guard started out scoped to the route alone, which meant one stuck
//! payment took the route's revenue to zero for every payer of it. On
//! Lightning that is one worker sweep. On x402 there is no status endpoint,
//! so a facilitator outage could zero a hot route for its whole duration.
//! WOR-2238 narrows it to the payer the stranded intent was minted for, by
//! storing a payer scope key beside the intent and matching on it.
//!
//! The scope key is what [`payer_scope_hash`] derives, and the input is the
//! only thing at this seam that is both stable across one payer's retries
//! and different between two payers: the caller identity the request
//! already proved to the proxy, in the order [`payer_principal`] resolves
//! it. It is deliberately not rail material. No rail offers a payer
//! identity here. This is the challenge path, so by construction no live
//! quote token addresses a durable challenge; Lightning and direct Stripe
//! carry no client credential at all and a Lightning invoice records no
//! payer; Payment Auth credentials bind to one challenge rather than to a
//! payer; and an x402 payload's canonical digest identifies one payment,
//! not one payer, so a client that re-signs would read as a new payer and
//! be handed the second bill this guard exists to prevent.
//!
//! Requests the proxy cannot identify keep the original behavior on both
//! sides: an intent minted for one stores no scope key and blocks every
//! payer, and a request carrying no identity waits on every unresolved
//! intent for the route. The narrowing only ever separates two payers the
//! proxy can actually tell apart.
//!
//! The retry path authenticates the presented quote token, addresses the
//! durable intent through
//! [`sbproxy_billing::types::derive_intent_id`] with the requirement id as
//! the request idempotency key, extracts the rail's credential, and hands
//! both to [`sbproxy_billing::service::BillingService::authorize`].
//!
//! Credentials by rail:
//!
//! - x402: the `PAYMENT-SIGNATURE` header, decoding to the pinned v2
//!   envelope; the proof is the canonicalized scheme payload.
//! - Payment Auth (`mpp`): exactly one `Authorization: Payment` field;
//!   two are a 400. Failures are `application/problem+json` under the
//!   canonical `https://paymentauth.org/problems/` types.
//! - Direct Stripe and Lightning: no separate client credential; the
//!   re-presented quote token is the proof, and the provider settles out
//!   of band.
//!
//! # What the gate reports
//!
//! Every terminal decision here is one row on
//! `sbproxy_payment_settlement_total`, under `operation="challenge"` or
//! `operation="redeem"`. Before WOR-2219 the family had a single writer,
//! the background reconciliation sweep, so the counter an operator would
//! reach for to graph settlement volume read zero while payments flowed
//! normally through this module. The `KeepLegacy` decisions are the one
//! exception and stay uncounted: settlement declined to serve the request
//! at all, so there is no settlement to report.

use std::sync::Arc;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::service::{
    AuthorizationDecision, BillingService, PaymentProblemCode, PreparedPaymentResponse,
    RedemptionRequest, RequirementInput,
};
use sbproxy_billing::store::IntentRecord;
use sbproxy_billing::types::{
    derive_intent_id, AdvertisedRail, IntentStatus, PaymentProof, SettlementRail,
    SignedPaymentRequirement,
};
use sbproxy_config::payments::{AdvertisedRailName, PaymentsConfig};
use sbproxy_config::types::FailureMode;
use sbproxy_modules::policy::ai_crawl::{resolve_agent_preferences, AiCrawlControlPolicy, Rail};
use sbproxy_modules::policy::payment_requirement::{
    PaymentRequirementCompiler, RequirementContext,
};
use sbproxy_modules::policy::quote_token::NonceCheck;
use sbproxy_observe::metrics::record_payment_settlement;
use sbproxy_security::crypto::{hkdf_derive_purpose, HkdfPurpose};

#[cfg(feature = "payment-mpp")]
use sbproxy_billing::payment_auth::{
    select_payment_credential, ChallengeOpaque, PaymentAuthError, PaymentAuthProblemCode,
    StripeChargeMethodDetails, StripeChargeRequest, CACHE_CONTROL_CHALLENGE, PROBLEM_CONTENT_TYPE,
    PROBLEM_TYPE_PREFIX,
};
#[cfg(feature = "payment-mpp")]
use sbproxy_billing::types::{PaymentRequirementDraft, RequirementTerms};
#[cfg(feature = "payment-x402")]
use sbproxy_billing::x402::{
    decode_x402_header, encode_x402_header, PaymentPayload, PAYMENT_SIGNATURE_HEADER,
};
#[cfg(feature = "payment-x402")]
use sbproxy_billing::x402_adapter::x402_payment_required;

use crate::billing_runtime::SettlementGateSeam;
use crate::context::{PaymentResponse, RequestContext};

/// The deny label a settlement 402 carries; matches the legacy crawl 402
/// so the response writer and dashboards keep one vocabulary for
/// "payment required".
const PAYMENT_LABEL: &str = "ai_crawl_payment";

/// The deny label for gate responses that are not a 402: the 406 rail
/// negotiation failure, the 400 duplicate credential, and the 503
/// infrastructure refusal. The response writer renders the stored
/// [`PaymentResponse`] verbatim for this label.
const SETTLEMENT_LABEL: &str = "ai_crawl_settlement";

/// How long a settlement challenge stays redeemable, in milliseconds.
///
/// Five minutes: long enough for every configured rail's settlement flow
/// (an x402 facilitator round trip, a card confirmation, a Lightning
/// invoice payment), short enough that an abandoned challenge expires
/// before the recovery worker has a backlog of them.
const CHALLENGE_TTL_MS: i64 = 300_000;

/// Fixed HKDF salt for [`payer_scope_hash`].
///
/// Fixed rather than random because the derivation has to reproduce across
/// requests, across restarts, and across processes sharing one settlement
/// database: the whole point is that the same payer computes the same value
/// tomorrow. A fixed salt plus a dedicated [`HkdfPurpose`] is the shape
/// `SealKey::fingerprint_hex` in `sbproxy-security` uses, and it is what
/// keeps this value from being a derivation of the same keyspace as
/// anything that signs or encrypts.
const PAYER_SCOPE_SALT: &[u8] = b"sbproxy.settlement.payer-scope.salt.v1";

/// Length, in bytes, of a stored payer scope key.
///
/// Sixteen rather than the four a published fingerprint gets: this value is
/// compared for equality to decide whether one payer waits on another's
/// stuck payment, so a collision is a payer wrongly refused a challenge, and
/// a deployment can hold far more distinct payers than a key ring holds
/// keys.
const PAYER_SCOPE_LEN: usize = 16;

/// Derives the durable payer scope key for one caller.
///
/// HKDF under a dedicated purpose rather than a hash of the identifier, for
/// the reason `bundle_var_fingerprint` gives: a plain hash of a short,
/// guessable value is a value anyone holding the database can enumerate back
/// to its input. The tenant is mixed into the keying material with a `NUL`
/// separator, which tenant ids and caller identifiers cannot contain, so the
/// same crawler under two tenants gets two unrelated scope keys and one
/// tenant's database says nothing about another's traffic.
///
/// The result is hex so it stores as SQLite `TEXT` and compares with `=`.
/// It goes in the settlement database and nowhere else: it is never a metric
/// label, never a log or tracing field, and never part of a response.
fn payer_scope_hash(tenant_id: &str, principal: &str) -> String {
    let mut ikm = Vec::with_capacity(tenant_id.len() + principal.len() + 1);
    ikm.extend_from_slice(tenant_id.as_bytes());
    ikm.push(0);
    ikm.extend_from_slice(principal.as_bytes());
    hex::encode(hkdf_derive_purpose(
        &ikm,
        PAYER_SCOPE_SALT,
        HkdfPurpose::SettlementPayerScope,
        PAYER_SCOPE_LEN,
    ))
}

/// Resolves the caller identity this request pays under, if any.
///
/// Two properties decide what is admissible here, and both are load
/// bearing. The value has to be **stable** across one payer's retries,
/// because an unstable key hands a stranded payer a fresh invoice, which is
/// worse than the route-wide guard it replaces. And it has to be
/// **distinct** between two payers, because a shared key is the route-wide
/// guard with extra steps.
///
/// In precedence:
///
/// 1. The accountable key id: an inbound credential the proxy authenticated
///    and reduced to a public, secret-free identifier. Stable because it
///    identifies a key rather than a request, distinct because two callers
///    holding different keys report different ids.
/// 2. A resolved agent identity, but only from a source that proved
///    something: a verified Web Bot Auth `keyid` or a forward-confirmed
///    reverse DNS match. That is the same predicate the upstream
///    `agent_class` verified header uses, and it excludes the `User-Agent`
///    regex match, which any client can assert. The three reserved
///    sentinels are excluded too: `human`, `anonymous`, and `unknown` are
///    shared by everyone who lands in them, so they identify a bucket
///    rather than a payer.
/// 3. Nothing, which stores no scope key and keeps this request under the
///    original route-wide guard.
///
/// The client IP is deliberately absent. It is neither stable (an egress
/// pool rotates it between two requests seconds apart) nor distinct (a NAT
/// shares one address between unrelated callers), so it fails both tests at
/// once and in the direction that costs money.
fn payer_principal(ctx: &RequestContext) -> Option<String> {
    if let Some(key_id) = ctx.accountable_key_id() {
        return Some(format!("key:{key_id}"));
    }
    verified_agent_principal(ctx)
}

/// The resolved agent identity, when the resolver actually proved one.
///
/// Mirrors `crate::agent_class::cap_binding_agent_id`, which rejects the
/// fallback verdict for the same reason: the resolver always stamps some
/// `agent_id`, so treating every stamp as an identity would put every
/// unidentified caller in one bucket and call it a payer. This is stricter
/// still, because a scope key decides whether a payer is refused a
/// challenge: only the two sources the request pipeline already labels
/// `verified` count, and the shared sentinels never do.
#[cfg(feature = "agent-class")]
fn verified_agent_principal(ctx: &RequestContext) -> Option<String> {
    use sbproxy_classifiers::AgentIdSource;
    if !matches!(
        ctx.agent_id_source,
        Some(AgentIdSource::BotAuth | AgentIdSource::Rdns)
    ) {
        return None;
    }
    let agent = ctx.agent_id.as_ref()?;
    if agent.is_sentinel() || agent.as_str().is_empty() {
        return None;
    }
    Some(format!("agent:{}", agent.as_str()))
}

/// A build without agent-class resolution has no agent identity to read,
/// so every request falls through to the route-wide guard unless it
/// authenticated an inbound credential.
#[cfg(not(feature = "agent-class"))]
fn verified_agent_principal(_ctx: &RequestContext) -> Option<String> {
    None
}

/// The proof scheme for rails whose credential is the quote token itself.
///
/// Direct Stripe settles by capturing the challenge-bound PaymentIntent
/// and Lightning settles by observing the invoice, so neither rail carries
/// a client credential on the retry. The re-presented quote token is a
/// faithful per-challenge identity for replay binding, and it is
/// deterministic across retries, which is what lets an interrupted
/// payment resume instead of reading as a replay.
const QUOTE_PROOF_SCHEME: &str = "crawler-quote";

// WOR-2219: what the request path contributes to
// `sbproxy_payment_settlement_total`.
//
// Until this landed the family had exactly one writer, the reconciliation
// sweep, so a counter named "payment settlement total" counted background
// recovery work and read zero while payments settled normally. The two
// halves are told apart by the `operation` label rather than by a fourth
// label or by a rewrite of the sweep's labels, because the sweep reports
// the reconciled attempt's own operation (`settle`, `verify`, and the rest
// of `AttemptOperation`) and every existing query is written against those
// values. The two spellings below are deliberately outside that set, so a
// dashboard reading the sweep keeps selecting exactly the rows it always
// did and a dashboard reading the money path selects only new ones.

/// The `operation` label for the gate pricing a request and issuing a 402.
pub(crate) const OP_CHALLENGE: &str = "challenge";

/// The `operation` label for the gate judging a presented proof.
pub(crate) const OP_REDEEM: &str = "redeem";

/// The `outcome` label for a durable challenge the gate prepared.
pub(crate) const OUTCOME_PREPARED: &str = "prepared";

/// The `outcome` label for a settled payment admitted to the origin.
pub(crate) const OUTCOME_SUCCEEDED: &str = "succeeded";

/// The `outcome` label for a redemption whose funds are still unresolved.
///
/// Distinct from every payment problem code on purpose: this is the row
/// where nothing about the money is asserted, which is the one state an
/// operator must not read as a refusal.
const OUTCOME_UNAVAILABLE: &str = "unavailable";

/// The `outcome` label for a preference set no configured rail satisfies.
const OUTCOME_NO_ACCEPTABLE_RAIL: &str = "no_acceptable_rail";

/// The `outcome` label for a challenge withheld over an unresolved payment.
///
/// Its own row rather than a share of `unavailable`, because this one says
/// something an operator has to act on: a payment for this content is stuck,
/// and until it resolves the route earns nothing. Alert on it.
///
/// This value keeps meaning exactly what it meant before WOR-2238: the whole
/// route is withheld. Every refusal counted here before the payer scope
/// existed was route-wide, so an alert already written against this series
/// keeps firing for the same severity it was written for. The narrowed case
/// got a new value rather than a share of this one, because moving the
/// route-wide case to a new name would have silently stopped those alerts on
/// the more expensive of the two outcomes.
const OUTCOME_UNRESOLVED_PAYMENT: &str = "unresolved_payment";

/// The `outcome` label for a challenge withheld from one payer, while the
/// rest of the route is still being challenged and billed (WOR-2238).
///
/// Materially less severe than [`OUTCOME_UNRESOLVED_PAYMENT`] and worth
/// separating for that reason alone: this one costs the revenue of a single
/// stuck payer, that one costs the revenue of the entire route. An operator
/// paging on the second does not want to be woken by the first.
///
/// Carries no payer identity, only the fact that a payer scope existed.
const OUTCOME_UNRESOLVED_PAYMENT_SCOPED: &str = "unresolved_payment_scoped";

/// The `rail` label for a challenge the gate abandoned before compiling a
/// requirement.
///
/// The settling rail is a field of the compiled draft, so until the compiler
/// has run there is no honest value: negotiation may have picked an advertised
/// name, but `lightning` is two settling rails and reporting it would put them
/// in one counter. Both refusals that stop this early, the 406 and the
/// withheld challenge over an unresolved payment, are worth counting anyway.
/// Leaving the 406 off the family would hide the one refusal that means
/// "crawlers keep asking to pay us in a currency we do not accept": revenue
/// the deployment is configured to decline.
const RAIL_NONE: &str = "none";

/// Record one settlement transition the request path decided.
///
/// The rail reported is the one that settles, never the one advertised.
/// The sweep at the other end of this family labels its rows with
/// [`SettlementRail`], so a gate that reported the advertised spelling
/// would put `lightning` and `lightning_cln` in one counter as if they were
/// different rails. `PaymentRequirementDraft::canonicalize` already proves
/// the two agree, which is why reading the draft's settlement rail is
/// enough.
fn record_gate_settlement(rail: Option<SettlementRail>, operation: &str, outcome: &str) {
    record_payment_settlement(
        rail.map_or(RAIL_NONE, SettlementRail::as_str),
        operation,
        outcome,
        1,
    );
}

/// Everything the gate reads off one request.
pub(crate) struct GateRequest<'a> {
    /// The request headers, unstripped: the gate is the one reader of the
    /// payment credential.
    pub(crate) headers: &'a http::HeaderMap,
    /// The matched origin hostname.
    pub(crate) host: &'a str,
    /// The request path, with no query string.
    pub(crate) path: &'a str,
    /// The tenant the matched origin resolves to.
    pub(crate) tenant: &'a str,
    /// The matched origin's stable identifier.
    pub(crate) origin_id: &'a str,
    /// The resolved agent identifier, or empty when none resolved.
    ///
    /// This is the pricing input: it selects a tier, and a `User-Agent`
    /// match is good enough for that. It is deliberately not the payer
    /// scope; see [`payer_hash`](Self::payer_hash).
    pub(crate) agent_id: &'a str,
    /// The durable payer scope key for this request (WOR-2238), or `None`
    /// when no caller identity resolved.
    ///
    /// Already derived: [`payer_scope_hash`] runs before the request
    /// reaches the gate, so nothing downstream of here ever holds raw payer
    /// material. `None` is the honest answer for an unidentified caller and
    /// keeps this request under the route-wide guard.
    pub(crate) payer_hash: Option<&'a str>,
    /// The `Accept` header, when present.
    pub(crate) accept: Option<&'a str>,
    /// The `Accept-Payment` header, when present.
    pub(crate) accept_payment: Option<&'a str>,
}

/// Everything the gate decides with.
pub(crate) struct GateDeps<'a> {
    /// The authoritative settlement service.
    pub(crate) service: &'a BillingService,
    /// The request-path material published beside it.
    pub(crate) seam: &'a SettlementGateSeam,
    /// The `proxy.payments` document the pinned pipeline was built from.
    pub(crate) payments: &'a PaymentsConfig,
    /// The `ai_crawl_control` policy that produced the 402.
    pub(crate) policy: &'a AiCrawlControlPolicy,
}

/// One rendered gate response, final in every byte.
pub(crate) struct GateResponse {
    /// The HTTP status.
    pub(crate) status: u16,
    /// The deny message for logs and metrics.
    pub(crate) message: String,
    /// The deny label the response writer routes on.
    pub(crate) label: &'static str,
    /// The exact response body and headers.
    pub(crate) response: PaymentResponse,
}

/// An infrastructure failure: the store, the signer, the compiler, or the
/// nonce ledger could not answer. Never a payment refusal.
pub(crate) struct GateFailure {
    /// Which step failed, for the log line.
    pub(crate) stage: &'static str,
    /// The redacted failure text.
    pub(crate) detail: String,
}

/// What the gate decided about one crawl 402.
pub(crate) enum GateDecision {
    /// A committed receipt authorizes this request; let it reach the
    /// origin.
    Allow,
    /// The legacy verdict stands unchanged (settlement cannot price or
    /// advertise this request).
    KeepLegacy,
    /// Answer with this exact response.
    Respond(GateResponse),
    /// Settlement infrastructure could not answer; the configured
    /// failure posture decides.
    Infrastructure(GateFailure),
}

/// What an admitting failure posture leaves behind.
pub(crate) enum FailureAction {
    /// Refuse the request with a 503.
    Refuse {
        /// The `Retry-After` value, in seconds.
        retry_after_seconds: u32,
    },
    /// Admit the request to the origin.
    Admit {
        /// The guarantee was waived and that fact is worth alerting on.
        waived: bool,
        /// Record what the gate would have done without admitting it.
        counterfactual: bool,
    },
}

/// Maps the configured posture onto what the gate does.
///
/// Matched exhaustively with no wildcard arm (the WOR-2121 rule): a fifth
/// posture is a fifth answer to "what happens to a payable request the
/// store could not judge", and inheriting an arm would be this module
/// deciding it on the operator's behalf.
pub(crate) const fn failure_action(mode: FailureMode) -> FailureAction {
    match mode {
        FailureMode::Closed => FailureAction::Refuse {
            retry_after_seconds: 2,
        },
        FailureMode::Open => FailureAction::Admit {
            waived: false,
            counterfactual: false,
        },
        FailureMode::Degraded => FailureAction::Admit {
            waived: true,
            counterfactual: false,
        },
        FailureMode::Observe => FailureAction::Admit {
            waived: false,
            counterfactual: true,
        },
    }
}

/// Runs the settlement gate over the policy chain's verdict.
///
/// A no-op unless the verdict is an `ai_crawl_control` 402, settlement is
/// active for the pinned pipeline generation, and the enforcer stashed
/// the policy. Turns the 402 into `None` when a payment durably settled,
/// and rewrites the stored challenge otherwise.
pub(crate) async fn apply(
    req: &pingora_http::RequestHeader,
    ctx: &mut RequestContext,
    verdict: Option<(u16, String, &'static str)>,
) -> Option<(u16, String, &'static str)> {
    let is_crawl_402 = matches!(&verdict, Some((402, _, _)))
        && matches!(
            ctx.deny_policy_type,
            Some("ai_crawl_payment") | Some("ai_crawl_multi_rail")
        );
    if !is_crawl_402 {
        return verdict;
    }
    let pipeline = Arc::clone(&ctx.pipeline);
    let Some(runtime) = pipeline.payments.as_ref() else {
        return verdict;
    };
    let Some(seam) = runtime.gate() else {
        return verdict;
    };
    let Some(payments) = pipeline.config.server.payments.as_ref() else {
        return verdict;
    };
    let Some(policy) = ctx.crawl_settlement_policy.clone() else {
        return verdict;
    };
    let fallback = verdict.as_ref().map_or("plugin", |(_, _, label)| *label);
    let failure_mode = seam.failure_mode;

    let tenant = ctx.tenant_id.to_string();
    let host = ctx.hostname.to_string();
    let origin_id = ctx
        .origin_idx
        .and_then(|index| pipeline.config.origins.get(index))
        .map_or_else(|| host.clone(), |origin| origin.origin_id.to_string());
    #[cfg(feature = "agent-class")]
    let agent_id: String = ctx
        .agent_id
        .as_ref()
        .map(|agent| agent.as_str().to_string())
        .unwrap_or_default();
    #[cfg(not(feature = "agent-class"))]
    let agent_id = String::new();
    let path = req.uri.path().to_string();
    // Derived before the gate runs, so the raw identifier never crosses
    // into the settlement path and the gate only ever handles the opaque
    // scope key.
    let payer_hash = payer_principal(ctx).map(|principal| payer_scope_hash(&tenant, &principal));
    let accept = req
        .headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let accept_payment = req
        .headers
        .get("accept-payment")
        .and_then(|value| value.to_str().ok());

    let decision = {
        let request = GateRequest {
            headers: &req.headers,
            host: &host,
            path: &path,
            tenant: &tenant,
            origin_id: &origin_id,
            agent_id: &agent_id,
            payer_hash: payer_hash.as_deref(),
            accept,
            accept_payment,
        };
        let deps = GateDeps {
            service: runtime.service().as_ref(),
            seam,
            payments,
            policy: policy.as_ref(),
        };
        decide(&request, &deps).await
    };

    match decision {
        GateDecision::KeepLegacy => verdict,
        GateDecision::Allow => {
            admit(ctx, "payment durably settled");
            None
        }
        GateDecision::Respond(response) => {
            ctx.deny_policy_type = Some(response.label);
            ctx.deny_reason = Some(format!("{}: {}", response.label, response.message));
            ctx.crawl_challenge = Some(response.response);
            Some((response.status, response.message, fallback))
        }
        GateDecision::Infrastructure(failure) => {
            tracing::warn!(
                stage = failure.stage,
                detail = %failure.detail,
                "settlement infrastructure could not answer a payable request",
            );
            match failure_action(failure_mode) {
                FailureAction::Refuse {
                    retry_after_seconds,
                } => {
                    let body = serde_json::json!({
                        "error": "settlement_unavailable",
                        "retry_after_seconds": retry_after_seconds,
                    })
                    .to_string();
                    ctx.deny_policy_type = Some(SETTLEMENT_LABEL);
                    ctx.deny_reason = Some(format!(
                        "{SETTLEMENT_LABEL}: infrastructure failure at {}",
                        failure.stage
                    ));
                    ctx.crawl_challenge = Some(
                        PaymentResponse::json(body)
                            .with_header("Retry-After", retry_after_seconds.to_string()),
                    );
                    Some((503, "settlement unavailable".to_string(), fallback))
                }
                FailureAction::Admit {
                    waived,
                    counterfactual,
                } => {
                    if waived {
                        tracing::warn!(
                            stage = failure.stage,
                            "settlement guarantee waived; request admitted unpaid (failure_mode: degraded)",
                        );
                    }
                    if counterfactual {
                        tracing::info!(
                            stage = failure.stage,
                            "settlement gate would have refused this request (failure_mode: observe)",
                        );
                    }
                    admit(ctx, "infrastructure failure admitted by failure_mode");
                    None
                }
            }
        }
    }
}

/// Clears the deny the enforcer staged and records the gate's allow.
fn admit(ctx: &mut RequestContext, reason: &'static str) {
    ctx.crawl_challenge = None;
    ctx.deny_policy_type = None;
    ctx.deny_reason = None;
    ctx.record_policy_decision(SETTLEMENT_LABEL, "allow");
    tracing::debug!(reason, "settlement gate admitted the request");
}

/// Decides one crawl 402 against durable settlement state.
pub(crate) async fn decide(request: &GateRequest<'_>, deps: &GateDeps<'_>) -> GateDecision {
    let now_ms = deps.service.clock().now_ms();
    let token = request
        .headers
        .get(deps.policy.header_name())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|token| !token.is_empty());

    if let Some(token) = token {
        match retry_path(request, deps, token, now_ms).await {
            Ok(RetryOutcome::Allow) => return GateDecision::Allow,
            Ok(RetryOutcome::Respond(response)) => return GateDecision::Respond(response),
            Ok(RetryOutcome::FreshChallenge(reason)) => {
                // The presented token does not address a live durable
                // challenge. That is the malformed-credential row of the
                // matrix: nothing was charged, nothing reaches the
                // origin, and the client gets a fresh 402 it can act on.
                tracing::debug!(
                    reason,
                    "settlement retry did not address a durable challenge; issuing a fresh one",
                );
            }
            Err(failure) => return GateDecision::Infrastructure(failure),
        }
    }

    match challenge_path(request, deps, now_ms).await {
        Ok(ChallengeOutcome::Respond(response)) => GateDecision::Respond(response),
        Ok(ChallengeOutcome::KeepLegacy(reason)) => {
            tracing::debug!(reason, "settlement gate left the legacy crawl challenge");
            GateDecision::KeepLegacy
        }
        Err(failure) => GateDecision::Infrastructure(failure),
    }
}

/// What the retry path concluded.
enum RetryOutcome {
    /// A committed receipt authorizes the request.
    Allow,
    /// Answer with this refusal.
    Respond(GateResponse),
    /// The token does not address a durable challenge; issue a fresh one.
    FreshChallenge(&'static str),
}

/// Redeems one presented quote token against its durable challenge.
async fn retry_path(
    request: &GateRequest<'_>,
    deps: &GateDeps<'_>,
    token: &str,
    now_ms: i64,
) -> Result<RetryOutcome, GateFailure> {
    let Ok(claims) = deps.seam.quote_signer.verify_claims(token) else {
        return Ok(RetryOutcome::FreshChallenge(
            "presented quote token did not authenticate",
        ));
    };
    if claims.shape != crate::payment_signer::SETTLEMENT_SHAPE {
        return Ok(RetryOutcome::FreshChallenge(
            "presented token is not a settlement quote",
        ));
    }
    let Some(requirement_id) = claims.requirement_id else {
        return Ok(RetryOutcome::FreshChallenge(
            "settlement quote carries no requirement id",
        ));
    };

    let intent_id = derive_intent_id(request.tenant, &requirement_id);
    let intent = deps
        .service
        .store()
        .load_intent(&intent_id)
        .await
        .map_err(|error| infra("load_intent", &error))?;
    let Some(intent) = intent else {
        return Ok(RetryOutcome::FreshChallenge(
            "no durable challenge exists for the presented quote",
        ));
    };
    let Ok(requirement) = intent.finalized_requirement() else {
        return Ok(RetryOutcome::FreshChallenge(
            "the durable challenge was never finalized",
        ));
    };
    let Some(requirement_digest) = intent.requirement_digest else {
        return Ok(RetryOutcome::FreshChallenge(
            "the durable challenge has no requirement digest",
        ));
    };
    let signed = SignedPaymentRequirement {
        requirement: requirement.clone(),
        draft_digest: intent.draft_digest,
        requirement_digest,
        // The presented token, not the stored one: `authorize` verifies
        // the signature and every claim binding against this value, so a
        // forged or transplanted token fails there rather than being
        // silently replaced by the real one.
        quote_token: token.to_string(),
    };

    let proof = match extract_proof(request, deps, &intent, token, now_ms)? {
        ProofExtraction::Proof(proof) => proof,
        ProofExtraction::Respond(response) => return Ok(RetryOutcome::Respond(response)),
    };

    let decision = deps
        .service
        .authorize(RedemptionRequest {
            signed,
            request_idempotency_key: requirement_id.clone(),
            proof,
        })
        .await
        .map_err(|error| infra("authorize", &error))?;

    match decision {
        AuthorizationDecision::Settled(_receipt) => {
            // Recheck the durable state at the decision boundary. The
            // receipt already came from a committed row, but the rule is
            // cheap to re-prove and this is the one place origin access
            // is granted.
            let recheck = deps
                .service
                .store()
                .load_intent(&intent_id)
                .await
                .map_err(|error| infra("recheck_intent", &error))?;
            let succeeded = recheck
                .as_ref()
                .is_some_and(|record| record.status == IntentStatus::Succeeded);
            if !succeeded {
                record_gate_settlement(
                    Some(intent.draft.settlement_rail),
                    OP_REDEEM,
                    OUTCOME_UNAVAILABLE,
                );
                return Ok(RetryOutcome::Respond(unavailable_response(2)));
            }
            // Single serve. The durable intent stays redeemable so an
            // interrupted payment can resume, so the request path burns
            // the requirement's nonce only here, after a committed
            // receipt authorized a response. Register first so a backend
            // that distinguishes unknown nonces cannot answer `Unknown`.
            if let Err(error) = deps.seam.nonce_store.register(&requirement_id) {
                return Err(infra_msg("nonce_register", &error.to_string()));
            }
            match deps.seam.nonce_store.check_and_consume(&requirement_id) {
                Ok(NonceCheck::Fresh) => {
                    // The one place a payment both settled durably and
                    // bought origin access, which is the only event an
                    // operator graphing settlement volume or revenue is
                    // asking about. Counted here rather than at the
                    // `Settled` arm above, because a committed receipt
                    // whose nonce was already burned served nobody.
                    record_gate_settlement(
                        Some(intent.draft.settlement_rail),
                        OP_REDEEM,
                        OUTCOME_SUCCEEDED,
                    );
                    Ok(RetryOutcome::Allow)
                }
                Ok(NonceCheck::AlreadyConsumed) => Ok(RetryOutcome::Respond(refusal_response(
                    deps,
                    request,
                    &intent,
                    PaymentProblemCode::ProofReplayed,
                )?)),
                Ok(NonceCheck::Unknown) => Err(infra_msg(
                    "nonce_consume",
                    "nonce store answered unknown after registration",
                )),
                Err(error) => Err(infra_msg("nonce_consume", &error.to_string())),
            }
        }
        AuthorizationDecision::PaymentRequired(problem) => Ok(RetryOutcome::Respond(
            refusal_response(deps, request, &intent, problem.code)?,
        )),
        AuthorizationDecision::Unavailable {
            retry_after_seconds,
        } => {
            record_gate_settlement(
                Some(intent.draft.settlement_rail),
                OP_REDEEM,
                OUTCOME_UNAVAILABLE,
            );
            Ok(RetryOutcome::Respond(unavailable_response(
                retry_after_seconds,
            )))
        }
    }
}

/// What credential extraction produced.
enum ProofExtraction {
    /// The rail's credential, ready for `authorize`.
    Proof(PaymentProof),
    /// A refusal in the rail's own failure shape.
    Respond(GateResponse),
}

/// Extracts the rail-specific credential for one durable challenge.
fn extract_proof(
    request: &GateRequest<'_>,
    deps: &GateDeps<'_>,
    intent: &IntentRecord,
    token: &str,
    now_ms: i64,
) -> Result<ProofExtraction, GateFailure> {
    // `now_ms` is only read by the Payment Auth arm; the other rails bind
    // expiry durably instead.
    let _ = now_ms;
    match intent.draft.advertised_rail {
        #[cfg(feature = "payment-x402")]
        AdvertisedRail::X402 => {
            let mut values = request
                .headers
                .get_all(PAYMENT_SIGNATURE_HEADER)
                .iter()
                .filter_map(|value| value.to_str().ok());
            let Some(first) = values.next() else {
                return Ok(ProofExtraction::Respond(refusal_response(
                    deps,
                    request,
                    intent,
                    PaymentProblemCode::ProofInvalid,
                )?));
            };
            if values.next().is_some() {
                // Two payment signatures is two payments; there is no
                // safe way to pick which one the client meant.
                return Ok(ProofExtraction::Respond(refusal_response(
                    deps,
                    request,
                    intent,
                    PaymentProblemCode::ProofInvalid,
                )?));
            }
            let Ok(payload) = decode_x402_header::<PaymentPayload>(first) else {
                return Ok(ProofExtraction::Respond(refusal_response(
                    deps,
                    request,
                    intent,
                    PaymentProblemCode::ProofInvalid,
                )?));
            };
            match payload.proof() {
                Ok(proof) => Ok(ProofExtraction::Proof(proof)),
                Err(_) => Ok(ProofExtraction::Respond(refusal_response(
                    deps,
                    request,
                    intent,
                    PaymentProblemCode::ProofInvalid,
                )?)),
            }
        }
        #[cfg(feature = "payment-mpp")]
        AdvertisedRail::Mpp => {
            let Some(binder) = deps.seam.challenge_binder.as_deref() else {
                return Err(infra_msg(
                    "payment_auth_binder",
                    "an mpp challenge was presented but no binder is configured",
                ));
            };
            let values: Vec<&str> = request
                .headers
                .get_all(http::header::AUTHORIZATION)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            let value = match select_payment_credential(values.iter().copied()) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(ProofExtraction::Respond(payment_auth_refusal(
                        deps, intent, error,
                    )?));
                }
            };
            // The crawl payment path never carries a body:
            // `check_with_pricing_exemption` allows anything but GET and
            // HEAD before pricing runs.
            let verified = match binder.verify_credential(value, None, now_ms) {
                Ok(verified) => verified,
                Err(error) => {
                    return Ok(ProofExtraction::Respond(payment_auth_refusal(
                        deps, intent, error,
                    )?));
                }
            };
            let bound = verified
                .opaque
                .as_ref()
                .is_some_and(|opaque| opaque.intent_id == intent.intent_id);
            if !bound {
                // The credential echoes a challenge this proxy issued,
                // but for a different intent than the presented quote
                // addresses.
                return Ok(ProofExtraction::Respond(payment_auth_refusal(
                    deps,
                    intent,
                    PaymentAuthError::InvalidChallenge,
                )?));
            }
            Ok(ProofExtraction::Proof(verified.proof))
        }
        AdvertisedRail::Stripe | AdvertisedRail::Lightning => {
            match PaymentProof::new(QUOTE_PROOF_SCHEME, token.to_string()) {
                Ok(proof) => Ok(ProofExtraction::Proof(proof)),
                Err(error) => Err(infra("quote_proof", &error)),
            }
        }
        #[cfg(not(feature = "payment-x402"))]
        AdvertisedRail::X402 => Ok(ProofExtraction::Respond(refusal_response(
            deps,
            request,
            intent,
            PaymentProblemCode::RailUnsupported,
        )?)),
        #[cfg(not(feature = "payment-mpp"))]
        AdvertisedRail::Mpp => Ok(ProofExtraction::Respond(refusal_response(
            deps,
            request,
            intent,
            PaymentProblemCode::RailUnsupported,
        )?)),
    }
}

/// What the challenge path concluded.
enum ChallengeOutcome {
    /// Answer with this challenge or negotiation failure.
    Respond(GateResponse),
    /// Settlement cannot serve this request; the legacy verdict stands.
    KeepLegacy(&'static str),
}

/// Prepares a durable challenge and renders the 402.
async fn challenge_path(
    request: &GateRequest<'_>,
    deps: &GateDeps<'_>,
    now_ms: i64,
) -> Result<ChallengeOutcome, GateFailure> {
    let advertisable = advertisable_rails(deps.payments);
    if advertisable.is_empty() {
        return Ok(ChallengeOutcome::KeepLegacy(
            "proxy.payments configures no advertisable rail",
        ));
    }

    // The matched tier's `rails:` override is the operator floor, exactly
    // as it is on the legacy multi-rail path.
    let tier_filter: Option<Vec<AdvertisedRailName>> = deps
        .policy
        .matched_tier_for_request(request.path, request.agent_id, request.accept)
        .and_then(|tier| tier.rails.clone())
        .map(|rails| rails.into_iter().map(advertised_for).collect());
    let floor: Vec<AdvertisedRailName> = match &tier_filter {
        Some(allowed) => advertisable
            .iter()
            .copied()
            .filter(|rail| allowed.contains(rail))
            .collect(),
        None => advertisable.clone(),
    };
    if floor.is_empty() {
        record_gate_settlement(None, OP_CHALLENGE, OUTCOME_NO_ACCEPTABLE_RAIL);
        return Ok(ChallengeOutcome::Respond(no_acceptable_rail_response(
            request,
            &advertisable,
        )));
    }

    let preferences = resolve_agent_preferences(request.accept_payment, request.accept);
    let selected = match &preferences {
        Some(preferences) => preferences
            .accepted
            .iter()
            .copied()
            .map(advertised_for)
            .find(|rail| floor.contains(rail)),
        None => floor.first().copied(),
    };
    let Some(rail) = selected else {
        record_gate_settlement(None, OP_CHALLENGE, OUTCOME_NO_ACCEPTABLE_RAIL);
        return Ok(ChallengeOutcome::Respond(no_acceptable_rail_response(
            request, &floor,
        )));
    };

    let price =
        deps.policy
            .resolve_price_for_request(request.path, request.agent_id, request.accept);
    if price.amount_micros == 0 {
        return Ok(ChallengeOutcome::KeepLegacy("route priced at zero"));
    }

    // WOR-2230: never bill twice for content whose first payment is
    // unresolved.
    //
    // An intent in `NeedsReconciliation` may already have moved a payer's
    // money, and nothing expires it: it sits there until a provider answers.
    // The service refuses to redeem one (the payer waits for the worker
    // instead), but that only helps a payer that still holds its quote token.
    // A payer that dropped an expired token, or one that was refused as a
    // replay, arrives here with no token at all, and a fresh invoice is a
    // second bill for the same article.
    //
    // The key is the content plus the payer scope the stranded intent was
    // minted under (WOR-2238). Scoping it to the content alone, which is
    // where this started, refused every payer of the route while one payment
    // on it was unresolved: correct, and on a rail with no status endpoint it
    // took a hot route's revenue to zero for the length of a provider outage.
    // Two payers the proxy can tell apart no longer wait on each other. Two
    // it cannot still do, because an unproven guess in that direction is the
    // double charge this guard exists to prevent.
    //
    // On a healthy rail the wait is one worker tick. On a rail with no status
    // endpoint it lasts until an operator resolves the intent with the
    // provider, which is why it gets a loud counter and a warning rather than
    // a quiet 503.
    //
    // Known and out of scope, both predating this: the lookup is a read with
    // no lock, so two simultaneous tokenless requests from the same payer can
    // still both pass it (the window is narrowed, not closed); and `/article`
    // and `/article/` are two routes and get two bills.
    let unresolved = deps
        .service
        .store()
        .unresolved_intent_for_route(
            request.tenant,
            request.origin_id,
            request.path,
            request.payer_hash,
        )
        .await
        .map_err(|error| infra("unresolved_intent_for_route", &error))?;
    if let Some(intent_id) = unresolved {
        // The intent id, the origin, and the route, and nothing about who is
        // paying. The scope key is a durable comparison key, not a diagnostic:
        // logging it would put a payer identifier on a settlement surface,
        // which is the promise `sbproxy-observe`'s payment recorders keep by
        // not taking one as a parameter at all.
        // `scope` is the one thing an operator cannot infer from the rest of
        // this line, and it changes what they should do. "payer" means the
        // guard narrowed: exactly the payer whose payment is stuck is
        // waiting, and every other caller on this route is still being
        // challenged and billed normally. "route" means it could not identify
        // the requester, so the whole route is withheld until the worker
        // resolves the intent, which is the revenue-affecting case WOR-2238
        // exists to bound. Without this field both render identically and a
        // stalled route looks like a healthy one.
        //
        // It carries no payer identity: it names which of two code paths
        // decided, not who. That keeps the promise `sbproxy-observe`'s payment
        // recorders make by not accepting a payer at all.
        let scoped = request.payer_hash.is_some();
        if scoped {
            tracing::warn!(
                intent_id = %intent_id,
                origin_id = request.origin_id,
                route = request.path,
                scope = "payer",
                "a payment from this payer is unresolved; withholding a fresh challenge \
                 from them rather than billing again for content they may already have \
                 paid for. Other payers on this route are unaffected",
            );
        } else {
            // The expensive case, and the one an operator has to be able to
            // find. Nothing identified the requester, so this withholds the
            // route from everyone until the worker resolves the intent. On a
            // rail with no status endpoint (x402) that can last as long as a
            // facilitator outage, and the route earns nothing for the
            // duration. Says why it could not narrow, because the fix is to
            // give callers an identity the gate can see, not to touch
            // payments config.
            tracing::warn!(
                intent_id = %intent_id,
                origin_id = request.origin_id,
                route = request.path,
                scope = "route",
                "a payment for this route is unresolved and the requester could not be \
                 identified, so the whole route is withheld rather than billing again \
                 for content that may already be paid for. Narrowing this to the single \
                 stuck payer needs the caller to present an accountable key or a \
                 verified agent identity",
            );
        }
        record_gate_settlement(
            None,
            OP_CHALLENGE,
            if scoped {
                OUTCOME_UNRESOLVED_PAYMENT_SCOPED
            } else {
                OUTCOME_UNRESOLVED_PAYMENT
            },
        );
        // The same two seconds the redeem path answers a stranded payment
        // with. One number for "come back when the worker has been round".
        return Ok(ChallengeOutcome::Respond(unavailable_response(2)));
    }

    // The requirement id doubles as the request idempotency key, because
    // a crawl GET carries no client Idempotency-Key. Minting it here,
    // before `prepare_requirement`, is what makes the durable pending
    // intent exist before the 402 is written.
    let ulid = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let requirement_id = format!("req_{ulid}");
    let quote_id = format!("quote_{ulid}");
    let compiler = PaymentRequirementCompiler::new(deps.payments);
    let draft = compiler
        .draft(&RequirementContext {
            requirement_id: &requirement_id,
            quote_id: &quote_id,
            tenant_id: request.tenant,
            origin_id: request.origin_id,
            route: request.path,
            price: &price,
            advertised_rail: rail,
            request_digest: None,
            expires_at_ms: now_ms.saturating_add(CHALLENGE_TTL_MS),
        })
        .map_err(|error| infra_msg("compile_requirement", &error.to_string()))?;

    let prepared = deps
        .service
        .prepare_requirement(RequirementInput {
            draft,
            request_idempotency_key: requirement_id,
            // Stamped on the row this call inserts, so if this payment is
            // the one that strands, the guard above knows whose it was.
            payer_hash: request.payer_hash.map(str::to_string),
        })
        .await
        .map_err(|error| infra("prepare_requirement", &error))?;

    // Counted once the durable pending intent exists, not once the 402 is
    // rendered: the intent is what the recovery worker will later expire or
    // reconcile, so this is the number the settlement funnel divides by.
    record_gate_settlement(
        Some(prepared.signed.requirement.draft.settlement_rail),
        OP_CHALLENGE,
        OUTCOME_PREPARED,
    );

    Ok(ChallengeOutcome::Respond(render_challenge(
        deps, request, rail, &prepared,
    )?))
}

/// The rails `proxy.payments` can advertise, in fixed operator order.
///
/// Boot already proved every configured rail has a compiled, registered
/// adapter, so configuration presence is the whole test.
fn advertisable_rails(payments: &PaymentsConfig) -> Vec<AdvertisedRailName> {
    let mut rails = Vec::with_capacity(4);
    if payments.rails.x402.is_some() {
        rails.push(AdvertisedRailName::X402);
    }
    if payments.protocols.payment_auth.is_some() && payments.rails.stripe.is_some() {
        rails.push(AdvertisedRailName::Mpp);
    }
    if payments.rails.stripe.as_ref().is_some_and(|stripe| {
        stripe
            .direct_payment_intent
            .as_ref()
            .is_some_and(|direct| direct.enabled)
    }) {
        rails.push(AdvertisedRailName::Stripe);
    }
    if payments.lightning_backend().ok().flatten().is_some() {
        rails.push(AdvertisedRailName::Lightning);
    }
    rails
}

/// Maps the crawl policy's negotiation vocabulary onto the configured one.
///
/// `Rail` has no direct-Stripe token, so direct Stripe is only selectable
/// when the client expresses no preference; that is deliberate, because
/// the direct mode is an operator opt-in rather than a negotiated one.
const fn advertised_for(rail: Rail) -> AdvertisedRailName {
    match rail {
        Rail::X402 => AdvertisedRailName::X402,
        Rail::Mpp => AdvertisedRailName::Mpp,
        Rail::Lightning => AdvertisedRailName::Lightning,
    }
}

/// The wire name of an advertised rail.
const fn rail_name(rail: AdvertisedRail) -> &'static str {
    match rail {
        AdvertisedRail::X402 => "x402",
        AdvertisedRail::Mpp => "mpp",
        AdvertisedRail::Stripe => "stripe",
        AdvertisedRail::Lightning => "lightning",
    }
}

/// Renders the 402 for one prepared challenge in its rail's wire shape.
fn render_challenge(
    deps: &GateDeps<'_>,
    request: &GateRequest<'_>,
    rail: AdvertisedRailName,
    prepared: &PreparedPaymentResponse,
) -> Result<GateResponse, GateFailure> {
    let token = prepared.signed.quote_token.clone();
    let message = "payment required".to_string();
    match rail {
        #[cfg(feature = "payment-x402")]
        AdvertisedRailName::X402 => {
            let required = x402_payment_required(&prepared.signed)
                .map_err(|error| infra_msg("x402_render", &error.to_string()))?;
            let body = serde_json::to_string(&required)
                .map_err(|error| infra_msg("x402_render", &error.to_string()))?;
            let encoded = encode_x402_header(&required)
                .map_err(|error| infra_msg("x402_render", &error.to_string()))?;
            let response = PaymentResponse::json(body)
                .with_header("PAYMENT-REQUIRED", encoded)
                .with_header(deps.policy.header_name(), token);
            Ok(GateResponse {
                status: 402,
                message,
                label: PAYMENT_LABEL,
                response,
            })
        }
        #[cfg(feature = "payment-mpp")]
        AdvertisedRailName::Mpp => {
            let header = mpp_challenge_header(
                deps,
                &prepared.signed.requirement.draft,
                &prepared.intent_id,
            )?
            .ok_or_else(|| {
                infra_msg(
                    "payment_auth_challenge",
                    "the mpp rail was selected but the draft carries no payment auth terms",
                )
            })?;
            let response = PaymentResponse::json(generic_challenge_body(deps, request, prepared))
                .with_header("WWW-Authenticate", header)
                .with_header("Cache-Control", CACHE_CONTROL_CHALLENGE.to_string())
                .with_header(deps.policy.header_name(), token);
            Ok(GateResponse {
                status: 402,
                message,
                label: PAYMENT_LABEL,
                response,
            })
        }
        _ => {
            let response = PaymentResponse::json(generic_challenge_body(deps, request, prepared))
                .with_header(deps.policy.header_name(), token);
            Ok(GateResponse {
                status: 402,
                message,
                label: PAYMENT_LABEL,
                response,
            })
        }
    }
}

/// The JSON challenge body for rails without their own body contract.
///
/// Every non-secret challenge field the adapter produced is included
/// verbatim, and the one-shot client secret, when a rail issued one, goes
/// into this immediate response and nowhere else.
fn generic_challenge_body(
    deps: &GateDeps<'_>,
    request: &GateRequest<'_>,
    prepared: &PreparedPaymentResponse,
) -> String {
    let draft = &prepared.signed.requirement.draft;
    let mut challenge = serde_json::Map::new();
    for (name, value) in &prepared.challenge_fields {
        challenge.insert(name.clone(), serde_json::Value::String(value.clone()));
    }
    if let Some(secret) = prepared.client_secret.as_ref() {
        challenge.insert(
            "client_secret".to_string(),
            serde_json::Value::String(secret.as_str().to_string()),
        );
    }
    serde_json::json!({
        "error": "payment_required",
        "rail": rail_name(draft.advertised_rail),
        "requirement_id": draft.requirement_id,
        "amount_micros": draft.amount.amount_micros,
        "currency": draft.amount.currency,
        "target": format!("{}{}", request.host, request.path),
        "header": deps.policy.header_name(),
        "expires_at_ms": draft.expires_at_ms,
        "challenge": challenge,
    })
    .to_string()
}

/// Rebuilds the signed requirement a finalized intent committed.
///
/// Gated with its only caller, the x402 refusal renderer, so a build
/// without that rail does not carry a helper nothing names.
#[cfg(feature = "payment-x402")]
fn stored_signed(intent: &IntentRecord) -> Option<SignedPaymentRequirement> {
    Some(SignedPaymentRequirement {
        requirement: intent.requirement.clone()?,
        draft_digest: intent.draft_digest,
        requirement_digest: intent.requirement_digest?,
        quote_token: intent.quote_token.clone()?,
    })
}

/// Renders a payment refusal and counts it.
///
/// Every refusal of a presented proof funnels through here, from the
/// credential extractor's malformed-credential arms to the service's own
/// verdict, so this is the one place the settlement counter can see all of
/// them without a call beside each `return`. Counted after rendering
/// succeeded, because a renderer that failed answers the client with an
/// infrastructure 503 rather than this refusal, and the metric has to agree
/// with what the client was actually told.
fn refusal_response(
    deps: &GateDeps<'_>,
    request: &GateRequest<'_>,
    intent: &IntentRecord,
    code: PaymentProblemCode,
) -> Result<GateResponse, GateFailure> {
    let response = render_refusal(deps, request, intent, code)?;
    record_gate_settlement(Some(intent.draft.settlement_rail), OP_REDEEM, code.as_str());
    Ok(response)
}

/// Renders a payment refusal in the intent's rail shape.
fn render_refusal(
    deps: &GateDeps<'_>,
    request: &GateRequest<'_>,
    intent: &IntentRecord,
    code: PaymentProblemCode,
) -> Result<GateResponse, GateFailure> {
    let message = format!("payment did not authorize: {code}");
    match intent.draft.advertised_rail {
        #[cfg(feature = "payment-x402")]
        AdvertisedRail::X402 => {
            let body = match stored_signed(intent)
                .and_then(|signed| x402_payment_required(&signed).ok())
            {
                Some(mut required) => {
                    required.error = Some(code.as_str().to_string());
                    serde_json::to_string(&required)
                        .map_err(|error| infra_msg("x402_render", &error.to_string()))?
                }
                None => generic_refusal_body(request, intent, code),
            };
            let mut response = PaymentResponse::json(body);
            if let Some(token) = intent.quote_token.as_deref() {
                response = response.with_header(deps.policy.header_name(), token.to_string());
            }
            Ok(GateResponse {
                status: 402,
                message,
                label: PAYMENT_LABEL,
                response,
            })
        }
        #[cfg(feature = "payment-mpp")]
        AdvertisedRail::Mpp => {
            let (type_uri, title) = payment_auth_problem(code);
            problem_response(deps, intent, type_uri, title, 402, message)
        }
        _ => {
            let mut response = PaymentResponse::json(generic_refusal_body(request, intent, code));
            if let Some(token) = intent.quote_token.as_deref() {
                response = response.with_header(deps.policy.header_name(), token.to_string());
            }
            Ok(GateResponse {
                status: 402,
                message,
                label: PAYMENT_LABEL,
                response,
            })
        }
    }
}

/// The JSON refusal body for rails without their own failure contract.
fn generic_refusal_body(
    request: &GateRequest<'_>,
    intent: &IntentRecord,
    code: PaymentProblemCode,
) -> String {
    serde_json::json!({
        "error": "payment_required",
        "code": code.as_str(),
        "rail": rail_name(intent.draft.advertised_rail),
        "requirement_id": intent.draft.requirement_id,
        "amount_micros": intent.draft.amount.amount_micros,
        "currency": intent.draft.amount.currency,
        "target": format!("{}{}", request.host, request.path),
    })
    .to_string()
}

/// The 503 for a payment whose outcome is genuinely unknown.
fn unavailable_response(retry_after_seconds: u32) -> GateResponse {
    let body = serde_json::json!({
        "error": "settlement_unavailable",
        "retry_after_seconds": retry_after_seconds,
    })
    .to_string();
    GateResponse {
        status: 503,
        message: "settlement outcome is not yet known".to_string(),
        label: SETTLEMENT_LABEL,
        response: PaymentResponse::json(body)
            .with_header("Retry-After", retry_after_seconds.to_string()),
    }
}

/// The 406 for a preference set that excludes every configured rail.
fn no_acceptable_rail_response(
    request: &GateRequest<'_>,
    supported: &[AdvertisedRailName],
) -> GateResponse {
    let names: Vec<&str> = supported.iter().map(|rail| rail.as_str()).collect();
    let body = serde_json::json!({
        "error": "no_acceptable_rail",
        "supported_rails": names,
        "target": format!("{}{}", request.host, request.path),
        "message": "Accept-Payment does not overlap with the settlement rails configured for this route.",
    })
    .to_string();
    GateResponse {
        status: 406,
        message: "no acceptable settlement rail".to_string(),
        label: SETTLEMENT_LABEL,
        response: PaymentResponse::json(body),
    }
}

/// Maps a service problem code onto the Payment Auth problem registry.
///
/// A code the draft registers keeps its canonical type and title; the
/// service's own closed code token rides under the same prefix otherwise,
/// so every failure type a client sees starts with the canonical
/// namespace.
#[cfg(feature = "payment-mpp")]
fn payment_auth_problem(code: PaymentProblemCode) -> (String, &'static str) {
    let registered = match code {
        PaymentProblemCode::ChallengeExpired => Some(PaymentAuthProblemCode::PaymentExpired),
        PaymentProblemCode::ChallengeMissing
        | PaymentProblemCode::ChallengeNotFinalized
        | PaymentProblemCode::RequirementMismatch => Some(PaymentAuthProblemCode::InvalidChallenge),
        PaymentProblemCode::ProofInvalid => Some(PaymentAuthProblemCode::MalformedCredential),
        PaymentProblemCode::Rejected | PaymentProblemCode::NotSettled => {
            Some(PaymentAuthProblemCode::VerificationFailed)
        }
        PaymentProblemCode::ProofReplayed
        | PaymentProblemCode::RailUnsupported
        | PaymentProblemCode::Internal => None,
    };
    match registered {
        Some(problem) => (problem.type_uri(), problem.title()),
        None => (
            format!("{PROBLEM_TYPE_PREFIX}{}", code.as_str()),
            "Payment did not authorize",
        ),
    }
}

/// Renders one `application/problem+json` refusal, with a fresh
/// challenge on every 402 as the draft requires.
#[cfg(feature = "payment-mpp")]
fn problem_response(
    deps: &GateDeps<'_>,
    intent: &IntentRecord,
    type_uri: String,
    title: &str,
    status: u16,
    message: String,
) -> Result<GateResponse, GateFailure> {
    let body = serde_json::json!({
        "type": type_uri,
        "title": title,
        "status": status,
    })
    .to_string();
    let mut response = PaymentResponse::typed(PROBLEM_CONTENT_TYPE.to_string(), body)
        .with_header("Cache-Control", CACHE_CONTROL_CHALLENGE.to_string());
    if status == 402 {
        if let Some(header) = mpp_challenge_header(deps, &intent.draft, &intent.intent_id)? {
            response = response.with_header("WWW-Authenticate", header);
        }
        if let Some(token) = intent.quote_token.as_deref() {
            response = response.with_header(deps.policy.header_name(), token.to_string());
        }
    }
    Ok(GateResponse {
        status,
        message,
        label: if status == 402 {
            PAYMENT_LABEL
        } else {
            SETTLEMENT_LABEL
        },
        response,
    })
}

/// Renders one typed Payment Auth refusal.
#[cfg(feature = "payment-mpp")]
fn payment_auth_refusal(
    deps: &GateDeps<'_>,
    intent: &IntentRecord,
    error: PaymentAuthError,
) -> Result<GateResponse, GateFailure> {
    let status = error.status();
    let (type_uri, title) = match error.problem_code() {
        Some(code) => (code.type_uri(), code.title()),
        None => (
            format!("{PROBLEM_TYPE_PREFIX}internal"),
            "Payment could not be processed",
        ),
    };
    let response = problem_response(
        deps,
        intent,
        type_uri,
        title,
        status,
        format!("payment auth refused: {error}"),
    )?;
    // The sibling of the count in `refusal_response`. This arm never
    // reaches that funnel, so an mpp deployment would otherwise be the one
    // configuration whose refusals left no trace on the family.
    record_gate_settlement(
        Some(intent.draft.settlement_rail),
        OP_REDEEM,
        payment_auth_outcome(error).as_str(),
    );
    Ok(response)
}

/// Maps a Payment Auth refusal onto the settlement counter's vocabulary.
///
/// The `outcome` label already carries the closed [`PaymentProblemCode`]
/// set for every other rail, and the Payment Auth registry spells its own
/// codes differently (`malformed-credential`, hyphenated). Reporting both
/// would give one label two vocabularies and make "why did redemptions
/// fail" a question no single query answers. The mapping runs one way and
/// only for the metric: the client still gets the registered problem type
/// verbatim.
#[cfg(feature = "payment-mpp")]
const fn payment_auth_outcome(error: PaymentAuthError) -> PaymentProblemCode {
    match error {
        PaymentAuthError::CredentialMissing
        | PaymentAuthError::DuplicateCredential
        | PaymentAuthError::MalformedCredential => PaymentProblemCode::ProofInvalid,
        PaymentAuthError::InvalidChallenge => PaymentProblemCode::RequirementMismatch,
        PaymentAuthError::Expired => PaymentProblemCode::ChallengeExpired,
        PaymentAuthError::MethodUnsupported => PaymentProblemCode::RailUnsupported,
        PaymentAuthError::VerificationFailed | PaymentAuthError::Insufficient => {
            PaymentProblemCode::Rejected
        }
        // None of these four says anything about the payment, which is why
        // the codec itself declines to answer them with a payment problem
        // document. The counter follows that judgement rather than
        // inventing a payment reason the request never had.
        PaymentAuthError::BodyTooLarge
        | PaymentAuthError::ChallengeTooLarge
        | PaymentAuthError::InsecureTransport
        | PaymentAuthError::Internal => PaymentProblemCode::Internal,
    }
}

/// Issues the `WWW-Authenticate: Payment` field for one draft.
///
/// Deterministic for a given draft and intent: the binder MACs the same
/// seven slots, so re-issuing the challenge on a refusal reproduces the
/// exact field the original 402 carried.
#[cfg(feature = "payment-mpp")]
fn mpp_challenge_header(
    deps: &GateDeps<'_>,
    draft: &PaymentRequirementDraft,
    intent_id: &str,
) -> Result<Option<String>, GateFailure> {
    let Some(binder) = deps.seam.challenge_binder.as_deref() else {
        return Ok(None);
    };
    let RequirementTerms::PaymentAuthStripeCharge {
        business_network_id,
        payment_method_types,
        ..
    } = &draft.terms
    else {
        return Ok(None);
    };
    let charge = StripeChargeRequest {
        amount: draft.settlement_amount.clone(),
        currency: draft.amount.currency.to_ascii_lowercase(),
        external_id: draft.requirement_id.clone(),
        method_details: StripeChargeMethodDetails {
            metadata: std::collections::BTreeMap::new(),
            network_id: business_network_id.clone(),
            payment_method_types: payment_method_types.clone(),
        },
    };
    let opaque = ChallengeOpaque {
        intent_id: intent_id.to_string(),
        provider: "stripe".to_string(),
    };
    let challenge = binder
        .issue(&charge, Some(&opaque), None, draft.expires_at_ms)
        .map_err(|error| infra_msg("payment_auth_challenge", &error.to_string()))?;
    let value = challenge
        .to_header_value()
        .map_err(|error| infra_msg("payment_auth_challenge", &error.to_string()))?;
    Ok(Some(value))
}

/// Builds an infrastructure failure from a billing error.
fn infra(stage: &'static str, error: &BillingError) -> GateFailure {
    GateFailure {
        stage,
        detail: error.to_string(),
    }
}

/// Builds an infrastructure failure from redacted text.
fn infra_msg(stage: &'static str, detail: &str) -> GateFailure {
    GateFailure {
        stage,
        detail: detail.to_string(),
    }
}

/// The origin-count matrix and the per-rail happy paths.
///
/// Run with every payment rail feature on, which is how the gate ships:
///
/// ```text
/// cargo nextest run -p sbproxy-core --features payment-x402,payment-mpp,payment-stripe,payment-lightning-cln settlement_gate
/// ```
///
/// The rail wire contracts (x402 v2, Payment Auth draft-01, Stripe
/// PaymentIntents, CLN) are pinned by sbproxy-billing's own contract
/// tests; these stub at the adapter seam and assert the gate's contract:
/// for every non-success authorization state the decision is not `Allow`,
/// the provider settle count does not move past what the state implies,
/// and no access receipt exists.
#[cfg(all(test, feature = "payment-x402", feature = "payment-mpp"))]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use sbproxy_billing::dispatch::DispatchContext;
    use sbproxy_billing::payment_auth::{ChallengeBinder, PaymentChallenge};
    use sbproxy_billing::registry::UsageEvent;
    use sbproxy_billing::registry::{
        AuthoritativePayment, ChallengeMaterial, ChallengePreparation, PaymentMethodAdapter,
        ProviderQueryResult, RailRegistry,
    };
    use sbproxy_billing::service::RequirementSigner;
    use sbproxy_billing::sqlite::SqliteSettlementStore;
    use sbproxy_billing::store::{
        BillingClock, ClaimedAttempt, ClaimedUsageEvent, CreateIntent, LeaseRecovery,
        PreparedAttempt, ProofReservation, ProviderAttempt, ReconciliationOutcome, SettlementStore,
        SharedSettlementStore, SystemClock, UsageOutcome,
    };
    use sbproxy_billing::types::{
        AttemptOperation, PaymentRequirementDraft, RecoveryEnvelopeRecord, SafeFailure,
        SettlementRail, SettlementReceipt,
    };
    use sbproxy_modules::policy::quote_token::{
        InMemoryNonceStore, NonceStore, QuoteTokenSigner, QuoteTokenVerifier,
    };

    use crate::payment_signer::QuoteRequirementSigner;

    /// A clock the test moves by hand, anchored to the real wall clock so
    /// quote-token `exp` claims (verified against real time) stay live.
    struct TestClock(AtomicI64);

    impl TestClock {
        fn anchored() -> Arc<Self> {
            Arc::new(Self(AtomicI64::new(SystemClock.now_ms())))
        }

        fn advance(&self, delta_ms: i64) {
            self.0.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    impl BillingClock for TestClock {
        fn now_ms(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// What the scripted rail does when asked to settle.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Script {
        Settle,
        Reject,
        NotSettled,
    }

    struct ScriptedState {
        script: Mutex<Script>,
        settle_calls: AtomicUsize,
    }

    /// A rail adapter the test scripts, following the dispatch-gate
    /// protocol exactly as the billing fixtures do.
    struct ScriptedAdapter {
        rail: SettlementRail,
        state: Arc<ScriptedState>,
        provider_handle: Option<&'static str>,
        client_secret: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl PaymentMethodAdapter for ScriptedAdapter {
        fn rail(&self) -> SettlementRail {
            self.rail
        }

        async fn prepare_challenge(
            &self,
            _request: ChallengePreparation,
            _dispatch: &DispatchContext,
        ) -> Result<ChallengeMaterial, BillingError> {
            let mut material = ChallengeMaterial::new(self.provider_handle.map(str::to_string));
            if let Some(secret) = self.client_secret {
                material.client_secret = Some(zeroize::Zeroizing::new(secret.to_string()));
            }
            Ok(material.with_field("provider", "scripted"))
        }

        async fn authorize_and_settle(
            &self,
            request: AuthoritativePayment,
            dispatch: &DispatchContext,
        ) -> Result<SettlementReceipt, BillingError> {
            self.state.settle_calls.fetch_add(1, Ordering::SeqCst);
            let script = *self.state.script.lock().expect("script lock");
            let intent_id = request.intent_id.clone();
            let rail = self.rail;
            let now_ms = request.now_ms;
            dispatch
                .run_write(|| async move {
                    match script {
                        Script::Settle => SettlementReceipt::new(
                            &intent_id,
                            rail,
                            "exact",
                            "provider_ref_1",
                            now_ms,
                        ),
                        Script::Reject => Err(BillingError::ProviderRejected),
                        Script::NotSettled => Err(BillingError::NotSettled),
                    }
                })
                .await
        }

        async fn query_attempt(
            &self,
            _attempt: &ProviderAttempt,
            _dispatch: &DispatchContext,
        ) -> Result<ProviderQueryResult, BillingError> {
            Ok(ProviderQueryResult::Unsupported)
        }
    }

    /// A store that cannot answer, for the infrastructure row of the
    /// matrix.
    struct FailingStore;

    #[async_trait::async_trait]
    impl SettlementStore for FailingStore {
        async fn create_or_get_challenge(
            &self,
            _draft: &PaymentRequirementDraft,
            _draft_digest: [u8; 32],
            _request_idempotency_key: &str,
            _payer_hash: Option<&str>,
        ) -> Result<CreateIntent, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn finalize_requirement(
            &self,
            _intent_id: &str,
            _signed: &SignedPaymentRequirement,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn latest_attempt(
            &self,
            _intent_id: &str,
            _operation: AttemptOperation,
        ) -> Result<Option<ProviderAttempt>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn prepare_attempt(
            &self,
            _intent_id: &str,
            _operation: AttemptOperation,
            _provider_idempotency_key: &str,
            _known_provider_handle: Option<&str>,
            _now_ms: i64,
        ) -> Result<PreparedAttempt, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_dispatch_started(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _now_ms: i64,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_succeeded(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _receipt: SettlementReceipt,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_retry_wait_before_dispatch(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _retry_at_ms: i64,
            _failure: SafeFailure,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_terminal(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _failure: SafeFailure,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_needs_reconciliation(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _failure: SafeFailure,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_challenge_prepared(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _provider_handle: Option<&str>,
            _now_ms: i64,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn load_intent(
            &self,
            _intent_id: &str,
        ) -> Result<Option<IntentRecord>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn load_attempt(
            &self,
            _attempt_id: &str,
        ) -> Result<Option<ProviderAttempt>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn load_access_receipt(
            &self,
            _intent_id: &str,
        ) -> Result<Option<SettlementReceipt>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn unresolved_intent_for_route(
            &self,
            _tenant_id: &str,
            _origin_id: &str,
            _route: &str,
            _payer_hash: Option<&str>,
        ) -> Result<Option<String>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn reserve_proof(
            &self,
            _intent_id: &str,
            _proof_digest: [u8; 32],
            _now_ms: i64,
        ) -> Result<ProofReservation, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn put_recovery_envelope(
            &self,
            _envelope: &RecoveryEnvelopeRecord,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn load_recovery_envelope(
            &self,
            _attempt_id: &str,
        ) -> Result<Option<RecoveryEnvelopeRecord>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn purge_recovery_envelope(&self, _attempt_id: &str) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn purge_expired_recovery_envelopes(
            &self,
            _now_ms: i64,
        ) -> Result<u64, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn expire_stale_challenges(
            &self,
            _now_ms: i64,
            _limit: u32,
        ) -> Result<u64, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn recover_stale_leases(
            &self,
            _now_ms: i64,
            _limit: u32,
        ) -> Result<LeaseRecovery, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn claim_reconciliation(
            &self,
            _now_ms: i64,
            _lease_ttl_ms: i64,
            _limit: u32,
        ) -> Result<Vec<ClaimedAttempt>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn record_reconciliation(
            &self,
            _attempt_id: &str,
            _lease_token: &str,
            _outcome: ReconciliationOutcome,
            _now_ms: i64,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn enqueue_usage_event(&self, _event: &UsageEvent) -> Result<bool, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn claim_usage_events(
            &self,
            _now_ms: i64,
            _lease_ttl_ms: i64,
            _limit: u32,
        ) -> Result<Vec<ClaimedUsageEvent>, BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn mark_usage_dispatch_started(
            &self,
            _reporter: &str,
            _usage_identifier: &str,
            _lease_token: &str,
            _now_ms: i64,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
        async fn record_usage_outcome(
            &self,
            _reporter: &str,
            _usage_identifier: &str,
            _lease_token: &str,
            _outcome: UsageOutcome,
            _now_ms: i64,
        ) -> Result<(), BillingError> {
            Err(BillingError::Storage("induced store failure"))
        }
    }

    /// The gate wired to a real SQLite store and one scripted rail.
    struct Gate {
        _dir: Option<tempfile::TempDir>,
        service: BillingService,
        seam: SettlementGateSeam,
        payments: PaymentsConfig,
        policy: AiCrawlControlPolicy,
        state: Arc<ScriptedState>,
        clock: Arc<TestClock>,
    }

    impl Gate {
        fn build(
            rail: SettlementRail,
            payments: PaymentsConfig,
            policy: AiCrawlControlPolicy,
            provider_handle: Option<&'static str>,
            client_secret: Option<&'static str>,
            store_override: Option<SharedSettlementStore>,
        ) -> Self {
            payments.validate().expect("payments fixture validates");
            let clock = TestClock::anchored();
            let dyn_clock: Arc<dyn BillingClock> = clock.clone();
            let (dir, store): (Option<tempfile::TempDir>, SharedSettlementStore) =
                match store_override {
                    Some(store) => (None, store),
                    None => {
                        let dir = tempfile::tempdir().expect("tempdir");
                        let store = SqliteSettlementStore::open(&dir.path().join("s.sqlite3"))
                            .expect("open settlement store")
                            .with_clock(Arc::clone(&dyn_clock))
                            .shared();
                        (Some(dir), store)
                    }
                };

            let quote_signer = QuoteTokenSigner::from_seed_bytes(
                &[7_u8; 32],
                "kid-test",
                "https://proxy.example",
                Duration::from_secs(600),
            );
            let verifying = quote_signer.verifying_key();
            let nonce_store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
            let verifier =
                QuoteTokenVerifier::single_key("kid-test", verifying, Arc::clone(&nonce_store));
            let requirement_signer = Arc::new(QuoteRequirementSigner::new(quote_signer, verifier));
            let dyn_signer: Arc<dyn RequirementSigner> = requirement_signer.clone();

            let state = Arc::new(ScriptedState {
                script: Mutex::new(Script::Settle),
                settle_calls: AtomicUsize::new(0),
            });
            let mut registry = RailRegistry::new();
            registry
                .register_adapter(Arc::new(ScriptedAdapter {
                    rail,
                    state: Arc::clone(&state),
                    provider_handle,
                    client_secret,
                }))
                .expect("register scripted adapter");

            let service = BillingService::builder(store)
                .adapters(registry)
                .signer(dyn_signer)
                .clock(dyn_clock)
                .build();

            let binder =
                ChallengeBinder::new("crawl", b"test-binding-key-material").expect("binder");
            let seam = SettlementGateSeam {
                quote_signer: requirement_signer,
                nonce_store,
                challenge_binder: Some(Arc::new(binder)),
                failure_mode: FailureMode::Closed,
            };

            Self {
                _dir: dir,
                service,
                seam,
                payments,
                policy,
                state,
                clock,
            }
        }

        fn x402() -> Self {
            Self::build(
                SettlementRail::X402,
                x402_payments(),
                crawl_policy(0.001, "USD"),
                None,
                None,
                None,
            )
        }

        fn mpp() -> Self {
            Self::build(
                SettlementRail::Stripe,
                mpp_payments(),
                crawl_policy(0.01, "USD"),
                None,
                None,
                None,
            )
        }

        fn stripe_direct() -> Self {
            Self::build(
                SettlementRail::Stripe,
                stripe_direct_payments(),
                crawl_policy(0.01, "USD"),
                Some("pi_test_1"),
                Some("cs_test_secret"),
                None,
            )
        }

        fn lightning() -> Self {
            /// A syntactically valid payment-hash handle: 64 hex chars.
            const CLN_PAYMENT_HASH: &str =
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            Self::build(
                SettlementRail::LightningCln,
                lightning_payments(),
                crawl_policy(0.0001, "BTC"),
                Some(CLN_PAYMENT_HASH),
                None,
                None,
            )
        }

        fn failing_store() -> Self {
            Self::build(
                SettlementRail::X402,
                x402_payments(),
                crawl_policy(0.001, "USD"),
                None,
                None,
                Some(Arc::new(FailingStore)),
            )
        }

        fn script(&self, script: Script) {
            *self.state.script.lock().expect("script lock") = script;
        }

        fn settle_calls(&self) -> usize {
            self.state.settle_calls.load(Ordering::SeqCst)
        }

        async fn decide_with(&self, headers: &http::HeaderMap) -> GateDecision {
            self.decide_path("/article", headers).await
        }

        /// The same decision against a named route, for the rules that are
        /// scoped to one piece of content rather than to the deployment.
        async fn decide_path(&self, path: &str, headers: &http::HeaderMap) -> GateDecision {
            self.decide_full(path, headers, None).await
        }

        /// The same decision made by a named payer (WOR-2238).
        ///
        /// Takes the principal rather than the derived key so a test reads
        /// as "GPTBot asks again" and the derivation stays exercised on the
        /// path the request pipeline uses.
        async fn decide_as(
            &self,
            path: &str,
            headers: &http::HeaderMap,
            principal: &str,
        ) -> GateDecision {
            let hash = payer_scope_hash("tenant-1", principal);
            self.decide_full(path, headers, Some(hash.as_str())).await
        }

        async fn decide_full(
            &self,
            path: &str,
            headers: &http::HeaderMap,
            payer_hash: Option<&str>,
        ) -> GateDecision {
            let accept = headers
                .get(http::header::ACCEPT)
                .and_then(|value| value.to_str().ok());
            let accept_payment = headers
                .get("accept-payment")
                .and_then(|value| value.to_str().ok());
            let request = GateRequest {
                headers,
                host: "blog.test",
                path,
                tenant: "tenant-1",
                origin_id: "origin-1",
                agent_id: "",
                payer_hash,
                accept,
                accept_payment,
            };
            let deps = GateDeps {
                service: &self.service,
                seam: &self.seam,
                payments: &self.payments,
                policy: &self.policy,
            };
            decide(&request, &deps).await
        }

        /// Issues one challenge and returns its rendered response.
        async fn challenge(&self, headers: &http::HeaderMap) -> GateResponse {
            match self.decide_with(headers).await {
                GateDecision::Respond(response) => {
                    assert_eq!(response.status, 402, "a challenge is a 402");
                    response
                }
                GateDecision::Allow => panic!("a challenge must not allow"),
                GateDecision::KeepLegacy => panic!("settlement should own this challenge"),
                GateDecision::Infrastructure(failure) => {
                    panic!("challenge failed at {}: {}", failure.stage, failure.detail)
                }
            }
        }

        /// The receipt the store would authorize a request with, if any.
        async fn receipt_for_token(&self, token: &str) -> Option<SettlementReceipt> {
            let claims = self
                .seam
                .quote_signer
                .verify_claims(token)
                .expect("token authenticates");
            let requirement_id = claims.requirement_id.expect("requirement id claim");
            let intent_id = derive_intent_id("tenant-1", &requirement_id);
            self.service
                .store()
                .load_access_receipt(&intent_id)
                .await
                .expect("store answers")
        }
    }

    fn crawl_policy(price: f64, currency: &str) -> AiCrawlControlPolicy {
        AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": price,
            "currency": currency,
            "header": "crawler-payment",
            "crawler_user_agents": ["GPTBot"],
        }))
        .expect("policy compiles")
    }

    fn payments_fixture(value: serde_json::Value) -> PaymentsConfig {
        serde_json::from_value(value).expect("payments fixture parses")
    }

    fn x402_payments() -> PaymentsConfig {
        payments_fixture(serde_json::json!({
            "state_path": "/var/lib/sbproxy/test-settlement.sqlite3",
            "challenge_binding_key": "secret://env/SB_TEST_BINDING_KEY",
            "rails": {"x402": {
                "network": "eip155:84532",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "quote_currency": "USD",
                "asset_decimals": 6,
                "pay_to": "0x1111111111111111111111111111111111111111",
                "max_timeout_seconds": 60,
                "facilitators": [
                    {"facilitator_url": "https://facilitator.test.sbproxy.dev/api"}
                ]
            }}
        }))
    }

    fn mpp_payments() -> PaymentsConfig {
        payments_fixture(serde_json::json!({
            "state_path": "/var/lib/sbproxy/test-settlement.sqlite3",
            "challenge_binding_key": "secret://env/SB_TEST_BINDING_KEY",
            "recovery_encryption": {
                "key_id": "rk1",
                "key": "secret://env/SB_TEST_RECOVERY_KEY"
            },
            "protocols": {"payment_auth": {"realm": "crawl"}},
            "rails": {"stripe": {
                "api_key": "secret://env/SB_TEST_STRIPE_KEY",
                "business_network_id": "bn_test",
                "quote_currency": "USD",
                "currency_decimals": 2,
                "payment_method_types": ["card"]
            }}
        }))
    }

    fn stripe_direct_payments() -> PaymentsConfig {
        payments_fixture(serde_json::json!({
            "state_path": "/var/lib/sbproxy/test-settlement.sqlite3",
            "challenge_binding_key": "secret://env/SB_TEST_BINDING_KEY",
            "recovery_encryption": {
                "key_id": "rk1",
                "key": "secret://env/SB_TEST_RECOVERY_KEY"
            },
            "rails": {"stripe": {
                "api_key": "secret://env/SB_TEST_STRIPE_KEY",
                "business_network_id": "bn_test",
                "quote_currency": "USD",
                "currency_decimals": 2,
                "payment_method_types": ["card"],
                "direct_payment_intent": {"enabled": true}
            }}
        }))
    }

    fn lightning_payments() -> PaymentsConfig {
        payments_fixture(serde_json::json!({
            "state_path": "/var/lib/sbproxy/test-settlement.sqlite3",
            "challenge_binding_key": "secret://env/SB_TEST_BINDING_KEY",
            "rails": {"lightning_cln": {
                "socket_path": "/var/run/lightning/lightning-rpc",
                "rune": "secret://env/SB_TEST_CLN_RUNE",
                "quote_currency": "BTC",
                "settlement_decimals": 11
            }}
        }))
    }

    fn crawler_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("GPTBot/1.0"),
        );
        headers
    }

    fn add_header(headers: &mut http::HeaderMap, name: &str, value: &str) {
        headers.append(
            http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            http::HeaderValue::from_str(value).expect("header value"),
        );
    }

    fn header_value(response: &GateResponse, name: &str) -> String {
        response
            .response
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("response carries {name}"))
    }

    fn quote_token_of(response: &GateResponse) -> String {
        header_value(response, "crawler-payment")
    }

    /// Builds a syntactically valid x402 credential from a challenge body.
    fn x402_credential(body: &str) -> String {
        let required: serde_json::Value = serde_json::from_str(body).expect("x402 body is JSON");
        let envelope = serde_json::json!({
            "x402Version": required["x402Version"],
            "resource": required["resource"],
            "accepted": required["accepts"][0],
            "payload": {"signature": "0xdeadbeef"},
            "extensions": required["extensions"],
        });
        encode_x402_header(&envelope).expect("encode x402 credential")
    }

    /// Builds a Payment Auth credential echoing one challenge header.
    fn mpp_credential(challenge_header: &str, spt: &str) -> String {
        let challenge =
            PaymentChallenge::parse_header_value(challenge_header).expect("challenge parses");
        let credential = serde_json::json!({
            "challenge": challenge,
            "payload": {"spt": spt},
        });
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&credential).expect("credential serializes"));
        format!("Payment {encoded}")
    }

    fn expect_respond(decision: GateDecision) -> GateResponse {
        match decision {
            GateDecision::Respond(response) => response,
            GateDecision::Allow => panic!("expected a response, got Allow"),
            GateDecision::KeepLegacy => panic!("expected a response, got KeepLegacy"),
            GateDecision::Infrastructure(failure) => {
                panic!(
                    "expected a response, got infra failure at {}",
                    failure.stage
                )
            }
        }
    }

    // --- Happy paths ---

    #[tokio::test]
    async fn x402_challenge_settle_allow() {
        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        assert!(challenge.response.body.contains("x402Version"));
        assert!(challenge.response.body.contains("accepts"));
        header_value(&challenge, "PAYMENT-REQUIRED");
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        let decision = gate.decide_with(&retry).await;
        assert!(
            matches!(decision, GateDecision::Allow),
            "settled retry allows"
        );
        assert_eq!(gate.settle_calls(), 1);
        assert!(gate.receipt_for_token(&token).await.is_some());
    }

    #[tokio::test]
    async fn mpp_challenge_settle_allow() {
        let gate = Gate::mpp();
        let challenge = gate.challenge(&crawler_headers()).await;
        let www = header_value(&challenge, "WWW-Authenticate");
        assert!(www.starts_with("Payment "), "challenge is a Payment scheme");
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "authorization",
            &mpp_credential(&www, "spt_test_12345"),
        );
        let decision = gate.decide_with(&retry).await;
        assert!(
            matches!(decision, GateDecision::Allow),
            "settled retry allows"
        );
        assert_eq!(gate.settle_calls(), 1);
    }

    #[tokio::test]
    async fn mpp_duplicate_credential_is_a_400_problem() {
        let gate = Gate::mpp();
        let challenge = gate.challenge(&crawler_headers()).await;
        let www = header_value(&challenge, "WWW-Authenticate");
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        let credential = mpp_credential(&www, "spt_test_12345");
        add_header(&mut retry, "authorization", &credential);
        add_header(&mut retry, "authorization", &credential);
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 400);
        assert_eq!(response.response.content_type, PROBLEM_CONTENT_TYPE);
        assert!(response.response.body.contains("malformed-credential"));
        assert_eq!(gate.settle_calls(), 0, "a 400 dispatches nothing");
        assert!(gate.receipt_for_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn stripe_direct_challenge_settle_allow() {
        let gate = Gate::stripe_direct();
        let challenge = gate.challenge(&crawler_headers()).await;
        assert!(
            challenge.response.body.contains("cs_test_secret"),
            "the one-shot client secret rides the immediate 402"
        );
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        let decision = gate.decide_with(&retry).await;
        assert!(
            matches!(decision, GateDecision::Allow),
            "settled retry allows"
        );
        assert_eq!(gate.settle_calls(), 1);
    }

    #[tokio::test]
    async fn lightning_challenge_settle_allow() {
        let gate = Gate::lightning();
        let mut headers = crawler_headers();
        add_header(&mut headers, "accept-payment", "lightning");
        let challenge = gate.challenge(&headers).await;
        assert!(challenge.response.body.contains("\"rail\":\"lightning\""));
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        let decision = gate.decide_with(&retry).await;
        assert!(
            matches!(decision, GateDecision::Allow),
            "settled retry allows"
        );
        assert_eq!(gate.settle_calls(), 1);
    }

    // --- The origin-count matrix: every non-success state stays denied ---

    #[tokio::test]
    async fn pending_payment_never_reaches_the_origin() {
        let gate = Gate::x402();
        gate.script(Script::NotSettled);
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 503, "verified-not-settled is unavailable");
        header_value(&response, "Retry-After");
        assert!(gate.receipt_for_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn rejected_payment_never_reaches_the_origin() {
        let gate = Gate::x402();
        gate.script(Script::Reject);
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 402);
        assert!(response.response.body.contains("rejected"));
        assert!(gate.receipt_for_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn expired_challenge_never_reaches_the_origin() {
        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);
        gate.clock.advance(CHALLENGE_TTL_MS + 1_000);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 402);
        assert!(response.response.body.contains("challenge_expired"));
        assert_eq!(
            gate.settle_calls(),
            0,
            "an expired challenge dispatches nothing"
        );
        assert!(gate.receipt_for_token(&token).await.is_none());
    }

    // --- A payment that may already have moved money is never re-billed ---
    //
    // WOR-2230. Both halves start the same way: a crawler retries before the
    // rail has settled, which strands the intent in `NeedsReconciliation`.
    // From there a payer can come back holding its quote token or having
    // dropped it, and until this landed the second route minted a fresh
    // invoice for content the first payment may already have covered.

    /// Strands one intent for `/article` and returns its retry headers.
    async fn strand(gate: &Gate) -> http::HeaderMap {
        gate.script(Script::NotSettled);
        let challenge = gate.challenge(&crawler_headers()).await;
        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &quote_token_of(&challenge));
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(
            response.status, 503,
            "verified but not settled is what strands an intent",
        );
        retry
    }

    #[tokio::test]
    async fn a_stranded_payment_outliving_its_challenge_still_answers_503() {
        let gate = Gate::x402();
        let retry = strand(&gate).await;

        // The provider stays unreachable past the challenge TTL. Nothing
        // expires a stranded intent, so all that has changed is the clock.
        gate.clock.advance(CHALLENGE_TTL_MS + 1_000);
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(
            response.status, 503,
            "an aged-out challenge over an unresolved payment is still a wait",
        );
        header_value(&response, "Retry-After");
        assert!(
            !response.response.body.contains("challenge_expired"),
            "a payer whose money may be gone must not be told to pay again: {}",
            response.response.body,
        );
        assert_eq!(
            gate.settle_calls(),
            1,
            "nothing was dispatched a second time"
        );
    }

    #[tokio::test]
    async fn a_stranded_payment_withholds_a_fresh_challenge_for_its_route() {
        let before = settlement_count("none", "challenge", "unresolved_payment");
        let gate = Gate::x402();
        strand(&gate).await;

        // A crawler with no token at all. This is the request that used to
        // mint a second invoice for the same article, whether it arrived
        // because the payer dropped an expired token or because it never had
        // one.
        let response = expect_respond(gate.decide_with(&crawler_headers()).await);
        assert_eq!(
            response.status, 503,
            "no fresh bill while a payment for this content is unresolved",
        );
        header_value(&response, "Retry-After");
        assert_eq!(gate.settle_calls(), 1);
        assert!(
            settlement_count("none", "challenge", "unresolved_payment") > before,
            "withholding a challenge takes a route's revenue to zero until the \
             payment resolves, which an operator has to be able to alert on",
        );

        // Scoped to the content, not the deployment: every other route is
        // still payable.
        let other = expect_respond(gate.decide_path("/other", &crawler_headers()).await);
        assert_eq!(
            other.status, 402,
            "one stuck payment must not stop the rest of the site earning",
        );
    }

    // --- WOR-2238: the wait belongs to the payer, not to the route ---
    //
    // The guard above is correct and, scoped to the route alone, expensive:
    // while one payer's payment is stuck every payer of that route is refused,
    // and on a rail with no status endpoint that lasts as long as the provider
    // outage does. These pin the narrowing and, more importantly, the three
    // cases where it must not narrow.

    /// Strands one intent for `/article` under a named payer.
    async fn strand_as(gate: &Gate, principal: &str) {
        gate.script(Script::NotSettled);
        let challenge = expect_respond(
            gate.decide_as("/article", &crawler_headers(), principal)
                .await,
        );
        assert_eq!(challenge.status, 402, "a challenge is a 402");

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &quote_token_of(&challenge));
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        let response = expect_respond(gate.decide_as("/article", &retry, principal).await);
        assert_eq!(
            response.status, 503,
            "verified but not settled is what strands an intent",
        );
    }

    #[tokio::test]
    async fn a_stranded_payer_does_not_withhold_the_route_from_another_payer() {
        let gate = Gate::x402();
        strand_as(&gate, "agent:gptbot").await;

        // The whole point of the ticket. A second crawler has paid nothing,
        // is owed nothing, and asking it to wait out someone else's stuck
        // facilitator call is revenue the route simply does not earn.
        let other = expect_respond(
            gate.decide_as("/article", &crawler_headers(), "agent:claudebot")
                .await,
        );
        assert_eq!(
            other.status, 402,
            "a different payer is still billable while someone else's payment is stuck",
        );
        assert!(
            !other.response.body.contains("settlement_unavailable"),
            "the second payer gets a real challenge, not a wait: {}",
            other.response.body,
        );
        assert_eq!(
            gate.settle_calls(),
            1,
            "issuing a challenge settles nothing"
        );
    }

    #[tokio::test]
    async fn the_payer_whose_payment_is_stuck_still_waits() {
        let gate = Gate::x402();
        strand_as(&gate, "agent:gptbot").await;

        // WOR-2230's protection, unchanged: the payer that dropped its token
        // comes back with nothing to present, and a fresh invoice for it
        // would be the second bill for an article it may already have paid
        // for.
        let again = expect_respond(
            gate.decide_as("/article", &crawler_headers(), "agent:gptbot")
                .await,
        );
        assert_eq!(
            again.status, 503,
            "the payer whose money may already be gone is never billed again",
        );
        header_value(&again, "Retry-After");
        assert_eq!(
            gate.settle_calls(),
            1,
            "nothing was dispatched a second time"
        );
    }

    #[tokio::test]
    async fn an_intent_with_no_payer_scope_still_withholds_the_whole_route() {
        let gate = Gate::x402();
        // `strand` mints without a payer scope, which is the shape of every
        // row an older build wrote and of every row minted for a caller this
        // proxy cannot identify.
        strand(&gate).await;

        let identified = expect_respond(
            gate.decide_as("/article", &crawler_headers(), "agent:gptbot")
                .await,
        );
        assert_eq!(
            identified.status, 503,
            "a legacy row names nobody, so it could be anybody's payment that is stuck; \
             upgrading must not turn one into a second bill",
        );

        let anonymous = expect_respond(gate.decide_with(&crawler_headers()).await);
        assert_eq!(
            anonymous.status, 503,
            "and an unidentified request keeps waiting on it too",
        );
    }

    #[tokio::test]
    async fn an_unidentified_request_waits_on_an_identified_payers_stuck_payment() {
        let gate = Gate::x402();
        strand_as(&gate, "agent:gptbot").await;

        // The conservative direction. This request carries no identity, so
        // it cannot be proved to be someone other than the stranded payer,
        // and guessing costs a double charge.
        let anonymous = expect_respond(gate.decide_with(&crawler_headers()).await);
        assert_eq!(
            anonymous.status, 503,
            "no identity means no proof this is a different payer",
        );
    }

    #[test]
    fn the_payer_scope_key_does_not_expose_its_principal() {
        // Mirrors `the_fingerprint_is_not_a_prefix_of_a_record_key` in
        // sbproxy-security: a stored derivation of a caller identifier must
        // not be a way to read the identifier back.
        let principal = "agent:gptbot";
        let hash = payer_scope_hash("tenant-1", principal);

        assert!(
            !hash.contains(principal) && !hash.contains("gptbot"),
            "the stored key must not carry its own input: {hash}",
        );
        assert!(
            !principal.starts_with(&hash) && !hash.starts_with(principal),
            "neither value is a prefix of the other: {hash}",
        );
        assert_eq!(
            hash.len(),
            PAYER_SCOPE_LEN * 2,
            "the key is a fixed-width hex derivation, so its length leaks nothing \
             about the length of the identifier behind it",
        );

        // Deterministic, which is what lets the same payer match tomorrow.
        assert_eq!(hash, payer_scope_hash("tenant-1", principal));
        // Distinct across payers, which is what makes the narrowing safe.
        assert_ne!(hash, payer_scope_hash("tenant-1", "agent:claudebot"));
        // Distinct across tenants, so one tenant's store says nothing about
        // another's traffic.
        assert_ne!(hash, payer_scope_hash("tenant-2", principal));

        // And it is not recoverable by deriving the same material under
        // another purpose, which is the separation the purpose enum exists
        // for.
        let mut ikm = Vec::new();
        ikm.extend_from_slice(b"tenant-1");
        ikm.push(0);
        ikm.extend_from_slice(principal.as_bytes());
        let other_purpose = hex::encode(hkdf_derive_purpose(
            &ikm,
            PAYER_SCOPE_SALT,
            HkdfPurpose::Mac,
            PAYER_SCOPE_LEN,
        ));
        assert_ne!(
            hash, other_purpose,
            "the same material under a different purpose must derive a different key",
        );
    }

    #[tokio::test]
    async fn the_payer_scope_key_never_reaches_a_settlement_metric() {
        let gate = Gate::x402();
        let principal = "agent:gptbot";
        strand_as(&gate, principal).await;
        // Both halves of the guard, so every settlement row this change can
        // produce has been written before the scrape is inspected.
        gate.decide_as("/article", &crawler_headers(), principal)
            .await;
        gate.decide_as("/article", &crawler_headers(), "agent:claudebot")
            .await;

        let hash = payer_scope_hash("tenant-1", principal);
        for family in prometheus::gather() {
            if !family.name().starts_with("sbproxy_payment") {
                continue;
            }
            for metric in family.get_metric() {
                for label in metric.get_label() {
                    assert!(
                        !label.name().contains("payer"),
                        "{} carries a payer label",
                        family.name(),
                    );
                    assert_ne!(
                        label.value(),
                        hash,
                        "{} carries a payer scope key as a label value",
                        family.name(),
                    );
                    assert!(
                        !label.value().contains("gptbot"),
                        "{} carries a payer identifier as a label value",
                        family.name(),
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn replayed_credential_never_settles_a_second_intent() {
        let gate = Gate::x402();
        let first = gate.challenge(&crawler_headers()).await;
        let first_token = quote_token_of(&first);
        let credential = x402_credential(&first.response.body);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &first_token);
        add_header(&mut retry, "PAYMENT-SIGNATURE", &credential);
        assert!(matches!(
            gate.decide_with(&retry).await,
            GateDecision::Allow
        ));
        assert_eq!(gate.settle_calls(), 1);

        // A second challenge, and the settled credential presented
        // against it: the proof digest is already bound to the first
        // intent.
        let second = gate.challenge(&crawler_headers()).await;
        let second_token = quote_token_of(&second);
        let mut replay = crawler_headers();
        add_header(&mut replay, "crawler-payment", &second_token);
        add_header(&mut replay, "PAYMENT-SIGNATURE", &credential);
        let response = expect_respond(gate.decide_with(&replay).await);
        assert_eq!(response.status, 402);
        assert!(response.response.body.contains("proof_replayed"));
        assert_eq!(gate.settle_calls(), 1, "a replay dispatches nothing");
        assert!(gate.receipt_for_token(&second_token).await.is_none());
    }

    #[tokio::test]
    async fn a_settled_credential_authorizes_exactly_once() {
        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);
        let credential = x402_credential(&challenge.response.body);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(&mut retry, "PAYMENT-SIGNATURE", &credential);
        assert!(matches!(
            gate.decide_with(&retry).await,
            GateDecision::Allow
        ));

        // Same token, same credential, second presentation: the durable
        // intent still holds its receipt (a resumable retry by design),
        // and the request-path nonce burn is what makes serving happen
        // exactly once.
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 402);
        assert!(response.response.body.contains("proof_replayed"));
        assert_eq!(gate.settle_calls(), 1, "the payment settled exactly once");
    }

    #[tokio::test]
    async fn wrong_rail_preference_is_a_406_with_no_intent() {
        let gate = Gate::x402();
        let mut headers = crawler_headers();
        add_header(&mut headers, "accept-payment", "lightning");
        let response = expect_respond(gate.decide_with(&headers).await);
        assert_eq!(response.status, 406);
        assert_eq!(response.label, "ai_crawl_settlement");
        assert!(response.response.body.contains("no_acceptable_rail"));
        assert!(response.response.body.contains("x402"));
        assert_eq!(gate.settle_calls(), 0);
    }

    #[tokio::test]
    async fn garbage_quote_token_gets_a_fresh_challenge() {
        let gate = Gate::x402();
        let mut headers = crawler_headers();
        add_header(&mut headers, "crawler-payment", "not-a-quote-token");
        let response = expect_respond(gate.decide_with(&headers).await);
        assert_eq!(response.status, 402, "a fresh challenge is issued");
        let fresh = quote_token_of(&response);
        assert_ne!(fresh, "not-a-quote-token");
        assert_eq!(gate.settle_calls(), 0);
    }

    #[tokio::test]
    async fn malformed_x402_credential_never_dispatches() {
        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(&mut retry, "PAYMENT-SIGNATURE", "!!!not-base64!!!");
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 402);
        assert!(response.response.body.contains("proof_invalid"));
        assert_eq!(gate.settle_calls(), 0);
        assert!(gate.receipt_for_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn missing_x402_credential_never_dispatches() {
        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);

        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        let response = expect_respond(gate.decide_with(&retry).await);
        assert_eq!(response.status, 402);
        assert!(response.response.body.contains("proof_invalid"));
        assert_eq!(gate.settle_calls(), 0);
    }

    #[tokio::test]
    async fn a_store_error_is_infrastructure_not_a_payment_outcome() {
        let gate = Gate::failing_store();
        let decision = gate.decide_with(&crawler_headers()).await;
        assert!(
            matches!(decision, GateDecision::Infrastructure(_)),
            "a store error is never a payment refusal and never an allow"
        );
        assert_eq!(gate.settle_calls(), 0);
    }

    // --- Negotiation and configuration edges ---

    #[tokio::test]
    async fn no_advertisable_rail_keeps_the_legacy_challenge() {
        let payments = payments_fixture(serde_json::json!({
            "state_path": "/var/lib/sbproxy/test-settlement.sqlite3",
            "challenge_binding_key": "secret://env/SB_TEST_BINDING_KEY",
        }));
        let gate = Gate::build(
            SettlementRail::X402,
            payments,
            crawl_policy(0.001, "USD"),
            None,
            None,
            None,
        );
        assert!(matches!(
            gate.decide_with(&crawler_headers()).await,
            GateDecision::KeepLegacy
        ));
    }

    #[tokio::test]
    async fn a_zero_price_keeps_the_legacy_challenge() {
        let gate = Gate::build(
            SettlementRail::X402,
            x402_payments(),
            crawl_policy(0.0, "USD"),
            None,
            None,
            None,
        );
        assert!(matches!(
            gate.decide_with(&crawler_headers()).await,
            GateDecision::KeepLegacy
        ));
    }

    // --- The money path leaves an operational trace (WOR-2219) ---
    //
    // The tests above all assert on the durable rows and the status codes,
    // which is exactly why the settlement counter could sit at zero through
    // a complete challenge, settle, allow, replay run without a single one
    // of them noticing.
    //
    // Each assertion is a strict increase rather than an exact value.
    // `prometheus::gather()` reads a process-global registry, and under a
    // threaded runner the sibling tests in this module settle the same
    // rails concurrently. "The counter moved" is the whole claim the
    // regression needs, and it is the claim that cannot go flaky.

    /// One `sbproxy_payment_settlement_total` series, or 0 when nothing has
    /// created it yet.
    fn settlement_count(rail: &str, operation: &str, outcome: &str) -> f64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_payment_settlement_total")
            .map(|family| {
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        let labelled = |name: &str, want: &str| {
                            metric
                                .get_label()
                                .iter()
                                .any(|label| label.name() == name && label.value() == want)
                        };
                        labelled("rail", rail)
                            && labelled("operation", operation)
                            && labelled("outcome", outcome)
                    })
                    .map(|metric| metric.get_counter().value())
                    .sum()
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn a_settled_payment_counts_a_settlement() {
        let before_challenge = settlement_count("x402", "challenge", "prepared");
        let before_settled = settlement_count("x402", "redeem", "succeeded");

        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);
        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        assert!(matches!(
            gate.decide_with(&retry).await,
            GateDecision::Allow
        ));

        assert!(
            settlement_count("x402", "challenge", "prepared") > before_challenge,
            "a prepared durable challenge is the denominator of the settlement funnel",
        );
        assert!(
            settlement_count("x402", "redeem", "succeeded") > before_settled,
            "a payment that bought origin access must move \
             sbproxy_payment_settlement_total, or an operator graphing revenue reads zero \
             while payments settle",
        );
    }

    #[tokio::test]
    async fn a_refused_redemption_counts_its_problem_code() {
        let before = settlement_count("x402", "redeem", "proof_replayed");

        let gate = Gate::x402();
        let challenge = gate.challenge(&crawler_headers()).await;
        let token = quote_token_of(&challenge);
        let mut retry = crawler_headers();
        add_header(&mut retry, "crawler-payment", &token);
        add_header(
            &mut retry,
            "PAYMENT-SIGNATURE",
            &x402_credential(&challenge.response.body),
        );
        assert!(matches!(
            gate.decide_with(&retry).await,
            GateDecision::Allow
        ));
        // Same token, same credential: the nonce is burned, so this is a
        // replay and the counter has to say which refusal it was.
        assert_eq!(expect_respond(gate.decide_with(&retry).await).status, 402);

        assert!(
            settlement_count("x402", "redeem", "proof_replayed") > before,
            "a replay is a distinct outcome, not an undifferentiated refusal",
        );
    }

    #[tokio::test]
    async fn a_rail_negotiation_failure_counts_against_no_rail() {
        let before = settlement_count("none", "challenge", "no_acceptable_rail");

        let gate = Gate::x402();
        let mut headers = crawler_headers();
        add_header(&mut headers, "accept-payment", "lightning");
        assert_eq!(expect_respond(gate.decide_with(&headers).await).status, 406);

        assert!(
            settlement_count("none", "challenge", "no_acceptable_rail") > before,
            "negotiation failed before a rail was chosen, so the row belongs to `none` \
             rather than to a rail that was never selected",
        );
    }

    // --- The failure posture is exhaustive and payment-independent ---

    #[test]
    fn only_the_closed_posture_refuses_on_infrastructure_failure() {
        assert!(matches!(
            failure_action(FailureMode::Closed),
            FailureAction::Refuse { .. }
        ));
        assert!(matches!(
            failure_action(FailureMode::Open),
            FailureAction::Admit {
                waived: false,
                counterfactual: false
            }
        ));
        assert!(matches!(
            failure_action(FailureMode::Degraded),
            FailureAction::Admit {
                waived: true,
                counterfactual: false
            }
        ));
        assert!(matches!(
            failure_action(FailureMode::Observe),
            FailureAction::Admit {
                waived: false,
                counterfactual: true
            }
        ));
    }
}
