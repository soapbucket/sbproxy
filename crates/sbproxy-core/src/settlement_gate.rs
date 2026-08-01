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

use std::sync::Arc;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::service::{
    AuthorizationDecision, BillingService, PaymentProblemCode, PreparedPaymentResponse,
    RedemptionRequest, RequirementInput,
};
use sbproxy_billing::store::IntentRecord;
use sbproxy_billing::types::{
    derive_intent_id, AdvertisedRail, IntentStatus, PaymentProof, SignedPaymentRequirement,
};
use sbproxy_config::payments::{AdvertisedRailName, PaymentsConfig};
use sbproxy_config::types::FailureMode;
use sbproxy_modules::policy::ai_crawl::{resolve_agent_preferences, AiCrawlControlPolicy, Rail};
use sbproxy_modules::policy::payment_requirement::{PaymentRequirementCompiler, RequirementContext};
use sbproxy_modules::policy::quote_token::NonceCheck;

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

/// The proof scheme for rails whose credential is the quote token itself.
///
/// Direct Stripe settles by capturing the challenge-bound PaymentIntent
/// and Lightning settles by observing the invoice, so neither rail carries
/// a client credential on the retry. The re-presented quote token is a
/// faithful per-challenge identity for replay binding, and it is
/// deterministic across retries, which is what lets an interrupted
/// payment resume instead of reading as a replay.
const QUOTE_PROOF_SCHEME: &str = "crawler-quote";

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
    pub(crate) agent_id: &'a str,
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
                Ok(NonceCheck::Fresh) => Ok(RetryOutcome::Allow),
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
        } => Ok(RetryOutcome::Respond(unavailable_response(
            retry_after_seconds,
        ))),
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
        return Ok(ChallengeOutcome::Respond(no_acceptable_rail_response(
            request, &floor,
        )));
    };

    let price = deps
        .policy
        .resolve_price_for_request(request.path, request.agent_id, request.accept);
    if price.amount_micros == 0 {
        return Ok(ChallengeOutcome::KeepLegacy("route priced at zero"));
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
        })
        .await
        .map_err(|error| infra("prepare_requirement", &error))?;

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
    if payments
        .rails
        .stripe
        .as_ref()
        .is_some_and(|stripe| {
            stripe
                .direct_payment_intent
                .as_ref()
                .is_some_and(|direct| direct.enabled)
        })
    {
        rails.push(AdvertisedRailName::Stripe);
    }
    if payments
        .lightning_backend()
        .ok()
        .flatten()
        .is_some()
    {
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
fn stored_signed(intent: &IntentRecord) -> Option<SignedPaymentRequirement> {
    Some(SignedPaymentRequirement {
        requirement: intent.requirement.clone()?,
        draft_digest: intent.draft_digest,
        requirement_digest: intent.requirement_digest?,
        quote_token: intent.quote_token.clone()?,
    })
}

/// Renders a payment refusal in the intent's rail shape.
fn refusal_response(
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
    problem_response(
        deps,
        intent,
        type_uri,
        title,
        status,
        format!("payment auth refused: {error}"),
    )
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
