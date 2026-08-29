//! The bridge between a normalized payment requirement and the x402 wire.
//!
//! [`x402`](crate::x402) owns the protocol: the pinned v2 shapes, the header
//! encoding, the local validation, the breaker, and the verify-then-settle
//! deadline. What it does not own is the crate's own
//! [`PaymentRequirement`], because the settler is deliberately written
//! against x402's vocabulary rather than this crate's. This module is the
//! translation, and it is the only one: every x402 object the proxy puts on
//! the wire is produced by a function here.
//!
//! # The projection has to be a pure function
//!
//! [`validate_echoed_payload`](crate::x402::validate_echoed_payload)
//! compares the payer's echoed resource,
//! obligation, and extension map against the signed challenge byte for byte.
//! The 402 is built at challenge time and the comparison happens on a later
//! request, in a different process for all this crate knows, so the two sides
//! can only agree if both are derived from the same durable requirement by
//! the same code. That is why [`x402_payment_required`] and
//! [`X402Adapter::authorize_and_settle`] both go through
//! [`x402_resource`], [`x402_accepted`], and [`x402_extensions`] rather than
//! each building their own view.
//!
//! # What the payer sends back is not trusted to describe itself
//!
//! The adapter never reads the resource, the obligation, or the extension out
//! of the credential and believes it. It rebuilds all three from the durable
//! signed requirement and uses the payer's bytes for exactly one thing: the
//! opaque scheme payload, which is the facilitator's to verify and which this
//! crate treats as an uninterpreted blob.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::dispatch::DispatchContext;
use crate::error::BillingError;
use crate::lifecycle::{PaymentLifecycleDecision, PaymentLifecycleOutcome, PaymentLifecyclePhase};
use crate::registry::{
    AuthoritativePayment, ChallengeMaterial, ChallengePreparation, PaymentMethodAdapter,
    ProviderQueryResult,
};
use crate::store::ProviderAttempt;
use crate::types::{
    PaymentRequirement, PaymentRequirementDraft, RequirementTerms, SettlementRail,
    SettlementReceipt, SignedPaymentRequirement,
};
use crate::x402::{
    FacilitatorTransport, PaymentPayload, PaymentRequired, PaymentRequirementsObject,
    RequirementExtension, ResourceDescriptor, SettleDispatchGate, SignedX402Challenge, X402Error,
    X402ExactSettler, X402QueryResult, X402_SCHEME_EXACT, X402_VERSION,
};

/// Projects the priced resource onto the x402 resource descriptor.
///
/// Only the URL is populated. The optional descriptive fields exist in the
/// pinned shape for a payer's benefit, and this crate has no source for them
/// that is part of the signed obligation. Leaving them absent is what keeps
/// the projection total: an optional field populated from configuration on
/// one code path and omitted on another would break the exact comparison the
/// credential is checked against.
#[must_use]
pub fn x402_resource(draft: &PaymentRequirementDraft) -> ResourceDescriptor {
    ResourceDescriptor {
        url: draft.route.clone(),
        description: None,
        mime_type: None,
        service_name: None,
        tags: None,
        icon_url: None,
    }
}

/// Projects the requirement onto the exact obligation a payer signs.
///
/// Every value comes from the durable draft or its typed x402 terms. There is
/// no second source for the amount, the network, the asset, the recipient,
/// the timeout, or the `extra` object, which is the property that lets the
/// settler compare an echoed obligation for exact equality.
///
/// # Errors
///
/// Returns [`X402Error::RequirementMismatch`] when the draft does not carry
/// x402 terms, or when the network, asset, or recipient the rail requires is
/// absent. A draft missing any of those could not have been advertised.
pub fn x402_accepted(
    draft: &PaymentRequirementDraft,
) -> Result<PaymentRequirementsObject, X402Error> {
    let RequirementTerms::X402Exact {
        max_timeout_seconds,
        extra,
        ..
    } = &draft.terms
    else {
        return Err(X402Error::RequirementMismatch);
    };

    Ok(PaymentRequirementsObject {
        scheme: X402_SCHEME_EXACT.to_string(),
        network: draft
            .network
            .clone()
            .ok_or(X402Error::RequirementMismatch)?,
        amount: draft.settlement_amount.clone(),
        asset: draft.asset.clone().ok_or(X402Error::RequirementMismatch)?,
        pay_to: draft.pay_to.clone().ok_or(X402Error::RequirementMismatch)?,
        max_timeout_seconds: *max_timeout_seconds,
        // An absent `extra` and an empty one are different bytes on the
        // wire, so an unconfigured object stays absent rather than
        // serializing as `{}`.
        extra: if extra.is_empty() {
            None
        } else {
            Some(extra.clone())
        },
    })
}

/// Builds the single-entry `sbproxy-requirement` extension map.
///
/// # Errors
///
/// Returns [`X402Error::ExtensionInvalid`] when the requirement identifier is
/// outside the published pattern or the quote is empty or oversized.
pub fn x402_extensions(
    draft: &PaymentRequirementDraft,
    quote_token: &str,
) -> Result<BTreeMap<String, serde_json::Value>, X402Error> {
    RequirementExtension::new(&draft.requirement_id, quote_token)?.to_extensions_map()
}

/// Builds the complete 402 body for one signed requirement.
///
/// This is the whole x402 challenge. The response path renders it as the JSON
/// body and as the `PAYMENT-REQUIRED` header, and nothing else constructs a
/// `PaymentRequired`.
///
/// # Errors
///
/// Returns whatever [`x402_accepted`] and [`x402_extensions`] return.
pub fn x402_payment_required(
    signed: &SignedPaymentRequirement,
) -> Result<PaymentRequired, X402Error> {
    let draft = &signed.requirement.draft;
    Ok(PaymentRequired {
        x402_version: X402_VERSION,
        error: None,
        resource: x402_resource(draft),
        accepts: vec![x402_accepted(draft)?],
        extensions: x402_extensions(draft, &signed.quote_token)?,
    })
}

/// The x402 rail, in the shape the registry holds adapters in.
///
/// A thin wrapper by design. Every protocol decision stays in
/// [`X402ExactSettler`]; this type translates the crate's vocabulary into the
/// settler's, hands it the dispatch gate, and translates the result back.
///
/// # One settler per configured facilitator
///
/// The registry holds one adapter per rail, but an operator may configure an
/// ordered list of facilitators. This type holds a settler for each, and
/// [`Self::authorize_and_settle`] picks the one the signed requirement named.
/// It never falls through to another candidate: choosing a second facilitator
/// after a settle has been dispatched is how one payment becomes two, so
/// fallback is allowed only at challenge time, by issuing a fresh challenge
/// that names a different facilitator and is signed as such.
///
/// A requirement naming a facilitator this build has no settler for is
/// refused rather than redirected. That happens when a configuration drops a
/// facilitator while a challenge naming it is still outstanding, and the
/// honest answer is that the obligation can no longer be honored.
pub struct X402Adapter<T: FacilitatorTransport> {
    settlers: Vec<Arc<X402ExactSettler<T>>>,
}

impl<T: FacilitatorTransport> X402Adapter<T> {
    /// Holds one settler per configured facilitator, in configured order.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::FacilitatorUrl`] for an empty list or for two
    /// settlers bound to the same normalized root. A duplicate would make
    /// which breaker guards a call depend on iteration order.
    pub fn new(settlers: Vec<Arc<X402ExactSettler<T>>>) -> Result<Self, X402Error> {
        if settlers.is_empty() {
            return Err(X402Error::FacilitatorUrl);
        }
        let mut roots: Vec<&str> = settlers
            .iter()
            .map(|settler| settler.endpoints().root())
            .collect();
        roots.sort_unstable();
        let total = roots.len();
        roots.dedup();
        if roots.len() != total {
            return Err(X402Error::FacilitatorUrl);
        }
        Ok(Self { settlers })
    }

    /// Finds the settler bound to the facilitator a requirement named.
    ///
    /// Both sides are normalized before comparison, so a configured root
    /// that differs from the stored one only by a trailing slash still
    /// resolves to the same facilitator.
    fn settler_for(
        &self,
        requirement: &PaymentRequirement,
    ) -> Result<&Arc<X402ExactSettler<T>>, BillingError> {
        let RequirementTerms::X402Exact {
            facilitator_url, ..
        } = &requirement.draft.terms
        else {
            return Err(X402Error::RequirementMismatch.into());
        };
        let selected = crate::x402::FacilitatorEndpoints::from_api_root(facilitator_url)
            .or_else(|_| crate::x402::FacilitatorEndpoints::loopback_http_for_test(facilitator_url))
            .map_err(BillingError::from)?;

        self.settlers
            .iter()
            .find(|settler| settler.endpoints().root() == selected.root())
            .ok_or(BillingError::RequirementMismatch)
    }

    /// Rebuilds the payer's envelope from durable state plus the credential.
    ///
    /// Three of the four members are reconstructed from the signed
    /// requirement rather than read out of the credential, so a payer cannot
    /// describe a different obligation than the one they were challenged
    /// with. The fourth, the opaque scheme payload, is the only part that
    /// comes from the wire, and it is passed through uninterpreted.
    fn rebuild_payload(request: &AuthoritativePayment) -> Result<PaymentPayload, BillingError> {
        let draft = &request.requirement.draft;
        let payload: serde_json::Value = serde_json::from_str(request.proof.expose_credential())
            .map_err(|_| BillingError::InvalidProof)?;

        Ok(PaymentPayload {
            x402_version: X402_VERSION,
            resource: x402_resource(draft),
            accepted: x402_accepted(draft)?,
            payload,
            extensions: x402_extensions(draft, &request.quote_token)?,
        })
    }
}

impl<T: FacilitatorTransport> std::fmt::Debug for X402Adapter<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let roots: Vec<&str> = self
            .settlers
            .iter()
            .map(|settler| settler.endpoints().root())
            .collect();
        formatter
            .debug_struct("X402Adapter")
            .field("facilitators", &roots)
            .finish()
    }
}

#[async_trait::async_trait]
impl<T: FacilitatorTransport> PaymentMethodAdapter for X402Adapter<T> {
    fn rail(&self) -> SettlementRail {
        SettlementRail::X402
    }

    fn manages_authorization_lifecycle(&self) -> bool {
        true
    }

    /// Creates nothing.
    ///
    /// x402 has no provider object behind a challenge: the obligation is the
    /// challenge. Preparation therefore contacts no facilitator, which is
    /// also why an x402 challenge cannot leave a dangling provider record
    /// behind if the process dies before the 402 is written.
    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        _dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError> {
        // Project once here so a draft that could never produce a valid
        // obligation fails while it is still a challenge, rather than on
        // the payer's retry.
        x402_accepted(&request.draft)?;
        Ok(ChallengeMaterial::new(None))
    }

    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError> {
        let payload = Self::rebuild_payload(&request)?;
        let draft = &request.requirement.draft;
        let resource = x402_resource(draft);
        let accepted = x402_accepted(draft)?;
        let extensions = x402_extensions(draft, &request.quote_token)?;

        let challenge = SignedX402Challenge {
            intent_id: &request.intent_id,
            resource: &resource,
            accepted: &accepted,
            extensions: &extensions,
        };

        let gate = ContextGate { dispatch };
        let settlement = self
            .settler_for(&request.requirement)?
            .authorize_and_settle(
                crate::x402::X402AuthorizationRequest {
                    challenge,
                    payload: &payload,
                    now_ms: request.now_ms,
                },
                &gate,
            )
            .await;

        // The settler owns the stamp through the gate, so the conclusion is
        // recorded here from whatever it proved. An ambiguous failure leaves
        // the attempt ambiguous and bound for reconciliation.
        dispatch.conclude_write(&settlement);
        Ok(settlement?.receipt)
    }

    /// Answers a status query.
    ///
    /// Always unsupported. x402 v2 at the pinned revision publishes no status
    /// or reorg endpoint, so an ambiguous settle stays in reconciliation
    /// rather than being resolved by a guess or retried into a second charge.
    async fn query_attempt(
        &self,
        _attempt: &ProviderAttempt,
        _dispatch: &DispatchContext,
    ) -> Result<ProviderQueryResult, BillingError> {
        // Every settler answers the same way, so the first one speaks for
        // the rail. The constructor guarantees there is one.
        match self.settlers[0].query_attempt() {
            X402QueryResult::Unsupported => Ok(ProviderQueryResult::Unsupported),
        }
    }
}

/// Adapts the durable dispatch context onto the settler's write gate.
///
/// The settler calls this exactly once, after `verify` answered and
/// immediately before `settle` leaves the process. That ordering is the whole
/// point of the gate: `verify` is a read and must not stamp a dispatch, while
/// `settle` moves money and must not leave without one.
struct ContextGate<'a> {
    dispatch: &'a DispatchContext,
}

#[async_trait::async_trait]
impl SettleDispatchGate for ContextGate<'_> {
    async fn payment_started(&self, phase: PaymentLifecyclePhase) -> PaymentLifecycleDecision {
        self.dispatch.payment_started(phase).await
    }

    fn payment_terminal(&self, phase: PaymentLifecyclePhase, outcome: PaymentLifecycleOutcome) {
        self.dispatch.payment_terminal(phase, outcome);
    }

    async fn stamp_settle_dispatch(&self) -> Result<(), BillingError> {
        self.dispatch.stamp_write().await
    }

    async fn attribute_facilitator_payer(
        &self,
        intent_id: &str,
        payer: &str,
    ) -> Result<(), BillingError> {
        self.dispatch.attribute_x402_payer(intent_id, payer).await
    }
}

/// Reports whether a requirement is one this rail can settle.
#[must_use]
pub fn settles_x402(requirement: &PaymentRequirement) -> bool {
    matches!(requirement.draft.terms, RequirementTerms::X402Exact { .. })
}
