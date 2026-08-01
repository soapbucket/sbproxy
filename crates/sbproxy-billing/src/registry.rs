//! Rail adapters, usage reporters, and the runtime registries that hold them.
//!
//! Two namespaces, deliberately separate. A [`PaymentMethodAdapter`] can
//! settle a payment and therefore authorize origin access. A
//! [`UsageReporter`] cannot: it has no way to build a
//! [`SettlementReceipt`], no way to reach `mark_succeeded`, and no way to
//! move an intent to [`crate::types::IntentStatus::Succeeded`]. Stripe
//! Meter Events are usage accounting, never proof of payment, and the type
//! system is where that is enforced rather than a code review comment.
//!
//! Registration is fallible in both namespaces. Two adapters claiming one
//! rail, or two reporters claiming one name, is a configuration error that
//! fails startup instead of silently picking a winner.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::dispatch::DispatchContext;
use crate::error::BillingError;
use crate::store::ProviderAttempt;
use crate::types::{
    PaymentProof, PaymentRequirement, PaymentRequirementDraft, SafeFailure, SettlementRail,
    SettlementReceipt,
};

/// Everything a rail needs to create the provider object a challenge names.
///
/// The draft is already canonical and already hashed. An adapter reads its
/// terms and nothing else; there is no second source for the amount, the
/// recipient, the network, the capture mode, or the expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePreparation {
    /// The durable intent this challenge belongs to.
    pub intent_id: String,
    /// The immutable draft.
    pub draft: PaymentRequirementDraft,
    /// Digest of the immutable draft, which direct-mode Stripe binds in
    /// PaymentIntent metadata because the identifier cannot bind itself.
    pub draft_digest: [u8; 32],
    /// Current time, in milliseconds since the epoch.
    pub now_ms: i64,
}

/// What a rail produced while preparing a challenge.
///
/// `client_secret` is the one value here that is secret. It goes into the
/// immediate 402 response object and nowhere else: it is never persisted,
/// never logged, and never part of a digest. That is why this struct has no
/// `Debug`.
pub struct ChallengeMaterial {
    /// The non-secret provider handle to fold into the final requirement.
    pub provider_handle: Option<String>,
    /// A one-shot client secret for the immediate response, if the rail
    /// issues one.
    pub client_secret: Option<Zeroizing<String>>,
    /// Non-secret fields the challenge codec renders onto the wire.
    pub challenge_fields: BTreeMap<String, String>,
}

impl ChallengeMaterial {
    /// Builds challenge material that carries no secret at all.
    pub fn new(provider_handle: Option<String>) -> Self {
        Self {
            provider_handle,
            client_secret: None,
            challenge_fields: BTreeMap::new(),
        }
    }

    /// Adds a non-secret challenge field.
    #[must_use]
    pub fn with_field(mut self, name: &str, value: &str) -> Self {
        self.challenge_fields
            .insert(name.to_string(), value.to_string());
        self
    }
}

/// Everything a rail needs to settle one payment authoritatively.
///
/// This struct has no `Debug` because it carries a live payment credential.
/// The credential's own `Debug` is redacted, but the rule in this crate is
/// that a type holding credentials does not get a derived `Debug` merely so
/// a test can print it.
pub struct AuthoritativePayment {
    /// The durable intent being settled.
    pub intent_id: String,
    /// The finalized, signed requirement.
    pub requirement: PaymentRequirement,
    /// Digest of the finalized requirement.
    pub requirement_digest: [u8; 32],
    /// The client's credential.
    pub proof: PaymentProof,
    /// Current time, in milliseconds since the epoch.
    pub now_ms: i64,
}

/// What a provider said about an outstanding attempt.
///
/// There is no variant that means "probably fine". A rail either answers
/// with provider-backed fact or says it cannot answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderQueryResult {
    /// The provider proved the payment settled; here is the real receipt.
    Settled(SettlementReceipt),
    /// The provider proved the write never landed.
    NotDispatched,
    /// The provider has the object and it is not resolved yet.
    StillPending,
    /// The provider proved the payment failed and no funds moved.
    Failed(SafeFailure),
    /// This rail has no documented way to answer this question.
    ///
    /// The attempt stays in reconciliation. It does not become a retry, and
    /// it does not become a success.
    Unsupported,
}

/// One settlement rail.
///
/// Implementations must not perform a network write directly. Every write
/// goes through [`DispatchContext::run_write`], which commits the dispatch
/// stamp first, so a process that dies mid-call leaves a record that says a
/// write may have landed.
#[async_trait::async_trait]
pub trait PaymentMethodAdapter: Send + Sync {
    /// Returns the rail this adapter settles.
    fn rail(&self) -> SettlementRail;

    /// Creates the provider object the challenge needs.
    ///
    /// This must not capture funds, call the origin, deliver the resource,
    /// or emit a receipt. A rail with nothing to create returns
    /// [`ChallengeMaterial::new`] with no handle.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] describing the redacted failure.
    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError>;

    /// Performs the rail's required verification and settlement.
    ///
    /// Returning `Ok` asserts that the rail reached its authoritative
    /// settled state. Verified but not settled is
    /// [`BillingError::NotSettled`], not a receipt.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] describing the redacted failure.
    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError>;

    /// Asks the provider what happened to an outstanding attempt.
    ///
    /// This is a read. It must not create, confirm, capture, or retry
    /// anything.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] describing the redacted failure.
    async fn query_attempt(
        &self,
        attempt: &ProviderAttempt,
        dispatch: &DispatchContext,
    ) -> Result<ProviderQueryResult, BillingError>;
}

/// One unit of usage to report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEvent {
    /// The reporter that owns this event.
    pub reporter: String,
    /// The caller's deduplication identifier, unique per reporter.
    pub usage_identifier: String,
    /// The tenant the usage belongs to.
    pub tenant_id: String,
    /// The origin the usage belongs to.
    pub origin_id: String,
    /// The provider's event name.
    pub event_name: String,
    /// The quantity, in whole units.
    pub quantity: u64,
    /// When the usage occurred, in milliseconds since the epoch.
    pub occurred_at_ms: i64,
    /// Non-secret attributes the reporter passes through.
    pub attributes: BTreeMap<String, String>,
}

/// Proof that a reporter accepted a usage event.
///
/// This is not a payment receipt and cannot become one. It has no rail, no
/// intent, and no settlement time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageReportReceipt {
    /// The reporter that accepted the event.
    pub reporter: String,
    /// The deduplication identifier that was accepted.
    pub usage_identifier: String,
    /// The provider's own reference, when it returned one.
    pub provider_reference: Option<String>,
    /// When the reporter accepted it, in milliseconds since the epoch.
    pub reported_at_ms: i64,
}

/// One usage reporter.
///
/// A reporter never authorizes anything. It cannot construct a
/// [`SettlementReceipt`], and the store refuses to settle an intent from a
/// meter-report attempt.
#[async_trait::async_trait]
pub trait UsageReporter: Send + Sync {
    /// Returns the stable name this reporter registers under.
    fn reporter_name(&self) -> &'static str;

    /// Reports one usage event.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] describing the redacted failure.
    async fn report(
        &self,
        event: &UsageEvent,
        dispatch: &DispatchContext,
    ) -> Result<UsageReportReceipt, BillingError>;
}

/// The compiled set of rails and reporters this process can use.
///
/// The two maps are separate namespaces. A rail name and a reporter name
/// never collide, and a duplicate in either one is rejected.
#[derive(Default)]
pub struct RailRegistry {
    adapters: HashMap<SettlementRail, Arc<dyn PaymentMethodAdapter>>,
    reporters: HashMap<String, Arc<dyn UsageReporter>>,
}

impl RailRegistry {
    /// Builds an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one settlement adapter.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::DuplicateAdapter`] when the rail is taken.
    pub fn register_adapter(
        &mut self,
        adapter: Arc<dyn PaymentMethodAdapter>,
    ) -> Result<(), BillingError> {
        let rail = adapter.rail();
        if self.adapters.contains_key(&rail) {
            return Err(BillingError::DuplicateAdapter(rail));
        }
        self.adapters.insert(rail, adapter);
        Ok(())
    }

    /// Registers one usage reporter.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::DuplicateReporter`] when the name is taken.
    pub fn register_reporter(
        &mut self,
        reporter: Arc<dyn UsageReporter>,
    ) -> Result<(), BillingError> {
        let name = reporter.reporter_name().to_string();
        if self.reporters.contains_key(&name) {
            return Err(BillingError::DuplicateReporter);
        }
        self.reporters.insert(name, reporter);
        Ok(())
    }

    /// Returns the adapter for a rail, if one is compiled and registered.
    pub fn adapter(&self, rail: SettlementRail) -> Option<Arc<dyn PaymentMethodAdapter>> {
        self.adapters.get(&rail).map(Arc::clone)
    }

    /// Returns the adapter for a rail, or names the missing cargo feature.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::AdapterNotRegistered`], whose rail carries
    /// [`SettlementRail::cargo_feature`] so startup can tell an operator
    /// exactly which feature to build with.
    pub fn require_adapter(
        &self,
        rail: SettlementRail,
    ) -> Result<Arc<dyn PaymentMethodAdapter>, BillingError> {
        self.adapter(rail)
            .ok_or(BillingError::AdapterNotRegistered(rail))
    }

    /// Returns the reporter registered under a name.
    pub fn reporter(&self, name: &str) -> Option<Arc<dyn UsageReporter>> {
        self.reporters.get(name).map(Arc::clone)
    }

    /// Returns the reporter registered under a name, or fails.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ReporterNotRegistered`].
    pub fn require_reporter(&self, name: &str) -> Result<Arc<dyn UsageReporter>, BillingError> {
        self.reporter(name)
            .ok_or(BillingError::ReporterNotRegistered)
    }

    /// Returns every registered rail, in a stable order.
    pub fn rails(&self) -> Vec<SettlementRail> {
        let mut rails: Vec<SettlementRail> = self.adapters.keys().copied().collect();
        rails.sort_by_key(|rail| rail.as_str());
        rails
    }

    /// Returns every registered reporter name, in a stable order.
    pub fn reporter_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.reporters.keys().cloned().collect();
        names.sort();
        names
    }

    /// Reports whether any adapter or reporter is registered.
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty() && self.reporters.is_empty()
    }
}

impl std::fmt::Debug for RailRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RailRegistry")
            .field("rails", &self.rails())
            .field("reporters", &self.reporter_names())
            .finish()
    }
}
