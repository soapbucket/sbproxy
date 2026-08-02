//! Shared fixtures for the settlement tests.
//!
//! Nothing here talks to a network or a real provider. The fixture adapter
//! records what it was asked to do and answers exactly what the test told it
//! to, which is what lets a test assert that a provider was called once and
//! never again.

// Each integration test binary uses a different subset of these fixtures, and
// an unused fixture in one binary is not dead code in the suite.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sbproxy_billing::dispatch::DispatchContext;
use sbproxy_billing::error::BillingError;
use sbproxy_billing::money::Money;
use sbproxy_billing::registry::{
    AuthoritativePayment, ChallengeMaterial, ChallengePreparation, PaymentMethodAdapter,
    ProviderQueryResult, UsageEvent, UsageReportReceipt, UsageReporter,
};
use sbproxy_billing::service::RequirementSigner;
use sbproxy_billing::store::{BillingClock, ProviderAttempt};
use sbproxy_billing::types::{
    AdvertisedRail, FailureCategory, PaymentProtocol, PaymentRequirement, PaymentRequirementDraft,
    RequirementTerms, SafeFailure, SettlementRail, SettlementReceipt, SignedPaymentRequirement,
};

/// Fails a test with a message instead of requiring `Debug` on the success
/// type, which would mean deriving `Debug` on types that hold credentials.
#[track_caller]
pub fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Fails a test with a message instead of requiring `Debug` on the error type.
#[track_caller]
pub fn expect_ok<T, E>(result: Result<T, E>, message: &str) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("{message}"),
    }
}

/// A clock the test moves by hand.
#[derive(Debug)]
pub struct TestClock {
    now_ms: AtomicI64,
}

impl TestClock {
    /// Starts a clock at a fixed instant.
    pub fn new(now_ms: i64) -> Arc<Self> {
        Arc::new(Self {
            now_ms: AtomicI64::new(now_ms),
        })
    }

    /// Moves the clock forward.
    pub fn advance(&self, delta_ms: i64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl BillingClock for TestClock {
    fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// What the fixture adapter does when it is asked to settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Behavior {
    /// Dispatch, then return a real receipt.
    #[default]
    Settle,
    /// Dispatch, then report an authoritative refusal.
    Reject,
    /// Dispatch, then report verified but not settled.
    NotSettled,
    /// Dispatch, then report an unparseable response.
    Malformed,
    /// Dispatch, then never answer.
    Hang,
    /// Refuse before dispatching, the way an open breaker does.
    BreakerOpen,
    /// Dispatch, then return a receipt that belongs to another intent.
    ForeignReceipt,
}

/// What the fixture adapter answers when it is asked to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryPlan {
    /// The provider proves the payment settled.
    Settled,
    /// The provider proves the write never landed.
    NotDispatched,
    /// The provider has it and it is unresolved.
    StillPending,
    /// The provider proves it failed.
    Failed,
    /// The rail cannot answer.
    #[default]
    Unsupported,
    /// The query itself fails.
    Error,
}

/// Everything the fixture adapter recorded, shared with the test.
#[derive(Debug, Default)]
pub struct FixtureState {
    /// How many times `authorize_and_settle` was entered.
    pub settle_calls: AtomicUsize,
    /// How many times the guarded provider write actually ran.
    pub provider_writes: AtomicUsize,
    /// How many times `prepare_challenge` was entered.
    pub prepare_calls: AtomicUsize,
    /// How many times `query_attempt` was entered.
    pub query_calls: AtomicUsize,
    /// Every provider idempotency key the adapter was handed, in order.
    pub keys: Mutex<Vec<String>>,
    /// Every provider handle a query was pointed at, in order.
    pub queried_handles: Mutex<Vec<Option<String>>>,
    /// What to do on the next settlement.
    pub behavior: Mutex<Behavior>,
    /// What to answer on the next query.
    pub query_plan: Mutex<QueryPlan>,
    /// The provider reference a successful settlement reports.
    pub provider_reference: Mutex<String>,
}

impl FixtureState {
    /// Builds shared state with the default behavior.
    pub fn new() -> Arc<Self> {
        let state = Self::default();
        *state.provider_reference.lock().expect("lock") = "pi_fixture_1".to_string();
        Arc::new(state)
    }

    /// Sets what the next settlement does.
    pub fn set_behavior(&self, behavior: Behavior) {
        *self.behavior.lock().expect("lock") = behavior;
    }

    /// Sets what the next query answers.
    pub fn set_query_plan(&self, plan: QueryPlan) {
        *self.query_plan.lock().expect("lock") = plan;
    }

    /// Returns how many settlements were entered.
    pub fn settle_calls(&self) -> usize {
        self.settle_calls.load(Ordering::SeqCst)
    }

    /// Returns how many guarded provider writes actually ran.
    pub fn provider_writes(&self) -> usize {
        self.provider_writes.load(Ordering::SeqCst)
    }

    /// Returns how many queries were entered.
    pub fn query_calls(&self) -> usize {
        self.query_calls.load(Ordering::SeqCst)
    }

    /// Returns every provider idempotency key the adapter saw.
    pub fn keys(&self) -> Vec<String> {
        self.keys.lock().expect("lock").clone()
    }

    /// Returns every provider handle a query was pointed at.
    pub fn queried_handles(&self) -> Vec<Option<String>> {
        self.queried_handles.lock().expect("lock").clone()
    }
}

/// A rail adapter that records everything and invents nothing.
pub struct FixtureAdapter {
    rail: SettlementRail,
    state: Arc<FixtureState>,
}

impl FixtureAdapter {
    /// Builds an adapter over shared recording state.
    pub fn new(rail: SettlementRail, state: Arc<FixtureState>) -> Arc<Self> {
        Arc::new(Self { rail, state })
    }
}

#[async_trait::async_trait]
impl PaymentMethodAdapter for FixtureAdapter {
    fn rail(&self) -> SettlementRail {
        self.rail
    }

    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError> {
        self.state.prepare_calls.fetch_add(1, Ordering::SeqCst);
        let state = Arc::clone(&self.state);
        let key = dispatch.provider_idempotency_key().to_string();
        dispatch
            .run_write(|| async move {
                state.keys.lock().expect("lock").push(key);
                state.provider_writes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await?;
        Ok(ChallengeMaterial::new(Some(format!(
            "handle_{}",
            request.draft.requirement_id
        ))))
    }

    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError> {
        self.state.settle_calls.fetch_add(1, Ordering::SeqCst);
        let behavior = *self.state.behavior.lock().expect("lock");
        if behavior == Behavior::BreakerOpen {
            // An open breaker refuses before anything is dispatched, which is
            // the one failure that leaves a retry provably safe.
            return Err(BillingError::ProviderUnavailable);
        }

        let state = Arc::clone(&self.state);
        let key = dispatch.provider_idempotency_key().to_string();
        let intent_id = request.intent_id.clone();
        let rail = self.rail;
        let now_ms = request.now_ms;
        dispatch
            .run_write(|| async move {
                state.keys.lock().expect("lock").push(key);
                state.provider_writes.fetch_add(1, Ordering::SeqCst);
                match behavior {
                    Behavior::Settle => {
                        let reference = state.provider_reference.lock().expect("lock").clone();
                        SettlementReceipt::new(&intent_id, rail, "stripe", &reference, now_ms)
                    }
                    Behavior::ForeignReceipt => SettlementReceipt::new(
                        "sbpi_someone_else",
                        rail,
                        "stripe",
                        "pi_other",
                        now_ms,
                    ),
                    Behavior::Reject => Err(BillingError::ProviderRejected),
                    Behavior::NotSettled => Err(BillingError::NotSettled),
                    Behavior::Malformed => Err(BillingError::ProviderMalformed),
                    Behavior::Hang => std::future::pending().await,
                    Behavior::BreakerOpen => Err(BillingError::ProviderUnavailable),
                }
            })
            .await
    }

    async fn query_attempt(
        &self,
        attempt: &ProviderAttempt,
        _dispatch: &DispatchContext,
    ) -> Result<ProviderQueryResult, BillingError> {
        self.state.query_calls.fetch_add(1, Ordering::SeqCst);
        self.state
            .queried_handles
            .lock()
            .expect("lock")
            .push(attempt.provider_handle.clone());
        self.state
            .keys
            .lock()
            .expect("lock")
            .push(attempt.provider_idempotency_key.clone());

        let plan = *self.state.query_plan.lock().expect("lock");
        match plan {
            QueryPlan::Settled => {
                let reference = self.state.provider_reference.lock().expect("lock").clone();
                Ok(ProviderQueryResult::Settled(SettlementReceipt::new(
                    &attempt.intent_id,
                    attempt.rail,
                    "stripe",
                    &reference,
                    1_700_000_500_000,
                )?))
            }
            QueryPlan::NotDispatched => Ok(ProviderQueryResult::NotDispatched),
            QueryPlan::StillPending => Ok(ProviderQueryResult::StillPending),
            QueryPlan::Failed => Ok(ProviderQueryResult::Failed(SafeFailure::category(
                FailureCategory::Rejected,
                false,
            ))),
            QueryPlan::Unsupported => Ok(ProviderQueryResult::Unsupported),
            QueryPlan::Error => Err(BillingError::ProviderUnavailable),
        }
    }
}

/// A usage reporter that records and never authorizes anything.
pub struct FixtureReporter {
    state: Arc<FixtureState>,
    fail: bool,
}

impl FixtureReporter {
    /// Builds a reporter that accepts every event.
    pub fn new(state: Arc<FixtureState>) -> Arc<Self> {
        Arc::new(Self { state, fail: false })
    }

    /// Builds a reporter that fails every event.
    pub fn failing(state: Arc<FixtureState>) -> Arc<Self> {
        Arc::new(Self { state, fail: true })
    }
}

#[async_trait::async_trait]
impl UsageReporter for FixtureReporter {
    fn reporter_name(&self) -> &'static str {
        "fixture_meter"
    }

    async fn report(
        &self,
        event: &UsageEvent,
        dispatch: &DispatchContext,
    ) -> Result<UsageReportReceipt, BillingError> {
        let state = Arc::clone(&self.state);
        let key = dispatch.provider_idempotency_key().to_string();
        let identifier = event.usage_identifier.clone();
        let occurred_at_ms = event.occurred_at_ms;
        let fail = self.fail;
        dispatch
            .run_write(|| async move {
                state.keys.lock().expect("lock").push(key);
                state.provider_writes.fetch_add(1, Ordering::SeqCst);
                if fail {
                    return Err(BillingError::ProviderRejected);
                }
                Ok(UsageReportReceipt {
                    reporter: "fixture_meter".to_string(),
                    usage_identifier: identifier,
                    provider_reference: Some("mbe_fixture".to_string()),
                    reported_at_ms: occurred_at_ms,
                })
            })
            .await
    }
}

/// A quote signer that binds the final requirement digest and nothing else.
pub struct FixtureSigner;

impl FixtureSigner {
    /// Returns the token this signer produces for a digest.
    pub fn token_for(digest: &[u8; 32]) -> String {
        format!("quote.{}", hex::encode(digest))
    }
}

impl RequirementSigner for FixtureSigner {
    fn sign(
        &self,
        _requirement: &PaymentRequirement,
        requirement_digest: &[u8; 32],
    ) -> Result<String, BillingError> {
        Ok(Self::token_for(requirement_digest))
    }

    fn verify(&self, signed: &SignedPaymentRequirement) -> Result<(), BillingError> {
        if signed.quote_token == Self::token_for(&signed.requirement_digest) {
            Ok(())
        } else {
            Err(BillingError::DigestMismatch)
        }
    }
}

/// Builds a canonical x402 draft.
pub fn sample_draft(
    tenant_id: &str,
    requirement_id: &str,
    expires_at_ms: i64,
) -> PaymentRequirementDraft {
    let mut draft = PaymentRequirementDraft {
        requirement_id: requirement_id.to_string(),
        protocol: PaymentProtocol::X402V2,
        advertised_rail: AdvertisedRail::X402,
        settlement_rail: SettlementRail::X402,
        method: "exact".to_string(),
        intent: "charge".to_string(),
        network: Some("base-sepolia".to_string()),
        asset: Some("usdc".to_string()),
        pay_to: Some("0xrecipient".to_string()),
        amount: Money::new(10_000, "usd").expect("valid money"),
        settlement_amount: String::new(),
        settlement_decimals: 6,
        terms: RequirementTerms::X402Exact {
            facilitator_url: "https://facilitator.test.sbproxy.dev".to_string(),
            max_timeout_seconds: 60,
            extra: BTreeMap::new(),
        },
        quote_id: "quote-1".to_string(),
        tenant_id: tenant_id.to_string(),
        origin_id: "origin-1".to_string(),
        route: "/paid".to_string(),
        expires_at_ms,
        request_digest: None,
    };
    draft.canonicalize().expect("canonical draft");
    draft
}

/// Signs a draft the way `prepare_requirement` would, without a provider call.
pub fn sign_draft(
    draft: &PaymentRequirementDraft,
    provider_handle: Option<&str>,
) -> SignedPaymentRequirement {
    let draft_digest = draft.digest().expect("draft digest");
    let requirement = PaymentRequirement {
        draft: draft.clone(),
        provider_handle: provider_handle.map(str::to_string),
    };
    let requirement_digest = requirement.digest().expect("requirement digest");
    SignedPaymentRequirement {
        requirement,
        draft_digest,
        requirement_digest,
        quote_token: FixtureSigner::token_for(&requirement_digest),
    }
}
