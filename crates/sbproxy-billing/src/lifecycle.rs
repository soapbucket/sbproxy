//! Rail-neutral payment lifecycle observation.
//!
//! A `started` event is the only event allowed to return an enforcing
//! decision. Terminal events are synchronous, observe-only notifications so
//! the billing path can hand them to a lossy queue without awaiting a hook.

use std::sync::Arc;

use crate::types::PaymentRequirementDraft;

const MAX_LABEL_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 128;

/// Stage of an authoritative payment operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentLifecyclePhase {
    /// A payment challenge is being prepared.
    Challenge,
    /// Payment evidence is being verified.
    Verify,
    /// A verified payment is being settled.
    Settle,
    /// An uncertain attempt is being reconciled.
    Reconcile,
}

/// Bounded result of a payment lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentLifecycleOutcome {
    /// The operation has not performed its protected effect.
    Started,
    /// The operation completed successfully.
    Succeeded,
    /// The operation was conclusively rejected.
    Rejected,
    /// The operation failed before an irreversible provider write.
    Failed,
    /// The operation may have performed an irreversible provider write.
    Ambiguous,
    /// The rail cannot perform the operation.
    Unsupported,
}

/// Decision returned for a payment lifecycle `started` event.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentLifecycleDecision {
    /// Continue the payment operation.
    #[default]
    Continue,
    /// Reject the payment operation before its protected effect.
    Reject,
}

/// Credential-free payment lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentLifecycleEvent {
    phase: PaymentLifecyclePhase,
    outcome: PaymentLifecycleOutcome,
    rail: String,
    method: Option<String>,
    network: Option<String>,
    asset: Option<String>,
    amount_micros: u64,
    currency: String,
    intent_id: String,
    request_id: Option<String>,
    provider_reference: Option<String>,
}

/// Completes a started lifecycle event even when an async operation exits
/// early or its future is cancelled.
pub(crate) struct PaymentLifecycleCompletion {
    observer: Arc<dyn PaymentLifecycleObserver>,
    event: Option<PaymentLifecycleEvent>,
    fallback: PaymentLifecycleOutcome,
}

impl PaymentLifecycleCompletion {
    pub(crate) fn new(
        observer: Arc<dyn PaymentLifecycleObserver>,
        event: PaymentLifecycleEvent,
        fallback: PaymentLifecycleOutcome,
    ) -> Self {
        Self {
            observer,
            event: Some(event),
            fallback,
        }
    }

    pub(crate) fn set_fallback(&mut self, fallback: PaymentLifecycleOutcome) {
        self.fallback = fallback;
    }

    pub(crate) fn terminal(&mut self, outcome: PaymentLifecycleOutcome) {
        if let Some(event) = self.event.take() {
            self.observer.terminal(event.with_outcome(outcome));
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.event = None;
    }
}

impl Drop for PaymentLifecycleCompletion {
    fn drop(&mut self) {
        self.terminal(self.fallback);
    }
}

impl PaymentLifecycleEvent {
    pub(crate) fn from_draft(
        phase: PaymentLifecyclePhase,
        outcome: PaymentLifecycleOutcome,
        intent_id: &str,
        draft: &PaymentRequirementDraft,
    ) -> Self {
        Self {
            phase,
            outcome,
            rail: draft.advertised_rail.as_str().to_owned(),
            method: bounded_label(&draft.method),
            network: draft.network.as_deref().and_then(bounded_value),
            asset: draft.asset.as_deref().and_then(bounded_value),
            amount_micros: draft.amount.amount_micros,
            currency: draft.amount.currency.clone(),
            intent_id: bounded_value(intent_id).unwrap_or_else(|| "redacted".to_owned()),
            request_id: bounded_value(&draft.requirement_id),
            provider_reference: None,
        }
    }

    pub(crate) fn with_outcome(mut self, outcome: PaymentLifecycleOutcome) -> Self {
        self.outcome = outcome;
        if outcome != PaymentLifecycleOutcome::Succeeded {
            self.provider_reference = None;
        }
        self
    }

    pub(crate) fn with_phase(mut self, phase: PaymentLifecyclePhase) -> Self {
        self.phase = phase;
        self
    }

    pub(crate) fn with_provider_reference(mut self, provider_reference: &str) -> Self {
        if self.outcome == PaymentLifecycleOutcome::Succeeded {
            self.provider_reference = bounded_value(provider_reference);
        }
        self
    }

    /// Return the lifecycle stage.
    pub const fn phase(&self) -> PaymentLifecyclePhase {
        self.phase
    }

    /// Return the bounded lifecycle outcome.
    pub const fn outcome(&self) -> PaymentLifecycleOutcome {
        self.outcome
    }

    /// Return the advertised payment rail.
    pub fn rail(&self) -> &str {
        &self.rail
    }

    /// Return the bounded payment method or scheme, when safe to expose.
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// Return the bounded settlement network, when present.
    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    /// Return the bounded settlement asset, when present.
    pub fn asset(&self) -> Option<&str> {
        self.asset.as_deref()
    }

    /// Return the amount in millionths of one major currency unit.
    pub const fn amount_micros(&self) -> u64 {
        self.amount_micros
    }

    /// Return the canonical uppercase currency code.
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Return the stable payment intent identifier.
    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }

    /// Return the bounded requirement or request identifier, when safe.
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Return a sanitized provider reference after durable success.
    pub fn provider_reference(&self) -> Option<&str> {
        self.provider_reference.as_deref()
    }
}

fn bounded_label(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        }))
    .then(|| value.to_owned())
}

fn bounded_value(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= MAX_VALUE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        }))
    .then(|| value.to_owned())
}

/// Observer installed on one immutable billing service generation.
#[async_trait::async_trait]
pub trait PaymentLifecycleObserver: Send + Sync {
    /// Inspect a `started` event before its protected effect.
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision;

    /// Observe a terminal event without awaiting extension work.
    fn terminal(&self, event: PaymentLifecycleEvent);
}

/// Observer used when a pipeline generation has no payment hooks.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpPaymentLifecycleObserver;

#[async_trait::async_trait]
impl PaymentLifecycleObserver for NoOpPaymentLifecycleObserver {
    async fn started(&self, _event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        PaymentLifecycleDecision::Continue
    }

    fn terminal(&self, _event: PaymentLifecycleEvent) {}
}
