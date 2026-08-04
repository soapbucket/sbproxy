//! Payment extension dispatch owned by one compiled pipeline generation.

use std::sync::Arc;

use sbproxy_observe::metrics::record_channel_drop;
use sbproxy_plugin::{
    PaymentExtensionDecision, PaymentExtensionEvent, PaymentExtensionOutcome, PaymentExtensionPhase,
};
use tokio::sync::mpsc;

use sbproxy_extension::bundle::PaymentExtensionChain;

use sbproxy_billing::{
    PaymentLifecycleDecision, PaymentLifecycleEvent, PaymentLifecycleObserver,
    PaymentLifecycleOutcome, PaymentLifecyclePhase,
};

/// Default number of terminal payment events retained for asynchronous dispatch.
const DEFAULT_TERMINAL_EVENT_CAPACITY: usize = 1_024;

/// Non-blocking sender for terminal payment extension events.
#[derive(Debug, Clone)]
struct TerminalEventQueue {
    sender: mpsc::Sender<QueuedPaymentEvent>,
}

#[derive(Debug)]
struct QueuedPaymentEvent {
    event: PaymentExtensionEvent,
    terminal: bool,
}

/// Runtime-specific dispatch for one payment extension event.
#[async_trait::async_trait]
pub trait PaymentEventDispatcher: Send + Sync {
    /// Await enforcing hooks before a payment operation starts.
    async fn enforce_started(&self, event: &PaymentExtensionEvent) -> PaymentExtensionDecision;

    /// Observe a started event without affecting the payment operation.
    async fn observe_started(&self, event: &PaymentExtensionEvent);

    /// Observe a terminal event after the authoritative outcome is known.
    async fn observe_terminal(&self, event: &PaymentExtensionEvent);
}

/// Concrete generation-pinned dispatcher for dynamic payment bundles.
pub struct BundlePaymentEventDispatcher {
    chain: PaymentExtensionChain,
}

impl BundlePaymentEventDispatcher {
    /// Wrap one immutable extension chain for the billing observer.
    #[must_use]
    pub const fn new(chain: PaymentExtensionChain) -> Self {
        Self { chain }
    }
}

#[async_trait::async_trait]
impl PaymentEventDispatcher for BundlePaymentEventDispatcher {
    async fn enforce_started(&self, event: &PaymentExtensionEvent) -> PaymentExtensionDecision {
        match self.chain.enforce_started(event).await {
            Ok(decision) => decision,
            Err(error) => {
                tracing::warn!(error = %error, "closed payment extension hook failed");
                PaymentExtensionDecision::Reject
            }
        }
    }

    async fn observe_started(&self, event: &PaymentExtensionEvent) {
        self.chain.observe_started(event).await;
    }

    async fn observe_terminal(&self, event: &PaymentExtensionEvent) {
        self.chain.observe_terminal(event).await;
    }
}

/// Billing observer that enforces `started` events and queues terminal events.
pub struct PaymentExtensionObserver {
    dispatcher: Arc<dyn PaymentEventDispatcher>,
    terminal: TerminalEventQueue,
}

impl PaymentExtensionObserver {
    /// Build an observer and start its generation-scoped terminal drain.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    #[must_use]
    pub fn new(dispatcher: Arc<dyn PaymentEventDispatcher>) -> Arc<Self> {
        let (terminal, receiver) = terminal_event_channel(DEFAULT_TERMINAL_EVENT_CAPACITY);
        tokio::spawn(drain_terminal_events(Arc::clone(&dispatcher), receiver));
        Arc::new(Self {
            dispatcher,
            terminal,
        })
    }
}

#[async_trait::async_trait]
impl PaymentLifecycleObserver for PaymentExtensionObserver {
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        let Some(event) = extension_event(event) else {
            return PaymentLifecycleDecision::Continue;
        };
        self.terminal.publish_started(event.clone());
        match self.dispatcher.enforce_started(&event).await {
            PaymentExtensionDecision::Continue => PaymentLifecycleDecision::Continue,
            PaymentExtensionDecision::Reject => PaymentLifecycleDecision::Reject,
        }
    }

    fn terminal(&self, event: PaymentLifecycleEvent) {
        if let Some(event) = extension_event(&event) {
            self.terminal.publish_terminal(event);
        }
    }
}

impl TerminalEventQueue {
    /// Enqueue a started observation when capacity is available.
    fn publish_started(&self, event: PaymentExtensionEvent) {
        self.publish(QueuedPaymentEvent {
            event,
            terminal: false,
        });
    }

    /// Enqueue a terminal observation when capacity is available.
    fn publish_terminal(&self, event: PaymentExtensionEvent) {
        self.publish(QueuedPaymentEvent {
            event,
            terminal: true,
        });
    }

    fn publish(&self, event: QueuedPaymentEvent) {
        if let Err(error) = self.sender.try_send(event) {
            let reason = match error {
                mpsc::error::TrySendError::Full(_) => "channel_full",
                mpsc::error::TrySendError::Closed(_) => "receiver_closed",
            };
            record_channel_drop("hooks", reason);
        }
    }
}

/// Construct the generation-scoped terminal event queue.
fn terminal_event_channel(
    capacity: usize,
) -> (TerminalEventQueue, mpsc::Receiver<QueuedPaymentEvent>) {
    let (sender, receiver) = mpsc::channel(capacity);
    (TerminalEventQueue { sender }, receiver)
}

async fn drain_terminal_events(
    dispatcher: Arc<dyn PaymentEventDispatcher>,
    mut receiver: mpsc::Receiver<QueuedPaymentEvent>,
) {
    while let Some(queued) = receiver.recv().await {
        if queued.terminal {
            dispatcher.observe_terminal(&queued.event).await;
        } else {
            dispatcher.observe_started(&queued.event).await;
        }
    }
}

fn extension_event(event: &PaymentLifecycleEvent) -> Option<PaymentExtensionEvent> {
    let mut builder = PaymentExtensionEvent::builder(
        extension_phase(event.phase()),
        extension_outcome(event.outcome()),
        event.rail(),
        event.amount_micros(),
        event.currency(),
    )
    .intent_id(event.intent_id());
    if let Some(method) = event.method() {
        builder = builder.method(method);
    }
    if let Some(network) = event.network() {
        builder = builder.network(network);
    }
    if let Some(asset) = event.asset() {
        builder = builder.asset(asset);
    }
    if let Some(request_id) = event.request_id() {
        builder = builder.request_id(request_id);
    }
    if let Some(provider_reference) = event.provider_reference() {
        builder = builder.provider_reference(provider_reference);
    }
    builder.build().ok()
}

const fn extension_phase(phase: PaymentLifecyclePhase) -> PaymentExtensionPhase {
    match phase {
        PaymentLifecyclePhase::Challenge => PaymentExtensionPhase::Challenge,
        PaymentLifecyclePhase::Verify => PaymentExtensionPhase::Verify,
        PaymentLifecyclePhase::Settle => PaymentExtensionPhase::Settle,
        PaymentLifecyclePhase::Reconcile => PaymentExtensionPhase::Reconcile,
    }
}

const fn extension_outcome(outcome: PaymentLifecycleOutcome) -> PaymentExtensionOutcome {
    match outcome {
        PaymentLifecycleOutcome::Started => PaymentExtensionOutcome::Started,
        PaymentLifecycleOutcome::Succeeded => PaymentExtensionOutcome::Succeeded,
        PaymentLifecycleOutcome::Rejected => PaymentExtensionOutcome::Rejected,
        PaymentLifecycleOutcome::Failed => PaymentExtensionOutcome::Failed,
        PaymentLifecycleOutcome::Ambiguous => PaymentExtensionOutcome::Ambiguous,
        PaymentLifecycleOutcome::Unsupported => PaymentExtensionOutcome::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_plugin::{PaymentExtensionEvent, PaymentExtensionOutcome, PaymentExtensionPhase};

    fn event(request_id: &str) -> PaymentExtensionEvent {
        PaymentExtensionEvent::builder(
            PaymentExtensionPhase::Settle,
            PaymentExtensionOutcome::Succeeded,
            "x402",
            1,
            "USD",
        )
        .request_id(request_id)
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn terminal_payment_events_preserve_order_and_fail_open_when_queue_is_full() {
        let (queue, mut receiver) = terminal_event_channel(1);
        let first = event("req_first");
        let dropped = event("req_dropped");

        queue.publish_terminal(first.clone());
        queue.publish_terminal(dropped);

        assert_eq!(receiver.recv().await.unwrap().event, first);
        assert!(receiver.try_recv().is_err());

        drop(receiver);
        queue.publish_terminal(event("req_closed"));
    }
}
