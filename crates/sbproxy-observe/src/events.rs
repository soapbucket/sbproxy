use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A typed proxy event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEvent {
    /// Discriminator identifying which kind of proxy event this is.
    pub event_type: EventType,
    /// Hostname (origin) the event is associated with.
    pub hostname: String,
    /// Unix epoch timestamp in milliseconds when the event was produced.
    pub timestamp: u64, // Unix millis
    /// Free-form JSON payload carrying event-specific data.
    pub data: serde_json::Value,
}

/// Enumeration of proxy event types emitted on the event bus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Event name `request_started`. A new request has begun processing.
    RequestStarted,
    /// Event name `request_completed`. A request finished successfully.
    RequestCompleted,
    /// Event name `request_error`. A request terminated with an error.
    RequestError,
    /// Event name `auth_denied`. Authentication rejected the request.
    AuthDenied,
    /// Event name `policy_denied`. A policy (rate limit, ACL, WAF) blocked the request.
    PolicyDenied,
    /// Event name `cache_hit`. A response was served from cache.
    CacheHit,
    /// Event name `cache_miss`. The cache lookup did not find a usable entry.
    CacheMiss,
    /// Event name `provider_selected`. An AI provider was chosen for routing.
    ProviderSelected,
    /// Event name `budget_exceeded`. A spending or quota budget was exhausted.
    BudgetExceeded,
    /// Event name `guardrail_triggered`. An AI guardrail flagged or blocked content.
    GuardrailTriggered,
    /// Event name `config_reloaded`. The proxy configuration was reloaded.
    ConfigReloaded,
}

/// Event subscriber callback type.
pub type EventHandler = Box<dyn Fn(&ProxyEvent) + Send + Sync>;

/// Event bus for publishing and subscribing to proxy events.
pub struct EventBus {
    handlers: Mutex<HashMap<EventType, Vec<Arc<EventHandler>>>>,
}

impl EventBus {
    /// Create a new empty event bus.
    pub fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to events of a specific type.
    pub fn subscribe(&self, event_type: EventType, handler: EventHandler) {
        let mut handlers = self.handlers.lock().unwrap();
        handlers
            .entry(event_type)
            .or_default()
            .push(Arc::new(handler));
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: &ProxyEvent) {
        let handlers = self.handlers.lock().unwrap();
        if let Some(subscribers) = handlers.get(&event.event_type) {
            for handler in subscribers {
                handler(event);
            }
        }
    }

    /// Number of subscribers for an event type.
    pub fn subscriber_count(&self, event_type: &EventType) -> usize {
        let handlers = self.handlers.lock().unwrap();
        handlers.get(event_type).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_event(event_type: EventType) -> ProxyEvent {
        ProxyEvent {
            event_type,
            hostname: "example.com".to_string(),
            timestamp: 1700000000000,
            data: serde_json::json!({"key": "value"}),
        }
    }

    #[test]
    fn test_subscribe_and_publish() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        bus.subscribe(
            EventType::RequestStarted,
            Box::new(move |_event| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let event = make_event(EventType::RequestStarted);
        bus.publish(&event);
        bus.publish(&event);

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU64::new(0));

        for _ in 0..3 {
            let c = counter.clone();
            bus.subscribe(
                EventType::CacheHit,
                Box::new(move |_event| {
                    c.fetch_add(1, Ordering::SeqCst);
                }),
            );
        }

        bus.publish(&make_event(EventType::CacheHit));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_no_subscriber_no_crash() {
        let bus = EventBus::new();
        // Publishing with no subscribers should not panic.
        bus.publish(&make_event(EventType::AuthDenied));
    }

    #[test]
    fn test_subscriber_count() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(&EventType::RequestStarted), 0);

        bus.subscribe(EventType::RequestStarted, Box::new(|_| {}));
        assert_eq!(bus.subscriber_count(&EventType::RequestStarted), 1);

        bus.subscribe(EventType::RequestStarted, Box::new(|_| {}));
        assert_eq!(bus.subscriber_count(&EventType::RequestStarted), 2);

        // Different event type is still 0.
        assert_eq!(bus.subscriber_count(&EventType::ConfigReloaded), 0);
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let event = make_event(EventType::GuardrailTriggered);
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ProxyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hostname, "example.com");
        assert_eq!(deserialized.event_type, EventType::GuardrailTriggered);
        assert_eq!(deserialized.timestamp, 1700000000000);
    }

    #[test]
    fn test_event_type_serialization() {
        let variants = vec![
            (EventType::RequestStarted, "\"request_started\""),
            (EventType::RequestCompleted, "\"request_completed\""),
            (EventType::RequestError, "\"request_error\""),
            (EventType::AuthDenied, "\"auth_denied\""),
            (EventType::PolicyDenied, "\"policy_denied\""),
            (EventType::CacheHit, "\"cache_hit\""),
            (EventType::CacheMiss, "\"cache_miss\""),
            (EventType::ProviderSelected, "\"provider_selected\""),
            (EventType::BudgetExceeded, "\"budget_exceeded\""),
            (EventType::GuardrailTriggered, "\"guardrail_triggered\""),
            (EventType::ConfigReloaded, "\"config_reloaded\""),
        ];

        for (variant, expected) in variants {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "Failed for {:?}", variant);
            let deserialized: EventType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    #[test]
    fn test_different_event_types_isolated() {
        let bus = EventBus::new();
        let started_count = Arc::new(AtomicU64::new(0));
        let error_count = Arc::new(AtomicU64::new(0));

        let sc = started_count.clone();
        bus.subscribe(
            EventType::RequestStarted,
            Box::new(move |_| {
                sc.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let ec = error_count.clone();
        bus.subscribe(
            EventType::RequestError,
            Box::new(move |_| {
                ec.fetch_add(1, Ordering::SeqCst);
            }),
        );

        bus.publish(&make_event(EventType::RequestStarted));
        assert_eq!(started_count.load(Ordering::SeqCst), 1);
        assert_eq!(error_count.load(Ordering::SeqCst), 0);

        bus.publish(&make_event(EventType::RequestError));
        assert_eq!(started_count.load(Ordering::SeqCst), 1);
        assert_eq!(error_count.load(Ordering::SeqCst), 1);
    }
}
