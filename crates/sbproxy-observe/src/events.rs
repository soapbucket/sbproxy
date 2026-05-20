use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Policy decision audit event emitted on every policy evaluation.
///
/// Bound to the audit event bus (see
/// `crates/sbproxy-core/src/policy_bus.rs`) and consumed asynchronously
/// per `docs/adr-policy-audit-binding.md`. The OSS substrate ships an
/// in-memory drain stub; the enterprise consumer adds tamper-evident
/// chaining and KMS-signed Merkle root commits downstream of the bus.
///
/// The OSS payload is intentionally a subset of the full ADR shape:
/// it carries the fields a regulator-defensible audit trail can be
/// reconstructed from in the OSS context (request correlation, the
/// stable verdict tag, and a coarse decision latency). Enterprise
/// extends the payload with the rendered rationale, the Cedar policy
/// content hash, judge call summaries, redacted input contexts, and
/// W3C trace correlation; those fields are out of scope for OSS so
/// they are not declared here. The struct is `#[non_exhaustive]` so
/// adding them later does not break consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyVerdictEvent {
    /// Idempotency key for the consumer; one UUID v4 per policy
    /// decision.
    pub event_id: uuid::Uuid,
    /// Correlates to the access log entry and any traces.
    pub request_id: String,
    /// Tenant identifier the request belongs to. Empty string in the
    /// single-tenant OSS default.
    pub tenant_id: String,
    /// Workspace identifier the request belongs to. Empty string in
    /// the single-tenant OSS default.
    pub workspace_id: String,
    /// Wall-clock instant the verdict was rendered.
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Stable identifier for the policy that fired.
    ///
    /// In OSS scope this is the policy_type string from the policy
    /// (`rate_limit`, `waf`, `ip_filter`, ...); the full Cedar policy
    /// UUID is enterprise scope and lands on the same field once the
    /// enterprise policy registry is wired.
    pub policy_id: String,
    /// Built-in dispatch path versus dynamic-dispatch plugin path.
    pub surface: PolicySurface,
    /// Coarse verdict tag suitable for metrics labels.
    ///
    /// The full [`sbproxy_plugin::PolicyDecision`] payload (status
    /// code, message, header list, confirm reason, webhook URL,
    /// expiry) belongs to the enterprise audit envelope and is
    /// captured there. The OSS event keeps only the tag so dashboards
    /// and SIEM rules can break down by verdict shape without
    /// inheriting the cardinality of the full payload.
    pub verdict: VerdictTag,
    /// Wall-clock duration from entering the dispatcher to the
    /// verdict being produced, in milliseconds. Coarse on purpose;
    /// the enterprise event carries a microsecond-resolution
    /// duration and a histogram-friendly seconds-as-f64 sibling.
    pub decision_latency_ms: u32,
}

impl PolicyVerdictEvent {
    /// Construct a [`PolicyVerdictEvent`] with the supplied fields.
    ///
    /// `#[non_exhaustive]` blocks out-of-crate struct-literal
    /// construction so the dispatcher in `sbproxy-core` cannot
    /// build one with `Self { ... }`. This constructor is the
    /// supported entry point; future fields land here with
    /// sensible defaults so existing call sites stay green.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: uuid::Uuid,
        request_id: String,
        tenant_id: String,
        workspace_id: String,
        occurred_at: chrono::DateTime<chrono::Utc>,
        policy_id: String,
        surface: PolicySurface,
        verdict: VerdictTag,
        decision_latency_ms: u32,
    ) -> Self {
        Self {
            event_id,
            request_id,
            tenant_id,
            workspace_id,
            occurred_at,
            policy_id,
            surface,
            verdict,
            decision_latency_ms,
        }
    }
}

/// Surface a policy decision was rendered on.
///
/// `BuiltIn` covers the 21 built-in OSS policy variants that dispatch
/// through the enum-arm path in `check_policies`. `Plugin` covers
/// dynamic-dispatch plugins registered via the
/// [`sbproxy_plugin::PolicyEnforcer`] trait.
///
/// Marked `#[non_exhaustive]` so future surfaces (Cedar, CEL, Lua,
/// JS, WASM, webhook) the enterprise audit binding distinguishes can
/// extend this enum without breaking external consumers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PolicySurface {
    /// One of the 21 OSS built-in policy enum arms.
    BuiltIn,
    /// A dynamic-dispatch [`sbproxy_plugin::PolicyEnforcer`] impl.
    Plugin,
}

impl PolicySurface {
    /// Stable label suitable for use as a Prometheus metric label.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::Plugin => "plugin",
        }
    }
}

/// Coarse verdict tag carried on a [`PolicyVerdictEvent`].
///
/// Mirrors [`sbproxy_plugin::PolicyDecision`] one-to-one for the OSS
/// scope: the full payload is captured by the enterprise audit
/// envelope, the tag here is the dashboard-friendly label.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum VerdictTag {
    /// Allow with no header decoration.
    Allow,
    /// Deny with an HTTP status and message.
    Deny,
    /// Hold pending human approval. Routes through `AllowWithHeaders`
    /// in OSS with `X-Policy-Confirm` stamped on the response.
    Confirm,
    /// Allow with response-header decoration.
    AllowWithHeaders,
}

impl VerdictTag {
    /// Stable label suitable for use as a Prometheus metric label.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Confirm => "confirm",
            Self::AllowWithHeaders => "allow_with_headers",
        }
    }
}

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
        let mut handlers = self.handlers.lock();
        handlers
            .entry(event_type)
            .or_default()
            .push(Arc::new(handler));
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: &ProxyEvent) {
        let handlers = self.handlers.lock();
        if let Some(subscribers) = handlers.get(&event.event_type) {
            for handler in subscribers {
                handler(event);
            }
        }
    }

    /// Number of subscribers for an event type.
    pub fn subscriber_count(&self, event_type: &EventType) -> usize {
        let handlers = self.handlers.lock();
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
