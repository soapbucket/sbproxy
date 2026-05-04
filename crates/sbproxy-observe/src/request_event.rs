// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! The `RequestEvent` envelope that the four Wave 8 P0 streams populate.
//!
//! Field set is locked by `docs/adr-event-envelope.md`. Stream-specific
//! refinements live in the companion ADRs (`adr-custom-properties.md`,
//! `adr-session-id.md`, `adr-user-id.md`). This module is the canonical
//! Rust shape; the protobuf wire format used by the ingest pipeline
//! mirrors it field-for-field.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

use crate::events::EventType;

/// Where the `user_id` envelope value was resolved from.
///
/// Stamped on every event whose `user_id` is set so ops can audit the
/// resolution path without reproducing the original headers and tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserIdSource {
    /// No user identity was resolved. The envelope's `user_id` field
    /// stays `None`; this variant only appears in metric labels and
    /// diagnostics.
    Anonymous,
    /// The caller supplied `X-Sb-User-Id` directly.
    Header,
    /// A JWT `sub` claim filled the value (verified by the auth provider).
    Jwt,
    /// A trusted upstream forward-auth gateway returned an authenticated
    /// user header (configurable name, defaults to `X-Authenticated-User`).
    ForwardAuth,
}

impl UserIdSource {
    /// Stable lowercase label. Matches the snake_case serde
    /// rename used by the envelope JSON / protobuf, so callers can
    /// stamp the value into Prometheus labels, CEL contexts, and
    /// audit logs without re-deriving it from the variant name.
    pub fn as_str(self) -> &'static str {
        match self {
            UserIdSource::Anonymous => "anonymous",
            UserIdSource::Header => "header",
            UserIdSource::Jwt => "jwt",
            UserIdSource::ForwardAuth => "forward_auth",
        }
    }
}

/// The canonical request envelope. One struct populated by all four
/// Wave 8 P0 streams (T1 properties, T2 sessions, T3 users, T4 ingest)
/// and consumed verbatim by the ingest pipeline.
///
/// Field semantics and caps live in the ADRs under `docs/adr-*.md`.
/// Adding a new top-level field is an envelope ADR amendment plus a
/// reserved protobuf field number; do not silently extend this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEvent {
    /// Generated at request entry (ULID, lexicographically time-sortable).
    /// Echoed to the client as `X-Sb-Request-Id` and trace-context.
    pub request_id: Ulid,

    /// Set when this request is a retry, replay, or sub-call inside an
    /// agent pattern. The portal reconstructs trees client-side.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_request_id: Option<Ulid>,

    /// Tenant key. Required in multi-tenant deployments; defaults to
    /// `"default"` in OSS single-tenant deployments.
    pub workspace_id: String,

    /// Origin hostname (matches `crate::events::ProxyEvent::hostname`).
    pub hostname: String,

    /// Unix epoch milliseconds at request start.
    pub timestamp_ms: u64,

    /// Wall-clock latency in milliseconds. Filled on
    /// `request_completed` / `request_error`; absent on
    /// `request_started`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub latency_ms: Option<u32>,

    /// Lifecycle discriminator.
    pub event_type: EventType,

    /// Per `adr-session-id.md`. ULID, optionally auto-generated for
    /// anonymous traffic when configured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<Ulid>,

    /// Per `adr-session-id.md`. Caller-supplied parent linkage; the
    /// proxy validates ULID format but does not check existence.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_session_id: Option<Ulid>,

    /// Per `adr-user-id.md`. Resolved via header / JWT / forward-auth
    /// precedence; subject to a length cap and per-workspace cardinality
    /// cap.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id: Option<String>,

    /// Where `user_id` was resolved from. Diagnostic field, never used
    /// as a metric label.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id_source: Option<UserIdSource>,

    /// Per `adr-custom-properties.md`. Lowercased keys, allowlist-checked,
    /// length-capped, redaction-applied. Empty map serializes as absent.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub properties: BTreeMap<String, String>,

    /// AI provider chosen (`openai`, `anthropic`, ...). Empty for
    /// non-AI traffic.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider: Option<String>,

    /// Model name. Empty for non-AI traffic.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,

    /// Prompt tokens (AI requests only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tokens_in: Option<u32>,

    /// Completion tokens (AI requests only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tokens_out: Option<u32>,

    /// Provider cache hit tokens (Anthropic prompt cache et al).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tokens_cached: Option<u32>,

    /// Estimated cost in micro-USD (1e-6 USD). Integer to keep
    /// ClickHouse aggregation exact.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cost_usd_micros: Option<u64>,

    /// HTTP status returned to the client.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub status_code: Option<u16>,

    /// Set when `event_type == RequestError`. Machine-readable class
    /// (`upstream_5xx`, `policy_blocked`, `auth_denied`, etc.).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error_class: Option<String>,

    /// ISO-3166-1 alpha-2 country (filled by geo enrichment when
    /// configured; see PORTAL.md gap 3.1 P2).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_geo: Option<String>,
}

impl RequestEvent {
    /// Build a fresh `RequestStarted` event with the current wall clock.
    /// Callers fill the optional dimensions (session, user, properties,
    /// AI fields) via direct field assignment after construction.
    pub fn new_started(hostname: String, request_id: Ulid, workspace_id: String) -> Self {
        Self {
            request_id,
            parent_request_id: None,
            workspace_id,
            hostname,
            timestamp_ms: now_millis(),
            latency_ms: None,
            event_type: EventType::RequestStarted,
            session_id: None,
            parent_session_id: None,
            user_id: None,
            user_id_source: None,
            properties: BTreeMap::new(),
            provider: None,
            model: None,
            tokens_in: None,
            tokens_out: None,
            tokens_cached: None,
            cost_usd_micros: None,
            status_code: None,
            error_class: None,
            request_geo: None,
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> RequestEvent {
        let mut props = BTreeMap::new();
        props.insert("environment".to_string(), "prod".to_string());
        props.insert("feature-flag".to_string(), "agent-v2".to_string());

        RequestEvent {
            request_id: Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
            parent_request_id: Some(Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAW").unwrap()),
            workspace_id: "ws_test".to_string(),
            hostname: "api.example.com".to_string(),
            timestamp_ms: 1_700_000_000_000,
            latency_ms: Some(120),
            event_type: EventType::RequestCompleted,
            session_id: Some(Ulid::from_string("01HQRP1KJVH3JPCJ8SAVAV6F4Z").unwrap()),
            parent_session_id: None,
            user_id: Some("user_42".to_string()),
            user_id_source: Some(UserIdSource::Header),
            properties: props,
            provider: Some("openai".to_string()),
            model: Some("gpt-4o".to_string()),
            tokens_in: Some(800),
            tokens_out: Some(150),
            tokens_cached: Some(200),
            cost_usd_micros: Some(4_500),
            status_code: Some(200),
            error_class: None,
            request_geo: Some("US".to_string()),
        }
    }

    #[test]
    fn new_started_populates_required_fields_and_leaves_optional_unset() {
        let id = Ulid::new();
        let ev =
            RequestEvent::new_started("api.example.com".to_string(), id, "ws_test".to_string());

        assert_eq!(ev.request_id, id);
        assert_eq!(ev.event_type, EventType::RequestStarted);
        assert_eq!(ev.hostname, "api.example.com");
        assert_eq!(ev.workspace_id, "ws_test");
        assert!(ev.timestamp_ms > 0);
        assert!(ev.session_id.is_none());
        assert!(ev.user_id.is_none());
        assert!(ev.properties.is_empty());
    }

    #[test]
    fn json_roundtrip_kitchen_sink() {
        let original = sample_event();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: RequestEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.parent_request_id, original.parent_request_id);
        assert_eq!(decoded.workspace_id, original.workspace_id);
        assert_eq!(decoded.session_id, original.session_id);
        assert_eq!(decoded.user_id, original.user_id);
        assert_eq!(decoded.user_id_source, original.user_id_source);
        assert_eq!(decoded.properties, original.properties);
        assert_eq!(decoded.cost_usd_micros, original.cost_usd_micros);
        assert_eq!(decoded.tokens_cached, original.tokens_cached);
    }

    #[test]
    fn unset_optionals_are_absent_from_json() {
        let ev = RequestEvent::new_started("h".to_string(), Ulid::new(), "ws".to_string());
        let json = serde_json::to_string(&ev).expect("serialize");

        // Optional fields default to `None` and should not appear in
        // the JSON payload (serde `skip_serializing_if = Option::is_none`).
        assert!(!json.contains("session_id"));
        assert!(!json.contains("user_id"));
        assert!(!json.contains("provider"));
        assert!(!json.contains("model"));
        assert!(!json.contains("tokens_in"));
        assert!(!json.contains("cost_usd_micros"));
        assert!(!json.contains("error_class"));
        assert!(!json.contains("request_geo"));
        assert!(!json.contains("properties")); // empty map skipped
                                               // Required fields ARE present.
        assert!(json.contains("request_id"));
        assert!(json.contains("workspace_id"));
        assert!(json.contains("hostname"));
        assert!(json.contains("timestamp_ms"));
        assert!(json.contains("event_type"));
    }

    #[test]
    fn event_type_serializes_snake_case() {
        let ev = RequestEvent {
            event_type: EventType::RequestError,
            ..RequestEvent::new_started("h".to_string(), Ulid::new(), "ws".to_string())
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"request_error\""));
    }

    #[test]
    fn user_id_source_serializes_snake_case() {
        let ev = RequestEvent {
            user_id: Some("u".to_string()),
            user_id_source: Some(UserIdSource::ForwardAuth),
            ..RequestEvent::new_started("h".to_string(), Ulid::new(), "ws".to_string())
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"forward_auth\""));
    }
}
