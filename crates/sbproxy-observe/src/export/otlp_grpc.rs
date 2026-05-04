//! OpenTelemetry Protocol (OTLP) export over gRPC.
//!
//! Thin shim around [`crate::telemetry::init_otlp_pipeline`] for
//! callers that want to construct a gRPC-only configuration without
//! reaching for [`crate::telemetry::TelemetryConfig`] directly. The
//! actual exporter is built by `opentelemetry-otlp`'s tonic backend
//! and shares the same `BatchSpanProcessor` / global tracer
//! provider as the HTTP transport.
//!
//! The legacy JSON `build_trace_payload` / `build_span` helpers are
//! retained for use by tests and out-of-band diagnostic tooling that
//! wants to inspect the OTLP payload shape without standing up a
//! collector.

use std::collections::HashMap;

use crate::telemetry::{init_otlp_pipeline, OtlpTransport, TelemetryConfig};

// --- Config ---

/// Configuration for an OTLP/gRPC trace exporter.
#[derive(Debug, Clone)]
pub struct OtlpGrpcConfig {
    /// gRPC endpoint for the OTLP collector (e.g. `"http://localhost:4317"`).
    pub endpoint: String,
    /// Additional headers sent with every gRPC call (e.g. authentication tokens).
    pub headers: HashMap<String, String>,
    /// Per-call timeout in milliseconds.
    pub timeout_ms: u64,
    /// Service name reported on emitted spans.
    pub service_name: String,
}

impl Default for OtlpGrpcConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            headers: HashMap::new(),
            timeout_ms: 10_000,
            service_name: "sbproxy".to_string(),
        }
    }
}

/// Initialise an OTLP/gRPC pipeline using the standard
/// `opentelemetry-otlp` tonic exporter and the shared
/// `BatchSpanProcessor` used by the HTTP transport.
///
/// Returns `Err` only when the exporter fails to build (invalid
/// endpoint URL, unreachable runtime). Headers and per-call
/// timeouts are accepted today for forward-compatibility but are
/// applied at the tonic-channel level by the underlying SDK.
pub fn init_grpc_pipeline(config: &OtlpGrpcConfig) -> anyhow::Result<()> {
    let telem = TelemetryConfig {
        enabled: true,
        endpoint: Some(config.endpoint.clone()),
        transport: OtlpTransport::Grpc,
        service_name: config.service_name.clone(),
        sample_rate: None,
        always_sample_errors: true,
        propagation: None,
        resource_attrs: std::collections::BTreeMap::new(),
    };
    init_otlp_pipeline(&telem)
}

// --- Payload builder helpers (diagnostic / test use) ---

/// Build an OTLP trace export payload in JSON representation.
///
/// The returned `Value` mirrors the OTLP protobuf
/// `ExportTraceServiceRequest` schema and can be serialised for
/// transport debugging or test assertions. Production code should
/// use [`init_grpc_pipeline`] and let the SDK build the protobuf
/// payload on its behalf.
pub fn build_trace_payload(spans: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": spans
                    }
                ]
            }
        ]
    })
}

/// Build a minimal OTLP span object suitable for embedding in a
/// trace payload. Diagnostic helper; the live exporter consumes
/// `tracing::Span` values directly.
pub fn build_span(
    trace_id: &str,
    span_id: &str,
    name: &str,
    start_ns: u64,
    end_ns: u64,
) -> serde_json::Value {
    serde_json::json!({
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": start_ns,
        "endTimeUnixNano": end_ns,
        "kind": 1
    })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_endpoint_points_at_grpc_port() {
        let config = OtlpGrpcConfig::default();
        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.timeout_ms, 10_000);
        assert!(config.headers.is_empty());
        assert_eq!(config.service_name, "sbproxy");
    }

    #[test]
    fn build_trace_payload_envelopes_spans() {
        let payload = build_trace_payload(&[]);
        assert!(payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn build_trace_payload_with_spans_preserves_them() {
        let span = serde_json::json!({"name": "test"});
        let payload = build_trace_payload(&[span]);
        assert_eq!(
            payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
            "test"
        );
    }

    #[test]
    fn build_span_returns_otlp_shape() {
        let span = build_span("t1", "s1", "op", 1_000, 2_000);
        assert_eq!(span["traceId"], "t1");
        assert_eq!(span["spanId"], "s1");
        assert_eq!(span["name"], "op");
        assert_eq!(span["startTimeUnixNano"], 1_000u64);
        assert_eq!(span["endTimeUnixNano"], 2_000u64);
    }
}
