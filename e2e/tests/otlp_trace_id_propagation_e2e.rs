//! Inbound-traceparent-to-exported-span trace ID propagation e2e.
//!
//! The hand-rolled `ctx.trace_ctx` system (used for log correlation)
//! and the OTel-SDK-exported-span system never shared state, so a
//! request carrying an inbound `traceparent` still exported a span
//! rooted at a fresh random trace ID. `request_phase.rs` now captures
//! whether `trace_ctx` came from a genuine inbound header
//! (`ctx.trace_parent_is_remote`); `ai_dispatch.rs` reads that flag at
//! the point it creates the `ai.request` span and calls
//! `sbproxy_observe::telemetry::parent_span_on_remote_trace_context`
//! explicitly, request-scoped, no ambient/thread-local OTel state
//! involved. This spawns the real binary, sends a request with a known
//! `traceparent`, and asserts the exported span's trace ID matches it.

#[path = "otlp_span_arrival_common/mod.rs"]
mod common;

use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const KNOWN_TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const KNOWN_TRACE_ID_HEX: &str = "0af7651916cd43dd8448eb211c80319c";

fn config(upstream_base: &str, collector_endpoint: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  observability:
    telemetry:
      enabled: true
      endpoint: "{collector_endpoint}"
      transport: grpc
      sample_rate: 1.0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
"#
    )
}

#[test]
fn inbound_traceparent_matches_the_exported_span_trace_id() {
    // Only the async collector bootstrap and the final async poll run
    // inside block_on; the harness's blocking HTTP call runs in plain
    // sync scope. See otlp_shutdown_flush_e2e.rs for why (e2e/src/lib.rs
    // documents that building ProxyHarness's internal blocking reqwest
    // client while already inside a tokio runtime panics on drop).
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let collector = rt.block_on(common::start_grpc_collector());

    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-trace-propagation",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
    .expect("start mock upstream");

    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url(), &collector.endpoint))
        .expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let resp = harness
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &body,
            &[("traceparent", KNOWN_TRACEPARENT)],
        )
        .expect("chat completion request");
    assert_eq!(resp.status, 200);

    let trace_id = rt.block_on(common::wait_for_span_trace_id_hex(
        &collector,
        "ai.request",
        Duration::from_secs(12),
    ));
    let trace_id = trace_id.expect("ai.request span did not arrive");

    assert_eq!(
        trace_id, KNOWN_TRACE_ID_HEX,
        "exported span must share the caller's trace ID, not a fresh random root"
    );
}
