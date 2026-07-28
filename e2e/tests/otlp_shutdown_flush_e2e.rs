//! Graceful-shutdown OTLP smoke test.
//!
//! `shutdown_otlp_pipeline` existed but nothing in the binary called
//! it; `crates/sbproxy-core/src/server/lifecycle.rs` now calls it right
//! after `server.run(...)` returns, once Pingora has fully drained.
//!
//! This is NOT proof that the flush call specifically is what delivers
//! the span. `OutcomeSamplingSpanProcessor` (telemetry.rs) exports each
//! span immediately on completion via its own dedicated worker thread
//! and channel (`spawn_trace_export_worker`), not a batched queue that
//! accumulates until something flushes it. By the time this test calls
//! `terminate_gracefully`, the request's span has very likely already
//! been sent to, and accepted by, the collector through that normal
//! near-immediate path -- independent of the shutdown hook. This test
//! would very likely still pass even with the `shutdown_otlp_pipeline()`
//! call in `lifecycle.rs` reverted; reliably forcing a span to still be
//! in flight at the exact instant SIGTERM arrives is a race this test
//! does not attempt to win (and this codebase's export design makes
//! that race close to unwinnable without an artificial delay that
//! would make the test's own pass/fail flaky instead).
//!
//! What this test DOES prove: the real binary, with telemetry enabled
//! end to end (a real `ai_proxy` request against a real OTLP
//! collector), completes a request and then exits cleanly on SIGTERM
//! without losing, hanging on, or panicking over the span that request
//! produced. A shutdown-path panic or hang inside the OTLP teardown
//! would fail this test; a reverted flush call, on its own, would not.

#[path = "otlp_span_arrival_common/mod.rs"]
mod common;

use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

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
fn a_request_survives_a_graceful_shutdown_without_hanging_or_panicking() {
    // Only the async collector bootstrap and the final async poll run
    // inside block_on. ProxyHarness's blocking HTTP calls and
    // terminate_gracefully's blocking sleep-poll loop run in plain
    // sync scope, matching every other e2e test that uses
    // ProxyHarness: e2e/src/lib.rs documents that building the
    // harness's internal blocking reqwest client while already inside
    // a tokio runtime panics on drop (tokio 1.52+), so the harness
    // must be created, used, and dropped outside any block_on.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let collector = rt.block_on(common::start_grpc_collector());

    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-shutdown-flush",
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

    let mut harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url(), &collector.endpoint))
            .expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("chat completion request");
    assert_eq!(
        resp.status, 200,
        "the request that produces the span must complete before shutdown"
    );

    // A generous margin over telemetry.rs's own 10s
    // TRACE_EXPORT_FLUSH_TIMEOUT, so a slow-but-working flush isn't
    // mistaken for a hung one. Plain sync call, outside block_on.
    harness
        .terminate_gracefully(Duration::from_secs(15))
        .expect("proxy must exit cleanly on SIGTERM without hanging");

    let arrived = rt.block_on(common::wait_for_any_span(
        &collector,
        Duration::from_secs(5),
    ));
    assert!(
        arrived,
        "no span arrived at the collector at all; the request-handling path itself is broken, \
         independent of shutdown timing"
    );
}
