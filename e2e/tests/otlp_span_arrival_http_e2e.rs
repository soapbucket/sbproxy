//! WOR-1217: HTTP/protobuf OTLP span-arrival e2e.
//!
//! Kept as a separate integration-test binary from the gRPC case so
//! the process-global tracing subscriber is initialized only once.

#[path = "otlp_span_arrival_common/mod.rs"]
mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ai_span_lands_at_http_otlp_collector_with_full_llm_vocabulary() {
    let collector = common::start_http_collector().await;
    common::assert_complete_ai_span_exports(
        sbproxy_observe::telemetry::OtlpTransport::Http,
        collector,
    )
    .await;
}
