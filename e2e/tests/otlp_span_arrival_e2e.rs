//! WOR-1217: gRPC OTLP span-arrival e2e.
//!
//! The tracing subscriber and OpenTelemetry tracer provider are
//! process-global, so HTTP/protobuf coverage lives in a sibling
//! integration-test binary. Each binary owns exactly one exporter
//! transport.

#[path = "otlp_span_arrival_common/mod.rs"]
mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ai_span_lands_at_grpc_otlp_collector_with_full_llm_vocabulary() {
    let collector = common::start_grpc_collector().await;
    common::assert_complete_ai_span_exports(
        sbproxy_observe::telemetry::OtlpTransport::Grpc,
        collector,
    )
    .await;
}
