//! WOR-1233: span-arrival end to end.
//!
//! Stands up a mock OTLP/gRPC collector (the real OTLP `TraceService`
//! contract), points the proxy's telemetry pipeline at it, emits an AI
//! request span through `sbproxy_ai::tracing_spans`, and asserts the span
//! lands at the collector with the GenAI (`gen_ai.*`) and OpenInference
//! (`llm.*`) vocabulary intact, including the derived USD cost and the
//! error/status fields this PR added.
//!
//! This lives in the e2e crate (not the unit-test gate) because it installs
//! a process-global tracer provider + subscriber and waits for the async
//! batch exporter's scheduled export, which makes it slow (a few seconds) and
//! timing-sensitive. Run it directly:
//!   cargo test -p sbproxy-e2e --test otlp_span_arrival_e2e

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry_proto::tonic::collector::trace::v1::{
    trace_service_server::{TraceService, TraceServiceServer},
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use tonic::{Request, Response, Status};

/// Mock OTLP/gRPC collector: stores every export request it receives.
#[derive(Clone, Default)]
struct MockCollector {
    received: Arc<Mutex<Vec<ExportTraceServiceRequest>>>,
}

#[tonic::async_trait]
impl TraceService for MockCollector {
    async fn export(
        &self,
        req: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        self.received.lock().unwrap().push(req.into_inner());
        Ok(Response::new(ExportTraceServiceResponse::default()))
    }
}

/// Collect every span name and attribute key seen across all export requests.
fn observed(
    received: &Arc<Mutex<Vec<ExportTraceServiceRequest>>>,
) -> (HashSet<String>, HashSet<String>) {
    let mut names = HashSet::new();
    let mut attrs = HashSet::new();
    for req in received.lock().unwrap().iter() {
        for rs in &req.resource_spans {
            for ss in &rs.scope_spans {
                for span in &ss.spans {
                    names.insert(span.name.clone());
                    for kv in &span.attributes {
                        attrs.insert(kv.key.clone());
                    }
                }
            }
        }
    }
    (names, attrs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ai_span_lands_at_otlp_collector_with_genai_vocabulary() {
    // 1. Start the mock collector on an ephemeral port.
    let received: Arc<Mutex<Vec<ExportTraceServiceRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let collector = MockCollector {
        received: received.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector))
            .serve_with_incoming(stream)
            .await
            .unwrap();
    });

    // 2. Point the telemetry pipeline at the mock, sampling everything.
    let cfg = sbproxy_observe::telemetry::TelemetryConfig {
        enabled: true,
        endpoint: Some(format!("http://{addr}")),
        transport: sbproxy_observe::telemetry::OtlpTransport::Grpc,
        sample_rate: Some(1.0),
        ..Default::default()
    };
    sbproxy_observe::telemetry::init_otlp_pipeline(&cfg).expect("init OTLP pipeline");

    // 3. Emit an AI request span with the full vocabulary this PR stamps.
    {
        let span = sbproxy_ai::tracing_spans::ai_request_span("chat", "POST");
        let _entered = span.enter();
        span.record("gen_ai.system", "openai");
        span.record("gen_ai.request.model", "gpt-4o");
        sbproxy_ai::tracing_spans::record_token_usage(&span, 17, 42);
        sbproxy_ai::tracing_spans::record_cost_usd(&span, 0.0012);
        sbproxy_ai::tracing_spans::record_error(
            &span,
            sbproxy_ai::tracing_spans::error_type::RATE_LIMITED,
            "rate limited",
        );
    }

    // 4. Wait for the batch processor's scheduled export to reach the
    //    collector (default delay is 5s; an explicit shutdown flush does not
    //    reliably force it across the crate's global-provider boundary), then
    //    shut the pipeline down cleanly.
    tokio::time::sleep(Duration::from_secs(6)).await;
    sbproxy_observe::telemetry::shutdown_otlp_pipeline();

    // 5. Assert the AI span arrived with the GenAI + OpenInference vocabulary.
    let (names, attrs) = observed(&received);
    assert!(
        names.contains("ai.request"),
        "the ai.request span must arrive at the OTLP collector; saw names {names:?}"
    );
    for key in [
        "gen_ai.system",
        "gen_ai.request.model",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.cost",
        "llm.token_count.total",
        "error.type",
    ] {
        assert!(
            attrs.contains(key),
            "exported span is missing the {key:?} attribute; saw {attrs:?}"
        );
    }
}
