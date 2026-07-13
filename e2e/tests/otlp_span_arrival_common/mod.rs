#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use opentelemetry_proto::tonic::collector::trace::v1::{
    trace_service_server::{TraceService, TraceServiceServer},
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue};
use prost::Message;
use tonic::{Request, Response, Status};

type Received = Arc<Mutex<Vec<ExportTraceServiceRequest>>>;

pub struct StartedCollector {
    pub endpoint: String,
    received: Received,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for StartedCollector {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Clone, Default)]
struct MockGrpcCollector {
    received: Received,
}

#[tonic::async_trait]
impl TraceService for MockGrpcCollector {
    async fn export(
        &self,
        req: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        self.received
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(req.into_inner());
        Ok(Response::new(ExportTraceServiceResponse::default()))
    }
}

pub async fn start_grpc_collector() -> StartedCollector {
    let received = Arc::new(Mutex::new(Vec::new()));
    let collector = MockGrpcCollector {
        received: received.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC OTLP collector");
    let addr = listener.local_addr().expect("collector local addr");
    let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector))
            .serve_with_incoming(stream)
            .await
            .expect("serve gRPC OTLP collector");
    });
    StartedCollector {
        endpoint: format!("http://{addr}"),
        received,
        handle,
    }
}

pub async fn start_http_collector() -> StartedCollector {
    let received = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/traces", post(collect_http_traces))
        .with_state(received.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP OTLP collector");
    let addr = listener.local_addr().expect("collector local addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve HTTP OTLP collector");
    });
    StartedCollector {
        endpoint: format!("http://{addr}/v1/traces"),
        received,
        handle,
    }
}

async fn collect_http_traces(State(received): State<Received>, body: Bytes) -> StatusCode {
    let req = ExportTraceServiceRequest::decode(body.as_ref())
        .expect("HTTP OTLP trace request protobuf decodes");
    received.lock().unwrap_or_else(|e| e.into_inner()).push(req);
    StatusCode::OK
}

pub async fn assert_complete_ai_span_exports(
    transport: sbproxy_observe::telemetry::OtlpTransport,
    collector: StartedCollector,
) {
    let cfg = sbproxy_observe::telemetry::TelemetryConfig {
        enabled: true,
        endpoint: Some(collector.endpoint.clone()),
        transport,
        service_name: "sbproxy-e2e".to_string(),
        sample_rate: Some(1.0),
        ..Default::default()
    };
    sbproxy_observe::telemetry::init_otlp_pipeline(&cfg).expect("init OTLP pipeline");

    emit_complete_ai_request_span();

    let attrs = wait_for_span_attrs(&collector.received, "ai.request", Duration::from_secs(12))
        .await
        .unwrap_or_else(|| {
            let names = observed_span_names(&collector.received);
            panic!("ai.request span did not arrive over {transport:?}; saw names {names:?}");
        });
    sbproxy_observe::telemetry::shutdown_otlp_pipeline();

    assert_attr(&attrs, "gen_ai.operation.name", "chat_completions");
    assert_attr(&attrs, "gen_ai.system", "openai");
    assert_attr(&attrs, "gen_ai.request.model", "gpt-4o");
    assert_attr(&attrs, "gen_ai.response.model", "gpt-4o-2024-08-06");
    assert_attr(&attrs, "gen_ai.response.id", "chatcmpl-wor1217");
    assert_attr(&attrs, "gen_ai.usage.input_tokens", "7");
    assert_attr(&attrs, "gen_ai.usage.output_tokens", "3");
    assert_attr(&attrs, "gen_ai.usage.cost", "0.000012");
    assert_attr(&attrs, "gen_ai.response.finish_reasons", "stop");
    assert_attr(&attrs, "llm.provider", "openai");
    assert_attr(&attrs, "llm.model_name", "gpt-4o");
    assert_attr(&attrs, "llm.token_count.prompt", "7");
    assert_attr(&attrs, "llm.token_count.completion", "3");
    assert_attr(&attrs, "llm.token_count.total", "10");
    assert_attr(&attrs, "llm.usage.total_cost", "0.000012");
    assert_attr(&attrs, "sbproxy.ai.cost_usd_micros", "12");
    assert_attr(&attrs, "input.value", "hello from WOR-1217");
    assert_attr(&attrs, "output.value", "collector received the span");

    // WOR-1877: the MCP execute_tool span arrives with the pinned
    // agent vocabulary and parents under the ai.request span, so the
    // agent request and its tool dispatch render as one trace.
    let tool_attrs = find_span_attrs(&collector.received, "mcp.execute_tool")
        .unwrap_or_else(|| {
            let names = observed_span_names(&collector.received);
            panic!("mcp.execute_tool span did not arrive over {transport:?}; saw names {names:?}");
        });
    assert_attr(&tool_attrs, "gen_ai.operation.name", "execute_tool");
    assert_attr(&tool_attrs, "gen_ai.tool.name", "search_docs");
    assert_attr(&tool_attrs, "sbproxy.mcp.server", "docs-server");
    assert_attr(&tool_attrs, "sbproxy.mcp.outcome", "ok");
    assert_attr(&tool_attrs, "sbproxy.mcp.cost_usd", "0.002");

    let (ai_trace, ai_span_id, _) =
        find_span_ids(&collector.received, "ai.request").expect("ai.request span ids");
    let (tool_trace, _, tool_parent) =
        find_span_ids(&collector.received, "mcp.execute_tool").expect("tool span ids");
    assert_eq!(
        ai_trace, tool_trace,
        "execute_tool must share the ai.request trace"
    );
    assert_eq!(
        tool_parent, ai_span_id,
        "execute_tool must parent under the ai.request span"
    );
}

fn emit_complete_ai_request_span() {
    let span = sbproxy_ai::tracing_spans::ai_request_span("chat_completions", "POST");
    let _entered = span.clone().entered();
    span.record("sbproxy.tenant_id", "tenant-wor1217");
    span.record("gen_ai.system", "openai");
    span.record("gen_ai.request.model", "gpt-4o");
    span.record("llm.provider", "openai");
    span.record("llm.model_name", "gpt-4o");
    sbproxy_ai::tracing_spans::record_request_params(&span, Some(0.2), Some(64), Some(0.9));
    sbproxy_ai::tracing_spans::record_response_identity(
        &span,
        "gpt-4o-2024-08-06",
        "chatcmpl-wor1217",
    );
    sbproxy_ai::tracing_spans::record_token_usage(&span, 7, 3);
    sbproxy_ai::tracing_spans::record_cost_usd_micros(&span, 12);
    sbproxy_ai::tracing_spans::record_finish_reasons(&span, &["stop"]);
    sbproxy_ai::tracing_spans::record_input_content(&span, "hello from WOR-1217");
    sbproxy_ai::tracing_spans::record_output_content(&span, "collector received the span");
    // WOR-1877: a tool dispatch made in service of this request; the
    // span parents under ai.request because that span is entered.
    let tool_span = sbproxy_ai::tracing_spans::execute_tool_span("search_docs", "docs-server");
    {
        let _tool_entered = tool_span.clone().entered();
        sbproxy_ai::tracing_spans::record_tool_outcome(&tool_span, "ok", Some(0.002));
    }
}

async fn wait_for_span_attrs(
    received: &Received,
    span_name: &str,
    timeout: Duration,
) -> Option<HashMap<String, String>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(attrs) = find_span_attrs(received, span_name) {
            return Some(attrs);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn find_span_attrs(received: &Received, span_name: &str) -> Option<HashMap<String, String>> {
    for req in received.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        for rs in &req.resource_spans {
            for ss in &rs.scope_spans {
                for span in &ss.spans {
                    if span.name == span_name {
                        return Some(
                            span.attributes
                                .iter()
                                .filter_map(|kv| {
                                    kv.value
                                        .as_ref()
                                        .map(|value| (kv.key.clone(), any_value_to_string(value)))
                                })
                                .collect(),
                        );
                    }
                }
            }
        }
    }
    None
}

/// WOR-1877: fetch `(trace_id, span_id, parent_span_id)` for the first
/// span with `span_name`, for parentage assertions across spans.
fn find_span_ids(received: &Received, span_name: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    for req in received.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        for rs in &req.resource_spans {
            for ss in &rs.scope_spans {
                for span in &ss.spans {
                    if span.name == span_name {
                        return Some((
                            span.trace_id.clone(),
                            span.span_id.clone(),
                            span.parent_span_id.clone(),
                        ));
                    }
                }
            }
        }
    }
    None
}

fn observed_span_names(received: &Received) -> HashSet<String> {
    let mut names = HashSet::new();
    for req in received.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        for rs in &req.resource_spans {
            for ss in &rs.scope_spans {
                for span in &ss.spans {
                    names.insert(span.name.clone());
                }
            }
        }
    }
    names
}

fn any_value_to_string(value: &AnyValue) -> String {
    match value.value.as_ref() {
        Some(any_value::Value::StringValue(v)) => v.clone(),
        Some(any_value::Value::BoolValue(v)) => v.to_string(),
        Some(any_value::Value::IntValue(v)) => v.to_string(),
        Some(any_value::Value::DoubleValue(v)) => v.to_string(),
        Some(any_value::Value::ArrayValue(v)) => format!("{:?}", v.values),
        Some(any_value::Value::KvlistValue(v)) => format!("{:?}", v.values),
        Some(any_value::Value::BytesValue(v)) => format!("{v:?}"),
        None => String::new(),
    }
}

fn assert_attr(attrs: &HashMap<String, String>, key: &str, expected: &str) {
    let actual = attrs
        .get(key)
        .unwrap_or_else(|| panic!("missing attribute {key}; saw {attrs:?}"));
    assert_eq!(actual, expected, "attribute {key}");
}
