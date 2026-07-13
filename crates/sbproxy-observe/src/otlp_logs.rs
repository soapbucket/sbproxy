//! WOR-1046: OTLP-logs sink output.
//!
//! Wraps `opentelemetry_otlp::LogExporter` behind a [`crate::sink_dispatcher::SinkOutput`]
//! so the dispatcher can ship rendered, redacted structured-log lines
//! to an OTLP collector. The exporter is fed through a
//! `BatchLogProcessor` so the hot path never blocks on the
//! collector's response; `flush` drains the batch on SIGHUP +
//! shutdown.
//!
//! ## Severity mapping
//!
//! The dispatcher exposes the canonical mapping in
//! [`crate::sink_dispatcher::otlp_severity_number`]; this module
//! mirrors it onto the [`opentelemetry::logs::Severity`] enum that
//! the SDK consumes. `trace` -> 1, `debug` -> 5, `info` -> 9,
//! `warn` -> 13, `error` / `fatal` -> 17.
//!
//! ## Resource attributes
//!
//! Every emitted record stamps `service.name = sbproxy`,
//! `service.version = env!("CARGO_PKG_VERSION")`, and
//! `service.instance.id = <hostname>`. Operators can layer any
//! `telemetry.resource_attrs` declared on the top-level block by
//! passing them in [`OtlpLogSinkOptions::resource_attrs`].

use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::logs::LoggerProvider as SdkLoggerProvider;
use opentelemetry_sdk::Resource;

use crate::sink_dispatcher::SinkOutput;
use crate::telemetry::OtlpTransport;

/// Transport selector for the OTLP-logs exporter. Inherits from the
/// top-level `telemetry.transport` value when the sink does not
/// override it.
pub type OtlpLogsTransport = OtlpTransport;

/// Build options for an [`OtlpLogSink`]. Mirrors the relevant subset
/// of `telemetry.<...>` so the dispatcher can construct one sink per
/// declared OTLP entry without re-deriving the defaults at every
/// emit.
#[derive(Debug, Clone)]
pub struct OtlpLogSinkOptions {
    /// OTLP collector endpoint.
    pub endpoint: String,
    /// Transport: HTTP/proto or gRPC.
    pub transport: OtlpLogsTransport,
    /// `service.name` resource attribute.
    pub service_name: String,
    /// Per-export timeout. Defaults to 10 seconds.
    pub timeout: std::time::Duration,
    /// Free-form resource attributes from `telemetry.resource_attrs`.
    pub resource_attrs: std::collections::BTreeMap<String, String>,
    /// Headers attached to every export request (WOR-1869). Values
    /// must already be resolved; the binary resolves secret
    /// references at boot and installs the set via
    /// [`crate::telemetry::install_resolved_otlp_headers`].
    pub headers: std::collections::BTreeMap<String, String>,
}

impl Default for OtlpLogSinkOptions {
    fn default() -> Self {
        Self {
            endpoint: crate::telemetry::DEFAULT_OTLP_ENDPOINT.to_string(),
            transport: OtlpTransport::default(),
            service_name: "sbproxy".to_string(),
            timeout: std::time::Duration::from_secs(10),
            resource_attrs: std::collections::BTreeMap::new(),
            headers: std::collections::BTreeMap::new(),
        }
    }
}

/// OTLP-logs sink. Owns an `SdkLoggerProvider` configured with a
/// batch processor and the operator-resolved resource attributes.
/// The dispatcher feeds each redacted JSON line through `write_line`,
/// which builds an OTel `LogRecord` and emits it on the embedded
/// `Logger`. The batch processor handles transport.
pub struct OtlpLogSink {
    provider: SdkLoggerProvider,
    logger_name: &'static str,
}

impl OtlpLogSink {
    /// Construct a sink from the provided options. Returns an error
    /// when the underlying exporter cannot be built (e.g. invalid
    /// endpoint URL or a misconfigured gRPC dial target). Callers
    /// typically log + continue rather than fail boot.
    pub fn new(options: OtlpLogSinkOptions) -> anyhow::Result<Self> {
        let endpoint = options.endpoint.clone();
        let timeout = options.timeout;

        // Build the OTLP exporter per the operator's transport choice.
        // The 0.27 OTLP-logs builder API mirrors the trace + metric
        // builders already wired in `telemetry.rs`.
        let exporter = match options.transport {
            OtlpTransport::Http => {
                let mut builder = opentelemetry_otlp::LogExporter::builder()
                    .with_http()
                    .with_endpoint(endpoint.clone())
                    .with_timeout(timeout);
                if !options.headers.is_empty() {
                    builder = builder.with_headers(options.headers.clone().into_iter().collect());
                }
                builder
                    .build()
                    .map_err(|e| anyhow::anyhow!("failed to build OTLP/HTTP log exporter: {}", e))?
            }
            OtlpTransport::Grpc => {
                let mut builder = opentelemetry_otlp::LogExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint.clone())
                    .with_timeout(timeout);
                if !options.headers.is_empty() {
                    builder = builder.with_metadata(crate::telemetry::tonic_metadata_from_headers(
                        &options.headers,
                    ));
                }
                builder
                    .build()
                    .map_err(|e| anyhow::anyhow!("failed to build OTLP/gRPC log exporter: {}", e))?
            }
        };

        // Resource: identifies this proxy instance to the collector.
        // The stamped instance id is the hostname; reverts to
        // `unknown-instance` on a hostname lookup error so we never
        // fail the build for a transient resolver issue.
        let instance_id = hostname_or_fallback();
        let mut kv = vec![
            KeyValue::new("service.name", options.service_name.clone()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("service.instance.id", instance_id),
        ];
        for (k, v) in &options.resource_attrs {
            kv.push(KeyValue::new(k.clone(), v.clone()));
        }
        let resource = Resource::new(kv);

        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(resource)
            .build();

        tracing::info!(
            endpoint = %endpoint,
            transport = ?options.transport,
            "OTLP log sink initialised"
        );

        Ok(Self {
            provider,
            logger_name: "sbproxy.logs",
        })
    }

    /// Force the provider to flush. Used by the shutdown handler so
    /// pending batches drain before the process exits.
    pub fn force_flush(&self) {
        // Provider exposes `force_flush`; the returned `Vec<LogResult<()>>`
        // is ignored because the dispatcher's `flush_all` is best-effort.
        let _ = self.provider.force_flush();
    }
}

impl Drop for OtlpLogSink {
    fn drop(&mut self) {
        // Best-effort flush on drop so a `Box<OtlpLogSink>` swapped
        // out by a reload also drains.
        let _ = self.provider.force_flush();
    }
}

impl SinkOutput for OtlpLogSink {
    fn write_line(&self, line: &str) {
        // The provider exposes a `logger` getter that returns a
        // `Logger` bound to this provider. We name the instrumentation
        // scope after the proxy itself so dashboards group every
        // sbproxy-emitted record under one scope.
        let logger = self.provider.logger(self.logger_name);
        let mut record = logger.create_log_record();

        // Parse the redacted JSON so we can extract the level field
        // and stamp the right OTel severity. On a parse failure we
        // default to Info severity and ship the raw text as the body.
        let (severity, level_text) = match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => {
                let level_str = v
                    .get("level")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("info");
                (severity_for_level(level_str), level_str_static(level_str))
            }
            Err(_) => (Severity::Info, "INFO"),
        };

        record.set_severity_number(severity);
        record.set_severity_text(level_text);
        record.set_body(AnyValue::String(line.to_string().into()));

        logger.emit(record);
    }

    fn flush(&self) {
        self.force_flush();
    }
}

/// Map a structured-log level string onto the OTel `Severity` enum.
/// Mirrors [`crate::sink_dispatcher::otlp_severity_number`] on the
/// number, then walks the `Severity` variants in spec order.
fn severity_for_level(level: &str) -> Severity {
    match level {
        "trace" => Severity::Trace,
        "debug" => Severity::Debug,
        "info" => Severity::Info,
        "warn" => Severity::Warn,
        "error" | "fatal" => Severity::Error,
        _ => Severity::Info,
    }
}

/// Map a level string onto an upper-cased `&'static str` so the
/// `set_severity_text` call is allocation-free for the well-known
/// shapes.
fn level_str_static(level: &str) -> &'static str {
    match level {
        "trace" => "TRACE",
        "debug" => "DEBUG",
        "info" => "INFO",
        "warn" => "WARN",
        "error" => "ERROR",
        "fatal" => "FATAL",
        _ => "INFO",
    }
}

/// Best-effort hostname lookup. Falls back to a static string on
/// failure so the exporter still ships a `service.instance.id`.
fn hostname_or_fallback() -> String {
    // We avoid pulling in a `hostname` crate; the `nix` shell-style
    // env var is enough for the deployments we care about and the
    // sentinel covers anything else.
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "sbproxy-instance".to_string())
}

/// Helper exposed for tests + the dispatcher's diagnostic logging.
/// Returns the OTLP severity number for an [`crate::logging::LogLevel`].
pub fn severity_number_for(level: crate::logging::LogLevel) -> u8 {
    crate::sink_dispatcher::otlp_severity_number(level)
}

// --- Mock OTLP HTTP collector for tests ---

/// Test-only mock OTLP/HTTP collector. Accepts inbound POSTs to
/// `/v1/logs` and stores the raw protobuf body so tests can assert on
/// the exporter's serialised payload. Built on a barebones
/// `tokio::net::TcpListener` to avoid taking on a new dev-dep.
#[cfg(test)]
pub struct MockOtlpCollector {
    /// Local address the listener is bound to. Tests use this to
    /// construct the exporter endpoint.
    pub addr: std::net::SocketAddr,
    /// Captured raw request bodies (protobuf-encoded).
    pub bodies: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Captured raw header blocks (request line + headers), one per
    /// request, so tests can assert configured auth headers arrive
    /// (WOR-1869).
    pub header_blocks: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(test)]
impl MockOtlpCollector {
    /// Start the mock collector on an ephemeral port. Returns the
    /// collector once the listener is bound. Callers must keep the
    /// returned handle alive for the duration of the test.
    pub async fn start() -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let bodies: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let header_blocks: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let bodies_clone = bodies.clone();
        let header_blocks_clone = header_blocks.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let bodies = bodies_clone.clone();
                let header_blocks = header_blocks_clone.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 65536];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    buf.truncate(n);
                    // Split headers / body on the CRLFCRLF marker.
                    let split = buf
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4)
                        .unwrap_or(buf.len());
                    let body = buf[split..].to_vec();
                    let head = String::from_utf8_lossy(&buf[..split]).to_string();
                    header_blocks
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(head);
                    bodies.lock().unwrap_or_else(|e| e.into_inner()).push(body);
                    // 200 OK with an empty body so the exporter does
                    // not retry.
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = socket.flush().await;
                });
            }
        });
        Ok(Self {
            addr,
            bodies,
            header_blocks,
            handle,
        })
    }

    /// Snapshot of the captured request header blocks.
    pub fn headers_snapshot(&self) -> Vec<String> {
        self.header_blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Number of accepted requests so far.
    pub fn request_count(&self) -> usize {
        self.bodies.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Snapshot of the captured bodies.
    pub fn snapshot(&self) -> Vec<Vec<u8>> {
        self.bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
impl Drop for MockOtlpCollector {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{EventType, LogLevel, Sink, StructuredLog};
    use crate::sink_dispatcher::{
        install_sink_dispatcher, reset_sink_dispatcher_for_test, CompiledSink, Profile,
        SinkDispatcher, SinkFormat, SinkScope,
    };

    /// WOR-1046: end-to-end smoke test through the mock collector.
    /// Build an `OtlpLogSink` pointing at the mock, dispatch one
    /// record, flush, and assert the collector saw at least one POST
    /// whose body length is non-zero (the protobuf payload contains
    /// the record). We do not decode the protobuf because doing so
    /// would require pulling in `prost` + the generated bindings,
    /// which is unnecessary for the round-trip assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn otlp_logs_exporter_round_trip_through_mock_collector() {
        let collector = match MockOtlpCollector::start().await {
            Ok(collector) => collector,
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == std::io::ErrorKind::PermissionDenied) =>
            {
                return;
            }
            Err(err) => panic!("mock collector starts: {err}"),
        };

        let endpoint = format!("http://{}/v1/logs", collector.addr);
        let options = OtlpLogSinkOptions {
            endpoint,
            transport: OtlpTransport::Http,
            service_name: "sbproxy-test".to_string(),
            timeout: std::time::Duration::from_secs(2),
            resource_attrs: std::collections::BTreeMap::new(),
            // WOR-1869: assert configured headers reach the collector.
            headers: std::collections::BTreeMap::from([(
                "authorization".to_string(),
                "Bearer wor1869-test-token".to_string(),
            )]),
        };
        let sink = match OtlpLogSink::new(options) {
            Ok(s) => s,
            Err(e) => panic!("OtlpLogSink::new failed: {e}"),
        };

        // Drop a record through the dispatcher so we exercise the
        // exact code path the runtime uses, including the redaction
        // pass.
        let dispatcher = SinkDispatcher::new(vec![CompiledSink {
            name: "otlp-mock".to_string(),
            scope: SinkScope::Proxy,
            target: Sink::AccessLog,
            format: SinkFormat::Compact,
            profile: Profile::Internal,
            output: Box::new(sink),
        }]);
        install_sink_dispatcher(dispatcher);

        let mut rec = StructuredLog::new(
            LogLevel::Info,
            "request completed",
            EventType::RequestCompleted,
        );
        rec.target = "sbproxy_modules::policy::ai_crawl".to_string();
        let live = crate::sink_dispatcher::current_sink_dispatcher().expect("dispatcher live");
        live.dispatch(&rec, Sink::AccessLog);

        // Flush to make sure the batch processor drains before we
        // assert.
        live.flush_all();

        // Give the exporter a moment to ship the batch. The 0.27 batch
        // processor flushes synchronously on `force_flush`, but the
        // mock collector's accept loop is async so we yield a couple
        // of times.
        for _ in 0..40 {
            if collector.request_count() > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let count = collector.request_count();
        assert!(
            count >= 1,
            "mock collector expected at least one POST, got {count}"
        );
        let snap = collector.snapshot();
        assert!(
            snap.iter().any(|b| !b.is_empty()),
            "every captured body should be non-empty; snap lengths: {:?}",
            snap.iter().map(|b| b.len()).collect::<Vec<_>>()
        );
        // WOR-1869: the configured auth header must reach the
        // collector on every export request.
        let heads = collector.headers_snapshot();
        assert!(
            heads.iter().any(|h| h
                .to_ascii_lowercase()
                .contains("authorization: bearer wor1869-test-token")),
            "expected authorization header on the export request; header blocks: {heads:?}"
        );

        reset_sink_dispatcher_for_test();
    }
}
