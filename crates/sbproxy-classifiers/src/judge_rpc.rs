// SPDX-License-Identifier: Apache-2.0
//
//! Classifier Judge gRPC service.
//!
//! The OSS Judge RPC is the gRPC version of
//! [`sbproxy_ai::judge::JudgeClient::semantic`]. The handler owns no
//! upstream state of its own: it borrows a single process-wide
//! [`JudgeClient`] (which already holds the upstream HTTP client, the
//! LRU cache, and the budget tracker) and serialises the verdict back
//! through the proto wire shape.
//!
//! The proto definition lives at `proto/judge.proto` and is compiled
//! into Rust types by `build.rs`. We include the generated module
//! here as [`proto`] and re-export the server type so callers can
//! register it on a [`tonic::transport::Server`].
//!
//! # Configuration
//!
//! Callers construct one [`JudgeRpcConfig`] from their own settings
//! file, hand it to [`build_judge_client`], and register the returned
//! [`JudgeRpcService`] on a tonic server. The configuration block
//! looks like:
//!
//! ```toml
//! [judge]
//! endpoint = "https://api.anthropic.com/v1/messages"
//! api_key_env = "ANTHROPIC_API_KEY"
//! timeout_ms = 2000
//! cache_capacity = 10000
//! budget_tokens = 1000000
//! ```
//!
//! # Error mapping
//!
//! [`JudgeError`] variants map to gRPC status codes:
//!
//! - [`JudgeError::BudgetExhausted`] -> [`tonic::Code::ResourceExhausted`]
//! - [`JudgeError::Timeout`] -> [`tonic::Code::DeadlineExceeded`]
//! - [`JudgeError::ProviderError`] / [`JudgeError::MalformedResponse`]
//!   -> [`tonic::Code::Internal`]
//!
//! Clients should map [`tonic::Code::ResourceExhausted`] to the same
//! `PolicyDecision::Deny` they apply to the local
//! `BudgetExhausted` failure mode.

use std::sync::Arc;

use sbproxy_ai::judge::{JudgeClient, JudgeConfig, JudgeError};
use sbproxy_plugin::PolicyDecision;
use serde::Deserialize;
use thiserror::Error;
use tonic::{Request, Response, Status};

/// Generated proto types and server traits for the Judge service.
///
/// `tonic::include_proto!` resolves to the `.rs` file emitted by
/// `tonic-build` for the `sbproxy.classifier.judge.v1` package.
pub mod proto {
    #![allow(missing_docs)]
    #![allow(clippy::doc_markdown)]
    #![allow(rustdoc::broken_intra_doc_links)]
    tonic::include_proto!("sbproxy.classifier.judge.v1");
}

/// Configuration block for the OSS Classifier Judge RPC service.
///
/// Maps directly to [`JudgeConfig`] but accepts deserialised TOML /
/// YAML field types so a host crate can plumb this into its config
/// schema without hand-rolling the conversion.
///
/// The `endpoint` field is parsed as a [`url::Url`] at
/// [`build_judge_client`] time; pass it as a string in the source
/// document. Missing optional fields fall back to the published
/// defaults on [`JudgeConfig`].
#[derive(Debug, Clone, Deserialize)]
pub struct JudgeRpcConfig {
    /// Upstream chat-completions endpoint to POST to.
    pub endpoint: String,
    /// Name of the environment variable holding the bearer API key.
    pub api_key_env: String,
    /// Per-call timeout in milliseconds. Defaults to
    /// [`JudgeConfig::DEFAULT_TIMEOUT_MS`].
    #[serde(default)]
    pub timeout_ms: Option<u32>,
    /// Maximum entries in the in-memory LRU cache. Defaults to
    /// [`JudgeConfig::DEFAULT_CACHE_CAPACITY`].
    #[serde(default)]
    pub cache_capacity: Option<usize>,
    /// Total token-equivalent budget before the tracker hard-fails.
    /// Defaults to one million tokens.
    #[serde(default)]
    pub budget_tokens: Option<u64>,
}

/// Default per-process token budget when the config block does not
/// override it. Matches the documented operator default (1M tokens).
pub const DEFAULT_BUDGET_TOKENS: u64 = 1_000_000;

/// Failure modes that surface when translating a [`JudgeRpcConfig`]
/// into a live [`JudgeClient`].
#[derive(Debug, Error)]
pub enum JudgeRpcConfigError {
    /// The configured `endpoint` did not parse as a URL.
    #[error("judge endpoint {0} is not a valid URL: {1}")]
    BadEndpoint(String, url::ParseError),
}

/// Build a single process-wide [`JudgeClient`] from a config block.
///
/// The returned [`Arc`] is cheap to clone and is what
/// [`JudgeRpcService::new`] takes ownership of. Build one client at
/// startup and reuse it across the lifetime of the process; do NOT
/// rebuild per request.
pub fn build_judge_client(cfg: &JudgeRpcConfig) -> Result<Arc<JudgeClient>, JudgeRpcConfigError> {
    let endpoint = url::Url::parse(&cfg.endpoint)
        .map_err(|e| JudgeRpcConfigError::BadEndpoint(cfg.endpoint.clone(), e))?;
    let judge_cfg = JudgeConfig {
        endpoint,
        api_key_env: cfg.api_key_env.clone(),
        timeout_ms: cfg.timeout_ms.unwrap_or(JudgeConfig::DEFAULT_TIMEOUT_MS),
        cache_capacity: cfg
            .cache_capacity
            .unwrap_or(JudgeConfig::DEFAULT_CACHE_CAPACITY),
        budget_tokens: cfg.budget_tokens.unwrap_or(DEFAULT_BUDGET_TOKENS),
    };
    Ok(Arc::new(JudgeClient::new(judge_cfg)))
}

/// Test-only trait the RPC handler uses to talk to a judge backend.
///
/// In production this is implemented by [`JudgeClient`] via the
/// [`JudgeClientLike for Arc<JudgeClient>`] blanket impl below. In
/// tests we substitute a stub so the gRPC layer can be exercised
/// without spinning up a live upstream.
#[async_trait::async_trait]
pub trait JudgeClientLike: Send + Sync + 'static {
    /// Evaluate `prompt` over `payload`. Mirrors the inherent method
    /// on [`JudgeClient`] one-for-one.
    async fn semantic(
        &self,
        prompt: &str,
        payload: serde_json::Value,
    ) -> Result<PolicyDecision, JudgeError>;
}

#[async_trait::async_trait]
impl JudgeClientLike for JudgeClient {
    async fn semantic(
        &self,
        prompt: &str,
        payload: serde_json::Value,
    ) -> Result<PolicyDecision, JudgeError> {
        JudgeClient::semantic(self, prompt, payload).await
    }
}

#[async_trait::async_trait]
impl<T: JudgeClientLike + ?Sized> JudgeClientLike for Arc<T> {
    async fn semantic(
        &self,
        prompt: &str,
        payload: serde_json::Value,
    ) -> Result<PolicyDecision, JudgeError> {
        (**self).semantic(prompt, payload).await
    }
}

/// gRPC service handler for the Classifier Judge service.
///
/// Generic over the judge backend so unit tests can swap in a stub.
/// Production wiring uses [`JudgeClient`] via [`build_judge_client`].
#[derive(Clone)]
pub struct JudgeRpcService<C: JudgeClientLike = JudgeClient> {
    client: Arc<C>,
}

impl<C: JudgeClientLike> JudgeRpcService<C> {
    /// Build a new handler that delegates every request into the
    /// supplied judge backend. The backend is held behind [`Arc`] so
    /// the handler stays cheap to clone.
    pub fn new(client: Arc<C>) -> Self {
        Self { client }
    }

    /// Register the handler on a [`tonic::transport::Server`].
    ///
    /// Returns the concrete generated server type. Callers chain
    /// this into `Server::builder().add_service(svc.into_server())`.
    pub fn into_server(self) -> proto::judge_server::JudgeServer<Self> {
        proto::judge_server::JudgeServer::new(self)
    }
}

#[async_trait::async_trait]
impl<C: JudgeClientLike> proto::judge_server::Judge for JudgeRpcService<C> {
    async fn semantic(
        &self,
        request: Request<proto::JudgeRequest>,
    ) -> Result<Response<proto::JudgeResponse>, Status> {
        let inner = request.into_inner();
        let payload = if inner.payload_json.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&inner.payload_json).map_err(|e| {
                Status::invalid_argument(format!("payload_json is not valid JSON: {e}"))
            })?
        };

        match self.client.semantic(&inner.prompt, payload).await {
            Ok(decision) => Ok(Response::new(decision_to_proto(decision))),
            Err(err) => Err(judge_error_to_status(err)),
        }
    }
}

/// Convert a [`PolicyDecision`] into the proto wire shape.
fn decision_to_proto(decision: PolicyDecision) -> proto::JudgeResponse {
    let mut out = proto::JudgeResponse {
        verdict_kind: proto::Verdict::Unspecified as i32,
        verdict: None,
        reason: String::new(),
        cached: false,
        cost_usd: 0.0,
    };
    match decision {
        PolicyDecision::Allow => {
            out.verdict_kind = proto::Verdict::Allow as i32;
        }
        PolicyDecision::Deny { status, message } => {
            out.verdict_kind = proto::Verdict::Deny as i32;
            out.reason = message.clone();
            out.verdict = Some(proto::judge_response::Verdict::Deny(proto::DenyVerdict {
                status: u32::from(status),
                message,
            }));
        }
        PolicyDecision::AllowWithHeaders { headers } => {
            out.verdict_kind = proto::Verdict::AllowWithHeaders as i32;
            let pb_headers = headers
                .into_iter()
                .map(|(name, value)| proto::Header { name, value })
                .collect();
            out.verdict = Some(proto::judge_response::Verdict::AllowWithHeaders(
                proto::AllowWithHeadersVerdict {
                    headers: pb_headers,
                },
            ));
        }
        PolicyDecision::Confirm {
            reason,
            webhook_url,
            expires_at,
            ..
        } => {
            out.verdict_kind = proto::Verdict::Confirm as i32;
            out.reason = reason.clone();
            out.verdict = Some(proto::judge_response::Verdict::Confirm(
                proto::ConfirmVerdict {
                    reason,
                    webhook_url: webhook_url.map(|u| u.to_string()).unwrap_or_default(),
                    expires_at: expires_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                },
            ));
        }
    }
    out
}

/// Map a [`JudgeError`] to the gRPC [`Status`] the RPC contract
/// publishes.
fn judge_error_to_status(err: JudgeError) -> Status {
    match err {
        JudgeError::BudgetExhausted => Status::resource_exhausted("budget exhausted"),
        JudgeError::Timeout => Status::deadline_exceeded("judge timeout"),
        JudgeError::ProviderError(msg) => Status::internal(format!("upstream: {msg}")),
        JudgeError::MalformedResponse(msg) => {
            Status::internal(format!("upstream malformed: {msg}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::judge_client::JudgeClient as ProtoClient;
    use proto::judge_server::JudgeServer as ProtoServer;
    use std::io::ErrorKind;
    use std::net::TcpListener as StdTcpListener;
    use std::time::Duration;
    use tokio::sync::Mutex;

    /// Test stub. Each call returns the next queued result from
    /// `responses`; if empty, returns a `ProviderError`. The stub
    /// records the (prompt, payload) it received so the test can
    /// assert wire-shape round-trip.
    struct StubJudge {
        responses: Mutex<Vec<Result<PolicyDecision, JudgeError>>>,
        last_call: Mutex<Option<(String, serde_json::Value)>>,
    }

    impl StubJudge {
        fn new(responses: Vec<Result<PolicyDecision, JudgeError>>) -> Self {
            Self {
                responses: Mutex::new(responses),
                last_call: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl JudgeClientLike for StubJudge {
        async fn semantic(
            &self,
            prompt: &str,
            payload: serde_json::Value,
        ) -> Result<PolicyDecision, JudgeError> {
            *self.last_call.lock().await = Some((prompt.to_string(), payload));
            let mut guard = self.responses.lock().await;
            if guard.is_empty() {
                return Err(JudgeError::ProviderError("stub exhausted".into()));
            }
            guard.remove(0)
        }
    }

    /// Bind an ephemeral local port and drop the listener so tonic
    /// can rebind on the same address. Mirrors the trick used by the
    /// e2e crate's `pick_free_port`; safe in tests because we
    /// immediately call `serve` from the spawned task.
    fn pick_free_port() -> Option<std::net::SocketAddr> {
        let listener = match StdTcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping judge RPC network test: loopback bind denied: {err}");
                return None;
            }
            Err(err) => panic!("failed to bind judge RPC test listener: {err}"),
        };
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        Some(addr)
    }

    /// Spawn an in-process tonic server backed by `stub` and return a
    /// connected gRPC client plus a shutdown handle. The server task
    /// runs until the shutdown receiver fires.
    async fn spawn_server(
        stub: Arc<StubJudge>,
    ) -> Option<(
        ProtoClient<tonic::transport::Channel>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        let addr = pick_free_port()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let svc = JudgeRpcService::new(stub);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(ProtoServer::new(svc))
                .serve_with_shutdown(addr, async {
                    let _ = rx.await;
                })
                .await;
        });

        // Wait for the listener to come up before dialling. Without
        // this, the first connect can race the bind and fail.
        for _ in 0..50 {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .timeout(Duration::from_secs(5));
        let channel = endpoint.connect().await.expect("grpc connect");
        let client = ProtoClient::new(channel);
        Some((client, tx))
    }

    #[tokio::test]
    async fn happy_path_allow_round_trips() {
        let stub = Arc::new(StubJudge::new(vec![Ok(PolicyDecision::Allow)]));
        let Some((mut client, shutdown)) = spawn_server(stub.clone()).await else {
            return;
        };

        let resp = client
            .semantic(proto::JudgeRequest {
                prompt: "classify this".to_string(),
                payload_json: r#"{"text":"hello"}"#.to_string(),
            })
            .await
            .expect("rpc")
            .into_inner();

        assert_eq!(resp.verdict_kind, proto::Verdict::Allow as i32);
        assert!(resp.verdict.is_none(), "allow has no oneof payload");
        // Stub saw the parsed JSON, not the raw string.
        let (prompt, payload) = stub.last_call.lock().await.clone().expect("call");
        assert_eq!(prompt, "classify this");
        assert_eq!(payload, serde_json::json!({"text": "hello"}));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn deny_verdict_carries_status_and_message() {
        let stub = Arc::new(StubJudge::new(vec![Ok(PolicyDecision::Deny {
            status: 451,
            message: "blocked by judge".into(),
        })]));
        let Some((mut client, shutdown)) = spawn_server(stub).await else {
            return;
        };

        let resp = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: "{}".into(),
            })
            .await
            .expect("rpc")
            .into_inner();

        assert_eq!(resp.verdict_kind, proto::Verdict::Deny as i32);
        assert_eq!(resp.reason, "blocked by judge");
        match resp.verdict {
            Some(proto::judge_response::Verdict::Deny(d)) => {
                assert_eq!(d.status, 451);
                assert_eq!(d.message, "blocked by judge");
            }
            other => panic!("expected deny payload, got {other:?}"),
        }
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn budget_exhausted_maps_to_resource_exhausted() {
        let stub = Arc::new(StubJudge::new(vec![Err(JudgeError::BudgetExhausted)]));
        let Some((mut client, shutdown)) = spawn_server(stub).await else {
            return;
        };

        let err = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: "{}".into(),
            })
            .await
            .expect_err("must surface as gRPC error");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("budget"));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn timeout_maps_to_deadline_exceeded() {
        let stub = Arc::new(StubJudge::new(vec![Err(JudgeError::Timeout)]));
        let Some((mut client, shutdown)) = spawn_server(stub).await else {
            return;
        };

        let err = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: "{}".into(),
            })
            .await
            .expect_err("must surface as gRPC error");
        assert_eq!(err.code(), tonic::Code::DeadlineExceeded);
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn malformed_response_maps_to_internal() {
        let stub = Arc::new(StubJudge::new(vec![Err(JudgeError::MalformedResponse(
            "no verdict".into(),
        ))]));
        let Some((mut client, shutdown)) = spawn_server(stub).await else {
            return;
        };

        let err = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: "{}".into(),
            })
            .await
            .expect_err("must surface as gRPC error");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(
            err.message().contains("upstream malformed"),
            "got {}",
            err.message()
        );
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn provider_error_maps_to_internal() {
        let stub = Arc::new(StubJudge::new(vec![Err(JudgeError::ProviderError(
            "503 boom".into(),
        ))]));
        let Some((mut client, shutdown)) = spawn_server(stub).await else {
            return;
        };

        let err = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: "{}".into(),
            })
            .await
            .expect_err("must surface as gRPC error");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("upstream"));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn invalid_payload_json_maps_to_invalid_argument() {
        let stub = Arc::new(StubJudge::new(vec![Ok(PolicyDecision::Allow)]));
        let Some((mut client, shutdown)) = spawn_server(stub).await else {
            return;
        };

        let err = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: "{not json".into(),
            })
            .await
            .expect_err("must surface as gRPC error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn empty_payload_json_is_treated_as_null() {
        let stub = Arc::new(StubJudge::new(vec![Ok(PolicyDecision::Allow)]));
        let Some((mut client, shutdown)) = spawn_server(stub.clone()).await else {
            return;
        };

        let _ = client
            .semantic(proto::JudgeRequest {
                prompt: "p".into(),
                payload_json: String::new(),
            })
            .await
            .expect("rpc");
        let (_, payload) = stub.last_call.lock().await.clone().expect("call");
        assert_eq!(payload, serde_json::Value::Null);
        let _ = shutdown.send(());
    }

    #[test]
    fn build_judge_client_rejects_bad_url() {
        let cfg = JudgeRpcConfig {
            endpoint: "not a url".into(),
            api_key_env: "X".into(),
            timeout_ms: None,
            cache_capacity: None,
            budget_tokens: None,
        };
        match build_judge_client(&cfg) {
            Ok(_) => panic!("must reject bad URL"),
            Err(JudgeRpcConfigError::BadEndpoint(input, _)) => {
                assert_eq!(input, "not a url");
            }
        }
    }

    #[test]
    fn build_judge_client_applies_defaults() {
        let cfg = JudgeRpcConfig {
            endpoint: "https://example.invalid/judge".into(),
            api_key_env: "ENV".into(),
            timeout_ms: None,
            cache_capacity: None,
            budget_tokens: None,
        };
        let client = match build_judge_client(&cfg) {
            Ok(c) => c,
            Err(e) => panic!("default build must succeed: {e:?}"),
        };
        // Budget tracker starts at the configured default.
        assert_eq!(client.budget().remaining(), DEFAULT_BUDGET_TOKENS);
    }

    #[test]
    fn confirm_decision_serialises_full_payload() {
        let when = chrono::Utc::now();
        let url = url::Url::parse("https://approver.invalid/webhook").unwrap();
        let decision = PolicyDecision::confirm("needs human", Some(url.clone()), Some(when));
        let out = decision_to_proto(decision);
        assert_eq!(out.verdict_kind, proto::Verdict::Confirm as i32);
        assert_eq!(out.reason, "needs human");
        match out.verdict {
            Some(proto::judge_response::Verdict::Confirm(c)) => {
                assert_eq!(c.reason, "needs human");
                assert_eq!(c.webhook_url, url.to_string());
                assert!(!c.expires_at.is_empty());
            }
            other => panic!("expected confirm payload, got {other:?}"),
        }
    }

    #[test]
    fn allow_with_headers_serialises_all_pairs() {
        let decision = PolicyDecision::AllowWithHeaders {
            headers: vec![
                ("x-sb-policy".into(), "pass".into()),
                ("x-sb-reason".into(), "stub".into()),
            ],
        };
        let out = decision_to_proto(decision);
        assert_eq!(out.verdict_kind, proto::Verdict::AllowWithHeaders as i32);
        match out.verdict {
            Some(proto::judge_response::Verdict::AllowWithHeaders(h)) => {
                assert_eq!(h.headers.len(), 2);
                assert_eq!(h.headers[0].name, "x-sb-policy");
                assert_eq!(h.headers[1].value, "stub");
            }
            other => panic!("expected allow_with_headers payload, got {other:?}"),
        }
    }
}
