//! TCP server on port 9400, using length-prefixed MessagePack.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `tcp.rs`. The
//! wire format is unchanged:
//!
//! ```text
//! [4-byte big-endian length][MessagePack-encoded Message]
//! [4-byte big-endian length][MessagePack-encoded Response]
//! ```
//!
//! Each accepted TCP connection spawns a task that loops forever, reading
//! one request and writing one response per iteration. Connections stay
//! open across many requests.
//!
//! `handle_connection` decodes a [`crate::protocol::Message`], branches on
//! `msg.cmd`, and dispatches to [`crate::registry`] for admin operations,
//! [`crate::heuristic::Classifier`] for classify/intent/content-type,
//! and [`crate::quality`] for quality scoring.
//!
//! Not ported from the enterprise `tcp.rs`: `embed`, `batch_embed`, and
//! `model_info`. Embedding is served over gRPC's `InferenceService` instead
//! (see `crate::grpc`), which is where the minimal sidecar already serves
//! it, so a caller wanting embeddings from either sidecar uses one RPC.

use crate::auth::AdminAuth;
use crate::heuristic;
use crate::protocol::{
    AdminResponse, ClassifyResponse, ContentTypeDetectResponse, IntentDetectResponse, Label,
    Message, QualityScoreResponse, StreamingSafetyResponse, VersionResponse,
};
use crate::quality;
use crate::registry::Registry;

const SERVER_NAME: &str = env!("CARGO_PKG_NAME");
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum accepted frame size. Tenant configs can be larger than classify
/// requests, so this is generous relative to a single prompt.
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

const TRANSPORT: &str = "tcp";
const ADMIN_TRANSPORT: &str = "admin_tcp";
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
const DEFAULT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, warn};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportMode {
    Public,
    Admin,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpLimits {
    pub max_connections: usize,
    pub io_timeout: Duration,
}

impl Default for TcpLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            io_timeout: DEFAULT_IO_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Classify,
    QualityScore,
    Register,
    Delete,
    List,
    Version,
    IntentDetect,
    StreamingSafety,
    ContentTypeDetect,
    Unknown,
}

impl Command {
    fn parse(raw: &str) -> Self {
        match raw {
            "" | "classify" => Self::Classify,
            "quality_score" => Self::QualityScore,
            "register" => Self::Register,
            "delete" => Self::Delete,
            "list" => Self::List,
            "version" => Self::Version,
            "intent_detect" => Self::IntentDetect,
            "streaming_safety" => Self::StreamingSafety,
            "content_type_detect" => Self::ContentTypeDetect,
            _ => Self::Unknown,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Classify => "classify",
            Self::QualityScore => "quality_score",
            Self::Register => "register",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Version => "version",
            Self::IntentDetect => "intent_detect",
            Self::StreamingSafety => "streaming_safety",
            Self::ContentTypeDetect => "content_type_detect",
            Self::Unknown => "unknown",
        }
    }

    fn is_admin(self) -> bool {
        matches!(self, Self::Register | Self::Delete | Self::List)
    }
}

/// Serve a pre-bound MessagePack listener until it errors.
pub async fn serve_on(
    listener: TcpListener,
    registry: Arc<Registry>,
    mode: TransportMode,
    auth: Option<Arc<AdminAuth>>,
    limits: TcpLimits,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if limits.max_connections == 0 || limits.io_timeout.is_zero() {
        return Err("TCP limits must be greater than zero".into());
    }
    if mode == TransportMode::Admin && auth.is_none() {
        return Err("admin TCP listener requires authentication".into());
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));

    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                crate::metrics::record_error(
                    if mode == TransportMode::Admin {
                        ADMIN_TRANSPORT
                    } else {
                        TRANSPORT
                    },
                    "unknown",
                    "resource_limit",
                );
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        debug!(peer = %peer, "TCP connection");

        let registry = Arc::clone(&registry);
        let auth = auth.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_connection(stream, &registry, mode, auth.as_deref(), limits).await
            {
                debug!(error = %e, "connection ended");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    registry: &Registry,
    mode: TransportMode,
    auth: Option<&AdminAuth>,
    limits: TcpLimits,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];

    loop {
        let read_len = tokio::time::timeout(limits.io_timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read timeout"))?;
        if let Err(e) = read_len {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(e.into());
        }

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_FRAME_BYTES {
            error!(len = msg_len, "message too large, closing");
            return Ok(());
        }

        let mut payload = vec![0u8; msg_len];
        tokio::time::timeout(limits.io_timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read timeout"))??;

        let msg: Message = match rmp_serde::from_slice(&payload) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "malformed request frame");
                crate::metrics::record_error(TRANSPORT, "decode", "malformed_frame");
                return Ok(());
            }
        };

        let command = Command::parse(&msg.cmd);
        let transport = if mode == TransportMode::Admin {
            ADMIN_TRANSPORT
        } else {
            TRANSPORT
        };
        let resp_bytes = if command.is_admin() && mode == TransportMode::Public {
            crate::metrics::record_error(transport, command.label(), "unauthorized");
            admin_error(
                command,
                msg.tenant.clone(),
                "admin command unavailable on public transport",
            )?
        } else if mode == TransportMode::Admin && !command.is_admin() {
            crate::metrics::record_error(transport, command.label(), "forbidden");
            admin_error(
                command,
                msg.tenant.clone(),
                "inference command unavailable on admin transport",
            )?
        } else {
            match command {
                Command::Classify => handle_classify(registry, &msg)?,
                Command::QualityScore => handle_quality_score(&msg)?,
                Command::Register | Command::Delete | Command::List => {
                    handle_admin(registry, auth.expect("admin mode validated"), command, &msg)?
                }
                Command::Version => handle_version()?,
                Command::IntentDetect => handle_intent_detect(&msg)?,
                Command::StreamingSafety => handle_streaming_safety(&msg)?,
                Command::ContentTypeDetect => handle_content_type_detect(&msg)?,
                Command::Unknown => {
                    warn!(cmd_len = msg.cmd.len(), "unknown command");
                    crate::metrics::record_error(transport, "unknown", "unknown_command");
                    admin_error(Command::Unknown, None, "unknown command")?
                }
            }
        };
        crate::metrics::record_request(transport, command.label());

        let resp_len = (resp_bytes.len() as u32).to_be_bytes();
        tokio::time::timeout(limits.io_timeout, async {
            stream.write_all(&resp_len).await?;
            stream.write_all(&resp_bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP write timeout"))??;
    }
}

fn admin_error(
    command: Command,
    tenant: Option<String>,
    error: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(rmp_serde::to_vec_named(&AdminResponse {
        ok: false,
        cmd: command.label().to_string(),
        tenant,
        error: Some(error.to_string()),
        tenants: None,
    })?)
}

fn handle_admin(
    registry: &Registry,
    auth: &AdminAuth,
    command: Command,
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let token = msg.admin_token.as_deref();
    if !auth.authenticated(token) {
        crate::metrics::record_error(ADMIN_TRANSPORT, command.label(), "unauthorized");
        return admin_error(command, msg.tenant.clone(), "unauthorized");
    }
    if matches!(command, Command::Register | Command::Delete)
        && !auth.authorize(token, msg.tenant.as_deref())
    {
        crate::metrics::record_error(ADMIN_TRANSPORT, command.label(), "forbidden");
        return admin_error(command, msg.tenant.clone(), "tenant scope forbidden");
    }
    match command {
        Command::Register => handle_register(registry, msg),
        Command::Delete => handle_delete(registry, msg),
        Command::List => handle_list(registry, auth, token),
        _ => unreachable!("only admin commands reach handle_admin"),
    }
}

fn handle_classify(
    registry: &Registry,
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let t0 = Instant::now();

    let tenant_id = msg.tenant.as_deref();
    let tenant = match registry.get(tenant_id) {
        Some(t) => t,
        None => {
            let tid = tenant_id.unwrap_or("(none)");
            warn!(tenant = %tid, "tenant not registered");
            crate::metrics::record_error(TRANSPORT, "classify", "tenant_not_registered");
            let resp = AdminResponse {
                ok: false,
                cmd: "classify".to_string(),
                tenant: Some(tid.to_string()),
                error: Some(format!("tenant not registered: {tid}")),
                tenants: None,
            };
            return Ok(rmp_serde::to_vec_named(&resp)?);
        }
    };

    let normalized = tenant.normalizer.normalize(&msg.text);
    let labels: Vec<Label> = tenant.classifier.classify(&normalized, msg.top_k);
    let latency_us = t0.elapsed().as_micros() as i64;

    let resp = ClassifyResponse {
        id: msg.id.clone(),
        labels,
        normalized,
        latency_us,
        tenant: tenant_id.unwrap_or("").to_string(),
    };

    Ok(rmp_serde::to_vec_named(&resp)?)
}

fn handle_quality_score(
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let t0 = Instant::now();
    let result = quality::quality_score(&msg.text);
    crate::metrics::record_quality_score(TRANSPORT, result.score);
    let latency_us = t0.elapsed().as_micros() as i64;

    let resp = QualityScoreResponse {
        id: msg.id.clone(),
        score: result.score,
        signals: result.signals,
        latency_us,
    };

    Ok(rmp_serde::to_vec_named(&resp)?)
}

fn handle_register(
    registry: &Registry,
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let tenant_id = match &msg.tenant {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            return Ok(rmp_serde::to_vec_named(&AdminResponse {
                ok: false,
                cmd: "register".to_string(),
                tenant: None,
                error: Some("tenant id required".to_string()),
                tenants: None,
            })?);
        }
    };

    let config = match &msg.config {
        Some(c) => c,
        None => {
            return Ok(rmp_serde::to_vec_named(&AdminResponse {
                ok: false,
                cmd: "register".to_string(),
                tenant: Some(tenant_id),
                error: Some("config required".to_string()),
                tenants: None,
            })?);
        }
    };

    match registry.register(&tenant_id, config) {
        Ok(_) => {
            crate::metrics::set_tenant_count(registry.tenant_count());
            Ok(rmp_serde::to_vec_named(&AdminResponse {
                ok: true,
                cmd: "register".to_string(),
                tenant: Some(tenant_id),
                error: None,
                tenants: None,
            })?)
        }
        Err(e) => {
            crate::metrics::record_error(TRANSPORT, "register", "invalid_config");
            Ok(rmp_serde::to_vec_named(&AdminResponse {
                ok: false,
                cmd: "register".to_string(),
                tenant: Some(tenant_id),
                error: Some(e),
                tenants: None,
            })?)
        }
    }
}

fn handle_delete(
    registry: &Registry,
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let tenant_id = match &msg.tenant {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            return Ok(rmp_serde::to_vec_named(&AdminResponse {
                ok: false,
                cmd: "delete".to_string(),
                tenant: None,
                error: Some("tenant id required".to_string()),
                tenants: None,
            })?);
        }
    };

    let existed = registry.delete(&tenant_id);
    crate::metrics::set_tenant_count(registry.tenant_count());

    Ok(rmp_serde::to_vec_named(&AdminResponse {
        ok: existed,
        cmd: "delete".to_string(),
        tenant: Some(tenant_id),
        error: if existed {
            None
        } else {
            Some("tenant not found".to_string())
        },
        tenants: None,
    })?)
}

fn handle_list(
    registry: &Registry,
    auth: &AdminAuth,
    token: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let visible = auth
        .visible_tenants(token, registry.list().into_iter().map(|tenant| tenant.id))
        .unwrap_or_default();
    let tenants = registry
        .list()
        .into_iter()
        .filter(|tenant| visible.iter().any(|id| id == &tenant.id))
        .collect();
    Ok(rmp_serde::to_vec_named(&AdminResponse {
        ok: true,
        cmd: "list".to_string(),
        tenant: None,
        error: None,
        tenants: Some(tenants),
    })?)
}

fn handle_version() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = VersionResponse {
        name: SERVER_NAME.to_string(),
        version: SERVER_VERSION.to_string(),
        mode: "heuristic".to_string(),
    };
    Ok(rmp_serde::to_vec_named(&resp)?)
}

fn handle_intent_detect(
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let text = msg.intent_text.as_deref().unwrap_or("");
    let (intent, confidence) = heuristic::detect_intent(text);
    let resp = IntentDetectResponse {
        intent: intent.to_string(),
        confidence,
    };
    Ok(rmp_serde::to_vec_named(&resp)?)
}

fn handle_streaming_safety(
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let tokens = msg.streaming_tokens.as_deref().unwrap_or("");
    let rules = msg.safety_rules.as_deref().unwrap_or(&[]);

    let (safe, blocked, reason) = heuristic::check_streaming_safety(tokens, rules);
    crate::metrics::record_safety_verdict(if safe { "safe" } else { "blocked" });

    let resp = StreamingSafetyResponse {
        safe,
        blocked,
        reason,
    };
    Ok(rmp_serde::to_vec_named(&resp)?)
}

fn handle_content_type_detect(
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let content = msg.detect_content.as_deref().unwrap_or("");
    let (content_type, confidence) = heuristic::detect_content_type(content);
    let resp = ContentTypeDetectResponse {
        content_type: content_type.to_string(),
        confidence,
    };
    Ok(rmp_serde::to_vec_named(&resp)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{TenantClassification, TenantConfig, TenantLabel};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sample_tenant_config() -> TenantConfig {
        TenantConfig {
            labels: vec![TenantLabel {
                name: "greeting".to_string(),
                patterns: vec![r"(?i)^(hi|hello)\b".to_string()],
                weight: 1.0,
            }],
            classification: Some(TenantClassification {
                confidence_threshold: 0.1,
                default_label: "greeting".to_string(),
                default_boost: 0.9,
            }),
            normalization: None,
        }
    }

    /// Bind the server on an ephemeral port, run one round-trip request
    /// through the real length-prefixed MessagePack framing, and return the
    /// decoded response bytes. Exercises `handle_connection` end to end
    /// rather than calling a handler function directly.
    async fn round_trip(registry: Arc<Registry>, msg: &Message) -> Vec<u8> {
        round_trip_with(registry, msg, TransportMode::Public, None).await
    }

    async fn round_trip_with(
        registry: Arc<Registry>,
        msg: &Message,
        mode: TransportMode,
        auth: Option<Arc<AdminAuth>>,
    ) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(
                stream,
                &registry,
                mode,
                auth.as_deref(),
                TcpLimits::default(),
            )
            .await;
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .expect("connect within timeout")
            .expect("connect succeeds");

        let payload = rmp_serde::to_vec_named(msg).unwrap();
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&payload).await.unwrap();

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    fn msg(cmd: &str) -> Message {
        Message {
            cmd: cmd.to_string(),
            id: "req-1".to_string(),
            text: String::new(),
            top_k: 3,
            tenant: None,
            config: None,
            admin_token: None,
            intent_text: None,
            streaming_tokens: None,
            safety_rules: None,
            detect_content: None,
        }
    }

    #[tokio::test]
    async fn register_then_classify_round_trips_over_the_wire() {
        let registry = Arc::new(Registry::new_empty());
        let auth = Arc::new(
            AdminAuth::from_json(
                br#"{"tokens":[{"token":"secret","tenants":["tenant.example"]}]}"#,
            )
            .unwrap(),
        );

        let mut register_msg = msg("register");
        register_msg.tenant = Some("tenant.example".to_string());
        register_msg.config = Some(sample_tenant_config());
        register_msg.admin_token = Some("secret".to_string());
        let resp = round_trip_with(
            Arc::clone(&registry),
            &register_msg,
            TransportMode::Admin,
            Some(auth),
        )
        .await;
        let admin: AdminResponse = rmp_serde::from_slice(&resp).unwrap();
        assert!(admin.ok, "{admin:?}");

        let mut classify_msg = msg("classify");
        classify_msg.tenant = Some("tenant.example".to_string());
        classify_msg.text = "hello there".to_string();
        let resp = round_trip(Arc::clone(&registry), &classify_msg).await;
        let classify: ClassifyResponse = rmp_serde::from_slice(&resp).unwrap();
        assert_eq!(classify.labels[0].label, "greeting");
    }

    #[tokio::test]
    async fn classify_for_unregistered_tenant_returns_an_admin_error() {
        let registry = Arc::new(Registry::new_empty());
        let mut classify_msg = msg("classify");
        classify_msg.tenant = Some("nobody.example".to_string());
        classify_msg.text = "hi".to_string();
        let resp = round_trip(registry, &classify_msg).await;
        let admin: AdminResponse = rmp_serde::from_slice(&resp).unwrap();
        assert!(!admin.ok);
        assert!(admin.error.unwrap().contains("not registered"));
    }

    #[tokio::test]
    async fn quality_score_round_trips_over_the_wire() {
        let registry = Arc::new(Registry::new_empty());
        let mut m = msg("quality_score");
        m.text = "A short reply.".to_string();
        let resp = round_trip(registry, &m).await;
        let decoded: QualityScoreResponse = rmp_serde::from_slice(&resp).unwrap();
        assert!((0.0..=1.0).contains(&decoded.score));
    }

    #[tokio::test]
    async fn unknown_command_gets_an_admin_error_not_a_dropped_connection() {
        let registry = Arc::new(Registry::new_empty());
        let resp = round_trip(registry, &msg("not-a-real-command")).await;
        let admin: AdminResponse = rmp_serde::from_slice(&resp).unwrap();
        assert!(!admin.ok);
        assert_eq!(admin.cmd, "unknown");
        assert_eq!(admin.error.as_deref(), Some("unknown command"));
    }

    #[tokio::test]
    async fn public_transport_rejects_admin_and_scopes_block_cross_tenant_changes() {
        let registry = Arc::new(Registry::new_empty());
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret-a","tenants":["tenant-a"]}]}"#)
                .unwrap(),
        );
        let mut register = msg("register");
        register.tenant = Some("tenant-b".to_string());
        register.config = Some(sample_tenant_config());
        register.admin_token = Some("secret-a".to_string());

        let public = round_trip(Arc::clone(&registry), &register).await;
        let public: AdminResponse = rmp_serde::from_slice(&public).unwrap();
        assert!(!public.ok);
        assert!(public.error.unwrap().contains("public transport"));

        let admin = round_trip_with(
            Arc::clone(&registry),
            &register,
            TransportMode::Admin,
            Some(auth),
        )
        .await;
        let admin: AdminResponse = rmp_serde::from_slice(&admin).unwrap();
        assert!(!admin.ok);
        assert_eq!(admin.error.as_deref(), Some("tenant scope forbidden"));
        assert_eq!(registry.tenant_count(), 0);
    }

    #[tokio::test]
    async fn stalled_tcp_frame_is_closed_by_the_io_deadline() {
        let registry = Arc::new(Registry::new_empty());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(
                stream,
                &registry,
                TransportMode::Public,
                None,
                TcpLimits {
                    max_connections: 1,
                    io_timeout: Duration::from_millis(20),
                },
            )
            .await
        });
        let _client = TcpStream::connect(address).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("connection task must not remain stuck")
            .unwrap();
        let error = result.expect_err("idle connection must hit its read deadline");
        assert!(error.to_string().contains("timeout"));
    }
}
