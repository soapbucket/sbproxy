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
use std::collections::HashMap;

const SERVER_NAME: &str = env!("CARGO_PKG_NAME");
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum accepted frame size. Tenant configs can be larger than classify
/// requests, so this is generous relative to a single prompt.
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_IN_FLIGHT_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct FrameAllocationProbe {
    declared_frames: std::sync::atomic::AtomicUsize,
    allocations: std::sync::atomic::AtomicUsize,
    current: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
    allocator_boundary_calls: std::sync::atomic::AtomicUsize,
    actual_payload_allocations: std::sync::atomic::AtomicUsize,
    actual_payload_allocation_bytes: std::sync::atomic::AtomicUsize,
    allocator_calls_without_live_lease: std::sync::atomic::AtomicUsize,
    allocator_bytes_without_live_lease: std::sync::atomic::AtomicUsize,
    actual_payload_allocations_without_live_lease: std::sync::atomic::AtomicUsize,
    current_actual_payload_bytes: std::sync::atomic::AtomicUsize,
    peak_actual_payload_bytes: std::sync::atomic::AtomicUsize,
    first_budget_owner_id: std::sync::atomic::AtomicUsize,
    distinct_budget_owner_ids: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl FrameAllocationProbe {
    fn observe_declared_frame(&self) {
        self.declared_frames
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn declared_frames(&self) -> usize {
        self.declared_frames
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn observe(self: &Arc<Self>, bytes: usize) -> FrameAllocationObservation {
        self.allocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let current = self
            .current
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst)
            + bytes;
        self.peak
            .fetch_max(current, std::sync::atomic::Ordering::SeqCst);
        FrameAllocationObservation {
            probe: Arc::clone(self),
            bytes,
        }
    }

    fn peak_bytes(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn allocations(&self) -> usize {
        self.allocations.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
struct FrameAllocationObservation {
    probe: Arc<FrameAllocationProbe>,
    bytes: usize,
}

#[cfg(test)]
impl Drop for FrameAllocationObservation {
    fn drop(&mut self) {
        self.probe
            .current
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
        self.probe
            .current_actual_payload_bytes
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BudgetedFrameError {
    LengthOverflow,
    BudgetExhausted,
}

struct BudgetedFrame {
    bytes: Vec<u8>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    #[cfg(test)]
    _observation: Option<FrameAllocationObservation>,
}

impl BudgetedFrame {
    #[cfg(test)]
    fn try_new(
        budget: Arc<tokio::sync::Semaphore>,
        bytes: usize,
        #[cfg(test)] allocation_probe: Option<&Arc<FrameAllocationProbe>>,
    ) -> Result<Self, BudgetedFrameError> {
        let permits = u32::try_from(bytes).map_err(|_| BudgetedFrameError::LengthOverflow)?;
        let permit = budget
            .try_acquire_many_owned(permits)
            .map_err(|_| BudgetedFrameError::BudgetExhausted)?;
        let payload = vec![0u8; bytes];
        #[cfg(test)]
        let observation = allocation_probe.map(|probe| probe.observe(bytes));
        Ok(Self {
            bytes: payload,
            _permit: permit,
            #[cfg(test)]
            _observation: observation,
        })
    }
}

impl std::ops::Deref for BudgetedFrame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl std::ops::DerefMut for BudgetedFrame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

const TRANSPORT: &str = "tcp";
#[cfg(test)]
const ADMIN_TRANSPORT: &str = "admin_tcp";
pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 128;
const DEFAULT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_LISTENER_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum TransportMode {
    Public,
    Admin,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpLimits {
    pub max_connections: usize,
    pub io_timeout: Duration,
}

impl TcpLimits {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(1..=DEFAULT_MAX_CONNECTIONS).contains(&self.max_connections) {
            anyhow::bail!("TCP max_connections must be in 1..=128");
        }
        if self.io_timeout.is_zero() || self.io_timeout > Duration::from_secs(60) {
            anyhow::bail!("TCP io_timeout must be in 1..=60000ms");
        }
        Ok(())
    }
}

pub(crate) fn frame_budget() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_FRAME_BYTES))
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
#[cfg(test)]
async fn serve_on(
    listener: TcpListener,
    registry: Arc<Registry>,
    mode: TransportMode,
    auth: Option<Arc<AdminAuth>>,
    limits: TcpLimits,
    frame_budget: Arc<tokio::sync::Semaphore>,
    #[cfg(test)] allocation_probe: Option<Arc<FrameAllocationProbe>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    limits.validate()?;
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
        let frame_budget = Arc::clone(&frame_budget);
        #[cfg(test)]
        let allocation_probe = allocation_probe.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(
                stream,
                &registry,
                mode,
                auth.as_deref(),
                limits,
                frame_budget,
                #[cfg(test)]
                allocation_probe,
            )
            .await
            {
                debug!(error = %e, "connection ended");
            }
        });
    }
}

#[cfg(test)]
async fn handle_connection(
    mut stream: TcpStream,
    registry: &Registry,
    mode: TransportMode,
    auth: Option<&AdminAuth>,
    limits: TcpLimits,
    frame_budget: Arc<tokio::sync::Semaphore>,
    #[cfg(test)] allocation_probe: Option<Arc<FrameAllocationProbe>>,
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
            crate::metrics::record_error(TRANSPORT, "decode", "resource_limit");
            debug!(len = msg_len, "message too large, closing");
            return Ok(());
        }

        #[cfg(test)]
        if let Some(probe) = &allocation_probe {
            probe.observe_declared_frame();
        }
        let mut payload = match BudgetedFrame::try_new(
            Arc::clone(&frame_budget),
            msg_len,
            #[cfg(test)]
            allocation_probe.as_ref(),
        ) {
            Ok(payload) => payload,
            Err(BudgetedFrameError::LengthOverflow) => {
                return Err(anyhow::anyhow!("TCP frame length cannot fit the byte budget").into());
            }
            Err(BudgetedFrameError::BudgetExhausted) => {
                let transport = if mode == TransportMode::Admin {
                    ADMIN_TRANSPORT
                } else {
                    TRANSPORT
                };
                crate::metrics::record_error(transport, "unknown", "resource_limit");
                debug!(len = msg_len, "TCP in-flight frame budget exhausted");
                return Ok(());
            }
        };
        tokio::time::timeout(limits.io_timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read timeout"))??;

        let msg: Message = match rmp_serde::from_slice(&payload) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "malformed request frame");
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
                    let auth = auth.ok_or_else(|| {
                        anyhow::anyhow!("admin TCP transport is missing its authentication policy")
                    })?;
                    handle_admin(registry, auth, command, &msg).await?
                }
                Command::Version => handle_version()?,
                Command::IntentDetect => handle_intent_detect(&msg)?,
                Command::StreamingSafety => handle_streaming_safety(&msg)?,
                Command::ContentTypeDetect => handle_content_type_detect(&msg)?,
                Command::Unknown => {
                    debug!(cmd_len = msg.cmd.len(), "unknown command");
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

fn sanitize(s: &str, max: usize) -> String {
    let (prefix, truncated) = if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        (&s[..end], true)
    } else {
        (s, false)
    };
    let suffix_len = if truncated { 3 } else { 0 };
    let mut sanitized = String::with_capacity(prefix.len() + suffix_len);
    sanitized.extend(prefix.chars().map(|character| {
        if character.is_control() {
            ' '
        } else {
            character
        }
    }));
    if truncated {
        sanitized.push_str("...");
    }
    sanitized
}

fn admin_error(
    command: Command,
    tenant: Option<String>,
    error: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(rmp_serde::to_vec_named(&AdminResponse {
        ok: false,
        cmd: command.label().to_string(),
        tenant: tenant.map(|t| sanitize(&t, 128)),
        error: Some(sanitize(error, 256)),
        tenants: None,
        next_cursor: None,
    })?)
}

#[cfg(test)]
async fn handle_admin(
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
        Command::Register => handle_register(registry, msg).await,
        Command::Delete => handle_delete(registry, msg),
        Command::List => handle_list(registry, auth, token, msg),
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
            debug!(tenant = %sanitize(tid, 128), "tenant not registered");
            crate::metrics::record_error(TRANSPORT, "classify", "tenant_not_registered");
            let resp = AdminResponse {
                ok: false,
                cmd: "classify".to_string(),
                tenant: Some(sanitize(tid, 128)),
                error: Some(format!("tenant not registered: {}", sanitize(tid, 64))),
                tenants: None,
                next_cursor: None,
            };
            return Ok(rmp_serde::to_vec_named(&resp)?);
        }
    };

    let normalized = tenant.normalizer.normalize(&msg.text);
    let labels: Vec<Label> = tenant.classifier.classify(&normalized, msg.top_k);
    let latency_us = t0.elapsed().as_micros() as i64;

    let resp = ClassifyResponse {
        id: sanitize(&msg.id, 128),
        labels,
        normalized,
        latency_us,
        tenant: sanitize(tenant_id.unwrap_or(""), 128),
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
        id: sanitize(&msg.id, 128),
        score: result.score,
        signals: result.signals,
        latency_us,
    };

    Ok(rmp_serde::to_vec_named(&resp)?)
}

async fn handle_register(
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
                next_cursor: None,
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
                next_cursor: None,
            })?);
        }
    };

    match registry.register_async(&tenant_id, config).await {
        Ok(_) => {
            crate::metrics::set_tenant_count(registry.tenant_count());
            Ok(rmp_serde::to_vec_named(&AdminResponse {
                ok: true,
                cmd: "register".to_string(),
                tenant: Some(tenant_id),
                error: None,
                tenants: None,
                next_cursor: None,
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
                next_cursor: None,
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
                next_cursor: None,
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
        next_cursor: None,
    })?)
}

fn handle_list(
    registry: &Registry,
    auth: &AdminAuth,
    token: Option<&str>,
    msg: &Message,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let page = registry
        .list_page_where(
            crate::registry::TenantPageBoundary::AdminTcp,
            msg.page_size.unwrap_or(32),
            msg.cursor.as_deref(),
            |tenant| auth.authorize(token, Some(tenant)),
        )
        .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
    Ok(rmp_serde::to_vec_named(&page.into_admin_response())?)
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

#[repr(transparent)]
struct FrameAllocationLease(tokio::sync::OwnedSemaphorePermit);

impl FrameAllocationLease {
    pub fn try_acquire(
        budget: Arc<tokio::sync::Semaphore>,
        bytes: usize,
    ) -> Result<Self, BudgetedFrameError> {
        let permits = u32::try_from(bytes).map_err(|_| BudgetedFrameError::LengthOverflow)?;
        let permit = Arc::clone(&budget)
            .try_acquire_many_owned(permits)
            .map_err(|_| BudgetedFrameError::BudgetExhausted)?;
        #[cfg(test)]
        frame_probe_enter_live_lease(permit.num_permits() as usize, &budget);
        Ok(Self(permit))
    }

    fn bytes(&self) -> usize {
        self.0.num_permits() as usize
    }

    fn into_permit(self) -> tokio::sync::OwnedSemaphorePermit {
        #[cfg(test)]
        {
            let lease = std::mem::ManuallyDrop::new(self);
            frame_probe_exit_live_lease(lease.bytes());
            // SAFETY: `lease` is not dropped after this read, so the permit
            // is moved out exactly once.
            unsafe { std::ptr::read(&lease.0) }
        }
        #[cfg(not(test))]
        {
            self.0
        }
    }
}

#[cfg(test)]
impl Drop for FrameAllocationLease {
    fn drop(&mut self) {
        frame_probe_exit_live_lease(self.bytes());
    }
}

impl BudgetedFrame {
    fn allocate_from_lease(
        lease: FrameAllocationLease,
        #[cfg(test)] allocation_probe: Option<&Arc<FrameAllocationProbe>>,
    ) -> Self {
        let bytes = lease.bytes();
        #[cfg(test)]
        if let Some(probe) = allocation_probe {
            frame_probe_note_allocator_boundary(probe, bytes);
        }
        #[cfg(test)]
        let _allocation_scope = frame_tracking_allocator_scope(bytes, allocation_probe);
        let payload = vec![0u8; bytes];
        #[cfg(test)]
        let observation = allocation_probe.map(|probe| probe.observe(bytes));
        Self {
            bytes: payload,
            _permit: lease.into_permit(),
            #[cfg(test)]
            _observation: observation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicWorkLimits {
    pub(crate) max_running: usize,
    pub(crate) max_queued: usize,
    pub(crate) deadline: Duration,
}

#[cfg(test)]
impl Default for PublicWorkLimits {
    fn default() -> Self {
        Self {
            max_running: 64,
            max_queued: 0,
            deadline: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
fn tcp_limits_key(limits: &TcpLimits) -> (usize, u128) {
    (limits.max_connections, limits.io_timeout.as_nanos())
}

#[cfg(test)]
fn public_work_limit_overrides(
) -> &'static std::sync::Mutex<std::collections::HashMap<(usize, u128), PublicWorkLimits>> {
    static OVERRIDES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(usize, u128), PublicWorkLimits>>,
    > = std::sync::OnceLock::new();
    OVERRIDES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

impl TcpLimits {
    #[cfg(test)]
    pub fn with_public_work_limits(self, limits: PublicWorkLimits) -> Self {
        public_work_limit_overrides()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(tcp_limits_key(&self), limits);
        self
    }

    #[cfg(test)]
    fn public_work_limits(&self) -> Option<PublicWorkLimits> {
        public_work_limit_overrides()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&tcp_limits_key(self))
            .copied()
    }
}

#[cfg(test)]
fn metric_command_label(command: crate::metrics::Command) -> &'static str {
    use crate::metrics::Command;

    match command {
        Command::Classify => "classify",
        Command::Embed => "embed",
        Command::Compress => "compress",
        Command::ModelInfo => "model_info",
        Command::Quality => "quality",
        Command::QualityScore => "quality_score",
        Command::Register => "register",
        Command::Delete => "delete",
        Command::List => "list",
        Command::Version => "version",
        Command::IntentDetect => "intent_detect",
        Command::StreamSafety => "stream_safety",
        Command::StreamingSafety => "streaming_safety",
        Command::ContentTypeDetect => "content_type_detect",
        Command::Decode => "decode",
        Command::Tenants => "tenants",
        Command::Healthz => "healthz",
        Command::Readyz => "readyz",
        Command::Metrics => "metrics",
        Command::Unknown => "unknown",
    }
}

#[cfg(test)]
#[derive(Default)]
struct PublicWorkerProbe {
    running: std::sync::atomic::AtomicUsize,
    total_worker_starts: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl PublicWorkerProbe {
    fn worker_started(&self) {
        self.running
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.total_worker_starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn worker_finished(&self) {
        self.running
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn running(&self) -> usize {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn total_worker_starts(&self) -> usize {
        self.total_worker_starts
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn wait_for_running(&self, expected: usize, within: Duration) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.running() == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "public worker running count did not reach {expected}; current value is {}",
                    self.running()
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct PublicWorkerBarrier {
    state: std::sync::Mutex<PublicWorkerBarrierState>,
    wake: std::sync::Condvar,
}

#[cfg(test)]
#[derive(Default)]
struct PublicWorkerBarrierState {
    entered: usize,
    released: usize,
    release_all: bool,
}

#[cfg(test)]
impl PublicWorkerBarrier {
    fn enter_and_wait(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.entered = state.entered.saturating_add(1);
        let ticket = state.entered;
        self.wake.notify_all();
        while !state.release_all && state.released < ticket {
            state = self
                .wake
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    pub(crate) fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.released = state.released.saturating_add(1);
        self.wake.notify_all();
    }

    pub(crate) async fn wait_until_entered(&self, within: Duration) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .entered
                > 0
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("public worker barrier was not entered before its deadline");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
enum TcpFault {
    LengthReadIo,
    PayloadReadIo,
    Handler(crate::metrics::Command),
    Serialize(crate::metrics::Command),
    Write(crate::metrics::Command),
    WriteDeadline(crate::metrics::Command),
    Flush(crate::metrics::Command),
    PanicAfterWrite(crate::metrics::Command),
}

#[cfg(test)]
#[derive(Debug)]
struct ArmedTcpFault {
    consumed: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ArmedTcpFault {
    fn mark_consumed(&self) {
        self.consumed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn assert_consumed_exactly_once(&self) {
        assert_eq!(
            self.consumed.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "TCP fault must be consumed exactly once"
        );
    }
}

#[cfg(test)]
struct PendingTcpFault {
    fault: TcpFault,
    armed: Arc<ArmedTcpFault>,
}

#[cfg(test)]
#[derive(Default)]
struct TcpModeCounters {
    active_connections: std::sync::atomic::AtomicUsize,
    connection_refusals: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[derive(Default)]
struct TcpControlState {
    public: TcpModeCounters,
    admin: TcpModeCounters,
    faults: std::sync::Mutex<
        std::collections::HashMap<TransportMode, std::collections::VecDeque<PendingTcpFault>>,
    >,
    public_worker_holds: std::sync::Mutex<
        std::collections::HashMap<
            &'static str,
            std::collections::VecDeque<(Arc<PublicWorkerBarrier>, Arc<ArmedTcpFault>)>,
        >,
    >,
    public_worker_probe: Arc<PublicWorkerProbe>,
}

#[cfg(test)]
#[derive(Default)]
struct TcpTestControl {
    state: Arc<TcpControlState>,
}

#[cfg(test)]
impl TcpTestControl {
    fn counters(&self, mode: TransportMode) -> &TcpModeCounters {
        match mode {
            TransportMode::Public => &self.state.public,
            TransportMode::Admin => &self.state.admin,
        }
    }

    fn arm_next(&self, mode: TransportMode, fault: TcpFault) -> Arc<ArmedTcpFault> {
        let armed = Arc::new(ArmedTcpFault {
            consumed: std::sync::atomic::AtomicUsize::new(0),
        });
        self.state
            .faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(mode)
            .or_default()
            .push_back(PendingTcpFault {
                fault,
                armed: Arc::clone(&armed),
            });
        armed
    }

    fn take_fault(&self, mode: TransportMode) -> Option<TcpFault> {
        let pending = self
            .state
            .faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&mode)
            .and_then(std::collections::VecDeque::pop_front);
        pending.map(|pending| {
            pending.armed.mark_consumed();
            pending.fault
        })
    }

    fn connection_started(&self, mode: TransportMode) {
        self.counters(mode)
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn connection_finished(&self, mode: TransportMode) {
        self.counters(mode)
            .active_connections
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn connection_refused(&self, mode: TransportMode) {
        self.counters(mode)
            .connection_refusals
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn active_connections(&self, mode: TransportMode) -> usize {
        self.counters(mode)
            .active_connections
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn wait_for_active_connections(
        &self,
        mode: TransportMode,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.active_connections(mode) == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "active connections for {mode:?} did not reach {expected}; current value is {}",
                    self.active_connections(mode)
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn wait_for_connection_refusals(
        &self,
        mode: TransportMode,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let current = self
                .counters(mode)
                .connection_refusals
                .load(std::sync::atomic::Ordering::SeqCst);
            if current >= expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "connection refusals for {mode:?} did not reach {expected}; current value is {current}"
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn public_worker_probe(&self) -> Arc<PublicWorkerProbe> {
        Arc::clone(&self.state.public_worker_probe)
    }

    fn hold_next_public_worker(
        &self,
        command: crate::metrics::Command,
        barrier: Arc<PublicWorkerBarrier>,
    ) -> Arc<ArmedTcpFault> {
        let armed = Arc::new(ArmedTcpFault {
            consumed: std::sync::atomic::AtomicUsize::new(0),
        });
        self.state
            .public_worker_holds
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(metric_command_label(command))
            .or_default()
            .push_back((barrier, Arc::clone(&armed)));
        armed
    }

    fn take_public_worker_hold(&self, command: &'static str) -> Option<Arc<PublicWorkerBarrier>> {
        let pending = self
            .state
            .public_worker_holds
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(command)
            .and_then(std::collections::VecDeque::pop_front);
        pending.map(|(barrier, armed)| {
            armed.mark_consumed();
            barrier
        })
    }
}

#[derive(Default)]
struct TcpListenerCleanupProbe {
    notify: tokio::sync::Notify,
    deadline_id: std::sync::atomic::AtomicU64,
    shutdown_requested: std::sync::atomic::AtomicBool,
    deadline: std::sync::Mutex<Option<tokio::time::Instant>>,
}

impl TcpListenerCleanupProbe {
    fn request_graceful_shutdown_before(&self, deadline: tokio::time::Instant) {
        let deadline = {
            let mut slot = self
                .deadline
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let deadline = match *slot {
                Some(current) if current <= deadline => current,
                _ => {
                    *slot = Some(deadline);
                    deadline
                }
            };
            deadline
        };
        self.deadline_id.store(
            tcp_instant_id(deadline),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.shutdown_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    #[cfg(test)]
    fn bind_failure_collection_deadline(&self, deadline: tokio::time::Instant) {
        *self
            .deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(deadline);
        self.deadline_id.store(
            tcp_instant_id(deadline),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.notify.notify_waiters();
    }

    fn shutdown_deadline_id(&self) -> u64 {
        self.deadline_id.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn collection_deadline(&self) -> Option<tokio::time::Instant> {
        *self
            .deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn ensure_failure_shutdown_deadline(&self) {
        if self.collection_deadline().is_none() {
            self.request_graceful_shutdown_before(
                tokio::time::Instant::now() + DEFAULT_LISTENER_CLEANUP_TIMEOUT,
            );
        }
    }

    async fn wait_for_shutdown(&self) {
        loop {
            let mut notified = Box::pin(self.notify.notified());
            notified.as_mut().enable();
            if self.shutdown_requested() {
                return;
            }
            notified.as_mut().await;
        }
    }

    async fn wait_for_deadline_update(&self, deadline_id: u64) {
        loop {
            let mut notified = Box::pin(self.notify.notified());
            notified.as_mut().enable();
            if self.shutdown_deadline_id() != deadline_id {
                return;
            }
            notified.as_mut().await;
        }
    }
}

fn tcp_instant_id(instant: tokio::time::Instant) -> u64 {
    crate::startup::deadline_id(instant)
}

#[derive(Clone, Default)]
pub(crate) struct TcpShutdownHandle {
    cleanup: Arc<TcpListenerCleanupProbe>,
}

impl TcpShutdownHandle {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn request_graceful_shutdown_before(&self, deadline: tokio::time::Instant) {
        self.cleanup.request_graceful_shutdown_before(deadline);
    }

    pub(crate) fn shutdown_deadline_id(&self) -> u64 {
        self.cleanup.shutdown_deadline_id()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TcpListenerExitReport {
    active_connection_children: usize,
    connection_children_spawned: usize,
    connection_children_finished: usize,
    connection_child_results_collected: usize,
    connection_child_panics: usize,
    connection_child_events_after_owner_return: usize,
    collection_deadline_id: u64,
}

impl TcpListenerExitReport {
    pub(crate) fn assert_quiescent_at_return(&self) -> anyhow::Result<()> {
        if self.active_connection_children != 0
            || self.connection_children_spawned != self.connection_children_finished
            || self.connection_children_spawned != self.connection_child_results_collected
            || self.connection_child_events_after_owner_return != 0
        {
            anyhow::bail!(
                "TCP owner cleanup incomplete: active={}, spawned={}, finished={}, collected={}, late_events={}",
                self.active_connection_children,
                self.connection_children_spawned,
                self.connection_children_finished,
                self.connection_child_results_collected,
                self.connection_child_events_after_owner_return,
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn active_connection_children(&self) -> usize {
        self.active_connection_children
    }

    #[cfg(test)]
    pub(crate) fn connection_children_spawned(&self) -> usize {
        self.connection_children_spawned
    }

    #[cfg(test)]
    pub(crate) fn connection_children_finished(&self) -> usize {
        self.connection_children_finished
    }

    #[cfg(test)]
    pub(crate) fn connection_child_results_collected(&self) -> usize {
        self.connection_child_results_collected
    }

    pub(crate) fn connection_child_panics(&self) -> usize {
        self.connection_child_panics
    }

    #[cfg(test)]
    pub(crate) fn connection_child_events_after_owner_return(&self) -> usize {
        self.connection_child_events_after_owner_return
    }

    pub(crate) fn collection_deadline_id(&self) -> u64 {
        self.collection_deadline_id
    }
}

#[derive(Debug)]
pub(crate) enum TcpListenerAssemblyError {
    InvalidConfig(anyhow::Error),
    MissingAdminAuthentication,
    Listener {
        error: std::io::Error,
        exit: TcpListenerExitReport,
    },
    ConnectionChildPanic {
        mode: TransportMode,
        exit: TcpListenerExitReport,
    },
    ConnectionChildCancelled {
        mode: TransportMode,
        exit: TcpListenerExitReport,
    },
    CleanupDeadlineExceeded {
        exit: TcpListenerExitReport,
    },
}

impl TcpListenerAssemblyError {
    #[cfg(test)]
    fn is_connection_child_panic(&self, mode: TransportMode) -> bool {
        matches!(self, Self::ConnectionChildPanic { mode: panic_mode, .. } if *panic_mode == mode)
    }

    pub(crate) fn exit_report(&self) -> Option<&TcpListenerExitReport> {
        match self {
            Self::InvalidConfig(_) | Self::MissingAdminAuthentication => None,
            Self::Listener { exit, .. }
            | Self::ConnectionChildPanic { exit, .. }
            | Self::ConnectionChildCancelled { exit, .. }
            | Self::CleanupDeadlineExceeded { exit } => Some(exit),
        }
    }
}

impl std::fmt::Display for TcpListenerAssemblyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "{error}"),
            Self::MissingAdminAuthentication => {
                write!(formatter, "admin TCP listener requires authentication")
            }
            Self::Listener { error, .. } => write!(formatter, "{error}"),
            Self::ConnectionChildPanic { mode, .. } => {
                write!(formatter, "{mode:?} connection child panicked")
            }
            Self::ConnectionChildCancelled { mode, .. } => {
                write!(formatter, "{mode:?} connection child was cancelled")
            }
            Self::CleanupDeadlineExceeded { .. } => {
                write!(
                    formatter,
                    "TCP listener cleanup exceeded its absolute deadline"
                )
            }
        }
    }
}

impl std::error::Error for TcpListenerAssemblyError {}

const CHILD_PANIC_SIGNAL: &str = "tcp connection child panic signal";

enum PendingOwnerFailure {
    Listener(std::io::Error),
    ConnectionChildPanic(TransportMode),
    ConnectionChildCancelled(TransportMode),
}

fn finalize_owner_result(
    mut report: TcpListenerExitReport,
    cleanup: &TcpListenerCleanupProbe,
    child_modes: HashMap<tokio::task::Id, TransportMode>,
    cleanup_deadline_exceeded: bool,
    first_failure: Option<PendingOwnerFailure>,
) -> Result<TcpListenerExitReport, TcpListenerAssemblyError> {
    report.collection_deadline_id = cleanup.shutdown_deadline_id();

    if !child_modes.is_empty() {
        return Err(TcpListenerAssemblyError::Listener {
            error: std::io::Error::other(format!(
                "TCP owner retained {} uncollected child mode attribution(s)",
                child_modes.len()
            )),
            exit: report,
        });
    }

    if report.assert_quiescent_at_return().is_err() || cleanup_deadline_exceeded {
        return Err(TcpListenerAssemblyError::CleanupDeadlineExceeded { exit: report });
    }

    match first_failure {
        Some(PendingOwnerFailure::Listener(error)) => Err(TcpListenerAssemblyError::Listener {
            error,
            exit: report,
        }),
        Some(PendingOwnerFailure::ConnectionChildPanic(mode)) => {
            Err(TcpListenerAssemblyError::ConnectionChildPanic { mode, exit: report })
        }
        Some(PendingOwnerFailure::ConnectionChildCancelled(mode)) => {
            Err(TcpListenerAssemblyError::ConnectionChildCancelled { mode, exit: report })
        }
        None => Ok(report),
    }
}

struct TcpListenerAssembly {
    registry: Arc<Registry>,
    auth: Option<Arc<AdminAuth>>,
    limits: TcpLimits,
    public_work_limits: Option<PublicWorkLimits>,
    frame_budget: Arc<tokio::sync::Semaphore>,
    shutdown: Arc<TcpListenerCleanupProbe>,
    #[cfg(test)]
    controls: Arc<TcpTestControl>,
    #[cfg(test)]
    allocation_probe: Option<Arc<FrameAllocationProbe>>,
}

impl TcpListenerAssembly {
    fn new(registry: Arc<Registry>, auth: Option<Arc<AdminAuth>>, limits: TcpLimits) -> Self {
        Self {
            registry,
            auth,
            limits,
            public_work_limits: None,
            frame_budget: frame_budget(),
            shutdown: Arc::new(TcpListenerCleanupProbe::default()),
            #[cfg(test)]
            controls: Arc::new(TcpTestControl::default()),
            #[cfg(test)]
            allocation_probe: None,
        }
    }

    fn with_public_work_limits(mut self, public_work_limits: Option<PublicWorkLimits>) -> Self {
        self.public_work_limits = public_work_limits;
        self
    }

    fn with_shutdown_handle(mut self, shutdown: TcpShutdownHandle) -> Self {
        self.shutdown = shutdown.cleanup;
        self
    }

    #[cfg(test)]
    fn with_test_control(mut self, controls: Arc<TcpTestControl>) -> Self {
        self.controls = controls;
        self
    }

    #[cfg(test)]
    fn with_test_cleanup_probe(mut self, cleanup: Arc<TcpListenerCleanupProbe>) -> Self {
        self.shutdown = cleanup;
        self
    }

    #[cfg(test)]
    fn with_test_allocation_probe(mut self, probe: Option<Arc<FrameAllocationProbe>>) -> Self {
        self.allocation_probe = probe;
        self
    }

    async fn serve_on(
        self,
        public: TcpListener,
        admin: Option<TcpListener>,
    ) -> Result<TcpListenerExitReport, TcpListenerAssemblyError> {
        let admin_auth = match (admin.is_some(), self.auth.as_ref()) {
            (true, Some(auth)) => Some(Arc::clone(auth)),
            (true, None) => return Err(TcpListenerAssemblyError::MissingAdminAuthentication),
            (false, _) => None,
        };
        let public_slots = Arc::new(tokio::sync::Semaphore::new(self.limits.max_connections));
        let admin_slots = Arc::new(tokio::sync::Semaphore::new(self.limits.max_connections));
        let public_executor = self.public_work_limits.and_then(|limits| {
            let admission = crate::admission::Admission::new(
                limits.max_running,
                limits.max_queued,
                limits.deadline,
            )
            .ok()?;
            Some(Arc::new(crate::admission::BlockingWorkExecutor::new(
                admission,
            )))
        });
        let mut children =
            tokio::task::JoinSet::<(TransportMode, Result<(), std::io::Error>)>::new();
        let mut child_modes = HashMap::<tokio::task::Id, TransportMode>::new();
        let mut report = TcpListenerExitReport::default();
        let cleanup = Arc::clone(&self.shutdown);
        #[cfg(test)]
        let controls = Arc::clone(&self.controls);
        let mut accepting = true;
        let mut first_failure: Option<PendingOwnerFailure> = None;
        let mut deadline_enforced = false;
        let mut cleanup_deadline_exceeded = false;
        let shutdown_cleanup = cleanup.clone();
        let shutdown = async move {
            shutdown_cleanup.wait_for_shutdown().await;
        };
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown, if accepting => {
                    accepting = false;
                }
                _ = async {
                    let deadline_id = cleanup.shutdown_deadline_id();
                    if let Some(deadline) = cleanup.collection_deadline() {
                        tokio::select! {
                            _ = tokio::time::sleep_until(deadline) => {}
                            _ = cleanup.wait_for_deadline_update(deadline_id) => {}
                        }
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if !deadline_enforced && (!accepting || first_failure.is_some()) && !children.is_empty() && cleanup.collection_deadline().is_some() => {
                    if cleanup
                        .collection_deadline()
                        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
                    {
                        children.abort_all();
                        deadline_enforced = true;
                        cleanup_deadline_exceeded = true;
                    }
                }
                child = children.join_next_with_id(), if !children.is_empty() => {
                    report.connection_child_results_collected += 1;
                    match child {
                        Some(Ok((task_id, (mode, result)))) => {
                            child_modes.remove(&task_id);
                            report.connection_children_finished += 1;
                            report.active_connection_children = report.active_connection_children.saturating_sub(1);
                            if let Err(error) = result {
                                if error.kind() == std::io::ErrorKind::Other
                                    && error.to_string() == CHILD_PANIC_SIGNAL
                                {
                                    report.connection_child_panics += 1;
                                    if first_failure.is_none() {
                                        first_failure = Some(PendingOwnerFailure::ConnectionChildPanic(mode));
                                        accepting = false;
                                        cleanup.ensure_failure_shutdown_deadline();
                                    }
                                } else if first_failure.is_none() {
                                    first_failure = Some(PendingOwnerFailure::Listener(error));
                                    accepting = false;
                                    cleanup.ensure_failure_shutdown_deadline();
                                }
                            }
                            #[cfg(test)]
                            controls.connection_finished(mode);
                        }
                        Some(Err(join_error)) => {
                            let mode = match child_modes.remove(&join_error.id()) {
                                Some(mode) => mode,
                                None => {
                                    if first_failure.is_none() {
                                        first_failure = Some(PendingOwnerFailure::Listener(
                                            std::io::Error::other(
                                                "TCP owner lost connection-child mode attribution",
                                            ),
                                        ));
                                        accepting = false;
                                        cleanup.ensure_failure_shutdown_deadline();
                                    }
                                    report.connection_children_finished += 1;
                                    report.active_connection_children =
                                        report.active_connection_children.saturating_sub(1);
                                    continue;
                                }
                            };
                            report.connection_children_finished += 1;
                            report.active_connection_children = report.active_connection_children.saturating_sub(1);
                            if join_error.is_cancelled() {
                                if !deadline_enforced && first_failure.is_none() {
                                    first_failure =
                                        Some(PendingOwnerFailure::ConnectionChildCancelled(mode));
                                    accepting = false;
                                    cleanup.ensure_failure_shutdown_deadline();
                                }
                            } else {
                                report.connection_child_panics += 1;
                                if first_failure.is_none() {
                                    first_failure =
                                        Some(PendingOwnerFailure::ConnectionChildPanic(mode));
                                    accepting = false;
                                    cleanup.ensure_failure_shutdown_deadline();
                                }
                            }
                            #[cfg(test)]
                            controls.connection_finished(mode);
                        }
                        None => {}
                    }
                }
                accepted = public.accept(), if accepting => {
                    let (stream, _peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            if first_failure.is_none() {
                                first_failure = Some(PendingOwnerFailure::Listener(error));
                                accepting = false;
                                cleanup.ensure_failure_shutdown_deadline();
                            }
                            continue;
                        }
                    };
                    if let Ok(permit) = Arc::clone(&public_slots).try_acquire_owned() {
                        report.connection_children_spawned += 1;
                        report.active_connection_children += 1;
                        #[cfg(test)]
                        controls.connection_started(TransportMode::Public);
                        let registry = Arc::clone(&self.registry);
                        let frame_budget = Arc::clone(&self.frame_budget);
                        #[cfg(test)]
                        let probe = self.allocation_probe.clone();
                        #[cfg(test)]
                        let control = Arc::clone(&self.controls);
                        let limits = self.limits;
                        let auth = self.auth.clone();
                        let public_executor = public_executor.clone();
                        let shutdown = Arc::clone(&cleanup);
                        let child = children.spawn(async move {
                            let _permit = permit;
                            let result = handle_production_connection(
                                stream,
                                &registry,
                                TransportMode::Public,
                                auth.as_deref(),
                                limits,
                                frame_budget,
                                public_executor,
                                Some(shutdown),
                                #[cfg(test)]
                                Some(control),
                                #[cfg(test)]
                                probe,
                            )
                            .await;
                            (TransportMode::Public, result)
                        });
                        child_modes.insert(child.id(), TransportMode::Public);
                    } else {
                        crate::metrics::begin_outcome(
                            crate::metrics::Transport::Tcp,
                            crate::metrics::Command::Unknown,
                        )
                        .failure(
                            crate::metrics::Stage::Admission,
                            crate::metrics::Reason::ResourceLimit,
                        );
                        #[cfg(test)]
                        controls.connection_refused(TransportMode::Public);
                    }
                }
                accepted = async {
                    match admin.as_ref() {
                        Some(listener) => Some(listener.accept().await),
                        None => None,
                    }
                }, if accepting && admin_auth.is_some() => {
                    let Some(accepted) = accepted else {
                        continue;
                    };
                    let (stream, _peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            if first_failure.is_none() {
                                first_failure = Some(PendingOwnerFailure::Listener(error));
                                accepting = false;
                                cleanup.ensure_failure_shutdown_deadline();
                            }
                            continue;
                        }
                    };
                    let Some(auth) = admin_auth.as_ref().map(Arc::clone) else {
                        first_failure = Some(PendingOwnerFailure::Listener(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "admin TCP listener requires authentication",
                        )));
                        accepting = false;
                        cleanup.ensure_failure_shutdown_deadline();
                        continue;
                    };
                    if let Ok(permit) = Arc::clone(&admin_slots).try_acquire_owned() {
                        report.connection_children_spawned += 1;
                        report.active_connection_children += 1;
                        #[cfg(test)]
                        controls.connection_started(TransportMode::Admin);
                        let registry = Arc::clone(&self.registry);
                        let frame_budget = Arc::clone(&self.frame_budget);
                        #[cfg(test)]
                        let probe = self.allocation_probe.clone();
                        #[cfg(test)]
                        let control = Arc::clone(&self.controls);
                        let limits = self.limits;
                        let shutdown = Arc::clone(&cleanup);
                        let child = children.spawn(async move {
                            let _permit = permit;
                            let result = handle_production_connection(
                                stream,
                                &registry,
                                TransportMode::Admin,
                                Some(auth.as_ref()),
                                limits,
                                frame_budget,
                                None,
                                Some(shutdown),
                                #[cfg(test)]
                                Some(control),
                                #[cfg(test)]
                                probe,
                            )
                            .await;
                            (TransportMode::Admin, result)
                        });
                        child_modes.insert(child.id(), TransportMode::Admin);
                    } else {
                        crate::metrics::begin_outcome(
                            crate::metrics::Transport::AdminTcp,
                            crate::metrics::Command::Unknown,
                        )
                        .failure(
                            crate::metrics::Stage::Admission,
                            crate::metrics::Reason::ResourceLimit,
                        );
                        #[cfg(test)]
                        controls.connection_refused(TransportMode::Admin);
                    }
                }
                else => {
                    if !accepting && children.is_empty() {
                        break;
                    }
                }
            }
        }

        finalize_owner_result(
            report,
            &cleanup,
            child_modes,
            cleanup_deadline_exceeded,
            first_failure,
        )
    }
}

pub(crate) async fn serve_listener_set(
    public: TcpListener,
    admin: Option<TcpListener>,
    registry: Arc<Registry>,
    auth: Option<Arc<AdminAuth>>,
    limits: TcpLimits,
    public_work_limits: Option<PublicWorkLimits>,
    shutdown: TcpShutdownHandle,
) -> Result<TcpListenerExitReport, TcpListenerAssemblyError> {
    limits
        .validate()
        .map_err(TcpListenerAssemblyError::InvalidConfig)?;
    if admin.is_some() && auth.is_none() {
        return Err(TcpListenerAssemblyError::MissingAdminAuthentication);
    }
    TcpListenerAssembly::new(registry, auth, limits)
        .with_public_work_limits(public_work_limits)
        .with_shutdown_handle(shutdown)
        .serve_on(public, admin)
        .await
}

#[derive(Clone, Copy)]
enum PlannedOutcome {
    Success,
    Failure(crate::metrics::Stage, crate::metrics::Reason),
}

fn metrics_transport(mode: TransportMode) -> crate::metrics::Transport {
    match mode {
        TransportMode::Public => crate::metrics::Transport::Tcp,
        TransportMode::Admin => crate::metrics::Transport::AdminTcp,
    }
}

fn metrics_command(command: Command) -> crate::metrics::Command {
    match command {
        Command::Classify => crate::metrics::Command::Classify,
        Command::QualityScore => crate::metrics::Command::QualityScore,
        Command::Register => crate::metrics::Command::Register,
        Command::Delete => crate::metrics::Command::Delete,
        Command::List => crate::metrics::Command::List,
        Command::Version => crate::metrics::Command::Version,
        Command::IntentDetect => crate::metrics::Command::IntentDetect,
        Command::StreamingSafety => crate::metrics::Command::StreamingSafety,
        Command::ContentTypeDetect => crate::metrics::Command::ContentTypeDetect,
        Command::Unknown => crate::metrics::Command::Unknown,
    }
}

enum HeaderRead {
    CleanEof,
    PartialEof,
    Timeout,
    Io,
    Length(usize),
}

async fn read_frame_length(
    stream: &mut TcpStream,
    io_timeout: Duration,
    shutdown: Option<&Arc<TcpListenerCleanupProbe>>,
) -> Result<HeaderRead, std::io::Error> {
    let mut len_buf = [0u8; 4];
    let mut filled = 0usize;
    loop {
        if shutdown.is_some_and(|cleanup| cleanup.shutdown_requested()) {
            return Ok(if filled == 0 {
                HeaderRead::CleanEof
            } else {
                HeaderRead::PartialEof
            });
        }
        let read = if let Some(cleanup) = shutdown {
            let mut notified = Box::pin(cleanup.notify.notified());
            notified.as_mut().enable();
            tokio::select! {
                _ = notified.as_mut() => {
                    continue;
                }
                read = tokio::time::timeout(io_timeout, stream.read(&mut len_buf[filled..])) => read,
            }
        } else {
            tokio::time::timeout(io_timeout, stream.read(&mut len_buf[filled..])).await
        };
        match read {
            Err(_) => return Ok(HeaderRead::Timeout),
            Ok(Ok(0)) if filled == 0 => return Ok(HeaderRead::CleanEof),
            Ok(Ok(0)) => return Ok(HeaderRead::PartialEof),
            Ok(Ok(count)) => {
                filled += count;
                if filled == len_buf.len() {
                    return Ok(HeaderRead::Length(u32::from_be_bytes(len_buf) as usize));
                }
            }
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) && filled == 0 =>
            {
                return Ok(HeaderRead::CleanEof);
            }
            Ok(Err(_error)) => return Ok(HeaderRead::Io),
        }
    }
}

async fn read_frame_payload(
    stream: &mut TcpStream,
    io_timeout: Duration,
    payload: &mut [u8],
) -> Result<Result<(), crate::metrics::Reason>, std::io::Error> {
    let mut filled = 0usize;
    while filled < payload.len() {
        let read = tokio::time::timeout(io_timeout, stream.read(&mut payload[filled..])).await;
        match read {
            Err(_) => return Ok(Err(crate::metrics::Reason::Deadline)),
            Ok(Ok(0)) => return Ok(Err(crate::metrics::Reason::MalformedFrame)),
            Ok(Ok(count)) => filled += count,
            Ok(Err(_error)) => return Ok(Err(crate::metrics::Reason::Io)),
        }
    }
    Ok(Ok(()))
}

async fn handle_production_connection(
    mut stream: TcpStream,
    registry: &Registry,
    mode: TransportMode,
    auth: Option<&AdminAuth>,
    limits: TcpLimits,
    frame_budget: Arc<tokio::sync::Semaphore>,
    public_executor: Option<Arc<crate::admission::BlockingWorkExecutor>>,
    shutdown: Option<Arc<TcpListenerCleanupProbe>>,
    #[cfg(test)] controls: Option<Arc<TcpTestControl>>,
    #[cfg(test)] allocation_probe: Option<Arc<FrameAllocationProbe>>,
) -> Result<(), std::io::Error> {
    loop {
        #[cfg(test)]
        let request_fault = controls
            .as_ref()
            .and_then(|controls| controls.take_fault(mode));

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::LengthReadIo)) {
            crate::metrics::begin_outcome(metrics_transport(mode), crate::metrics::Command::Decode)
                .failure(crate::metrics::Stage::Read, crate::metrics::Reason::Io);
            return Ok(());
        }

        let msg_len =
            match read_frame_length(&mut stream, limits.io_timeout, shutdown.as_ref()).await? {
                HeaderRead::CleanEof => return Ok(()),
                HeaderRead::PartialEof => {
                    crate::metrics::begin_outcome(
                        metrics_transport(mode),
                        crate::metrics::Command::Decode,
                    )
                    .failure(
                        crate::metrics::Stage::Read,
                        crate::metrics::Reason::MalformedFrame,
                    );
                    return Ok(());
                }
                HeaderRead::Timeout => {
                    crate::metrics::begin_outcome(
                        metrics_transport(mode),
                        crate::metrics::Command::Decode,
                    )
                    .failure(
                        crate::metrics::Stage::Read,
                        crate::metrics::Reason::Deadline,
                    );
                    return Ok(());
                }
                HeaderRead::Io => {
                    crate::metrics::begin_outcome(
                        metrics_transport(mode),
                        crate::metrics::Command::Decode,
                    )
                    .failure(crate::metrics::Stage::Read, crate::metrics::Reason::Io);
                    return Ok(());
                }
                HeaderRead::Length(length) => length,
            };

        if msg_len > MAX_FRAME_BYTES {
            crate::metrics::begin_outcome(metrics_transport(mode), crate::metrics::Command::Decode)
                .failure(
                    crate::metrics::Stage::Limit,
                    crate::metrics::Reason::ResourceLimit,
                );
            return Ok(());
        }

        #[cfg(test)]
        if let Some(probe) = &allocation_probe {
            probe.observe_declared_frame();
        }
        let lease = match FrameAllocationLease::try_acquire(Arc::clone(&frame_budget), msg_len) {
            Ok(lease) => lease,
            Err(BudgetedFrameError::LengthOverflow | BudgetedFrameError::BudgetExhausted) => {
                crate::metrics::begin_outcome(
                    metrics_transport(mode),
                    crate::metrics::Command::Decode,
                )
                .failure(
                    crate::metrics::Stage::Admission,
                    crate::metrics::Reason::ResourceLimit,
                );
                return Ok(());
            }
        };
        let mut payload = BudgetedFrame::allocate_from_lease(
            lease,
            #[cfg(test)]
            allocation_probe.as_ref(),
        );

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::PayloadReadIo)) {
            crate::metrics::begin_outcome(metrics_transport(mode), crate::metrics::Command::Decode)
                .failure(crate::metrics::Stage::Read, crate::metrics::Reason::Io);
            return Ok(());
        }

        match read_frame_payload(&mut stream, limits.io_timeout, &mut payload).await? {
            Ok(()) => {}
            Err(reason) => {
                crate::metrics::begin_outcome(
                    metrics_transport(mode),
                    crate::metrics::Command::Decode,
                )
                .failure(crate::metrics::Stage::Read, reason);
                return Ok(());
            }
        }

        let msg: Message = match rmp_serde::from_slice(&payload) {
            Ok(msg) => msg,
            Err(_) => {
                crate::metrics::begin_outcome(
                    metrics_transport(mode),
                    crate::metrics::Command::Decode,
                )
                .failure(
                    crate::metrics::Stage::Decode,
                    crate::metrics::Reason::MalformedFrame,
                );
                return Ok(());
            }
        };
        let command = Command::parse(&msg.cmd);
        let outcome =
            crate::metrics::begin_outcome(metrics_transport(mode), metrics_command(command));
        let (response, planned_outcome) = match (mode, command) {
            (TransportMode::Public, Command::Classify) => {
                if registry.get(msg.tenant.as_deref()).is_none() {
                    (
                        admin_error(
                            Command::Classify,
                            msg.tenant.clone(),
                            &format!(
                                "tenant not registered: {}",
                                sanitize(msg.tenant.as_deref().unwrap_or("(none)"), 64)
                            ),
                        )
                        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                        PlannedOutcome::Failure(
                            crate::metrics::Stage::Handler,
                            crate::metrics::Reason::TenantNotFound,
                        ),
                    )
                } else {
                    #[cfg(test)]
                    if let Some(executor) = public_executor.as_ref() {
                        let tenant_id = msg.tenant.clone();
                        let text = msg.text.clone();
                        let top_k = msg.top_k;
                        let registered_tenant = registry.get(tenant_id.as_deref());
                        let request_id = msg.id.clone();
                        let controls = controls.clone();
                        match executor
                            .run_blocking("classify", move || {
                                if let Some(controls) = &controls {
                                    controls.public_worker_probe().worker_started();
                                }
                                let worker_result = (|| {
                                    if let Some(controls) = &controls {
                                        if let Some(barrier) =
                                            controls.take_public_worker_hold("classify")
                                        {
                                            barrier.enter_and_wait();
                                        }
                                    }
                                    let tenant = registered_tenant
                                        .ok_or_else(|| anyhow::anyhow!("missing tenant"))?;
                                    let normalized = tenant.normalizer.normalize(&text);
                                    let labels = tenant.classifier.classify(&normalized, top_k);
                                    Ok(ClassifyResponse {
                                        id: sanitize(&request_id, 128),
                                        labels,
                                        normalized,
                                        latency_us: 0,
                                        tenant: tenant_id.unwrap_or_default(),
                                    })
                                })();
                                if let Some(controls) = &controls {
                                    controls.public_worker_probe().worker_finished();
                                }
                                worker_result
                            })
                            .await
                        {
                            Ok(response) => (
                                rmp_serde::to_vec_named(&response).map_err(|error| {
                                    std::io::Error::new(std::io::ErrorKind::Other, error)
                                })?,
                                PlannedOutcome::Success,
                            ),
                            Err(status) if status.code() == tonic::Code::ResourceExhausted => (
                                admin_error(
                                    Command::Classify,
                                    msg.tenant.clone(),
                                    "classifier inference queue is full",
                                )
                                .map_err(|error| {
                                    std::io::Error::new(std::io::ErrorKind::Other, error)
                                })?,
                                PlannedOutcome::Failure(
                                    crate::metrics::Stage::Admission,
                                    crate::metrics::Reason::QueueFull,
                                ),
                            ),
                            Err(status) if status.code() == tonic::Code::DeadlineExceeded => (
                                admin_error(
                                    Command::Classify,
                                    msg.tenant.clone(),
                                    "classifier inference deadline exceeded",
                                )
                                .map_err(|error| {
                                    std::io::Error::new(std::io::ErrorKind::Other, error)
                                })?,
                                PlannedOutcome::Failure(
                                    crate::metrics::Stage::Worker,
                                    crate::metrics::Reason::Deadline,
                                ),
                            ),
                            Err(_status) => (
                                admin_error(
                                    Command::Classify,
                                    msg.tenant.clone(),
                                    "classifier inference failed",
                                )
                                .map_err(|error| {
                                    std::io::Error::new(std::io::ErrorKind::Other, error)
                                })?,
                                PlannedOutcome::Failure(
                                    crate::metrics::Stage::Worker,
                                    crate::metrics::Reason::InferenceFailed,
                                ),
                            ),
                        }
                    } else {
                        (
                            handle_classify(registry, &msg).map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::Other, error)
                            })?,
                            PlannedOutcome::Success,
                        )
                    }
                    #[cfg(not(test))]
                    {
                        let _ = &public_executor;
                        (
                            handle_classify(registry, &msg).map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::Other, error)
                            })?,
                            PlannedOutcome::Success,
                        )
                    }
                }
            }
            (TransportMode::Public, Command::QualityScore) => (
                handle_quality_score(&msg)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Success,
            ),
            (TransportMode::Public, Command::Version) => (
                handle_version()
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Success,
            ),
            (TransportMode::Public, Command::IntentDetect) => (
                handle_intent_detect(&msg)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Success,
            ),
            (TransportMode::Public, Command::StreamingSafety) => (
                handle_streaming_safety(&msg)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Success,
            ),
            (TransportMode::Public, Command::ContentTypeDetect) => (
                handle_content_type_detect(&msg)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Success,
            ),
            (TransportMode::Admin, Command::Register | Command::Delete | Command::List) => {
                let auth = auth.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, "missing admin auth")
                })?;
                if !auth.authenticated(msg.admin_token.as_deref()) {
                    (
                        admin_error(command, msg.tenant.clone(), "unauthorized").map_err(
                            |error| std::io::Error::new(std::io::ErrorKind::Other, error),
                        )?,
                        PlannedOutcome::Failure(
                            crate::metrics::Stage::Authorize,
                            crate::metrics::Reason::Unauthorized,
                        ),
                    )
                } else if matches!(command, Command::Register | Command::Delete)
                    && !auth.authorize(msg.admin_token.as_deref(), msg.tenant.as_deref())
                {
                    (
                        admin_error(command, msg.tenant.clone(), "tenant scope forbidden")
                            .map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::Other, error)
                            })?,
                        PlannedOutcome::Failure(
                            crate::metrics::Stage::Authorize,
                            crate::metrics::Reason::Forbidden,
                        ),
                    )
                } else {
                    match command {
                        Command::Register => {
                            let bytes = handle_register(registry, &msg).await.map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::Other, error)
                            })?;
                            let response_ok = rmp_serde::from_slice::<AdminResponse>(&bytes)
                                .map(|response| response.ok)
                                .unwrap_or(false);
                            let planned = if msg.tenant.is_none()
                                || msg.tenant.as_deref() == Some("")
                                || msg.config.is_none()
                            {
                                PlannedOutcome::Failure(
                                    crate::metrics::Stage::Handler,
                                    crate::metrics::Reason::MissingField,
                                )
                            } else if response_ok {
                                PlannedOutcome::Success
                            } else {
                                PlannedOutcome::Failure(
                                    crate::metrics::Stage::Handler,
                                    crate::metrics::Reason::InvalidConfig,
                                )
                            };
                            (bytes, planned)
                        }
                        Command::Delete => {
                            let bytes = handle_delete(registry, &msg).map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::Other, error)
                            })?;
                            let response_ok = rmp_serde::from_slice::<AdminResponse>(&bytes)
                                .map(|response| response.ok)
                                .unwrap_or(false);
                            let planned =
                                if msg.tenant.is_none() || msg.tenant.as_deref() == Some("") {
                                    PlannedOutcome::Failure(
                                        crate::metrics::Stage::Handler,
                                        crate::metrics::Reason::MissingField,
                                    )
                                } else if response_ok {
                                    PlannedOutcome::Success
                                } else {
                                    PlannedOutcome::Failure(
                                        crate::metrics::Stage::Handler,
                                        crate::metrics::Reason::TenantNotFound,
                                    )
                                };
                            (bytes, planned)
                        }
                        Command::List => {
                            match handle_list(registry, auth, msg.admin_token.as_deref(), &msg) {
                                Ok(bytes) => (bytes, PlannedOutcome::Success),
                                Err(error) => (
                                    admin_error(command, None, &error.to_string()).map_err(
                                        |serialize_error| {
                                            std::io::Error::new(
                                                std::io::ErrorKind::Other,
                                                serialize_error,
                                            )
                                        },
                                    )?,
                                    PlannedOutcome::Failure(
                                        crate::metrics::Stage::Handler,
                                        crate::metrics::Reason::ResourceLimit,
                                    ),
                                ),
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
            (TransportMode::Public, command) if command.is_admin() => (
                admin_error(
                    command,
                    msg.tenant.clone(),
                    "admin command unavailable on public transport",
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Failure(
                    crate::metrics::Stage::Authorize,
                    crate::metrics::Reason::Forbidden,
                ),
            ),
            (TransportMode::Admin, command) if !command.is_admin() => (
                admin_error(
                    command,
                    msg.tenant.clone(),
                    "inference command unavailable on admin transport",
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Failure(
                    crate::metrics::Stage::Authorize,
                    crate::metrics::Reason::Forbidden,
                ),
            ),
            (_, Command::Unknown) => (
                admin_error(Command::Unknown, None, "unknown command")
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Failure(
                    crate::metrics::Stage::Route,
                    crate::metrics::Reason::UnknownCommand,
                ),
            ),
            _ => (
                admin_error(command, msg.tenant.clone(), "unsupported command")
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?,
                PlannedOutcome::Failure(
                    crate::metrics::Stage::Handler,
                    crate::metrics::Reason::Internal,
                ),
            ),
        };

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::Handler(fault_command)) if fault_command == metrics_command(command))
        {
            outcome.failure(
                crate::metrics::Stage::Handler,
                crate::metrics::Reason::Internal,
            );
            return Ok(());
        }

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::Serialize(fault_command)) if fault_command == metrics_command(command))
        {
            outcome.failure(
                crate::metrics::Stage::Encode,
                crate::metrics::Reason::Internal,
            );
            return Ok(());
        }

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::WriteDeadline(fault_command)) if fault_command == metrics_command(command))
        {
            outcome.failure(
                crate::metrics::Stage::Write,
                crate::metrics::Reason::Deadline,
            );
            return Ok(());
        }

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::Write(fault_command)) if fault_command == metrics_command(command))
            || matches!(request_fault, Some(TcpFault::Flush(fault_command)) if fault_command == metrics_command(command))
        {
            outcome.failure(crate::metrics::Stage::Write, crate::metrics::Reason::Io);
            return Ok(());
        }

        let resp_len = (response.len() as u32).to_be_bytes();
        let write_result = tokio::time::timeout(limits.io_timeout, async {
            stream.write_all(&resp_len).await?;
            stream.write_all(&response).await?;
            stream.flush().await
        })
        .await;

        match write_result {
            Err(_) => {
                outcome.failure(
                    crate::metrics::Stage::Write,
                    crate::metrics::Reason::Deadline,
                );
                return Ok(());
            }
            Ok(Err(_error)) => {
                outcome.failure(crate::metrics::Stage::Write, crate::metrics::Reason::Io);
                return Ok(());
            }
            Ok(Ok(())) => {}
        }

        match planned_outcome {
            PlannedOutcome::Success => outcome.success(),
            PlannedOutcome::Failure(stage, reason) => outcome.failure(stage, reason),
        }

        #[cfg(test)]
        if matches!(request_fault, Some(TcpFault::PanicAfterWrite(fault_command)) if fault_command == metrics_command(command))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                CHILD_PANIC_SIGNAL,
            ));
        }
    }
}

#[cfg(test)]
std::thread_local! {
    // A raw probe address is safe here because the allocation scope borrows
    // the owning Arc and clears the cell before that borrow can end. The
    // global allocator performs atomics only: no locks, maps, or allocations.
    static FRAME_TRACKING_CONTEXT: std::cell::Cell<Option<(usize, usize, usize)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn frame_probe_enter_live_lease(bytes: usize, budget: &Arc<tokio::sync::Semaphore>) {
    FRAME_TRACKING_CONTEXT.with(|context| {
        context.set(Some((0, bytes, Arc::as_ptr(budget) as usize)));
    });
}

#[cfg(test)]
fn frame_probe_exit_live_lease(_: usize) {
    FRAME_TRACKING_CONTEXT.with(|context| context.set(None));
}

#[cfg(test)]
fn frame_probe_note_allocator_boundary(probe: &Arc<FrameAllocationProbe>, bytes: usize) {
    probe
        .allocator_boundary_calls
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    FRAME_TRACKING_CONTEXT.with(|context| match context.get() {
        Some((_, lease_bytes, owner_id)) => {
            debug_assert_eq!(lease_bytes, bytes);
            let first = probe
                .first_budget_owner_id
                .load(std::sync::atomic::Ordering::SeqCst);
            if first == 0 {
                if probe
                    .first_budget_owner_id
                    .compare_exchange(
                        0,
                        owner_id,
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    probe
                        .distinct_budget_owner_ids
                        .store(1, std::sync::atomic::Ordering::SeqCst);
                }
            } else if first != owner_id {
                probe
                    .distinct_budget_owner_ids
                    .fetch_max(2, std::sync::atomic::Ordering::SeqCst);
            }
            context.set(Some((Arc::as_ptr(probe) as usize, lease_bytes, owner_id)));
        }
        None => {
            probe
                .allocator_calls_without_live_lease
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            probe
                .allocator_bytes_without_live_lease
                .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
        }
    });
}

#[cfg(test)]
struct FrameTrackingAllocatorScope;

#[cfg(test)]
impl Drop for FrameTrackingAllocatorScope {
    fn drop(&mut self) {
        FRAME_TRACKING_CONTEXT.with(|context| {
            if let Some((_, bytes, owner_id)) = context.get() {
                context.set(Some((0, bytes, owner_id)));
            }
        });
    }
}

#[cfg(test)]
fn frame_tracking_allocator_scope(
    _: usize,
    _: Option<&Arc<FrameAllocationProbe>>,
) -> FrameTrackingAllocatorScope {
    FrameTrackingAllocatorScope
}

#[cfg(test)]
pub(crate) struct FrameTrackingAllocator<A> {
    inner: A,
}

#[cfg(test)]
impl<A> FrameTrackingAllocator<A> {
    pub(crate) const fn new(inner: A) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
unsafe impl<A: std::alloc::GlobalAlloc> std::alloc::GlobalAlloc for FrameTrackingAllocator<A> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        FRAME_TRACKING_CONTEXT.with(|context| {
            if let Some((probe_address, lease_bytes, _owner_id)) = context.get() {
                if probe_address != 0 && layout.size() >= lease_bytes {
                    // SAFETY: the active allocation scope retains the Arc
                    // whose address was stored in this thread-local cell.
                    let probe = unsafe { &*(probe_address as *const FrameAllocationProbe) };
                    probe
                        .actual_payload_allocations
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    probe
                        .actual_payload_allocation_bytes
                        .fetch_add(layout.size(), std::sync::atomic::Ordering::SeqCst);
                    let current = probe
                        .current_actual_payload_bytes
                        .fetch_add(layout.size(), std::sync::atomic::Ordering::SeqCst)
                        .saturating_add(layout.size());
                    probe
                        .peak_actual_payload_bytes
                        .fetch_max(current, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        unsafe { self.inner.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { self.inner.dealloc(ptr, layout) }
    }
}

#[cfg(test)]
impl FrameAllocationProbe {
    async fn acquire_unique() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn allocator_boundary_calls(&self) -> usize {
        self.allocator_boundary_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn actual_payload_allocations(&self) -> usize {
        self.actual_payload_allocations
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn actual_payload_allocation_bytes(&self) -> usize {
        self.actual_payload_allocation_bytes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn allocator_calls_without_live_lease(&self) -> usize {
        self.allocator_calls_without_live_lease
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn allocator_bytes_without_live_lease(&self) -> usize {
        self.allocator_bytes_without_live_lease
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn actual_payload_allocations_without_live_lease(&self) -> usize {
        self.actual_payload_allocations_without_live_lease
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn peak_actual_payload_bytes(&self) -> usize {
        self.peak_actual_payload_bytes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn distinct_budget_owner_ids(&self) -> usize {
        self.distinct_budget_owner_ids
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn wait_for_allocations(&self, expected: usize, within: Duration) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.allocations() == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "frame allocations did not reach {expected}; current value is {}",
                    self.allocations()
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn wait_for_declared_frames(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.declared_frames() == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "declared frames did not reach {expected}; current value is {}",
                    self.declared_frames()
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn wait_for_current_bytes(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.current.load(std::sync::atomic::Ordering::SeqCst) == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "current frame bytes did not reach {expected}; current value is {}",
                    self.current.load(std::sync::atomic::Ordering::SeqCst)
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        TenantClassification, TenantConfig, TenantLabel, TenantNormRule, TenantNormalization,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    trait AmbiguousIfFrameLeaseClone<Marker> {
        fn assert_not_clone() {}
    }

    impl<T: ?Sized> AmbiguousIfFrameLeaseClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfFrameLeaseClone<u8> for T {}

    trait AmbiguousIfFrameLeaseDefault<Marker> {
        fn assert_not_default() {}
    }

    impl<T: ?Sized> AmbiguousIfFrameLeaseDefault<()> for T {}
    impl<T: ?Sized + Default> AmbiguousIfFrameLeaseDefault<u8> for T {}

    struct WarningCounter(Arc<AtomicUsize>);

    impl tracing::Subscriber for WarningCounter {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.level() == &tracing::Level::WARN
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, _: &tracing::Event<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

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

    fn independent_source_bytes(config: &TenantConfig) -> usize {
        let classifier = config
            .labels
            .iter()
            .flat_map(|label| label.patterns.iter())
            .map(String::len)
            .sum::<usize>();
        let normalizer = config
            .normalization
            .iter()
            .flat_map(|normalization| normalization.rules.iter())
            .map(|rule| rule.pattern.len() + rule.replace.len())
            .sum::<usize>();
        classifier + normalizer
    }

    fn independent_persistent_string_bytes(config: &TenantConfig) -> usize {
        let labels = config
            .labels
            .iter()
            .map(|label| label.name.len() + label.patterns.iter().map(String::len).sum::<usize>())
            .sum::<usize>();
        let default_label = config
            .classification
            .as_ref()
            .map_or(0, |classification| classification.default_label.len());
        let normalization = config
            .normalization
            .iter()
            .flat_map(|normalization| normalization.rules.iter())
            .map(|rule| rule.name.len() + rule.pattern.len() + rule.replace.len())
            .sum::<usize>();
        labels + default_label + normalization
    }

    fn independent_serialized_config_bytes(config: &TenantConfig) -> usize {
        rmp_serde::to_vec_named(config)
            .expect("the test-owned wire serialization oracle is valid")
            .len()
    }

    fn independent_tenant_info_bytes(info: &crate::protocol::TenantInfo) -> usize {
        info.id.len() + info.labels.iter().map(String::len).sum::<usize>()
    }

    #[tokio::test]
    async fn cleanup_probe_wait_for_shutdown_observes_pre_signaled_shutdown() {
        let cleanup = TcpListenerCleanupProbe::default();
        cleanup
            .request_graceful_shutdown_before(tokio::time::Instant::now() + Duration::from_secs(1));

        tokio::time::timeout(Duration::from_secs(1), cleanup.wait_for_shutdown())
            .await
            .expect("pre-signaled TCP shutdown must not miss its notify wake");
    }

    #[tokio::test]
    async fn cleanup_probe_wait_for_deadline_update_observes_pre_signaled_update() {
        let cleanup = TcpListenerCleanupProbe::default();
        let original_id = cleanup.shutdown_deadline_id();
        cleanup
            .request_graceful_shutdown_before(tokio::time::Instant::now() + Duration::from_secs(1));

        tokio::time::timeout(
            Duration::from_secs(1),
            cleanup.wait_for_deadline_update(original_id),
        )
        .await
        .expect("pre-signaled TCP deadline update must not miss its notify wake");
    }

    async fn wire_exchange(stream: &mut TcpStream, message: &Message) -> Vec<u8> {
        wire_exchange_before(
            stream,
            message,
            tokio::time::Instant::now() + Duration::from_secs(3),
        )
        .await
    }

    async fn wire_exchange_before(
        stream: &mut TcpStream,
        message: &Message,
        deadline: tokio::time::Instant,
    ) -> Vec<u8> {
        let payload = rmp_serde::to_vec_named(message).unwrap();
        tokio::time::timeout_at(deadline, async {
            stream
                .write_all(&(payload.len() as u32).to_be_bytes())
                .await?;
            stream.write_all(&payload).await?;
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).await?;
            let response_len = u32::from_be_bytes(length) as usize;
            assert!(
                response_len <= MAX_FRAME_BYTES,
                "wire response declared {response_len} bytes above the {MAX_FRAME_BYTES}-byte test ceiling"
            );
            let mut response = vec![0u8; response_len];
            stream.read_exact(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        })
        .await
        .expect("wire exchange reached its shared absolute deadline")
        .expect("wire exchange succeeds")
    }

    async fn bounded_tcp_connect(address: std::net::SocketAddr, case: &str) -> TcpStream {
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(address))
            .await
            .unwrap_or_else(|_| panic!("TCP connect deadline expired: {case}"))
            .unwrap_or_else(|error| panic!("TCP connect failed for {case}: {error}"))
    }

    async fn raw_exchange_until_close(
        address: std::net::SocketAddr,
        bytes: &[u8],
        shutdown_write: bool,
    ) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(bytes).await?;
            if shutdown_write {
                stream.shutdown().await?;
            }
            let mut response = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(read) => {
                        let next = response
                            .len()
                            .checked_add(read)
                            .expect("raw TCP response length cannot overflow usize");
                        assert!(
                            next <= MAX_FRAME_BYTES + 4,
                            "raw TCP response exceeded its framed response capture ceiling"
                        );
                        response.extend_from_slice(&chunk[..read]);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::NotConnected
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok::<_, std::io::Error>(response)
        })
        .await
        .expect("raw TCP terminal wait is bounded")
        .expect("raw TCP terminal capture succeeds")
    }

    async fn assert_socket_refused_without_response(mut stream: TcpStream, case: &str) {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte)).await {
            Ok(Ok(0)) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Ok(Ok(read)) => panic!("{case} returned {read} unexpected response bytes"),
            Ok(Err(error)) => panic!("{case} failed with an unexpected socket error: {error}"),
            Err(_) => panic!("{case} did not reach EOF/reset before its deadline"),
        }
    }

    struct BoundedHttpResponse {
        status: u16,
        body: Vec<u8>,
    }

    async fn bounded_http_tenant_response(
        address: std::net::SocketAddr,
        path: &str,
        token: &str,
        max_body_bytes: usize,
    ) -> BoundedHttpResponse {
        const MAX_HEADER_BYTES: usize = 8 * 1024;

        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = TcpStream::connect(address).await?;
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
            );
            assert!(
                request.len() <= MAX_HEADER_BYTES,
                "HTTP tenant-page request exceeds its test ceiling"
            );
            stream.write_all(request.as_bytes()).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                let capture_ceiling = MAX_HEADER_BYTES
                    .checked_add(max_body_bytes)
                    .expect("HTTP tenant-page capture ceiling cannot overflow");
                let next = response
                    .len()
                    .checked_add(read)
                    .expect("HTTP tenant-page captured-byte count cannot overflow");
                assert!(
                    next <= capture_ceiling,
                    "HTTP tenant-page response exceeds its total capture ceiling"
                );
                response.extend_from_slice(&chunk[..read]);
            }
            let split = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("HTTP tenant-page response has a bounded header terminator");
            assert!(split <= MAX_HEADER_BYTES);
            let header = std::str::from_utf8(&response[..split]).unwrap();
            let status = header
                .lines()
                .next()
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .expect("HTTP tenant-page response has a numeric status");
            let body = response[split + 4..].to_vec();
            assert!(body.len() <= max_body_bytes);
            Ok::<_, std::io::Error>(BoundedHttpResponse { status, body })
        })
        .await
        .expect("HTTP tenant-page exchange has one absolute deadline")
        .expect("HTTP tenant-page exchange succeeds")
    }

    async fn bounded_http_tenant_page(
        address: std::net::SocketAddr,
        path: &str,
        token: &str,
        max_body_bytes: usize,
    ) -> Vec<u8> {
        let response = bounded_http_tenant_response(address, path, token, max_body_bytes).await;
        assert_eq!(
            response.status, 200,
            "authenticated tenant page must be a 200 response"
        );
        response.body
    }

    struct TestTcpListenerPair {
        public_address: std::net::SocketAddr,
        admin_address: std::net::SocketAddr,
        task: tokio::task::JoinHandle<Result<TcpListenerExitReport, TcpListenerAssemblyError>>,
        cleanup: Arc<TcpListenerCleanupProbe>,
    }

    async fn spawn_production_listener_pair(
        registry: Arc<Registry>,
        auth: Arc<AdminAuth>,
        limits: TcpLimits,
        controls: Arc<TcpTestControl>,
        allocation_probe: Option<Arc<FrameAllocationProbe>>,
    ) -> TestTcpListenerPair {
        let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_address = public.local_addr().unwrap();
        let admin_address = admin.local_addr().unwrap();
        let cleanup = Arc::new(TcpListenerCleanupProbe::default());
        let public_work_limits = limits.public_work_limits();
        // `TcpListenerAssembly` is the deliberately absent production owner:
        // main and this fixture must enter this exact path, and only it can
        // construct the opaque cross-listener `FrameBudget`.
        let assembly = TcpListenerAssembly::new(registry, Some(auth), limits)
            .with_public_work_limits(public_work_limits)
            .with_test_control(controls)
            .with_test_allocation_probe(allocation_probe)
            .with_test_cleanup_probe(Arc::clone(&cleanup));
        let task = tokio::spawn(async move { assembly.serve_on(public, Some(admin)).await });
        TestTcpListenerPair {
            public_address,
            admin_address,
            task,
            cleanup,
        }
    }

    impl TestTcpListenerPair {
        fn bind_failure_collection_deadline(&self, deadline: tokio::time::Instant) {
            self.cleanup.bind_failure_collection_deadline(deadline);
        }

        async fn stop(self) {
            assert!(
                !self.task.is_finished(),
                "paired production TCP listener exited before explicit cleanup"
            );
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            self.cleanup.request_graceful_shutdown_before(deadline);
            let join = tokio::time::timeout_at(deadline, self.task)
                .await
                .expect("paired production TCP listeners join before cleanup deadline")
                .expect("paired production TCP owner task must not panic");
            let exit =
                join.expect("paired production TCP listeners report clean graceful shutdown");
            exit.assert_quiescent_at_return()
                .expect("paired TCP owner returns only after collecting every child result");
            assert_eq!(exit.active_connection_children(), 0);
            assert_eq!(
                exit.connection_children_spawned(),
                exit.connection_children_finished(),
                "paired listener cleanup may not detach a frame/response child"
            );
            assert_eq!(
                exit.connection_child_results_collected(),
                exit.connection_children_spawned(),
                "the paired owner must join and inspect every connection child"
            );
            assert_eq!(exit.connection_child_panics(), 0);
            assert_eq!(exit.connection_child_events_after_owner_return(), 0);
            assert_eq!(
                exit.collection_deadline_id(),
                self.cleanup.shutdown_deadline_id()
            );
        }

        async fn expect_connection_child_panic_before(
            self,
            mode: TransportMode,
            deadline: tokio::time::Instant,
        ) {
            let joined = tokio::time::timeout_at(deadline, self.task)
                .await
                .expect("connection-child panic reaches the paired owner before its deadline")
                .expect("the paired owner task itself must not panic");
            let error =
                joined.expect_err("a response-then-panic child must fail the outer listener owner");
            assert!(
                error.is_connection_child_panic(mode),
                "the surfaced listener error retains the panicking child's transport: {error}"
            );
            let exit = error
                .exit_report()
                .expect("connection-child panic errors retain their exit report");
            exit.assert_quiescent_at_return()
                .expect("panic reaches the owner only after all sibling results are collected");
            assert_eq!(exit.active_connection_children(), 0);
            assert_eq!(
                exit.connection_children_spawned(),
                exit.connection_children_finished()
            );
            assert_eq!(
                exit.connection_child_results_collected(),
                exit.connection_children_spawned(),
                "outer failure is reported only after every child result is collected"
            );
            assert_eq!(exit.connection_child_panics(), 1);
            assert_eq!(
                exit.connection_child_events_after_owner_return(),
                0,
                "the response-then-panic case cannot be repaired by a detached reaper"
            );
            assert_eq!(
                exit.collection_deadline_id(),
                self.cleanup.shutdown_deadline_id()
            );
        }
    }

    #[tokio::test]
    async fn paired_owner_rejects_missing_admin_auth_before_permit_or_connection_accounting() {
        let registry = Arc::new(Registry::new_empty());
        let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let controls = Arc::new(TcpTestControl::default());

        let error = TcpListenerAssembly::new(registry, None, TcpLimits::default())
            .with_test_control(Arc::clone(&controls))
            .serve_on(public, Some(admin))
            .await
            .expect_err("admin listener without authentication must be rejected at owner entry");

        assert!(matches!(
            error,
            TcpListenerAssemblyError::MissingAdminAuthentication
        ));
        assert_eq!(controls.active_connections(TransportMode::Public), 0);
        assert_eq!(controls.active_connections(TransportMode::Admin), 0);
        assert_eq!(
            controls
                .counters(TransportMode::Public)
                .connection_refusals
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            controls
                .counters(TransportMode::Admin)
                .connection_refusals
                .load(Ordering::SeqCst),
            0
        );
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
                frame_budget(),
                None,
            )
            .await;
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .expect("connect within timeout")
            .expect("connect succeeds");

        wire_exchange(&mut stream, msg).await
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
            page_size: None,
            cursor: None,
        }
    }

    fn clone_message(message: &Message) -> Message {
        rmp_serde::from_slice(&rmp_serde::to_vec_named(message).unwrap()).unwrap()
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

    #[tokio::test(flavor = "current_thread")]
    async fn repeated_unknown_tenants_return_bounded_sanitized_errors() {
        let registry = Arc::new(Registry::new_empty());
        let hostile_tenant = format!("attacker\nheader\r{}", "é".repeat(2_048));
        let warning_count = Arc::new(AtomicUsize::new(0));
        let _subscriber =
            tracing::subscriber::set_default(WarningCounter(Arc::clone(&warning_count)));

        for _ in 0..8 {
            let mut classify_msg = msg("classify");
            classify_msg.tenant = Some(hostile_tenant.clone());
            classify_msg.text = "hi".to_string();
            let response = round_trip(Arc::clone(&registry), &classify_msg).await;
            let response: AdminResponse = rmp_serde::from_slice(&response).unwrap();
            let tenant = response
                .tenant
                .expect("unknown tenant echoed in bounded form");
            let error = response.error.expect("unknown tenant error");

            assert!(tenant.len() <= 131);
            assert!(error.len() <= 96);
            assert!(!tenant.chars().any(char::is_control));
            assert!(!error.chars().any(char::is_control));
        }
        assert_eq!(
            warning_count.load(Ordering::Relaxed),
            0,
            "routine unknown-tenant refusals must not emit one warning per request"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp() {
        let registry = Arc::new(Registry::new_empty());
        let warning_count = Arc::new(AtomicUsize::new(0));
        let _subscriber =
            tracing::subscriber::set_default(WarningCounter(Arc::clone(&warning_count)));

        for tenant in [None, Some(String::new())] {
            let mut classify_msg = msg("classify");
            classify_msg.tenant = tenant;
            classify_msg.text = "hi".to_string();
            let response = round_trip(Arc::clone(&registry), &classify_msg).await;
            let response: AdminResponse = rmp_serde::from_slice(&response).unwrap();

            assert!(!response.ok);
            assert!(response.error.unwrap().contains("not registered"));
        }
        assert_eq!(
            warning_count.load(Ordering::Relaxed),
            0,
            "omitted and empty tenant refusals must not emit release-level warnings"
        );
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
    async fn public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        const FRAME_SLOTS: usize = MAX_IN_FLIGHT_FRAME_BYTES / MAX_FRAME_BYTES;
        // Admission and allocation are two different ownership transitions:
        // the semaphore is acquired first, then the non-forgeable lease is
        // consumed by value at the only Vec allocation boundary and retained
        // by BudgetedFrame.  Moving `vec![0; bytes]` before either function
        // cannot satisfy these signatures or the allocator-boundary probe.
        type FrameLeaseFactory = fn(
            Arc<tokio::sync::Semaphore>,
            usize,
        ) -> Result<FrameAllocationLease, BudgetedFrameError>;
        type BudgetedFrameAllocator =
            fn(FrameAllocationLease, Option<&Arc<FrameAllocationProbe>>) -> BudgetedFrame;
        let _frame_lease_factory: FrameLeaseFactory = FrameAllocationLease::try_acquire;
        let _budgeted_frame_allocator: BudgetedFrameAllocator = BudgetedFrame::allocate_from_lease;
        let _ = <FrameAllocationLease as AmbiguousIfFrameLeaseClone<_>>::assert_not_clone;
        let _ = <FrameAllocationLease as AmbiguousIfFrameLeaseDefault<_>>::assert_not_default;
        assert_eq!(
            std::mem::size_of::<FrameAllocationLease>(),
            std::mem::size_of::<tokio::sync::OwnedSemaphorePermit>(),
            "an admission lease cannot hide a Vec, Box, or other payload owner"
        );
        assert_eq!(
            std::mem::align_of::<FrameAllocationLease>(),
            std::mem::align_of::<tokio::sync::OwnedSemaphorePermit>()
        );

        let outcomes = OutcomeProbe::acquire_unique().await;
        let registry = Arc::new(Registry::new_empty());
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#).unwrap(),
        );
        let probe = FrameAllocationProbe::acquire_unique().await;
        let pair = spawn_production_listener_pair(
            registry,
            auth,
            TcpLimits {
                max_connections: DEFAULT_MAX_CONNECTIONS,
                io_timeout: Duration::from_secs(60),
            },
            Arc::new(TcpTestControl::default()),
            Some(Arc::clone(&probe)),
        )
        .await;

        let mut held = Vec::new();
        for (mode, address) in [
            (TransportMode::Public, pair.public_address),
            (TransportMode::Admin, pair.admin_address),
            (TransportMode::Public, pair.public_address),
            (TransportMode::Admin, pair.admin_address),
        ] {
            let mut stream =
                tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(address))
                    .await
                    .expect("exact-limit frame socket connects")
                    .unwrap();
            tokio::time::timeout(
                Duration::from_secs(3),
                stream.write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes()),
            )
            .await
            .expect("maximum frame header write is bounded")
            .unwrap();
            held.push((mode, stream));
        }
        probe
            .wait_for_allocations(FRAME_SLOTS, Duration::from_secs(3))
            .await
            .expect("the exact cross-listener frame budget becomes resident");

        for (name, address, transport) in [
            ("public frame plus one", pair.public_address, Transport::Tcp),
            (
                "admin frame plus one",
                pair.admin_address,
                Transport::AdminTcp,
            ),
        ] {
            let before = outcomes.snapshot();
            let mut plus_one =
                tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(address))
                    .await
                    .expect("plus-one frame socket connect is bounded")
                    .unwrap();
            tokio::time::timeout(
                Duration::from_secs(3),
                plus_one.write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes()),
            )
            .await
            .expect("plus-one frame header write is bounded")
            .unwrap();
            assert_socket_refused_without_response(plus_one, name).await;
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Admission,
                    Reason::ResourceLimit,
                ),
                name,
            );
        }
        probe
            .wait_for_declared_frames(FRAME_SLOTS + 2, Duration::from_secs(3))
            .await
            .expect("both plus-one headers reach the production frame owner");
        let declared_at_limit = probe.declared_frames();
        let allocations_at_limit = probe.allocations();
        let allocator_calls_at_limit = probe.allocator_boundary_calls();
        let actual_vec_allocations_at_limit = probe.actual_payload_allocations();
        let actual_vec_bytes_at_limit = probe.actual_payload_allocation_bytes();
        let peak_at_limit = probe.peak_bytes();

        let public_index = held
            .iter()
            .position(|(mode, _)| *mode == TransportMode::Public)
            .unwrap();
        drop(held.swap_remove(public_index));
        probe
            .wait_for_current_bytes(
                MAX_IN_FLIGHT_FRAME_BYTES - MAX_FRAME_BYTES,
                Duration::from_secs(3),
            )
            .await
            .expect("dropping public ownership returns one shared frame lease");
        let mut admin_recovery =
            bounded_tcp_connect(pair.admin_address, "admin cross-listener recovery").await;
        tokio::time::timeout(
            Duration::from_secs(3),
            admin_recovery.write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes()),
        )
        .await
        .expect("admin recovery header write is bounded")
        .unwrap();
        probe
            .wait_for_allocations(FRAME_SLOTS + 1, Duration::from_secs(3))
            .await
            .expect("admin reuses a lease released by public");

        let admin_index = held
            .iter()
            .position(|(mode, _)| *mode == TransportMode::Admin)
            .unwrap();
        drop(held.swap_remove(admin_index));
        probe
            .wait_for_current_bytes(
                MAX_IN_FLIGHT_FRAME_BYTES - MAX_FRAME_BYTES,
                Duration::from_secs(3),
            )
            .await
            .expect("dropping admin ownership returns one shared frame lease");
        let mut public_recovery =
            bounded_tcp_connect(pair.public_address, "public cross-listener recovery").await;
        tokio::time::timeout(
            Duration::from_secs(3),
            public_recovery.write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes()),
        )
        .await
        .expect("public recovery header write is bounded")
        .unwrap();
        probe
            .wait_for_allocations(FRAME_SLOTS + 2, Duration::from_secs(3))
            .await
            .expect("public reuses a lease released by admin");
        let allocations_after_recovery = probe.allocations();
        let allocator_calls_after_recovery = probe.allocator_boundary_calls();
        let actual_vec_allocations_after_recovery = probe.actual_payload_allocations();
        let peak_after_recovery = probe.peak_bytes();

        drop(admin_recovery);
        drop(public_recovery);
        drop(held);
        pair.stop().await;

        assert_eq!(declared_at_limit, FRAME_SLOTS + 2);
        assert_eq!(allocations_at_limit, FRAME_SLOTS);
        assert_eq!(allocator_calls_at_limit, FRAME_SLOTS);
        assert_eq!(actual_vec_allocations_at_limit, FRAME_SLOTS);
        assert_eq!(actual_vec_bytes_at_limit, MAX_IN_FLIGHT_FRAME_BYTES);
        assert_eq!(peak_at_limit, MAX_IN_FLIGHT_FRAME_BYTES);
        assert_eq!(allocations_after_recovery, FRAME_SLOTS + 2);
        assert_eq!(allocator_calls_after_recovery, FRAME_SLOTS + 2);
        assert_eq!(actual_vec_allocations_after_recovery, FRAME_SLOTS + 2);
        assert_eq!(peak_after_recovery, MAX_IN_FLIGHT_FRAME_BYTES);
        assert_eq!(
            probe.allocator_calls_without_live_lease(),
            0,
            "the actual Vec allocation boundary is unreachable without a live frame lease"
        );
        assert_eq!(
            probe.allocator_bytes_without_live_lease(),
            0,
            "a refused fifth four-MiB frame must allocate zero payload bytes"
        );
        assert_eq!(
            probe.actual_payload_allocations_without_live_lease(),
            0,
            "the global allocator observed no real four-MiB Vec before admission"
        );
        assert_eq!(
            probe.peak_actual_payload_bytes(),
            MAX_IN_FLIGHT_FRAME_BYTES,
            "a transient refused allocation cannot hide between adjacent probe calls"
        );
        assert_eq!(
            probe.distinct_budget_owner_ids(),
            1,
            "public and admin allocations must originate from one opaque assembly owner"
        );
    }

    #[tokio::test]
    async fn paired_tcp_listener_surfaces_connection_child_panic_after_response() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Transport,
        };

        let outcomes = OutcomeProbe::acquire_unique().await;
        let registry = Arc::new(Registry::new_empty());
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#).unwrap(),
        );
        let controls = Arc::new(TcpTestControl::default());
        let pair = spawn_production_listener_pair(
            registry,
            auth,
            TcpLimits::default(),
            Arc::clone(&controls),
            None,
        )
        .await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        pair.bind_failure_collection_deadline(deadline);
        let fault = controls.arm_next(
            TransportMode::Public,
            TcpFault::PanicAfterWrite(MetricCommand::Version),
        );
        let before = outcomes.snapshot();
        let mut client = tokio::time::timeout_at(deadline, TcpStream::connect(pair.public_address))
            .await
            .expect("response-then-panic connect shares the case deadline")
            .unwrap();
        let response: VersionResponse = rmp_serde::from_slice(
            &wire_exchange_before(&mut client, &msg("version"), deadline).await,
        )
        .unwrap();
        assert_eq!(response.name, SERVER_NAME);
        assert_eq!(response.version, SERVER_VERSION);
        fault.assert_consumed_exactly_once();
        before.assert_exact_terminal_delta(
            OutcomeExpectation::success(Transport::Tcp, MetricCommand::Version),
            "response completed before connection-child panic",
        );
        drop(client);

        pair.expect_connection_child_panic_before(TransportMode::Public, deadline)
            .await;
    }

    #[tokio::test]
    async fn authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery() {
        const MAX_TENANTS: usize = 64;
        const MAX_LIST_PAGE: usize = 32;
        const PAGINATION_PAGE_SIZE: usize = 7;
        const HTTP_PAGE_SIZE: usize = 3;
        const SPARSE_TCP_PAGE_SIZE: usize = 5;
        const SPARSE_HTTP_PAGE_SIZE: usize = 2;
        const HTTP_REFUSAL_CAPTURE_BYTES: usize = 8 * 1024;
        // Hand-derived MessagePack named-map size:
        // map + ok + cmd + tenants key/array + seven 39-byte tenant maps +
        // next_cursor key/value = 1 + 4 + 9 + 9 + (7 * 39) + 30.
        // This literal is independent of AdminResponse and rmp-serde.
        const EXACT_ADMIN_FIRST_PAGE_MSGPACK_BYTES: usize = 326;
        const EXACT_HTTP_FIRST_PAGE_JSON: &[u8] = br#"{"tenants":[{"id":"tenant-00.example","labels":["greeting"]},{"id":"tenant-01.example","labels":["greeting"]},{"id":"tenant-02.example","labels":["greeting"]}],"next_cursor":"tenant-02.example"}"#;
        let mut expected_ids = (0..MAX_TENANTS)
            .map(|index| format!("tenant-{index:02}.example"))
            .collect::<std::collections::BTreeSet<_>>();
        let sparse_visible_ids = (0..MAX_TENANTS)
            .filter(|index| index % 2 == 0)
            .map(|index| format!("tenant-{index:02}.example"))
            .collect::<std::collections::BTreeSet<_>>();
        let sparse_hidden_ids = (0..MAX_TENANTS)
            .filter(|index| index % 2 == 1)
            .map(|index| format!("tenant-{index:02}.example"))
            .collect::<std::collections::BTreeSet<_>>();
        let expected_first_page = AdminResponse {
            ok: true,
            cmd: "list".to_string(),
            tenant: None,
            error: None,
            tenants: Some(
                expected_ids
                    .iter()
                    .take(PAGINATION_PAGE_SIZE)
                    .map(|id| crate::protocol::TenantInfo {
                        id: id.clone(),
                        labels: vec!["greeting".to_string()],
                    })
                    .collect(),
            ),
            next_cursor: Some("tenant-06.example".to_string()),
        };
        let max_list_response_bytes = EXACT_ADMIN_FIRST_PAGE_MSGPACK_BYTES;
        let max_http_list_response_bytes = EXACT_HTTP_FIRST_PAGE_JSON.len();
        let exact_http_first_page: serde_json::Value =
            serde_json::from_slice(EXACT_HTTP_FIRST_PAGE_JSON)
                .expect("the independent literal HTTP page oracle is valid JSON");
        let exact_page_materialized_bytes = expected_first_page
            .tenants
            .as_ref()
            .unwrap()
            .iter()
            .map(independent_tenant_info_bytes)
            .sum::<usize>();
        let max_page_materialized_bytes = exact_page_materialized_bytes * 2;
        let compile_probe = Arc::new(crate::registry::TenantCompileProbe::default());
        let list_probe = Arc::new(crate::registry::TenantListProbe::default());
        let limits = crate::registry::TenantRegistryLimits::production_defaults()
            .with_max_tenants(MAX_TENANTS)
            .with_max_list_page(MAX_LIST_PAGE)
            .with_max_list_materialized_bytes(max_page_materialized_bytes)
            .with_max_admin_list_response_bytes(max_list_response_bytes)
            .with_max_http_list_response_bytes(max_http_list_response_bytes);
        assert_eq!(
            limits.max_list_materialized_bytes(),
            max_page_materialized_bytes
        );
        assert_eq!(
            limits.max_admin_list_response_bytes(),
            max_list_response_bytes
        );
        assert_eq!(
            limits.max_http_list_response_bytes(),
            max_http_list_response_bytes
        );
        let budget = crate::registry::TenantRegistryBudget::new(limits.clone())
            .unwrap()
            .with_test_list_probe(Arc::clone(&list_probe));
        let compiler = crate::registry::TenantCompiler::bounded(2)
            .unwrap()
            .with_test_probe(Arc::clone(&compile_probe));
        let registry = Arc::new(Registry::new(budget, compiler));
        let sparse_grants = sparse_visible_ids.iter().cloned().collect::<Vec<_>>();
        let auth_fixture = serde_json::to_vec(&serde_json::json!({
            "tokens": [
                {"token": "secret", "tenants": ["*"]},
                {"token": "sparse", "tenants": sparse_grants},
            ]
        }))
        .unwrap();
        let auth = Arc::new(AdminAuth::from_json(&auth_fixture).unwrap());
        let pair = spawn_production_listener_pair(
            Arc::clone(&registry),
            Arc::clone(&auth),
            TcpLimits::default(),
            Arc::new(TcpTestControl::default()),
            None,
        )
        .await;
        let mut admin = bounded_tcp_connect(pair.admin_address, "registry admin session").await;

        let mut empty_list = msg("list");
        empty_list.admin_token = Some("secret".to_string());
        empty_list.page_size = Some(MAX_LIST_PAGE);
        let empty_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &empty_list).await).unwrap();
        assert!(empty_response.ok);
        assert!(empty_response.tenants.unwrap_or_default().is_empty());
        assert!(empty_response.next_cursor.is_none());
        empty_list.page_size = Some(MAX_LIST_PAGE + 1);
        let page_size_plus_one: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &empty_list).await).unwrap();
        assert!(
            !page_size_plus_one.ok,
            "page-size plus one is refused even when an empty result would fit by bytes"
        );

        let orthogonal_accounting = TenantConfig {
            labels: vec![TenantLabel {
                name: "L".to_string(),
                patterns: vec!["aa".to_string(), "bbb".to_string()],
                weight: 1.0,
            }],
            classification: Some(TenantClassification {
                confidence_threshold: 0.1,
                default_label: "D".to_string(),
                default_boost: 0.5,
            }),
            normalization: Some(TenantNormalization {
                unicode_nfkc: false,
                trim: false,
                rules: vec![
                    TenantNormRule {
                        name: "en".to_string(),
                        pattern: "cccc".to_string(),
                        replace: "ddddd".to_string(),
                        enabled: true,
                    },
                    TenantNormRule {
                        name: "dis".to_string(),
                        pattern: "ffffff".to_string(),
                        replace: "ggggggg".to_string(),
                        enabled: false,
                    },
                ],
            }),
        };
        assert_eq!(
            independent_source_bytes(&orthogonal_accounting),
            2 + 3 + 4 + 5 + 6 + 7,
            "classifier, enabled-normalizer, and disabled-normalizer source components use a literal oracle",
        );
        assert_eq!(
            independent_persistent_string_bytes(&orthogonal_accounting),
            1 + 2 + 3 + 1 + 2 + 4 + 5 + 3 + 6 + 7,
            "label/default/rule names and every pattern/replacement contribute independently",
        );

        for index in 0..MAX_TENANTS {
            let mut register = msg("register");
            let tenant_id = format!("tenant-{index:02}.example");
            register.tenant = Some(tenant_id);
            register.config = Some(sample_tenant_config());
            register.admin_token = Some("secret".to_string());
            let response: AdminResponse =
                rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();
            assert!(response.ok, "exact-limit tenant {index} must register");
        }
        let exact_count = registry.tenant_count();
        compile_probe
            .wait_for_completed(MAX_TENANTS, Duration::from_secs(3))
            .await
            .expect("the accepted controls compile on the bounded executor");

        let mut exact_page = msg("list");
        exact_page.admin_token = Some("secret".to_string());
        exact_page.page_size = Some(PAGINATION_PAGE_SIZE);
        let admin_exact_admissions_before =
            list_probe.lifetime_response_admissions(crate::registry::TenantPageBoundary::AdminTcp);
        let admin_exact_materializations_before =
            list_probe.lifetime_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp);
        let admin_exact_string_clones_before =
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::AdminTcp);
        let exact_page_bytes = wire_exchange(&mut admin, &exact_page).await;
        assert_eq!(
            exact_page_bytes.len(),
            max_list_response_bytes,
            "the deterministic first page reaches the exact response-byte ceiling"
        );
        let exact_page_response: AdminResponse = rmp_serde::from_slice(&exact_page_bytes).unwrap();
        assert_eq!(exact_page_response.ok, expected_first_page.ok);
        assert_eq!(exact_page_response.cmd, expected_first_page.cmd);
        assert_eq!(
            exact_page_response
                .tenants
                .as_ref()
                .expect("exact MessagePack page contains tenants")
                .iter()
                .map(|tenant| tenant.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "tenant-00.example",
                "tenant-01.example",
                "tenant-02.example",
                "tenant-03.example",
                "tenant-04.example",
                "tenant-05.example",
                "tenant-06.example",
            ]
        );
        assert_eq!(
            exact_page_response.next_cursor.as_deref(),
            Some("tenant-06.example")
        );
        assert_eq!(
            list_probe.lifetime_response_admissions(crate::registry::TenantPageBoundary::AdminTcp,),
            admin_exact_admissions_before + 1,
            "the exact MessagePack page acquires one response lease"
        );
        assert_eq!(
            list_probe
                .lifetime_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp,),
            admin_exact_materializations_before + PAGINATION_PAGE_SIZE
        );
        assert_eq!(
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::AdminTcp,),
            admin_exact_string_clones_before + (2 * PAGINATION_PAGE_SIZE),
            "each admitted projection clones one id and one label"
        );
        assert_eq!(
            list_probe.lifetime_materializations_without_response_admission(
                crate::registry::TenantPageBoundary::AdminTcp,
            ),
            0,
            "MessagePack admission precedes the actual TenantInfo/String clone boundary"
        );
        assert_eq!(
            list_probe.lifetime_string_clones_without_response_admission(
                crate::registry::TenantPageBoundary::AdminTcp,
            ),
            0
        );

        let mut expanded = sample_tenant_config();
        expanded.labels[0].name.push('x');
        expanded
            .classification
            .as_mut()
            .unwrap()
            .default_label
            .push('x');
        let mut replace = msg("register");
        replace.tenant = Some("tenant-00.example".to_string());
        replace.config = Some(expanded);
        replace.admin_token = Some("secret".to_string());
        let replace_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &replace).await).unwrap();
        assert!(replace_response.ok);
        let tenant_page_serializations_before_plus_one =
            list_probe.page_serializations(crate::registry::TenantPageBoundary::AdminTcp);
        let tenant_page_materializations_before_plus_one =
            list_probe.lifetime_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp);
        let tenant_page_string_clones_before_plus_one =
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::AdminTcp);
        let tenant_page_refusals_before_plus_one = list_probe
            .lifetime_response_admission_refusals(crate::registry::TenantPageBoundary::AdminTcp);
        let no_page_serialization =
            list_probe.forbid_page_serialization(crate::registry::TenantPageBoundary::AdminTcp);
        let no_page_materialization =
            list_probe.forbid_page_materialization(crate::registry::TenantPageBoundary::AdminTcp);
        let oversized_page: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &exact_page).await).unwrap();
        no_page_serialization.assert_not_triggered();
        no_page_materialization.assert_not_triggered();
        drop(no_page_serialization);
        drop(no_page_materialization);
        assert!(
            !oversized_page.ok,
            "a one-byte-larger deterministic page must be refused before serialization"
        );
        assert_eq!(
            list_probe.page_serializations(crate::registry::TenantPageBoundary::AdminTcp),
            tenant_page_serializations_before_plus_one,
            "response-byte admission precedes tenant-page serialization"
        );
        assert_eq!(
            list_probe
                .lifetime_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp,),
            tenant_page_materializations_before_plus_one,
            "a refused MessagePack page performs zero TenantInfo materializations"
        );
        assert_eq!(
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::AdminTcp,),
            tenant_page_string_clones_before_plus_one,
            "a refused MessagePack page performs zero id/label String clones"
        );
        assert_eq!(
            list_probe.lifetime_response_admission_refusals(
                crate::registry::TenantPageBoundary::AdminTcp,
            ),
            tenant_page_refusals_before_plus_one + 1
        );
        replace.config = Some(sample_tenant_config());
        let restore_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &replace).await).unwrap();
        assert!(restore_response.ok);

        list_probe.reset_materialization(crate::registry::TenantPageBoundary::AdminTcp);
        let expected_all_materialized_bytes = expected_ids
            .iter()
            .map(|id| id.len() + "greeting".len())
            .sum::<usize>();
        let mut tcp_seen = std::collections::BTreeSet::new();
        let mut cursor = None;
        let mut tcp_terminated = false;
        for page_index in 0..=MAX_TENANTS / PAGINATION_PAGE_SIZE {
            let mut list = msg("list");
            list.admin_token = Some("secret".to_string());
            list.page_size = Some(PAGINATION_PAGE_SIZE);
            list.cursor = cursor.clone();
            let bytes = wire_exchange(&mut admin, &list).await;
            assert!(bytes.len() <= max_list_response_bytes);
            let page: AdminResponse = rmp_serde::from_slice(&bytes).unwrap();
            assert!(page.ok, "TCP tenant page {page_index} succeeds");
            let tenants = page.tenants.unwrap_or_default();
            assert!(tenants.len() <= PAGINATION_PAGE_SIZE);
            for tenant in tenants {
                assert!(
                    tcp_seen.insert(tenant.id.clone()),
                    "TCP cursor repeated tenant {}",
                    tenant.id
                );
            }
            match page.next_cursor {
                Some(next) => {
                    assert_ne!(Some(&next), cursor.as_ref(), "TCP cursor must advance");
                    assert!(
                        next.len() <= 128
                            && next.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                            })
                    );
                    cursor = Some(next);
                }
                None => {
                    tcp_terminated = true;
                    break;
                }
            }
        }
        assert!(
            tcp_terminated,
            "TCP pagination must terminate with no cursor"
        );
        assert_eq!(
            tcp_seen, expected_ids,
            "TCP pagination traverses all 64 keys"
        );
        assert_eq!(
            list_probe.peak_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp,),
            PAGINATION_PAGE_SIZE,
            "the admin callsite materializes one bounded page, never clone-all then slice"
        );
        assert_eq!(
            list_probe.peak_materialized_bytes(crate::registry::TenantPageBoundary::AdminTcp,),
            exact_page_materialized_bytes
        );
        assert_eq!(
            list_probe.total_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp,),
            MAX_TENANTS
        );
        assert_eq!(
            list_probe.total_materialized_bytes(crate::registry::TenantPageBoundary::AdminTcp,),
            expected_all_materialized_bytes
        );
        assert_eq!(
            list_probe.materializations_without_page_budget(
                crate::registry::TenantPageBoundary::AdminTcp,
            ),
            0,
            "entry and byte leases precede every TCP tenant clone"
        );

        list_probe.reset_materialization(crate::registry::TenantPageBoundary::AdminTcp);
        let mut sparse_tcp_seen = std::collections::BTreeSet::new();
        let mut sparse_tcp_cursor = None;
        let mut sparse_tcp_terminated = false;
        for page_index in 0..=MAX_TENANTS / SPARSE_TCP_PAGE_SIZE {
            let mut list = msg("list");
            list.admin_token = Some("sparse".to_string());
            list.page_size = Some(SPARSE_TCP_PAGE_SIZE);
            list.cursor = sparse_tcp_cursor.clone();
            let bytes = wire_exchange(&mut admin, &list).await;
            for hidden in &sparse_hidden_ids {
                assert!(
                    !bytes
                        .windows(hidden.len())
                        .any(|window| window == hidden.as_bytes()),
                    "TCP scoped page or cursor disclosed hidden tenant {hidden}"
                );
            }
            let page: AdminResponse = rmp_serde::from_slice(&bytes).unwrap();
            assert!(page.ok, "sparse TCP tenant page {page_index} succeeds");
            for tenant in page.tenants.unwrap_or_default() {
                assert!(sparse_visible_ids.contains(&tenant.id));
                assert!(
                    sparse_tcp_seen.insert(tenant.id.clone()),
                    "sparse TCP cursor repeated visible tenant {}",
                    tenant.id
                );
            }
            match page.next_cursor {
                Some(next) => {
                    assert!(
                        sparse_visible_ids.contains(&next),
                        "a scoped TCP cursor may name only the last visible tenant"
                    );
                    assert_ne!(Some(&next), sparse_tcp_cursor.as_ref());
                    sparse_tcp_cursor = Some(next);
                }
                None => {
                    sparse_tcp_terminated = true;
                    break;
                }
            }
        }
        assert!(sparse_tcp_terminated);
        assert_eq!(
            sparse_tcp_seen, sparse_visible_ids,
            "filter-before-page traversal returns every alternating visible tenant"
        );
        assert_eq!(
            list_probe.peak_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp,),
            SPARSE_TCP_PAGE_SIZE
        );
        assert_eq!(
            list_probe.total_materialized_entries(crate::registry::TenantPageBoundary::AdminTcp,),
            sparse_visible_ids.len()
        );
        assert!(
            list_probe.peak_materialized_bytes(crate::registry::TenantPageBoundary::AdminTcp,)
                <= max_page_materialized_bytes
        );
        assert_eq!(
            list_probe.materializations_without_page_budget(
                crate::registry::TenantPageBoundary::AdminTcp,
            ),
            0
        );

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_address = http_listener.local_addr().unwrap();
        let ready = crate::health::ReadyState::new();
        ready.mark_ready();
        let http_controls = Arc::new(crate::health::HttpTestControl::default());
        let http_registry = Arc::clone(&registry);
        let http_auth = Arc::clone(&auth);
        let server_http_controls = Arc::clone(&http_controls);
        let http_task = tokio::spawn(async move {
            crate::health::serve_on(
                http_listener,
                http_registry,
                ready,
                Some(http_auth),
                crate::health::HttpLimits {
                    max_connections: 2,
                    io_timeout: Duration::from_secs(2),
                }
                .with_test_control(server_http_controls),
            )
            .await
        });

        let http_exact_admissions_before =
            list_probe.lifetime_response_admissions(crate::registry::TenantPageBoundary::Http);
        let http_exact_materializations_before =
            list_probe.lifetime_materialized_entries(crate::registry::TenantPageBoundary::Http);
        let http_exact_string_clones_before =
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::Http);
        let exact_http = bounded_http_tenant_response(
            http_address,
            "/tenants?page_size=3",
            "secret",
            max_http_list_response_bytes,
        )
        .await;
        assert_eq!(exact_http.status, 200);
        assert_eq!(
            exact_http.body.len(),
            max_http_list_response_bytes,
            "the independent JSON fixture reaches the exact HTTP response-byte ceiling"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&exact_http.body).unwrap(),
            exact_http_first_page,
            "HTTP admission is checked against the transport's literal JSON wire shape"
        );
        assert_eq!(
            list_probe.lifetime_response_admissions(crate::registry::TenantPageBoundary::Http,),
            http_exact_admissions_before + 1
        );
        assert_eq!(
            list_probe.lifetime_materialized_entries(crate::registry::TenantPageBoundary::Http,),
            http_exact_materializations_before + HTTP_PAGE_SIZE
        );
        assert_eq!(
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::Http),
            http_exact_string_clones_before + (2 * HTTP_PAGE_SIZE)
        );
        assert_eq!(
            list_probe.lifetime_materializations_without_response_admission(
                crate::registry::TenantPageBoundary::Http,
            ),
            0,
            "HTTP admission precedes the actual JSON projection clone boundary"
        );
        assert_eq!(
            list_probe.lifetime_string_clones_without_response_admission(
                crate::registry::TenantPageBoundary::Http,
            ),
            0
        );

        let mut http_expanded = sample_tenant_config();
        http_expanded.labels[0].name.push('x');
        http_expanded
            .classification
            .as_mut()
            .unwrap()
            .default_label
            .push('x');
        let mut http_replace = msg("register");
        http_replace.tenant = Some("tenant-00.example".to_string());
        http_replace.config = Some(http_expanded);
        http_replace.admin_token = Some("secret".to_string());
        let http_replace_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &http_replace).await).unwrap();
        assert!(http_replace_response.ok);
        let http_serializations_before_plus_one =
            list_probe.page_serializations(crate::registry::TenantPageBoundary::Http);
        let http_materializations_before_plus_one =
            list_probe.lifetime_materialized_entries(crate::registry::TenantPageBoundary::Http);
        let http_string_clones_before_plus_one =
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::Http);
        let http_refusals_before_plus_one = list_probe
            .lifetime_response_admission_refusals(crate::registry::TenantPageBoundary::Http);
        let forbid_http_serialization =
            list_probe.forbid_page_serialization(crate::registry::TenantPageBoundary::Http);
        let forbid_http_materialization =
            list_probe.forbid_page_materialization(crate::registry::TenantPageBoundary::Http);
        let http_plus_one = bounded_http_tenant_response(
            http_address,
            "/tenants?page_size=3",
            "secret",
            HTTP_REFUSAL_CAPTURE_BYTES,
        )
        .await;
        forbid_http_serialization.assert_not_triggered();
        forbid_http_materialization.assert_not_triggered();
        drop(forbid_http_serialization);
        drop(forbid_http_materialization);
        assert_eq!(
            http_plus_one.status, 507,
            "the one-byte-oversized JSON page is refused before serialization"
        );
        assert!(
            http_plus_one.body.len() <= HTTP_REFUSAL_CAPTURE_BYTES,
            "the HTTP refusal body remains independently byte bounded"
        );
        assert_eq!(
            list_probe.page_serializations(crate::registry::TenantPageBoundary::Http),
            http_serializations_before_plus_one,
            "HTTP response-byte admission precedes the JSON serializer"
        );
        assert_eq!(
            list_probe.lifetime_materialized_entries(crate::registry::TenantPageBoundary::Http),
            http_materializations_before_plus_one,
            "a refused JSON page performs zero TenantInfo materializations"
        );
        assert_eq!(
            list_probe.lifetime_string_clones(crate::registry::TenantPageBoundary::Http),
            http_string_clones_before_plus_one,
            "a refused JSON page performs zero id/label String clones"
        );
        assert_eq!(
            list_probe
                .lifetime_response_admission_refusals(crate::registry::TenantPageBoundary::Http,),
            http_refusals_before_plus_one + 1
        );
        http_replace.config = Some(sample_tenant_config());
        let http_restore_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &http_replace).await).unwrap();
        assert!(http_restore_response.ok);

        list_probe.reset_materialization(crate::registry::TenantPageBoundary::Http);
        let mut http_seen = std::collections::BTreeSet::new();
        let mut http_cursor: Option<String> = None;
        let mut http_terminated = false;
        for page_index in 0..MAX_TENANTS {
            let path = match &http_cursor {
                Some(cursor) => format!("/tenants?page_size={HTTP_PAGE_SIZE}&cursor={cursor}"),
                None => format!("/tenants?page_size={HTTP_PAGE_SIZE}"),
            };
            let body = bounded_http_tenant_page(
                http_address,
                &path,
                "secret",
                max_http_list_response_bytes,
            )
            .await;
            let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let tenants = page["tenants"]
                .as_array()
                .expect("HTTP tenant pagination returns a typed page object");
            assert!(tenants.len() <= HTTP_PAGE_SIZE);
            for tenant in tenants {
                let id = tenant["id"].as_str().expect("tenant page entry has an id");
                assert!(
                    http_seen.insert(id.to_string()),
                    "HTTP cursor repeated tenant {id}"
                );
            }
            match page["next_cursor"].as_str() {
                Some(next) => {
                    assert_ne!(
                        Some(next),
                        http_cursor.as_deref(),
                        "HTTP cursor must advance"
                    );
                    assert!(
                        next.len() <= 128
                            && next.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                            })
                    );
                    http_cursor = Some(next.to_string());
                }
                None => {
                    http_terminated = true;
                    break;
                }
            }
            assert!(
                page_index + 1 < MAX_TENANTS,
                "HTTP pagination must terminate"
            );
        }
        assert!(
            http_terminated,
            "HTTP pagination must terminate with no cursor"
        );
        assert_eq!(
            http_seen, expected_ids,
            "authenticated HTTP pagination traverses the same complete registry"
        );
        let expected_http_peak_bytes = expected_ids
            .iter()
            .take(HTTP_PAGE_SIZE)
            .map(|id| id.len() + "greeting".len())
            .sum::<usize>();
        assert_eq!(
            list_probe.peak_materialized_entries(crate::registry::TenantPageBoundary::Http),
            HTTP_PAGE_SIZE,
            "the HTTP callsite must not clone the full registry before slicing"
        );
        assert_eq!(
            list_probe.peak_materialized_bytes(crate::registry::TenantPageBoundary::Http),
            expected_http_peak_bytes
        );
        assert_eq!(
            list_probe.total_materialized_entries(crate::registry::TenantPageBoundary::Http),
            MAX_TENANTS
        );
        assert_eq!(
            list_probe.total_materialized_bytes(crate::registry::TenantPageBoundary::Http),
            expected_all_materialized_bytes
        );
        assert_eq!(
            list_probe
                .materializations_without_page_budget(crate::registry::TenantPageBoundary::Http,),
            0,
            "HTTP acquires its entry and byte page lease before materialization"
        );

        list_probe.reset_materialization(crate::registry::TenantPageBoundary::Http);
        let mut sparse_http_seen = std::collections::BTreeSet::new();
        let mut sparse_http_cursor: Option<String> = None;
        let mut sparse_http_terminated = false;
        for page_index in 0..MAX_TENANTS {
            let path = match &sparse_http_cursor {
                Some(cursor) => {
                    format!("/tenants?page_size={SPARSE_HTTP_PAGE_SIZE}&cursor={cursor}")
                }
                None => format!("/tenants?page_size={SPARSE_HTTP_PAGE_SIZE}"),
            };
            let body = bounded_http_tenant_page(
                http_address,
                &path,
                "sparse",
                max_http_list_response_bytes,
            )
            .await;
            for hidden in &sparse_hidden_ids {
                assert!(
                    !body
                        .windows(hidden.len())
                        .any(|window| window == hidden.as_bytes()),
                    "HTTP scoped page or cursor disclosed hidden tenant {hidden}"
                );
            }
            let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
            for tenant in page["tenants"].as_array().unwrap() {
                let id = tenant["id"].as_str().unwrap();
                assert!(sparse_visible_ids.contains(id));
                assert!(
                    sparse_http_seen.insert(id.to_string()),
                    "sparse HTTP cursor repeated visible tenant {id}"
                );
            }
            match page["next_cursor"].as_str() {
                Some(next) => {
                    assert!(
                        sparse_visible_ids.contains(next),
                        "a scoped HTTP cursor may name only the last visible tenant"
                    );
                    assert_ne!(Some(next), sparse_http_cursor.as_deref());
                    sparse_http_cursor = Some(next.to_string());
                }
                None => {
                    sparse_http_terminated = true;
                    break;
                }
            }
            assert!(page_index + 1 < MAX_TENANTS);
        }
        assert!(sparse_http_terminated);
        assert_eq!(sparse_http_seen, sparse_visible_ids);
        assert_eq!(
            list_probe.peak_materialized_entries(crate::registry::TenantPageBoundary::Http),
            SPARSE_HTTP_PAGE_SIZE
        );
        assert_eq!(
            list_probe.total_materialized_entries(crate::registry::TenantPageBoundary::Http),
            sparse_visible_ids.len()
        );
        assert!(
            list_probe.peak_materialized_bytes(crate::registry::TenantPageBoundary::Http)
                <= max_page_materialized_bytes
        );
        assert_eq!(
            list_probe
                .materializations_without_page_budget(crate::registry::TenantPageBoundary::Http,),
            0
        );
        for boundary in [
            crate::registry::TenantPageBoundary::AdminTcp,
            crate::registry::TenantPageBoundary::Http,
        ] {
            assert_eq!(
                list_probe.lifetime_materializations_without_response_admission(boundary),
                0,
                "window resets cannot erase a pre-admission materialization violation"
            );
            assert_eq!(
                list_probe.lifetime_string_clones_without_response_admission(boundary),
                0,
                "window resets cannot erase a pre-admission String-clone violation"
            );
        }
        assert!(
            !http_task.is_finished(),
            "HTTP pagination listener exited before explicit cleanup"
        );
        let http_shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        http_controls.request_graceful_shutdown_before(http_shutdown_deadline);
        let join = tokio::time::timeout_at(http_shutdown_deadline, http_task)
            .await
            .expect("HTTP pagination listener joins before its cleanup deadline")
            .expect("HTTP pagination listener task must not panic");
        let exit = join.expect("HTTP pagination listener reports clean graceful shutdown");
        exit.assert_quiescent_at_return()
            .expect("HTTP pagination owner returns with no delayed child reaper");
        assert_eq!(exit.active_connection_children(), 0);
        assert_eq!(
            exit.connection_children_spawned(),
            exit.connection_children_finished(),
            "HTTP pagination cleanup may not detach a completed response child"
        );
        assert_eq!(
            exit.connection_child_results_collected(),
            exit.connection_children_spawned(),
            "HTTP shutdown must collect every connection-child result"
        );
        assert_eq!(exit.connection_child_panics(), 0);
        assert_eq!(exit.connection_child_events_after_owner_return(), 0);
        assert_eq!(
            exit.collection_deadline_id(),
            http_controls.shutdown_deadline_id()
        );

        let mut original_identities = expected_ids
            .iter()
            .map(|id| (id.clone(), registry.get(Some(id)).unwrap()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(registry.snapshot_ids(), expected_ids);
        let compilation_before_refusals = compile_probe.started();
        let compile_sentinel = compile_probe.forbid_compilation();

        let mut plus_one = msg("register");
        plus_one.tenant = Some("overflow-one.example".to_string());
        plus_one.config = Some(sample_tenant_config());
        plus_one.admin_token = Some("secret".to_string());
        let plus_one_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &plus_one).await).unwrap();
        let count_after_plus_one = registry.tenant_count();

        let mut repeated = msg("register");
        repeated.tenant = Some("overflow-two.example".to_string());
        repeated.config = Some(sample_tenant_config());
        repeated.admin_token = Some("secret".to_string());
        let repeated_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &repeated).await).unwrap();
        let count_after_repeated = registry.tenant_count();
        compile_sentinel.assert_not_triggered();

        assert_eq!(
            registry.snapshot_ids(),
            expected_ids,
            "both refused tenant ids must be absent from the complete original key set"
        );
        assert!(registry.get(Some("overflow-one.example")).is_none());
        assert!(registry.get(Some("overflow-two.example")).is_none());
        assert_eq!(compile_probe.started(), compilation_before_refusals);
        for (id, original) in &original_identities {
            let current = registry.get(Some(id)).unwrap();
            assert!(
                Arc::ptr_eq(original, &current),
                "refused registration replaced original tenant identity: {id}"
            );
        }
        drop(compile_sentinel);

        let mut delete = msg("delete");
        delete.tenant = Some("tenant-00.example".to_string());
        delete.admin_token = Some("secret".to_string());
        let delete_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &delete).await).unwrap();
        assert!(registry.get(Some("tenant-00.example")).is_none());
        let deleted_reader = original_identities
            .remove("tenant-00.example")
            .expect("the deleted tenant still has one deliberate reader");
        let compilation_before_reader_release = compile_probe.started();
        let live_reader_compile_sentinel = compile_probe.forbid_compilation();
        let held_reader_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &plus_one).await).unwrap();
        live_reader_compile_sentinel.assert_not_triggered();
        drop(live_reader_compile_sentinel);
        assert_eq!(compile_probe.started(), compilation_before_reader_release);
        assert!(registry.get(Some("overflow-one.example")).is_none());
        drop(deleted_reader);
        let recovery_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &plus_one).await).unwrap();
        let count_after_recovery = registry.tenant_count();

        let mut public =
            bounded_tcp_connect(pair.public_address, "registry recovery classify").await;
        let mut classify = msg("classify");
        classify.tenant = Some("overflow-one.example".to_string());
        classify.text = "hello".to_string();
        let classify_response: ClassifyResponse =
            rmp_serde::from_slice(&wire_exchange(&mut public, &classify).await).unwrap();

        pair.stop().await;

        assert_eq!(exact_count, MAX_TENANTS);
        assert!(!plus_one_response.ok, "tenant 65 must be refused");
        assert_eq!(count_after_plus_one, MAX_TENANTS, "refusal must be atomic");
        assert!(!repeated_response.ok, "repeated overflow must be refused");
        assert_eq!(
            count_after_repeated, MAX_TENANTS,
            "repeated refusal must not grow state"
        );
        assert!(delete_response.ok);
        assert!(
            !held_reader_response.ok,
            "deletion cannot reuse persistent capacity while the old tenant Arc is still live"
        );
        assert!(
            recovery_response.ok,
            "released tenant capacity must be reusable"
        );
        assert_eq!(count_after_recovery, MAX_TENANTS);
        expected_ids.remove("tenant-00.example");
        expected_ids.insert("overflow-one.example".to_string());
        assert_eq!(registry.snapshot_ids(), expected_ids);
        for (id, original) in &original_identities {
            assert!(Arc::ptr_eq(original, &registry.get(Some(id)).unwrap()));
        }
        assert_eq!(classify_response.tenant, "overflow-one.example");
        assert_eq!(classify_response.labels[0].label, "greeting");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation() {
        const MAX_PATTERNS: usize = 64;
        const MAX_RULES: usize = 64;
        const MAX_SOURCE_BYTES: usize = 256 * 1024;
        const MAX_CONFIG_BYTES: usize = 512 * 1024;
        let limits = crate::registry::TenantRegistryLimits::production_defaults()
            .with_max_config_bytes_per_tenant(MAX_CONFIG_BYTES);
        assert_eq!(limits.max_patterns_per_tenant(), MAX_PATTERNS);
        assert_eq!(limits.max_normalization_rules_per_tenant(), MAX_RULES);
        assert_eq!(limits.max_source_bytes_per_tenant(), MAX_SOURCE_BYTES);
        assert_eq!(limits.max_config_bytes_per_tenant(), MAX_CONFIG_BYTES);
        let compile_probe = Arc::new(crate::registry::TenantCompileProbe::default());
        let warnings_at_start = compile_probe.warnings_emitted();
        let budget = crate::registry::TenantRegistryBudget::new(limits.clone()).unwrap();
        let compiler = crate::registry::TenantCompiler::bounded(2)
            .unwrap()
            .with_test_probe(Arc::clone(&compile_probe));
        let registry = Arc::new(Registry::new(budget, compiler));
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#).unwrap(),
        );
        let pair = spawn_production_listener_pair(
            Arc::clone(&registry),
            auth,
            TcpLimits::default(),
            Arc::new(TcpTestControl::default()),
            None,
        )
        .await;
        let mut admin =
            bounded_tcp_connect(pair.admin_address, "aggregate registry admin session").await;

        let labels = (0..8)
            .map(|label| TenantLabel {
                name: format!("label-{label}"),
                patterns: (0..8)
                    .map(|pattern| format!("^p{label}-{pattern}$"))
                    .collect(),
                weight: 1.0,
            })
            .collect::<Vec<_>>();
        let mut exact_patterns = sample_tenant_config();
        exact_patterns.labels = labels.clone();
        exact_patterns
            .classification
            .as_mut()
            .unwrap()
            .default_label = "label-0".to_string();
        assert_eq!(
            exact_patterns
                .labels
                .iter()
                .map(|label| label.patterns.len())
                .sum::<usize>(),
            MAX_PATTERNS,
            "the accepted pattern control is aggregate across labels"
        );
        let mut register = msg("register");
        register.tenant = Some("patterns-exact.example".to_string());
        register.config = Some(exact_patterns);
        register.admin_token = Some("secret".to_string());
        let exact_pattern_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();

        let mut pattern_plus_one = sample_tenant_config();
        pattern_plus_one.labels = labels;
        pattern_plus_one
            .classification
            .as_mut()
            .unwrap()
            .default_label = "label-0".to_string();
        pattern_plus_one.labels[7].patterns.push("(".to_string());
        register.tenant = Some("patterns-plus-one.example".to_string());
        register.config = Some(pattern_plus_one);
        let compile_before_pattern_plus_one = compile_probe.started();
        let pattern_compile_sentinel = compile_probe.forbid_compilation();
        let warnings_before_pattern_plus_one = compile_probe.warnings_emitted();
        let pattern_plus_one_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();
        let warnings_after_pattern_plus_one = compile_probe.warnings_emitted();
        let count_after_pattern_plus_one = registry.tenant_count();
        pattern_compile_sentinel.assert_not_triggered();
        drop(pattern_compile_sentinel);
        assert_eq!(compile_probe.started(), compile_before_pattern_plus_one);

        let exact_rules = (0..MAX_RULES)
            .map(|index| TenantNormRule {
                name: format!("rule-{index}"),
                pattern: if index % 2 == 0 { "x" } else { "(" }.to_string(),
                replace: "r".to_string(),
                enabled: index % 2 == 0,
            })
            .collect::<Vec<_>>();
        let mut exact_rule_count = sample_tenant_config();
        exact_rule_count.normalization = Some(TenantNormalization {
            unicode_nfkc: false,
            trim: false,
            rules: exact_rules.clone(),
        });
        let normalizer_compiles_before = compile_probe.enabled_normalizer_programs_started();
        let normalizer_warnings_before = compile_probe.warnings_emitted();
        register.tenant = Some("rules-exact.example".to_string());
        register.config = Some(exact_rule_count);
        let exact_rule_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();
        compile_probe
            .wait_for_enabled_normalizer_programs(
                normalizer_compiles_before + MAX_RULES / 2,
                Duration::from_secs(3),
            )
            .await
            .expect("only enabled normalization rules compile on the bounded executor");
        assert_eq!(
            compile_probe.warnings_emitted(),
            normalizer_warnings_before,
            "the cross-thread production compile path neither compiles nor warns for disabled invalid normalization patterns"
        );

        let mut rule_plus_one = sample_tenant_config();
        let mut rules_plus_one = exact_rules.clone();
        rules_plus_one.push(TenantNormRule {
            name: "disabled-overflow".to_string(),
            pattern: "(".to_string(),
            replace: String::new(),
            enabled: false,
        });
        rule_plus_one.normalization = Some(TenantNormalization {
            unicode_nfkc: false,
            trim: false,
            rules: rules_plus_one,
        });
        let compile_before_rule_plus_one = compile_probe.started();
        let rule_compile_sentinel = compile_probe.forbid_compilation();
        register.tenant = Some("rules-plus-one.example".to_string());
        register.config = Some(rule_plus_one);
        let rule_plus_one_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();
        rule_compile_sentinel.assert_not_triggered();
        drop(rule_compile_sentinel);
        assert_eq!(compile_probe.started(), compile_before_rule_plus_one);

        let mut exact_bytes = sample_tenant_config();
        exact_bytes.labels = vec![TenantLabel {
            name: "mixed-classifier".to_string(),
            patterns: vec!["^cheap-classifier-pattern$".to_string()],
            weight: 1.0,
        }];
        exact_bytes.classification.as_mut().unwrap().default_label = "mixed-classifier".to_string();
        exact_bytes.normalization = Some(TenantNormalization {
            unicode_nfkc: false,
            trim: false,
            rules: vec![
                TenantNormRule {
                    name: "enabled-cheap".to_string(),
                    pattern: "x".to_string(),
                    replace: "y".to_string(),
                    enabled: true,
                },
                TenantNormRule {
                    name: "disabled-persistent-input".to_string(),
                    pattern: "(".to_string(),
                    replace: String::new(),
                    enabled: false,
                },
            ],
        });
        let measured = independent_source_bytes(&exact_bytes);
        exact_bytes.normalization.as_mut().unwrap().rules[1]
            .replace
            .push_str(
                &"r".repeat(
                    MAX_SOURCE_BYTES
                        .checked_sub(measured)
                        .expect("the cheap mixed fixture must fit below the source-byte limit"),
                ),
            );
        assert_eq!(
            independent_source_bytes(&exact_bytes),
            MAX_SOURCE_BYTES,
            "classifier plus enabled and disabled normalizer source is one aggregate"
        );
        register.tenant = Some("mixed-bytes-exact.example".to_string());
        register.config = Some(exact_bytes.clone());
        let exact_byte_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();

        let mut bytes_plus_one = exact_bytes;
        bytes_plus_one.normalization.as_mut().unwrap().rules[1]
            .replace
            .push('r');
        register.tenant = Some("bytes-plus-one.example".to_string());
        register.config = Some(bytes_plus_one);
        let compile_before_bytes_plus_one = compile_probe.started();
        let bytes_compile_sentinel = compile_probe.forbid_compilation();
        let warnings_before_bytes_plus_one = compile_probe.warnings_emitted();
        let byte_plus_one_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();
        let warnings_after_bytes_plus_one = compile_probe.warnings_emitted();
        let count_after_byte_plus_one = registry.tenant_count();
        bytes_compile_sentinel.assert_not_triggered();
        drop(bytes_compile_sentinel);
        assert_eq!(compile_probe.started(), compile_before_bytes_plus_one);

        let mut exact_config_bytes = sample_tenant_config();
        exact_config_bytes.normalization = Some(TenantNormalization {
            unicode_nfkc: false,
            trim: false,
            rules: vec![TenantNormRule {
                name: "n".to_string(),
                pattern: "(".to_string(),
                replace: String::new(),
                enabled: false,
            }],
        });
        let config_target = limits.max_config_bytes_per_tenant();
        for _ in 0..8 {
            let config_measured = independent_serialized_config_bytes(&exact_config_bytes);
            match config_measured.cmp(&config_target) {
                std::cmp::Ordering::Equal => break,
                std::cmp::Ordering::Greater => {
                    let name =
                        &mut exact_config_bytes.normalization.as_mut().unwrap().rules[0].name;
                    let shrink = config_measured - config_target;
                    assert!(
                        shrink <= name.len(),
                        "the cheap config fixture must fit below the config-byte limit"
                    );
                    name.truncate(name.len() - shrink);
                }
                std::cmp::Ordering::Less => {
                    exact_config_bytes.normalization.as_mut().unwrap().rules[0]
                        .name
                        .push_str(&"n".repeat(config_target - config_measured))
                }
            }
        }
        assert_eq!(
            independent_serialized_config_bytes(&exact_config_bytes),
            config_target
        );
        register.tenant = Some("config-bytes-exact.example".to_string());
        register.config = Some(exact_config_bytes.clone());
        let exact_config_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();

        exact_config_bytes.normalization.as_mut().unwrap().rules[0]
            .name
            .push('n');
        register.tenant = Some("config-bytes-plus-one.example".to_string());
        register.config = Some(exact_config_bytes);
        let compile_before_config_plus_one = compile_probe.started();
        let config_compile_sentinel = compile_probe.forbid_compilation();
        let config_plus_one_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &register).await).unwrap();
        config_compile_sentinel.assert_not_triggered();
        drop(config_compile_sentinel);
        assert_eq!(compile_probe.started(), compile_before_config_plus_one);

        pair.stop().await;

        assert!(exact_pattern_response.ok);
        assert!(!pattern_plus_one_response.ok);
        assert_eq!(count_after_pattern_plus_one, 1);
        assert_eq!(
            warnings_after_pattern_plus_one,
            warnings_before_pattern_plus_one
        );
        assert!(exact_rule_response.ok);
        assert!(!rule_plus_one_response.ok);
        assert!(exact_byte_response.ok);
        assert!(!byte_plus_one_response.ok);
        assert_eq!(count_after_byte_plus_one, 3);
        assert_eq!(
            warnings_after_bytes_plus_one,
            warnings_before_bytes_plus_one
        );
        assert!(exact_config_response.ok);
        assert!(!config_plus_one_response.ok);
        assert_eq!(registry.tenant_count(), 4);
        assert_eq!(
            compile_probe.disabled_normalizer_programs_started(),
            0,
            "disabled rules consume persistent count/source/config bytes but no program reservation"
        );
        assert_eq!(
            compile_probe.warnings_emitted(),
            warnings_at_start,
            "disabled invalid rules and preflight-refused invalid inputs never warn from the cross-thread compiler"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compiled_program_budget_weights_old_and_new_tenant_generations_until_final_drop() {
        const CLASSIFIER_PROGRAM_BYTES: usize = 48 * 1024;
        const NORMALIZER_PROGRAM_BYTES: usize = 64 * 1024;
        const PROCESS_COMPILED_BYTES: usize = 320 * 1024;

        let weights = crate::registry::CompiledProgramWeights {
            classifier_pattern_bytes: CLASSIFIER_PROGRAM_BYTES,
            enabled_normalization_rule_bytes: NORMALIZER_PROGRAM_BYTES,
        };
        assert_eq!(weights.reservation_bytes(1, 0), CLASSIFIER_PROGRAM_BYTES);
        assert_eq!(
            weights.reservation_bytes(3, 2),
            3 * CLASSIFIER_PROGRAM_BYTES + 2 * NORMALIZER_PROGRAM_BYTES
        );
        assert_eq!(
            weights.reservation_bytes(1, 0) + weights.reservation_bytes(3, 2),
            PROCESS_COMPILED_BYTES,
            "one old program plus the weighted replacement reaches the exact process budget"
        );

        let reservations = Arc::new(crate::registry::CompiledReservationProbe::default());
        let compile_probe = Arc::new(crate::registry::TenantCompileProbe::default());
        let limits = crate::registry::TenantRegistryLimits::production_defaults()
            .with_compiled_program_weights(weights)
            .with_max_compiled_program_bytes(PROCESS_COMPILED_BYTES);
        let budget = crate::registry::TenantRegistryBudget::new(limits)
            .unwrap()
            .with_test_reservation_probe(Arc::clone(&reservations));
        let compiler = crate::registry::TenantCompiler::bounded(2)
            .unwrap()
            .with_test_probe(Arc::clone(&compile_probe));
        let registry = Arc::new(Registry::new(budget, compiler));
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#).unwrap(),
        );
        let pair = spawn_production_listener_pair(
            Arc::clone(&registry),
            auth,
            TcpLimits::default(),
            Arc::new(TcpTestControl::default()),
            None,
        )
        .await;
        let mut admin = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(pair.admin_address),
        )
        .await
        .expect("compiled-budget admin connect is bounded")
        .unwrap();

        let mut old_register = msg("register");
        old_register.tenant = Some("replace.example".to_string());
        old_register.config = Some(sample_tenant_config());
        old_register.admin_token = Some("secret".to_string());
        let old_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &old_register).await).unwrap();
        assert!(old_response.ok);
        reservations
            .wait_for_current_bytes(CLASSIFIER_PROGRAM_BYTES, Duration::from_secs(3))
            .await
            .expect("the one-pattern old tenant owns one weighted reservation");
        assert_eq!(compile_probe.classifier_programs_started(), 1);
        let old_reader = registry
            .get(Some("replace.example"))
            .expect("the deliberate reader owns the old generation");

        let mut replacement = sample_tenant_config();
        replacement.labels[0].patterns = vec![
            "^one$".to_string(),
            "^two$".to_string(),
            "^three$".to_string(),
        ];
        replacement.normalization = Some(TenantNormalization {
            unicode_nfkc: false,
            trim: false,
            rules: vec![
                TenantNormRule {
                    name: "enabled-one".to_string(),
                    pattern: "one".to_string(),
                    replace: "1".to_string(),
                    enabled: true,
                },
                TenantNormRule {
                    name: "enabled-two".to_string(),
                    pattern: "two".to_string(),
                    replace: "2".to_string(),
                    enabled: true,
                },
            ],
        });
        let mut replacement_register = msg("register");
        replacement_register.tenant = Some("replace.example".to_string());
        replacement_register.config = Some(replacement);
        replacement_register.admin_token = Some("secret".to_string());
        let replacement_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &replacement_register).await).unwrap();
        assert!(replacement_response.ok);
        reservations
            .wait_for_current_bytes(PROCESS_COMPILED_BYTES, Duration::from_secs(3))
            .await
            .expect("old plus new generation reservations coexist at the exact limit");
        assert_eq!(reservations.peak_bytes(), PROCESS_COMPILED_BYTES);
        assert_eq!(compile_probe.classifier_programs_started(), 4);
        assert_eq!(compile_probe.enabled_normalizer_programs_started(), 2);

        let mut extra = msg("register");
        extra.tenant = Some("extra.example".to_string());
        extra.config = Some(sample_tenant_config());
        extra.admin_token = Some("secret".to_string());
        let compile_before_refusal = compile_probe.started();
        let no_compile = compile_probe.forbid_compilation();
        let refused: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &extra).await).unwrap();
        no_compile.assert_not_triggered();
        drop(no_compile);
        assert!(!refused.ok);
        assert_eq!(compile_probe.started(), compile_before_refusal);
        assert!(registry.get(Some("extra.example")).is_none());
        assert_eq!(reservations.current_bytes(), PROCESS_COMPILED_BYTES);

        drop(old_reader);
        reservations
            .wait_for_current_bytes(
                3 * CLASSIFIER_PROGRAM_BYTES + 2 * NORMALIZER_PROGRAM_BYTES,
                Duration::from_secs(3),
            )
            .await
            .expect("only final Arc drop releases the old generation reservation");
        let recovered: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut admin, &extra).await).unwrap();
        assert!(recovered.ok);
        reservations
            .wait_for_current_bytes(PROCESS_COMPILED_BYTES, Duration::from_secs(3))
            .await
            .expect("the released weighted capacity is exactly reusable");
        assert_eq!(compile_probe.classifier_programs_started(), 5);
        assert_eq!(compile_probe.enabled_normalizer_programs_started(), 2);
        assert_eq!(reservations.peak_bytes(), PROCESS_COMPILED_BYTES);
        pair.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_classification_timeout_retains_bounded_worker_lease_and_recovers() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        struct ReleaseWorkerOnDrop(Option<Arc<PublicWorkerBarrier>>);

        impl ReleaseWorkerOnDrop {
            fn release(&mut self) {
                if let Some(barrier) = self.0.take() {
                    barrier.release();
                }
            }
        }

        impl Drop for ReleaseWorkerOnDrop {
            fn drop(&mut self) {
                self.release();
            }
        }

        let outcomes = OutcomeProbe::acquire_unique().await;
        let registry = Arc::new(Registry::new_empty());
        registry
            .register("tenant.example", &sample_tenant_config())
            .expect("control tenant registers");
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#).unwrap(),
        );
        let controls = Arc::new(TcpTestControl::default());
        let worker_probe = controls.public_worker_probe();
        let pair = spawn_production_listener_pair(
            registry,
            auth,
            TcpLimits::default().with_public_work_limits(PublicWorkLimits {
                max_running: 1,
                max_queued: 0,
                deadline: Duration::from_millis(100),
            }),
            Arc::clone(&controls),
            None,
        )
        .await;
        let barrier = Arc::new(PublicWorkerBarrier::default());
        let mut release_worker = ReleaseWorkerOnDrop(Some(Arc::clone(&barrier)));
        let hold = controls.hold_next_public_worker(MetricCommand::Classify, Arc::clone(&barrier));
        let mut request = msg("classify");
        request.tenant = Some("tenant.example".to_string());
        request.text = "hello".to_string();

        let deadline_before = outcomes.snapshot();
        let first_request = clone_message(&request);
        let public_address = pair.public_address;
        let first = tokio::spawn(async move {
            let mut stream =
                bounded_tcp_connect(public_address, "held public classify worker").await;
            wire_exchange(&mut stream, &first_request).await
        });
        barrier
            .wait_until_entered(Duration::from_secs(3))
            .await
            .expect("the real public classify worker owns the running lease");
        hold.assert_consumed_exactly_once();
        let first_response = tokio::time::timeout(Duration::from_secs(3), first)
            .await
            .expect("timed-out public call reaches a bounded response")
            .unwrap();
        assert!(
            !rmp_serde::from_slice::<AdminResponse>(&first_response)
                .unwrap()
                .ok
        );
        deadline_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Tcp,
                MetricCommand::Classify,
                Stage::Worker,
                Reason::Deadline,
            ),
            "public classify deadline",
        );
        assert_eq!(worker_probe.running(), 1);

        let refusal_before = outcomes.snapshot();
        let mut replacement =
            bounded_tcp_connect(pair.public_address, "public worker plus one").await;
        let replacement_response: AdminResponse =
            rmp_serde::from_slice(&wire_exchange(&mut replacement, &request).await).unwrap();
        assert!(!replacement_response.ok);
        assert_eq!(worker_probe.total_worker_starts(), 1);
        refusal_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Tcp,
                MetricCommand::Classify,
                Stage::Admission,
                Reason::QueueFull,
            ),
            "public classify worker saturation",
        );

        release_worker.release();
        worker_probe
            .wait_for_running(0, Duration::from_secs(3))
            .await
            .expect("non-cancellable public worker returns its lease only on exit");
        let recovery_before = outcomes.snapshot();
        let mut recovery = bounded_tcp_connect(pair.public_address, "public worker recovery").await;
        let recovery_response: ClassifyResponse =
            rmp_serde::from_slice(&wire_exchange(&mut recovery, &request).await).unwrap();
        assert_eq!(recovery_response.labels[0].label, "greeting");
        recovery_before.assert_exact_terminal_delta(
            OutcomeExpectation::success(Transport::Tcp, MetricCommand::Classify),
            "public classify worker recovery",
        );
        pair.stop().await;
    }

    #[tokio::test]
    async fn public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        fn framed(message: &Message) -> Vec<u8> {
            let payload = rmp_serde::to_vec_named(message).unwrap();
            let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(&payload);
            bytes
        }

        let outcomes = OutcomeProbe::acquire_unique().await;
        let registry = Arc::new(Registry::new_empty());
        let auth = Arc::new(
            AdminAuth::from_json(
                br#"{"tokens":[{"token":"secret","tenants":["*"]},{"token":"scoped","tenants":["tenant-a.example"]}]}"#,
            )
            .unwrap(),
        );
        let controls = Arc::new(TcpTestControl::default());
        let pair = spawn_production_listener_pair(
            Arc::clone(&registry),
            auth,
            TcpLimits {
                max_connections: 1,
                io_timeout: Duration::from_millis(250),
            },
            Arc::clone(&controls),
            None,
        )
        .await;

        macro_rules! assert_wire_case {
            ($name:literal, $address:expr, $message:expr, $expected:expr, $check:expr) => {{
                let before = outcomes.snapshot();
                let mut stream =
                    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect($address))
                        .await
                        .unwrap_or_else(|_| panic!("TCP matrix connect timed out: {}", $name))
                        .unwrap();
                let bytes = wire_exchange(&mut stream, &$message).await;
                ($check)(&bytes);
                before.assert_exact_terminal_delta($expected, $name);
                let mode = if $address == pair.public_address {
                    TransportMode::Public
                } else {
                    TransportMode::Admin
                };
                drop(stream);
                controls
                    .wait_for_active_connections(mode, 0, Duration::from_secs(3))
                    .await
                    .expect("completed TCP matrix connection releases its permit");
            }};
        }

        macro_rules! wait_mode_idle {
            ($mode:expr, $case:expr) => {
                controls
                    .wait_for_active_connections($mode, 0, Duration::from_secs(3))
                    .await
                    .unwrap_or_else(|_| panic!("TCP matrix connection did not release: {}", $case));
            };
        }

        for (name, mode, address, transport) in [
            (
                "public",
                TransportMode::Public,
                pair.public_address,
                Transport::Tcp,
            ),
            (
                "admin",
                TransportMode::Admin,
                pair.admin_address,
                Transport::AdminTcp,
            ),
        ] {
            let before = outcomes.snapshot();
            let response = raw_exchange_until_close(address, &[], true).await;
            wait_mode_idle!(mode, format!("{name} clean zero-byte EOF"));
            assert!(response.is_empty());
            before.assert_no_terminal_delta(&format!("{name} clean zero-byte EOF"));

            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &[0, 0], true).await;
            wait_mode_idle!(mode, format!("{name} partial length prefix"));
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Read,
                    Reason::MalformedFrame,
                ),
                &format!("{name} partial length prefix"),
            );

            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &[], false).await;
            wait_mode_idle!(mode, format!("{name} header deadline"));
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Read,
                    Reason::Deadline,
                ),
                &format!("{name} header deadline"),
            );

            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &4u32.to_be_bytes(), false).await;
            wait_mode_idle!(mode, format!("{name} payload deadline"));
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Read,
                    Reason::Deadline,
                ),
                &format!("{name} payload deadline"),
            );

            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &((MAX_FRAME_BYTES + 1) as u32).to_be_bytes(), true)
                .await;
            wait_mode_idle!(mode, format!("{name} oversized frame"));
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Limit,
                    Reason::ResourceLimit,
                ),
                &format!("{name} oversized frame"),
            );

            let mut malformed = 3u32.to_be_bytes().to_vec();
            malformed.extend_from_slice(&[0xc1, 0xc1, 0xc1]);
            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &malformed, true).await;
            wait_mode_idle!(mode, format!("{name} malformed MessagePack"));
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Decode,
                    Reason::MalformedFrame,
                ),
                &format!("{name} malformed MessagePack"),
            );

            let length_fault = controls.arm_next(mode, TcpFault::LengthReadIo);
            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &[0], false).await;
            wait_mode_idle!(mode, format!("{name} length read I/O"));
            length_fault.assert_consumed_exactly_once();
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Read,
                    Reason::Io,
                ),
                &format!("{name} length read I/O"),
            );

            let payload_fault = controls.arm_next(mode, TcpFault::PayloadReadIo);
            let before = outcomes.snapshot();
            raw_exchange_until_close(address, &4u32.to_be_bytes(), false).await;
            wait_mode_idle!(mode, format!("{name} payload read I/O"));
            payload_fault.assert_consumed_exactly_once();
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Decode,
                    Stage::Read,
                    Reason::Io,
                ),
                &format!("{name} payload read I/O"),
            );

            let mut occupying = bounded_tcp_connect(address, "TCP matrix slot holder").await;
            controls
                .wait_for_active_connections(mode, 1, Duration::from_secs(3))
                .await
                .expect("the exact TCP listener permit is held");
            let before = outcomes.snapshot();
            let refused = bounded_tcp_connect(address, "TCP matrix slot plus one").await;
            controls
                .wait_for_connection_refusals(mode, 1, Duration::from_secs(3))
                .await
                .expect("plus-one TCP connection refusal is observed by the owner");
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    transport,
                    MetricCommand::Unknown,
                    Stage::Admission,
                    Reason::ResourceLimit,
                ),
                &format!("{name} connection slot"),
            );
            assert_socket_refused_without_response(refused, &format!("{name} connection plus one"))
                .await;
            tokio::time::timeout(Duration::from_secs(3), occupying.shutdown())
                .await
                .expect("TCP matrix slot-holder shutdown is bounded")
                .unwrap();
            controls
                .wait_for_active_connections(mode, 0, Duration::from_secs(3))
                .await
                .expect("the listener permit recovers after client close");
        }

        let mut register = msg("register");
        register.tenant = Some("tenant.example".to_string());
        register.config = Some(sample_tenant_config());
        register.admin_token = Some("secret".to_string());
        assert_wire_case!(
            "register success",
            pair.admin_address,
            clone_message(&register),
            OutcomeExpectation::success(Transport::AdminTcp, MetricCommand::Register),
            |bytes: &Vec<u8>| assert!(rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );

        let mut persistent = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(pair.public_address),
        )
        .await
        .expect("persistent-frame connection has a bounded connect")
        .unwrap();
        controls
            .wait_for_active_connections(TransportMode::Public, 1, Duration::from_secs(3))
            .await
            .expect("one production connection owns all persistent-frame attempts");
        for (name, command, request, succeeds) in [
            (
                "persistent frame one version",
                MetricCommand::Version,
                msg("version"),
                true,
            ),
            (
                "persistent frame two quality",
                MetricCommand::QualityScore,
                {
                    let mut request = msg("quality_score");
                    request.text = "ordinary response".to_string();
                    request
                },
                true,
            ),
            (
                "persistent frame three unknown tenant",
                MetricCommand::Classify,
                {
                    let mut request = msg("classify");
                    request.tenant = Some("missing-on-persistent.example".to_string());
                    request.text = "hello".to_string();
                    request
                },
                false,
            ),
        ] {
            let before = outcomes.snapshot();
            let bytes = wire_exchange(&mut persistent, &request).await;
            if succeeds {
                assert!(!bytes.is_empty());
                before.assert_exact_terminal_delta(
                    OutcomeExpectation::success(Transport::Tcp, command),
                    name,
                );
            } else {
                assert!(!rmp_serde::from_slice::<AdminResponse>(&bytes).unwrap().ok);
                before.assert_exact_terminal_delta(
                    OutcomeExpectation::failure(
                        Transport::Tcp,
                        command,
                        Stage::Handler,
                        Reason::TenantNotFound,
                    ),
                    name,
                );
            }
            assert_eq!(
                controls.active_connections(TransportMode::Public),
                1,
                "every frame finalizes while the same connection remains live"
            );
        }
        drop(persistent);
        controls
            .wait_for_active_connections(TransportMode::Public, 0, Duration::from_secs(3))
            .await
            .expect("persistent-frame connection returns its listener permit");

        let mut classify = msg("classify");
        classify.tenant = Some("tenant.example".to_string());
        classify.text = "hello".to_string();
        assert_wire_case!(
            "classify success",
            pair.public_address,
            classify,
            OutcomeExpectation::success(Transport::Tcp, MetricCommand::Classify),
            |bytes: &Vec<u8>| assert!(!bytes.is_empty())
        );
        for (name, command, message) in [
            ("quality success", MetricCommand::QualityScore, {
                let mut message = msg("quality_score");
                message.text = "ordinary response".to_string();
                message
            }),
            ("version success", MetricCommand::Version, msg("version")),
            ("intent success", MetricCommand::IntentDetect, {
                let mut message = msg("intent_detect");
                message.intent_text = Some("please write code".to_string());
                message
            }),
            ("stream safety success", MetricCommand::StreamingSafety, {
                let mut message = msg("streaming_safety");
                message.streaming_tokens = Some("safe".to_string());
                message.safety_rules = Some(vec!["forbidden".to_string()]);
                message
            }),
            ("content type success", MetricCommand::ContentTypeDetect, {
                let mut message = msg("content_type_detect");
                message.detect_content = Some("fn main() {}".to_string());
                message
            }),
        ] {
            let before = outcomes.snapshot();
            let mut stream =
                bounded_tcp_connect(pair.public_address, "public success matrix case").await;
            assert!(!wire_exchange(&mut stream, &message).await.is_empty());
            before.assert_exact_terminal_delta(
                OutcomeExpectation::success(Transport::Tcp, command),
                name,
            );
            drop(stream);
            controls
                .wait_for_active_connections(TransportMode::Public, 0, Duration::from_secs(3))
                .await
                .expect("public command connection releases its permit");
        }

        let mut list = msg("list");
        list.admin_token = Some("secret".to_string());
        assert_wire_case!(
            "list success",
            pair.admin_address,
            list,
            OutcomeExpectation::success(Transport::AdminTcp, MetricCommand::List),
            |bytes: &Vec<u8>| assert!(rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );

        let mut unknown_tenant = msg("classify");
        unknown_tenant.tenant = Some("missing.example".to_string());
        assert_wire_case!(
            "unknown tenant",
            pair.public_address,
            unknown_tenant,
            OutcomeExpectation::failure(
                Transport::Tcp,
                MetricCommand::Classify,
                Stage::Handler,
                Reason::TenantNotFound,
            ),
            |bytes: &Vec<u8>| assert!(!rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );
        assert_wire_case!(
            "unknown command",
            pair.public_address,
            msg("not-real"),
            OutcomeExpectation::failure(
                Transport::Tcp,
                MetricCommand::Unknown,
                Stage::Route,
                Reason::UnknownCommand,
            ),
            |bytes: &Vec<u8>| assert!(!rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );

        let mut public_register = clone_message(&register);
        public_register.admin_token = None;
        assert_wire_case!(
            "admin command on public transport",
            pair.public_address,
            public_register,
            OutcomeExpectation::failure(
                Transport::Tcp,
                MetricCommand::Register,
                Stage::Authorize,
                Reason::Forbidden,
            ),
            |bytes: &Vec<u8>| assert!(!rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );
        let mut admin_classify = msg("classify");
        admin_classify.tenant = Some("tenant.example".to_string());
        admin_classify.text = "hello".to_string();
        assert_wire_case!(
            "inference command on admin transport",
            pair.admin_address,
            admin_classify,
            OutcomeExpectation::failure(
                Transport::AdminTcp,
                MetricCommand::Classify,
                Stage::Authorize,
                Reason::Forbidden,
            ),
            |bytes: &Vec<u8>| assert!(!rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );
        for (name, token, reason) in [
            ("admin missing token", None, Reason::Unauthorized),
            (
                "admin invalid token",
                Some("wrong".to_string()),
                Reason::Unauthorized,
            ),
            (
                "admin forbidden scope",
                Some("scoped".to_string()),
                Reason::Forbidden,
            ),
        ] {
            let mut request = msg("register");
            request.tenant = Some("outside-scope.example".to_string());
            request.config = Some(sample_tenant_config());
            request.admin_token = token;
            let before = outcomes.snapshot();
            let mut stream =
                bounded_tcp_connect(pair.admin_address, "admin auth matrix case").await;
            let response: AdminResponse =
                rmp_serde::from_slice(&wire_exchange(&mut stream, &request).await).unwrap();
            assert!(!response.ok);
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    Transport::AdminTcp,
                    MetricCommand::Register,
                    Stage::Authorize,
                    reason,
                ),
                name,
            );
            drop(stream);
            controls
                .wait_for_active_connections(TransportMode::Admin, 0, Duration::from_secs(3))
                .await
                .expect("admin auth connection releases its permit");
        }

        for (name, command, reason, mut request) in [
            (
                "register missing tenant",
                MetricCommand::Register,
                Reason::MissingField,
                {
                    let mut request = msg("register");
                    request.config = Some(sample_tenant_config());
                    request.admin_token = Some("secret".to_string());
                    request
                },
            ),
            (
                "register missing config",
                MetricCommand::Register,
                Reason::MissingField,
                {
                    let mut request = msg("register");
                    request.tenant = Some("missing-config.example".to_string());
                    request.admin_token = Some("secret".to_string());
                    request
                },
            ),
            (
                "register invalid config",
                MetricCommand::Register,
                Reason::InvalidConfig,
                {
                    let mut request = msg("register");
                    request.tenant = Some("invalid.example".to_string());
                    request.config = Some(TenantConfig {
                        labels: Vec::new(),
                        classification: None,
                        normalization: None,
                    });
                    request.admin_token = Some("secret".to_string());
                    request
                },
            ),
            (
                "delete missing tenant",
                MetricCommand::Delete,
                Reason::MissingField,
                {
                    let mut request = msg("delete");
                    request.admin_token = Some("secret".to_string());
                    request
                },
            ),
            (
                "delete unknown tenant",
                MetricCommand::Delete,
                Reason::TenantNotFound,
                {
                    let mut request = msg("delete");
                    request.tenant = Some("absent.example".to_string());
                    request.admin_token = Some("secret".to_string());
                    request
                },
            ),
        ] {
            request
                .admin_token
                .get_or_insert_with(|| "secret".to_string());
            let before = outcomes.snapshot();
            let mut stream =
                bounded_tcp_connect(pair.admin_address, "admin handler matrix case").await;
            let response: AdminResponse =
                rmp_serde::from_slice(&wire_exchange(&mut stream, &request).await).unwrap();
            assert!(!response.ok, "{name}");
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(Transport::AdminTcp, command, Stage::Handler, reason),
                name,
            );
            drop(stream);
            controls
                .wait_for_active_connections(TransportMode::Admin, 0, Duration::from_secs(3))
                .await
                .expect("admin handler connection releases its permit");
        }

        let mut quality = msg("quality_score");
        quality.text = "handler fault".to_string();
        let mut faulted_list = msg("list");
        faulted_list.admin_token = Some("secret".to_string());
        for (name, mode, address, transport, command, request) in [
            (
                "public handler failure",
                TransportMode::Public,
                pair.public_address,
                Transport::Tcp,
                MetricCommand::QualityScore,
                quality,
            ),
            (
                "admin handler failure",
                TransportMode::Admin,
                pair.admin_address,
                Transport::AdminTcp,
                MetricCommand::List,
                clone_message(&faulted_list),
            ),
        ] {
            let armed = controls.arm_next(mode, TcpFault::Handler(command));
            let before = outcomes.snapshot();
            let response = raw_exchange_until_close(address, &framed(&request), true).await;
            wait_mode_idle!(mode, name);
            assert!(response.is_empty(), "{name}");
            armed.assert_consumed_exactly_once();
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(transport, command, Stage::Handler, Reason::Internal),
                name,
            );
        }

        let mut list_for_faults = msg("list");
        list_for_faults.admin_token = Some("secret".to_string());
        for (name, mode, address, transport, command, fault, request, stage, reason) in [
            (
                "public response serialization failure",
                TransportMode::Public,
                pair.public_address,
                Transport::Tcp,
                MetricCommand::Version,
                TcpFault::Serialize(MetricCommand::Version),
                msg("version"),
                Stage::Encode,
                Reason::Internal,
            ),
            (
                "admin response serialization failure",
                TransportMode::Admin,
                pair.admin_address,
                Transport::AdminTcp,
                MetricCommand::List,
                TcpFault::Serialize(MetricCommand::List),
                clone_message(&list_for_faults),
                Stage::Encode,
                Reason::Internal,
            ),
            (
                "public response write failure",
                TransportMode::Public,
                pair.public_address,
                Transport::Tcp,
                MetricCommand::Version,
                TcpFault::Write(MetricCommand::Version),
                msg("version"),
                Stage::Write,
                Reason::Io,
            ),
            (
                "admin response write failure",
                TransportMode::Admin,
                pair.admin_address,
                Transport::AdminTcp,
                MetricCommand::List,
                TcpFault::Write(MetricCommand::List),
                clone_message(&list_for_faults),
                Stage::Write,
                Reason::Io,
            ),
            (
                "public response write deadline",
                TransportMode::Public,
                pair.public_address,
                Transport::Tcp,
                MetricCommand::Version,
                TcpFault::WriteDeadline(MetricCommand::Version),
                msg("version"),
                Stage::Write,
                Reason::Deadline,
            ),
            (
                "admin response write deadline",
                TransportMode::Admin,
                pair.admin_address,
                Transport::AdminTcp,
                MetricCommand::List,
                TcpFault::WriteDeadline(MetricCommand::List),
                clone_message(&list_for_faults),
                Stage::Write,
                Reason::Deadline,
            ),
            (
                "public response flush failure",
                TransportMode::Public,
                pair.public_address,
                Transport::Tcp,
                MetricCommand::Version,
                TcpFault::Flush(MetricCommand::Version),
                msg("version"),
                Stage::Write,
                Reason::Io,
            ),
            (
                "admin response flush failure",
                TransportMode::Admin,
                pair.admin_address,
                Transport::AdminTcp,
                MetricCommand::List,
                TcpFault::Flush(MetricCommand::List),
                clone_message(&list_for_faults),
                Stage::Write,
                Reason::Io,
            ),
        ] {
            let armed = controls.arm_next(mode, fault);
            let before = outcomes.snapshot();
            let response = raw_exchange_until_close(address, &framed(&request), true).await;
            wait_mode_idle!(mode, name);
            assert!(response.is_empty(), "{name}");
            armed.assert_consumed_exactly_once();
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(transport, command, stage, reason),
                name,
            );
        }

        let mut delete = msg("delete");
        delete.tenant = Some("tenant.example".to_string());
        delete.admin_token = Some("secret".to_string());
        assert_wire_case!(
            "delete success",
            pair.admin_address,
            delete,
            OutcomeExpectation::success(Transport::AdminTcp, MetricCommand::Delete),
            |bytes: &Vec<u8>| assert!(rmp_serde::from_slice::<AdminResponse>(bytes).unwrap().ok)
        );

        pair.stop().await;
    }

    #[tokio::test]
    async fn public_listener_caps_simultaneous_header_only_max_frames_at_16_mib() {
        let limits = TcpLimits {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            io_timeout: Duration::from_secs(5),
        };
        limits
            .validate()
            .expect("the documented public connection ceiling must be accepted");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let registry = Arc::new(Registry::new_empty());
        let allocation_probe = Arc::new(FrameAllocationProbe::default());
        let server = tokio::spawn(serve_on(
            listener,
            registry,
            TransportMode::Public,
            None,
            limits,
            frame_budget(),
            Some(Arc::clone(&allocation_probe)),
        ));

        // Four maximum frames consume the proposed 16 MiB process budget.
        // A fifth header must be refused before its 4 MiB body allocation,
        // even though all five connections fit under the connection ceiling.
        let mut clients = Vec::new();
        for _ in 0..5 {
            let mut client =
                tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(address))
                    .await
                    .expect("public listener must accept promptly")
                    .unwrap();
            client
                .write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes())
                .await
                .unwrap();
            clients.push(client);
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while allocation_probe.declared_frames() < clients.len()
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if allocation_probe.declared_frames() == clients.len() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let declared_frames = allocation_probe.declared_frames();
        let allocations = allocation_probe.allocations();
        let peak_bytes = allocation_probe.peak_bytes();
        drop(clients);
        server.abort();
        let _ = server.await;
        assert_eq!(
            declared_frames, 5,
            "all five maximum frame headers must reach the public framing boundary"
        );
        assert_eq!(
            allocations, 4,
            "only the four leased frames may call the payload allocator"
        );
        assert_eq!(
            peak_bytes,
            16 * 1024 * 1024,
            "the allocator-coupled observation must stay behind the aggregate lease"
        );
    }

    #[tokio::test]
    async fn oversized_tcp_frame_refusal_records_closed_error_labels() {
        let before = crate::metrics::error_count("tcp", "decode", "resource_limit");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_on(
            listener,
            Arc::new(Registry::new_empty()),
            TransportMode::Public,
            None,
            TcpLimits {
                max_connections: 1,
                io_timeout: Duration::from_secs(1),
            },
            frame_budget(),
            None,
        ));

        let mut client = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(address))
            .await
            .expect("oversized-frame client must connect promptly")
            .unwrap();
        client
            .write_all(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        let mut closed = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut closed))
            .await
            .expect("oversized-frame refusal must close the connection promptly");
        match read {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("oversized-frame connection remained usable: {other:?}"),
        }

        let after = crate::metrics::error_count("tcp", "decode", "resource_limit");
        server.abort();
        let _ = server.await;
        assert_eq!(
            after - before,
            1,
            "oversized TCP frames must increment tcp/decode/resource_limit"
        );
    }

    #[tokio::test]
    async fn serve_on_defensively_rejects_limits_above_the_connection_ceiling() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registry = Arc::new(Registry::new_empty());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = started_tx.send(());
            serve_on(
                listener,
                registry,
                TransportMode::Public,
                None,
                TcpLimits {
                    max_connections: DEFAULT_MAX_CONNECTIONS + 1,
                    io_timeout: Duration::from_millis(100),
                },
                frame_budget(),
                None,
            )
            .await
        });

        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        if !server.is_finished() {
            server.abort();
            let _ = server.await;
            panic!("serve_on awaited a connection before fully validating TCP limits");
        }

        let error = server
            .await
            .unwrap()
            .expect_err("serve_on must reject an excessive connection limit");
        assert_eq!(error.to_string(), "TCP max_connections must be in 1..=128");
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
                frame_budget(),
                None,
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

    #[test]
    fn sanitize_preserves_utf8_boundaries() {
        let tenant = format!("{}é", "a".repeat(127));
        let sanitized = sanitize(&tenant, 128);

        assert_eq!(sanitized, format!("{}...", "a".repeat(127)));
    }

    #[test]
    fn config_rejects_out_of_bounds_tcp_limits() {
        for (max, timeout) in [
            (0, Duration::from_millis(100)),
            (DEFAULT_MAX_CONNECTIONS + 1, Duration::from_millis(100)),
            (usize::MAX, Duration::from_millis(100)),
            (10, Duration::from_millis(0)),
            (10, Duration::from_secs(61)),
            (10, Duration::MAX),
        ] {
            let limits = TcpLimits {
                max_connections: max,
                io_timeout: timeout,
            };
            assert!(limits.validate().is_err());
        }
    }
}
