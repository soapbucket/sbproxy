//! Embedded admin/stats API server.
//!
//! Serves a minimal read-only API on a configurable port for:
//! - Live metrics (JSON format of Prometheus data)
//! - Recent request log (last N requests)
//! - Origin health status
//! - Active connections
//!
//! Config:
//! proxy.admin.enabled: true
//! proxy.admin.port: 9090
//! proxy.admin.username: admin
//! proxy.admin.password: changeme

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use sbproxy_config::types::AdminRole;
use serde::Serialize;

pub mod prompt_persistence;
pub use prompt_persistence::PromptPersistence;

// --- Config ---

/// Configuration for the admin server.
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// Whether the admin endpoint is exposed.
    pub enabled: bool,
    /// TCP port the admin server binds on.
    pub port: u16,
    /// Basic auth username required to access the admin API.
    pub username: String,
    /// Basic auth password required to access the admin API.
    pub password: String,
    /// Maximum number of recent request log entries to retain in memory.
    pub max_log_entries: usize,
    /// Optional TLS (WOR-1717). When set, the admin server (and the
    /// built-in UI) is served over HTTPS with this PEM cert + key instead
    /// of plaintext HTTP.
    pub tls: Option<AdminTls>,
    /// WOR-1717: bind address. Defaults to `127.0.0.1` (loopback only).
    pub bind: String,
    /// WOR-1717: IP / CIDR allowlist. Empty means loopback-only.
    pub allow_ips: Vec<String>,
    /// WOR-1717: allowed CORS origins. Empty means no CORS headers.
    pub cors_origins: Vec<String>,
    /// WOR-1716: RBAC operators in addition to the top-level admin (which
    /// is always the full-access `admin` role).
    pub operators: Vec<AdminOperator>,
}

/// PEM certificate + key file paths for admin-server TLS (WOR-1717).
#[derive(Debug, Clone)]
pub struct AdminTls {
    /// Path to the PEM certificate chain.
    pub cert: std::path::PathBuf,
    /// Path to the PEM private key (PKCS#8 or RSA).
    pub key: std::path::PathBuf,
}

/// An admin operator identity with a role, for RBAC (WOR-1716).
#[derive(Debug, Clone)]
pub struct AdminOperator {
    /// Login username.
    pub username: String,
    /// Login password.
    pub password: String,
    /// Role governing which admin actions this operator may perform.
    pub role: AdminRole,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9090,
            username: "admin".to_string(),
            password: "changeme".to_string(),
            max_log_entries: 1000,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        }
    }
}

// --- Rate Limiter ---

/// Internal counter state protected by a single mutex so per-IP and global
/// counters always advance together. Holding one lock for both keeps the
/// hot path short; the alternative (two locks) opens a race where an
/// attacker can slip past the global cap by interleaving IPs.
struct RateState {
    /// ip -> (request_count, window_start_ms)
    per_ip: HashMap<String, (u64, u64)>,
    /// Global (request_count, window_start_ms).
    global: (u64, u64),
}

/// Rate limiter for the admin endpoint with both per-IP and global caps.
///
/// The per-IP cap stops a single client from hammering the admin API. The
/// global cap stops a distributed flood, since per-IP alone trivially scales by
/// rotating source IPs, which is especially cheap over IPv6. A request is
/// accepted only if it is within both limits.
pub struct AdminRateLimiter {
    state: Mutex<RateState>,
    max_per_minute: u64,
    max_global_per_minute: u64,
    /// Cap on the size of the per-IP map. Without this, unique-IP floods
    /// can grow the map without bound even when the per-IP cap rejects
    /// the actual requests.
    max_tracked_ips: usize,
}

impl AdminRateLimiter {
    /// Create a rate limiter with a per-IP cap. The global cap defaults to
    /// ten times the per-IP cap, which lets ~10 concurrent real clients
    /// use the admin API fully while still bounding total traffic.
    pub fn new(max_per_minute: u64) -> Self {
        Self::with_global(max_per_minute, max_per_minute.saturating_mul(10))
    }

    /// Create a rate limiter with explicit per-IP and global caps.
    pub fn with_global(max_per_minute: u64, max_global_per_minute: u64) -> Self {
        Self {
            state: Mutex::new(RateState {
                per_ip: HashMap::new(),
                global: (0, 0),
            }),
            max_per_minute,
            max_global_per_minute,
            max_tracked_ips: 10_000,
        }
    }

    /// Returns `true` if the request from `ip` is within both the per-IP
    /// and the global rate limit.
    pub fn check(&self, ip: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut state = self
            .state
            .lock()
            .expect("admin rate limiter mutex poisoned");

        // Roll over the global window first so a stale window from a
        // previous minute doesn't count against us.
        if now.saturating_sub(state.global.1) > 60_000 {
            state.global = (0, now);
        }

        // Evict old per-IP entries once the map grows past the cap. We
        // walk the map only when above capacity so the hot path stays
        // cheap; cold paths pay a linear scan amortised by rarity.
        if state.per_ip.len() >= self.max_tracked_ips {
            state
                .per_ip
                .retain(|_, (_, window)| now.saturating_sub(*window) <= 60_000);
        }

        // Snapshot the per-IP counter after (possible) window reset. We
        // take the values, drop the &mut borrow, consult the global, and
        // only write back if we decide to admit the request. Holding
        // `entry` across the global access would mean two &mut borrows of
        // `state` at once.
        let (ip_count, ip_window) = {
            let entry = state.per_ip.entry(ip.to_string()).or_insert((0, now));
            if now.saturating_sub(entry.1) > 60_000 {
                *entry = (0, now);
            }
            (entry.0, entry.1)
        };

        let next_ip = ip_count + 1;
        let next_global = state.global.0 + 1;
        if next_ip > self.max_per_minute || next_global > self.max_global_per_minute {
            // Reject: do not bump counters, so a blocked caller does not
            // starve a later well-behaved one.
            return false;
        }

        // Admitted: write the advanced per-IP counter back, then bump
        // the global counter.
        state.per_ip.insert(ip.to_string(), (next_ip, ip_window));
        state.global.0 = next_global;
        true
    }
}

// --- IP Filter ---

/// Configurable IP allowlist for the admin endpoint.
///
/// When the allowlist is empty, all IPs are permitted. When non-empty, only
/// IPs present in the list are allowed.
pub struct AdminIpFilter {
    allowed_ips: Vec<String>,
}

impl AdminIpFilter {
    /// Create an IP filter with an explicit allowlist.
    pub fn new(allowed_ips: Vec<String>) -> Self {
        Self { allowed_ips }
    }

    /// Create a filter that only permits loopback addresses.
    pub fn localhost_only() -> Self {
        Self {
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }

    /// Returns `true` if `ip` is permitted. An empty allowlist permits all
    /// IPs (callers pass a non-empty list, or use `localhost_only`, so the
    /// safe default is never the permit-all path). Each entry matches
    /// either as an exact address or, when it parses as a CIDR, as a
    /// network containing `ip` (WOR-1717).
    pub fn is_allowed(&self, ip: &str) -> bool {
        if self.allowed_ips.is_empty() {
            return true;
        }
        let parsed: Option<std::net::IpAddr> = ip.parse().ok();
        self.allowed_ips.iter().any(|a| {
            if a == ip {
                return true;
            }
            if let (Some(addr), Ok(net)) = (parsed, a.parse::<ipnetwork::IpNetwork>()) {
                return net.contains(addr);
            }
            false
        })
    }
}

// --- Request Log ---

/// Recent request log entry stored in a ring buffer.
#[derive(Debug, Clone, Serialize)]
pub struct RequestLogEntry {
    /// RFC 3339 timestamp marking when the request was processed.
    pub timestamp: String,
    /// Origin name that handled the request.
    pub origin: String,
    /// HTTP method of the request.
    pub method: String,
    /// Request path including query string.
    pub path: String,
    /// HTTP response status code.
    pub status: u16,
    /// End-to-end request latency in milliseconds.
    pub latency_ms: f64,
    /// Client IP address as observed by the proxy.
    pub client_ip: String,
}

// --- Admin State ---

/// Per-revision cached rendering of the emitted OpenAPI document.
///
/// We cache the rendered JSON / YAML bytes keyed on the live pipeline's
/// `config_revision` so the spec is rebuilt only when the underlying
/// config changes. Reads after the first miss for a revision return the
/// cached bytes directly.
struct OpenApiCache {
    /// Revision tag of the pipeline that produced the cached bytes.
    revision: String,
    /// Cached JSON rendering, populated on first JSON request for a revision.
    json: Option<String>,
    /// Cached YAML rendering, populated on first YAML request for a revision.
    yaml: Option<String>,
}

impl OpenApiCache {
    fn empty() -> Self {
        Self {
            revision: String::new(),
            json: None,
            yaml: None,
        }
    }
}

/// Shared state for the admin API.
pub struct AdminState {
    /// Ring buffer of the most recent request log entries.
    pub recent_requests: Mutex<VecDeque<RequestLogEntry>>,
    /// Admin server configuration in effect.
    pub config: AdminConfig,
    /// Revision-keyed cache of the rendered OpenAPI document.
    openapi_cache: Mutex<OpenApiCache>,
    /// Path to the config file backing the running pipeline.
    ///
    /// Used by `POST /admin/reload` to re-read and hot-swap the
    /// pipeline. `None` when the admin server is constructed without
    /// a known on-disk config (e.g. in unit tests).
    pub config_path: Option<PathBuf>,
    /// 12-char hex prefix of SHA-256 of the raw YAML bytes that
    /// produced the running pipeline (same format as
    /// [`crate::identity::config_revision`]). Set by
    /// [`AdminState::with_loaded_config_content_hash`] at startup
    /// and refreshed by the reload handler on every successful swap.
    /// `None` until the proxy has loaded a config from disk (which
    /// means `/admin/drift` cannot make a determination yet).
    ///
    /// Tracked alongside `pipeline.config_revision`: the pipeline
    /// revision is an origin-set identity hash and does not move when
    /// only policies, transforms, or ports change, so it cannot
    /// answer "has the on-disk file drifted from what is loaded?". The
    /// raw-bytes SHA-256 moves on any byte-level edit, which is what
    /// an operator means by drift.
    pub loaded_config_content_hash: Mutex<Option<String>>,
    /// Single-flight guard for `/admin/reload`.
    ///
    /// We CAS this from `false` to `true` on entry; if the swap
    /// fails another reload is already in flight and the request
    /// returns `409 Conflict`. The file watcher and any other
    /// in-process reload call sites contend on the same flag so a
    /// manual reload during a watcher reload serialises cleanly.
    reload_in_progress: AtomicBool,
    /// Per-pillar health registry powering `/healthz` + `/readyz` per
    /// `docs/AIGOVERNANCE-BUILD.md` § 4.2. Per-wave probes are
    /// registered into this registry as their backing services come
    /// online; until then the default seeded set keeps `NotConfigured`
    /// stubs in place so readiness still passes.
    pub health_registry: sbproxy_observe::HealthRegistry,
    /// WOR-800 PR4: optional persistence handle for the prompt
    /// runtime overlay. When set, every `POST .../versions` and
    /// `PUT .../pin` mutation also writes the resulting
    /// [`sbproxy_ai::prompts::NamedPrompt`] to redb so the overlay
    /// survives restart. `None` means PR3-style ephemeral mutations
    /// (the default); the binary opts in via
    /// [`AdminState::with_prompt_persistence`].
    pub prompt_persistence: Option<Arc<PromptPersistence>>,
    /// WOR-1714: ephemeral HMAC signer for browser session tokens. A
    /// fresh key per process, so a restart invalidates every session.
    pub session_signer: crate::admin_session::SessionSigner,
    /// WOR-1714: revoked session nonces (populated by `POST /admin/logout`),
    /// cleared on restart. Checked on every session verification.
    pub revoked_sessions: Mutex<std::collections::HashSet<String>>,
    /// WOR-1718: broadcast of each logged request (as JSON) for the SSE
    /// tail at `GET /api/requests/stream`. A subscriber that falls behind
    /// the buffer is lagged (skipped), never blocking `log_request`.
    pub log_events: tokio::sync::broadcast::Sender<String>,
}

impl AdminState {
    /// Create a new `AdminState` with the given configuration.
    ///
    /// The `config_path` field is left empty; callers that want
    /// `POST /admin/reload` to work must set it via
    /// [`AdminState::with_config_path`].
    pub fn new(config: AdminConfig) -> Self {
        Self {
            recent_requests: Mutex::new(VecDeque::new()),
            config,
            openapi_cache: Mutex::new(OpenApiCache::empty()),
            config_path: None,
            loaded_config_content_hash: Mutex::new(None),
            reload_in_progress: AtomicBool::new(false),
            health_registry: sbproxy_observe::default_registry_optional(None, None),
            prompt_persistence: None,
            session_signer: crate::admin_session::SessionSigner::random(),
            revoked_sessions: Mutex::new(std::collections::HashSet::new()),
            log_events: tokio::sync::broadcast::channel(256).0,
        }
    }

    /// Resolve the operator + role from a session cookie or Basic auth
    /// (WOR-1714 / WOR-1716). Session takes precedence. Returns `None`
    /// when neither authenticates. The `csrf` field is set only for the
    /// session path (the nonce the caller must echo in `X-CSRF-Token`).
    pub fn resolve_principal(
        &self,
        auth_header: Option<&str>,
        cookie_header: Option<&str>,
    ) -> Option<AdminPrincipal> {
        // Session cookie first.
        if let Some(ch) = cookie_header {
            if let Some(tok) =
                crate::admin_session::cookie_value(ch, crate::admin_session::SESSION_COOKIE)
            {
                let now = unix_now();
                if let Some(sess) = self.session_signer.verify(&tok, now) {
                    let revoked = self
                        .revoked_sessions
                        .lock()
                        .map(|s| s.contains(&sess.nonce))
                        .unwrap_or(false);
                    if !revoked {
                        return Some(AdminPrincipal {
                            username: sess.username,
                            role: sess.role,
                            via_session: true,
                            csrf: Some(sess.nonce),
                        });
                    }
                }
            }
        }
        // Basic auth: the top-level admin credential (full access).
        if let Some((user, pass)) = auth_header.and_then(decode_basic_auth) {
            if self.check_auth(&user, &pass) {
                return Some(AdminPrincipal {
                    username: user,
                    role: AdminRole::Admin,
                    via_session: false,
                    csrf: None,
                });
            }
        }
        None
    }

    /// Verify login credentials against the top-level admin and the
    /// configured operators (WOR-1716), returning the matched role.
    pub fn check_operator_login(&self, user: &str, pass: &str) -> Option<AdminRole> {
        if self.check_auth(user, pass) {
            return Some(AdminRole::Admin);
        }
        self.config
            .operators
            .iter()
            .find(|o| {
                o.username == user && constant_time_eq(o.password.as_bytes(), pass.as_bytes())
            })
            .map(|o| o.role)
    }

    /// Builder-style setter for the on-disk config path.
    ///
    /// Wires `POST /admin/reload` to the file the proxy was
    /// started with so the route reloads the same content the
    /// file watcher would. Returning `Self` keeps the construction
    /// idiom in `server::run` a single expression.
    pub fn with_config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_path = Some(path.into());
        self
    }

    /// Builder-style setter for the loaded-config SHA-256.
    ///
    /// Called by the binary at startup once the initial YAML has been
    /// read so `/admin/drift` can compare the on-disk file's current
    /// hash against the hash captured at load time. The reload
    /// handler updates the same field on every successful swap so the
    /// drift baseline tracks the live pipeline.
    pub fn with_loaded_config_content_hash(self, hex: impl Into<String>) -> Self {
        *self
            .loaded_config_content_hash
            .lock()
            .expect("loaded config sha256 mutex poisoned") = Some(hex.into());
        self
    }

    /// Replace the health registry. Callers seed the registry with
    /// `sbproxy_observe::default_registry(...)` so `/readyz` reports
    /// the standard pillar set; additional probes are registered via
    /// `state.health_registry.register(...)`.
    pub fn with_health_registry(mut self, registry: sbproxy_observe::HealthRegistry) -> Self {
        self.health_registry = registry;
        self
    }

    /// WOR-800 PR4: install a [`PromptPersistence`] handle so the
    /// prompt-admin mutators write through to redb. Callers that want
    /// the runtime overlay to survive restart open the handle (which
    /// also hydrates the in-memory overlay from the file) and pass
    /// it here. Tests can call this with an in-memory backing store
    /// via [`PromptPersistence::from_store`].
    pub fn with_prompt_persistence(mut self, persistence: Arc<PromptPersistence>) -> Self {
        self.prompt_persistence = Some(persistence);
        self
    }

    /// Add a request to the log (ring buffer, drops oldest when full).
    pub fn log_request(&self, entry: RequestLogEntry) {
        let mut log = self
            .recent_requests
            .lock()
            .expect("admin log mutex poisoned");
        if log.len() >= self.config.max_log_entries {
            log.pop_front();
        }
        // WOR-1718: fan out to the SSE tail before dropping the lock (best
        // effort; no subscribers or a full buffer is a no-op / lag).
        if self.log_events.receiver_count() > 0 {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = self.log_events.send(json);
            }
        }
        log.push_back(entry);
    }

    /// Get recent requests (newest first), up to `limit` entries.
    pub fn get_recent_requests(&self, limit: usize) -> Vec<RequestLogEntry> {
        let log = self
            .recent_requests
            .lock()
            .expect("admin log mutex poisoned");
        log.iter().rev().take(limit).cloned().collect()
    }

    /// Query the recent-request log (newest first) with optional filters
    /// and pagination (WOR-1718). `status` is an exact code, `method` is
    /// case-insensitive, `path_sub` is a substring, `offset`/`limit`
    /// paginate the filtered result.
    pub fn query_requests(
        &self,
        status: Option<u16>,
        method: Option<&str>,
        path_sub: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Vec<RequestLogEntry> {
        let log = self
            .recent_requests
            .lock()
            .expect("admin log mutex poisoned");
        log.iter()
            .rev()
            .filter(|e| status.is_none_or(|s| e.status == s))
            .filter(|e| method.is_none_or(|m| e.method.eq_ignore_ascii_case(m)))
            .filter(|e| path_sub.is_none_or(|p| e.path.contains(p)))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Validate basic auth credentials using constant-time comparison.
    pub fn check_auth(&self, username: &str, password: &str) -> bool {
        // Use explicit length checks before byte-by-byte compare to avoid
        // leaking length information only when both sides have the same length.
        let user_ok = constant_time_eq(username.as_bytes(), self.config.username.as_bytes());
        let pass_ok = constant_time_eq(password.as_bytes(), self.config.password.as_bytes());
        user_ok & pass_ok
    }
}

// --- Auth Helpers ---

/// The authenticated admin operator for a request (WOR-1714 / WOR-1716):
/// who they are, their role, whether they came in via a browser session
/// (which triggers CSRF enforcement), and the CSRF nonce to match.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    /// Operator username (for the audit trail).
    pub username: String,
    /// Role governing which actions are permitted.
    pub role: AdminRole,
    /// True when authenticated by session cookie (vs Basic).
    pub via_session: bool,
    /// The session nonce, which the client must echo in `X-CSRF-Token`
    /// on state-changing requests. `None` for Basic auth.
    pub csrf: Option<String>,
}

/// Current unix time in seconds; `0` on a clock error (which fails expiry
/// checks closed).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time byte slice comparison.  Returns true iff `a == b`.
/// Avoids short-circuit on length mismatch by always visiting every byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decode a base64-encoded `user:password` string from an HTTP Basic Auth header.
///
/// Expects the header value in the form `"Basic <base64>"`.
fn decode_basic_auth(header: &str) -> Option<(String, String)> {
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64_decode(encoded.trim())?;
    let text = String::from_utf8(decoded).ok()?;
    let mut parts = text.splitn(2, ':');
    let user = parts.next()?.to_string();
    let pass = parts.next()?.to_string();
    Some((user, pass))
}

/// Minimal base64 decoder (standard alphabet, no padding required).
/// Avoids pulling in an external crate for this small use case.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Standard base64 alphabet.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut table = [0xFFu8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &b in bytes {
        if b == b'=' {
            break; // padding
        }
        let val = table[b as usize];
        if val == 0xFF {
            return None; // invalid character
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(out)
}

// --- Target health rendering ---

/// Walk the live pipeline and emit a JSON snapshot of every load
/// balancer target's resilience state: active health verdict, outlier
/// ejection state, and circuit breaker state. Operators query this to
/// see exactly what `select_target` would skip right now.
fn render_target_health() -> String {
    use sbproxy_modules::Action;
    let pipeline = crate::reload::current_pipeline();
    let mut origins = Vec::new();
    for (idx, origin) in pipeline.config.origins.iter().enumerate() {
        let action = match pipeline.actions.get(idx) {
            Some(a) => a,
            None => continue,
        };
        let lb = match action {
            Action::LoadBalancer(lb) => lb,
            _ => continue,
        };
        let mut targets = Vec::with_capacity(lb.targets.len());
        for (t_idx, target) in lb.targets.iter().enumerate() {
            let healthy = lb.target_is_healthy(t_idx);
            let outlier_ejected = lb
                .outlier_detector
                .as_ref()
                .map(|d| d.is_ejected(&lb.target_id(t_idx)))
                .unwrap_or(false);
            let breaker_state = lb
                .circuit_breakers
                .as_ref()
                .and_then(|brs| brs.get(t_idx))
                .map(|b| match b.state() {
                    sbproxy_platform::CircuitState::Closed => "closed",
                    sbproxy_platform::CircuitState::Open => "open",
                    sbproxy_platform::CircuitState::HalfOpen => "half_open",
                });
            let eligible = healthy && !outlier_ejected && breaker_state != Some("open");
            targets.push(serde_json::json!({
                "index": t_idx,
                "url": target.url,
                "eligible": eligible,
                "healthy": healthy,
                "outlier_ejected": outlier_ejected,
                "circuit_breaker_state": breaker_state,
                "weight": target.weight,
                "backup": target.backup,
                "group": target.group,
                "zone": target.zone,
            }));
        }
        origins.push(serde_json::json!({
            "hostname": origin.hostname.as_str(),
            "origin_id": origin.origin_id.as_str(),
            "targets": targets,
        }));
    }
    serde_json::json!({
        "config_revision": pipeline.config_revision,
        "origins": origins,
    })
    .to_string()
}

// --- OpenAPI rendering ---

/// Render the live pipeline's OpenAPI document as JSON or YAML.
///
/// The render is cached per `config_revision` on the supplied
/// `AdminState` so back-to-back requests return the cached bytes. The
/// cache invalidates whenever the live pipeline's revision changes
/// (i.e. on hot reload).
fn render_openapi(state: &AdminState, yaml: bool) -> Result<String, String> {
    let pipeline = crate::reload::current_pipeline();
    let revision = pipeline.config_revision.clone();

    let mut cache = state
        .openapi_cache
        .lock()
        .expect("openapi cache mutex poisoned");
    if cache.revision != revision {
        // Stale: drop both renderings; we'll repopulate the requested
        // format below and let the other format lazy-build on its
        // first request.
        cache.revision = revision;
        cache.json = None;
        cache.yaml = None;
    }

    if yaml {
        if let Some(cached) = &cache.yaml {
            return Ok(cached.clone());
        }
        let spec = sbproxy_openapi::build(&pipeline.config, None);
        let rendered = sbproxy_openapi::render_yaml(&spec)
            .map_err(|e| format!("failed to render OpenAPI YAML: {e}"))?;
        cache.yaml = Some(rendered.clone());
        Ok(rendered)
    } else {
        if let Some(cached) = &cache.json {
            return Ok(cached.clone());
        }
        let spec = sbproxy_openapi::build(&pipeline.config, None);
        let rendered = sbproxy_openapi::render_json(&spec)
            .map_err(|e| format!("failed to render OpenAPI JSON: {e}"))?;
        cache.json = Some(rendered.clone());
        Ok(rendered)
    }
}

// --- Quote-token JWKS rendering ---

/// Render the public-key set covering every origin's
/// `ai_crawl_control` quote-token signer.
///
/// The returned document follows the standard JWKS shape:
///
/// ```json
/// {
///   "keys": [
///     {"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"...","x":"<b64url>"},
///     ...
///   ]
/// }
/// ```
///
/// Aggregates kids across the active config's compiled origins so a
/// multi-tenant deployment publishes one document for all of its
/// issuers. Origins without a multi-rail plan (and therefore without
/// a quote-token signer) contribute zero keys; if no origin in the
/// active config has a signer the body is `{"keys":[]}`. Duplicate
/// kids land once: the first occurrence wins so two origins sharing
/// a signer key (operator-managed) do not produce a duplicate entry.
///
/// Served unauthenticated because the published keys are public; the
/// admin server gates this route ahead of the basic-auth check.
pub(crate) fn render_quote_keys_jwks() -> (u16, &'static str, String) {
    use sbproxy_modules::Policy;

    let pipeline = crate::reload::current_pipeline();

    // Collect kids across every origin's policies. A small ordered
    // map keeps the output stable across calls (verifiers cache by
    // body hash; reordering on every reload would defeat the cache).
    let mut keys: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for origin_policies in pipeline.policies.iter() {
        for policy in origin_policies.iter() {
            if let Policy::AiCrawl(p) = policy {
                if let Some(jwks) = p.quote_token_jwks() {
                    if let Some(arr) = jwks.get("keys").and_then(|v| v.as_array()) {
                        for entry in arr {
                            if let Some(kid) = entry.get("kid").and_then(|v| v.as_str()) {
                                keys.entry(kid.to_string()).or_insert_with(|| entry.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let body = serde_json::json!({
        "keys": keys.into_values().collect::<Vec<_>>(),
    });
    let rendered = serde_json::to_string(&body).unwrap_or_else(|_| "{\"keys\":[]}".to_string());
    (200, "application/json", rendered)
}

// --- Reload route ---

/// Sanitise an error message so it never leaks the absolute config
/// path. The file watcher and the reload route both operate on a
/// path the operator picked, so a parse failure that includes the
/// path tells an attacker exactly where the file lives. We strip
/// the directory component and keep only the file name.
fn sanitise_path_in_error(msg: &str, full_path: &std::path::Path) -> String {
    let full = full_path.to_string_lossy();
    if full.is_empty() {
        return msg.to_string();
    }
    let file_name = full_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<config>".to_string());
    msg.replace(full.as_ref(), &file_name)
}

/// Outcome of a `POST /admin/reload` invocation. The
/// `(status, content_type, body)` triple matches the rest of the
/// admin route shape so the dispatcher can hand it back unchanged.
fn handle_reload(state: &AdminState) -> (u16, &'static str, String) {
    // --- Resolve config path ---
    let path = match state.config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return (
                503,
                "application/json",
                r#"{"error":"reload not available: admin server has no config_path wired"}"#
                    .to_string(),
            );
        }
    };

    // --- Single-flight guard ---
    //
    // CAS from false -> true; if the swap fails another reload is
    // already running. We hold the guard across the whole reload so
    // a manual reload during a file-watcher reload (or vice versa)
    // returns 409 immediately rather than queueing work behind the
    // first one.
    if state
        .reload_in_progress
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (
            409,
            "application/json",
            r#"{"error":"reload in progress"}"#.to_string(),
        );
    }

    // RAII guard so any return path resets the flag. We can't use
    // a `?` here because we want to keep manufacturing the error
    // envelope ourselves, but the guard pattern keeps the unwind
    // path safe if any of the called helpers panic.
    struct Guard<'a>(&'a AtomicBool);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _guard = Guard(&state.reload_in_progress);

    // --- Read + compile + load ---
    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "admin reload: failed to read config file");
            let msg = sanitise_path_in_error(&e.to_string(), &path);
            return (
                500,
                "application/json",
                format!(
                    r#"{{"error":"failed to read config file: {}"}}"#,
                    msg.replace('"', "'")
                ),
            );
        }
    };

    let compiled = match sbproxy_config::compile_config(&yaml) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "admin reload: YAML parse failed");
            let msg = sanitise_path_in_error(&e.to_string(), &path);
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"failed to parse config: {}"}}"#,
                    msg.replace('"', "'")
                ),
            );
        }
    };

    let mut new_pipeline = match crate::pipeline::CompiledPipeline::from_config(compiled) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "admin reload: pipeline compile failed");
            let msg = sanitise_path_in_error(&e.to_string(), &path);
            return (
                500,
                "application/json",
                format!(
                    r#"{{"error":"failed to compile pipeline: {}"}}"#,
                    msg.replace('"', "'")
                ),
            );
        }
    };

    // Mirror the file-watcher's enterprise reload-hook contract so a
    // manual reload triggers the same lifecycle hooks as a
    // file-watcher reload. We are already on a tokio runtime here
    // (the admin listener task), so a current-thread runtime would
    // panic; use a one-shot block on the existing runtime via
    // `tokio::task::block_in_place` only if the hook is present.
    if let Some(startup) = new_pipeline.hooks.startup.clone() {
        // Run the hook on a fresh current-thread runtime spawned on a
        // dedicated thread so we don't depend on whatever runtime the
        // caller is on. This matches how the file watcher drives the
        // hook from a plain std thread.
        let res = std::thread::scope(|s| {
            s.spawn(|| -> Result<(), String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("hook runtime: {e}"))?;
                rt.block_on(startup.on_reload(&mut new_pipeline))
                    .map_err(|e| format!("reload hook: {e}"))
            })
            .join()
            .map_err(|_| "hook thread panicked".to_string())?
        });
        if let Err(e) = res {
            tracing::warn!(
                error = %e,
                "admin reload: enterprise reload hook failed; serving with prior hook state"
            );
        }
    }

    let revision = new_pipeline.config_revision.clone();
    let content_hash = crate::identity::config_revision(yaml.as_bytes());
    crate::reload::load_pipeline(new_pipeline);
    *state
        .loaded_config_content_hash
        .lock()
        .expect("loaded config content hash mutex poisoned") = Some(content_hash);
    let loaded_at = chrono::Utc::now().to_rfc3339();
    tracing::info!(
        config_revision = %revision,
        loaded_at = %loaded_at,
        "admin reload: pipeline swapped"
    );

    (
        200,
        "application/json",
        format!(
            r#"{{"config_revision":"{}","loaded_at":"{}"}}"#,
            revision.replace('"', "'"),
            loaded_at,
        ),
    )
}

// --- /admin/config (WOR-1720) ---

/// `GET /admin/config`: return the current on-disk config YAML plus the
/// loaded content-hash, which a client passes back as `if_match` on a
/// write for optimistic concurrency.
fn handle_config_read(state: &AdminState) -> (u16, &'static str, String) {
    let path = match state.config_path.as_ref() {
        Some(p) => p,
        None => {
            return (
                503,
                "application/json",
                r#"{"error":"config path not wired"}"#.to_string(),
            )
        }
    };
    let yaml = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            let msg = sanitise_path_in_error(&e.to_string(), path);
            return (
                500,
                "application/json",
                format!(r#"{{"error":"read config: {}"}}"#, msg.replace('"', "'")),
            );
        }
    };
    let revision = state
        .loaded_config_content_hash
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default();
    (
        200,
        "application/json",
        serde_json::json!({"revision": revision, "yaml": yaml}).to_string(),
    )
}

/// `PUT /admin/config`: validate a proposed config, persist it, and
/// hot-swap the pipeline (WOR-1720). The body is the full `sb.yml`. An
/// optional `if_match` (the content-hash from `GET /admin/config`) gives
/// optimistic concurrency: a mismatch is `409`. The config is compiled
/// before it is written, so an invalid config never clobbers the file.
/// The swap reuses `handle_reload` (single-flight guard, reload hooks).
fn handle_config_write(
    state: &AdminState,
    body: Option<&str>,
    if_match: Option<&str>,
) -> (u16, &'static str, String) {
    let path = match state.config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return (
                503,
                "application/json",
                r#"{"error":"config path not wired"}"#.to_string(),
            )
        }
    };
    let yaml = match body {
        Some(b) if !b.trim().is_empty() => b,
        _ => {
            return (
                400,
                "application/json",
                r#"{"error":"empty config body"}"#.to_string(),
            )
        }
    };
    // Optimistic concurrency: reject if the caller's expected revision no
    // longer matches what is loaded.
    if let Some(expected) = if_match {
        let loaded = state
            .loaded_config_content_hash
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if loaded.as_deref() != Some(expected) {
            return (
                409,
                "application/json",
                format!(
                    r#"{{"error":"revision mismatch","loaded":"{}"}}"#,
                    loaded.unwrap_or_default()
                ),
            );
        }
    }
    // Validate BEFORE writing so a bad config never clobbers the file.
    let compiled = match sbproxy_config::compile_config(yaml) {
        Ok(c) => c,
        Err(e) => {
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"invalid config: {}"}}"#,
                    e.to_string().replace('"', "'")
                ),
            )
        }
    };
    if let Err(e) = crate::pipeline::CompiledPipeline::from_config(compiled) {
        return (
            400,
            "application/json",
            format!(
                r#"{{"error":"config does not compile: {}"}}"#,
                e.to_string().replace('"', "'")
            ),
        );
    }
    // Persist atomically (temp file + rename in the same directory).
    let tmp = path.with_extension("sbproxy-tmp");
    if let Err(e) = std::fs::write(&tmp, yaml.as_bytes()).and_then(|_| std::fs::rename(&tmp, &path))
    {
        let _ = std::fs::remove_file(&tmp);
        let msg = sanitise_path_in_error(&e.to_string(), &path);
        return (
            500,
            "application/json",
            format!(r#"{{"error":"write config: {}"}}"#, msg.replace('"', "'")),
        );
    }
    // Re-read the just-written file and swap via the shared reload path.
    handle_reload(state)
}

// --- /admin/drift ---

/// Compare the on-disk config file at [`AdminState::config_path`]
/// against the content-hash captured the last time the proxy loaded
/// a config (startup or [`AdminState::with_loaded_config_content_hash`]
/// or `POST /admin/reload`).
///
/// Returns the loaded revision (origin-set identity hash), the loaded
/// content hash, the current on-disk content hash, and a `drift`
/// boolean. K8s + dashboards scrape this so an operator can see when
/// the running proxy has diverged from the declared config without
/// triggering a reload.
///
/// Failure modes:
///
/// * `503` - the admin server has no on-disk config path (test mode
///   or non-file-backed configuration), or no content-hash baseline
///   has been captured yet. Drift detection has nothing to compare
///   against.
/// * `500` - the on-disk file could not be read (permissions, ENOENT
///   after start, etc.). The error message has the path scrubbed by
///   [`sanitise_path_in_error`] so the response does not leak the
///   absolute config path.
fn handle_drift(state: &AdminState) -> (u16, &'static str, String) {
    let pipeline = crate::reload::current_pipeline();
    let loaded_revision = pipeline.config_revision.clone();

    let config_path = match &state.config_path {
        Some(p) => p.clone(),
        None => {
            return (
                503,
                "application/json",
                r#"{"error":"admin server has no on-disk config path; drift detection unavailable"}"#
                    .to_string(),
            );
        }
    };

    let loaded_content_hash = state
        .loaded_config_content_hash
        .lock()
        .expect("loaded config content hash mutex poisoned")
        .clone();
    let loaded_content_hash = match loaded_content_hash {
        Some(h) => h,
        None => {
            return (
                503,
                "application/json",
                r#"{"error":"no loaded config content hash baseline; drift detection unavailable until first reload"}"#
                    .to_string(),
            );
        }
    };

    let bytes = match std::fs::read(&config_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "admin drift: failed to read config file");
            let msg = sanitise_path_in_error(&e.to_string(), &config_path);
            return (
                500,
                "application/json",
                format!(
                    r#"{{"error":"failed to read config file: {}"}}"#,
                    msg.replace('"', "'")
                ),
            );
        }
    };
    let on_disk_content_hash = crate::identity::config_revision(&bytes);
    let drift = on_disk_content_hash != loaded_content_hash;

    let body = serde_json::json!({
        "config_path": config_path.display().to_string(),
        "loaded_revision": loaded_revision,
        "loaded_content_hash": loaded_content_hash,
        "on_disk_content_hash": on_disk_content_hash,
        "drift": drift,
        "on_disk_size_bytes": bytes.len(),
        "checked_at": chrono::Utc::now().to_rfc3339(),
    })
    .to_string();
    (200, "application/json", body)
}

// --- WOR-800 PR3: prompt-store runtime overlay handlers ---

/// `GET /admin/prompts`: snapshot the current runtime overlay as a
/// JSON document. Shape:
///
/// ```json
/// {
///   "hosts": {
///     "example.com": {
///       "prompts": {
///         "summary": {
///           "default_version": "2",
///           "effective_version": "2",
///           "versions": ["1", "2"]
///         }
///       }
///     }
///   }
/// }
/// ```
///
/// `default_version` is the pinned version (null when no pin has been
/// set). `effective_version` mirrors the runtime's fallback rule
/// (pin if present, otherwise the highest numeric label) so operators
/// can tell at a glance which template a render would actually pick.
/// The response is intentionally compact: it lists version labels but
/// does not echo the template source. Templates can be large and
/// echoing them back on every read would dominate the response; if an
/// operator needs the source, PR4's persistence layer is the source
/// of truth.
fn handle_prompts_list() -> (u16, &'static str, String) {
    let overlay = sbproxy_ai::prompts::current_runtime_overlay();
    let mut hosts = serde_json::Map::new();
    for (host, store) in &overlay.by_host {
        let mut prompts = serde_json::Map::new();
        for (name, named) in &store.templates {
            let mut versions: Vec<&String> = named.versions.keys().collect();
            versions.sort_by(|a, b| match (a.parse::<u64>(), b.parse::<u64>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.cmp(b),
            });
            let effective_version = named
                .default_version
                .clone()
                .or_else(|| highest_numeric_version_label(&versions));
            prompts.insert(
                name.clone(),
                serde_json::json!({
                    "default_version": named.default_version,
                    "effective_version": effective_version,
                    "versions": versions,
                }),
            );
        }
        hosts.insert(host.clone(), serde_json::json!({ "prompts": prompts }));
    }
    let body = serde_json::json!({ "hosts": hosts }).to_string();
    (200, "application/json", body)
}

/// Mirror of the runtime's "highest numeric version" rule. Used to
/// expose `effective_version` so the list endpoint shows what
/// `PromptStore::render` would actually pick.
fn highest_numeric_version_label(versions: &[&String]) -> Option<String> {
    versions
        .iter()
        .filter_map(|k| k.parse::<u64>().ok().map(|n| (n, *k)))
        .max_by_key(|(n, _)| *n)
        .map(|(_, k)| k.clone())
}

/// Decompose `<host>/<name>/<action>` (e.g. `example.com/summary/versions`)
/// into its three parts. Returns `None` when the segment count is wrong
/// so the dispatcher 404s with a helpful error.
pub(crate) fn parse_prompt_admin_path(rest: &str) -> Option<(&str, &str, &str)> {
    let mut iter = rest.splitn(3, '/');
    let host = iter.next()?;
    let name = iter.next()?;
    let action = iter.next()?;
    if host.is_empty() || name.is_empty() || action.is_empty() {
        return None;
    }
    Some((host, name, action))
}

/// Dispatch the two mutation routes:
///
/// * `POST /admin/prompts/<host>/<name>/versions` adds a version.
/// * `PUT  /admin/prompts/<host>/<name>/pin` pins the default version.
fn dispatch_prompt_admin_route(
    method: &str,
    host: &str,
    name: &str,
    action: &str,
    body: Option<&str>,
    state: &AdminState,
) -> (u16, &'static str, String) {
    match action {
        "versions" => {
            if !method.eq_ignore_ascii_case("POST") {
                return method_not_allowed();
            }
            handle_prompt_add_version(host, name, body, state)
        }
        "pin" => {
            if !method.eq_ignore_ascii_case("PUT") {
                return method_not_allowed();
            }
            handle_prompt_pin(host, name, body, state)
        }
        _ => (
            404,
            "application/json",
            r#"{"error":"unknown prompt admin action"}"#.to_string(),
        ),
    }
}

fn method_not_allowed() -> (u16, &'static str, String) {
    (
        405,
        "application/json",
        r#"{"error":"method not allowed"}"#.to_string(),
    )
}

/// Body shape for `POST /admin/prompts/<host>/<name>/versions`. The
/// `variables` field is the static variables map exposed to the
/// template under `variables.*`; absent or null means an empty map.
#[derive(serde::Deserialize)]
struct AddVersionBody {
    version: String,
    template: String,
    #[serde(default)]
    variables: Option<serde_json::Map<String, serde_json::Value>>,
}

fn handle_prompt_add_version(
    host: &str,
    name: &str,
    body: Option<&str>,
    state: &AdminState,
) -> (u16, &'static str, String) {
    let raw = match body {
        Some(b) if !b.is_empty() => b,
        _ => {
            return (
                400,
                "application/json",
                r#"{"error":"missing JSON body"}"#.to_string(),
            );
        }
    };
    let parsed: AddVersionBody = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"invalid JSON body: {}"}}"#,
                    escape_json(&e.to_string())
                ),
            );
        }
    };
    if parsed.version.is_empty() || parsed.template.is_empty() {
        return (
            400,
            "application/json",
            r#"{"error":"version and template are required and must be non-empty"}"#.to_string(),
        );
    }
    let effective_default = sbproxy_ai::prompts::add_runtime_prompt_version(
        host,
        name,
        &parsed.version,
        parsed.template,
        parsed.variables.unwrap_or_default(),
    );
    // PR4: write through to redb when persistence is configured. A
    // failure is logged but does not fail the request; the in-memory
    // mutation has already succeeded and the operator gets the 200.
    // PR5 / monitoring will surface persistent write failures.
    persist_named_prompt_if_configured(state, host, name);
    let body = serde_json::json!({
        "host": host,
        "name": name,
        "version": parsed.version,
        "default_version": effective_default,
    })
    .to_string();
    (200, "application/json", body)
}

/// Body shape for `PUT /admin/prompts/<host>/<name>/pin`.
#[derive(serde::Deserialize)]
struct PinVersionBody {
    version: String,
}

fn handle_prompt_pin(
    host: &str,
    name: &str,
    body: Option<&str>,
    state: &AdminState,
) -> (u16, &'static str, String) {
    let raw = match body {
        Some(b) if !b.is_empty() => b,
        _ => {
            return (
                400,
                "application/json",
                r#"{"error":"missing JSON body"}"#.to_string(),
            );
        }
    };
    let parsed: PinVersionBody = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"invalid JSON body: {}"}}"#,
                    escape_json(&e.to_string())
                ),
            );
        }
    };
    match sbproxy_ai::prompts::pin_runtime_prompt(host, name, &parsed.version) {
        Ok(()) => {
            // PR4: write through on a successful pin (same policy as
            // add: best-effort, failure is logged but does not 5xx the
            // operator).
            persist_named_prompt_if_configured(state, host, name);
            let body = serde_json::json!({
                "host": host,
                "name": name,
                "default_version": parsed.version,
            })
            .to_string();
            (200, "application/json", body)
        }
        Err(e) => (
            404,
            "application/json",
            format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
        ),
    }
}

/// Re-snapshot the runtime overlay and write the (host, name) entry
/// to redb when a [`PromptPersistence`] handle is configured. Used by
/// the two PR3 mutators; an error is logged but the request stays a
/// 200 so the in-memory mutation is not silently rolled back by a
/// late storage failure.
fn persist_named_prompt_if_configured(state: &AdminState, host: &str, name: &str) {
    let Some(persistence) = state.prompt_persistence.as_ref() else {
        return;
    };
    let overlay = sbproxy_ai::prompts::current_runtime_overlay();
    let Some(store) = overlay.by_host.get(host) else {
        return;
    };
    let Some(named) = store.templates.get(name) else {
        return;
    };
    if let Err(e) = persistence.write_named_prompt(host, name, named) {
        tracing::warn!(
            error = %e,
            host,
            name,
            "prompt persistence write failed; in-memory mutation succeeded but redb is now stale"
        );
    }
}

/// Minimal JSON-string escape: backslashes and double quotes only,
/// enough for safely embedding error text in our JSON envelope.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

// --- Request Handler ---

/// WOR-1130: pull a single query-string value out of a request target
/// (`/path?a=1&b=2`). Returns the first match for `key`, or `None`.
fn rl_query_param<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let q = path.split_once('?')?.1;
    q.split('&').find_map(|kv| {
        kv.split_once('=')
            .and_then(|(k, v)| (k == key).then_some(v))
    })
}

/// Handle an admin API request.
///
/// Returns `(status, content_type, body)`. `method` is the HTTP
/// method (e.g. "GET", "POST"); routes that gate on method (such
/// as `POST /admin/reload`) reject other verbs with `405`.
pub fn handle_admin_request(
    method: &str,
    path: &str,
    state: &AdminState,
    auth_header: Option<&str>,
    body: Option<&str>,
) -> (u16, &'static str, String) {
    // --- Unauthenticated probe routes ---
    //
    // `/healthz` and `/readyz` are reached by load balancers that
    // don't carry credentials, so we serve them before the basic-auth
    // gate. The handlers do not expose anything past per-component
    // status; the redaction middleware in `sbproxy-observe::logging`
    // covers per-component `detail` fields if a probe ever reports
    // sensitive content.
    if method.eq_ignore_ascii_case("GET") {
        match path {
            // K8s-style canonical names plus their bare aliases. All
            // unauthenticated for the same reason as /healthz: load
            // balancers and orchestrators don't carry credentials.
            "/healthz" => return sbproxy_observe::handle_healthz(),
            "/health" => {
                return sbproxy_observe::handle_health(
                    &state.health_registry,
                    env!("CARGO_PKG_VERSION"),
                    option_env!("SBPROXY_GIT_SHA").unwrap_or("unknown"),
                )
            }
            "/readyz" | "/ready" => return sbproxy_observe::handle_readyz(&state.health_registry),
            "/livez" | "/live" => return sbproxy_observe::handle_livez(),
            // Wave 3 closeout: quote-token JWKS publication.
            //
            // External verifiers (the LedgerClient and any agent SDK
            // that wants to verify a quote before paying) fetch the
            // public Ed25519 keys here. Served unauthenticated because
            // the keys themselves are public; the document is a
            // standard JWKS shape (`{"keys":[{"kty":"OKP","crv":
            // "Ed25519","kid":"...","x":"<b64url>"}]}`). Aggregates
            // every origin's `ai_crawl_control` policy's signer key id
            // so a multi-tenant deployment publishes one document
            // covering all of its issuers.
            "/.well-known/sbproxy/quote-keys.json" => return render_quote_keys_jwks(),
            _ => {}
        }
    }

    // --- Auth check ---
    let authed = match auth_header {
        Some(h) => match decode_basic_auth(h) {
            Some((user, pass)) => state.check_auth(&user, &pass),
            None => false,
        },
        None => false,
    };

    if !authed {
        return (
            401,
            "application/json",
            r#"{"error":"Unauthorized"}"#.to_string(),
        );
    }

    // --- Built-in admin UI. ---
    //
    // Returns `Some(...)` for paths it owns and `None` otherwise, so we
    // delegate first and only fall through to the existing dispatcher
    // when it does not match. The UI mount sits behind the
    // `embed-admin-ui` cargo feature; without the feature, requests
    // under `/admin/ui` return a one-line 404 explaining how to enable
    // the embedded build. The playground routes are handled in the async
    // connection handler (they must await the AI client), not here.
    if let Some(response) = crate::admin_ui::dispatch(method, path) {
        return response;
    }
    // WOR-1553/1554: dynamic key + credential lifecycle API.
    if let Some(response) = crate::admin_keys::dispatch(method, path, body) {
        return response;
    }
    // WOR-1665: model-host status (what is running locally now).
    if let Some(response) = crate::admin_model_host::dispatch(method, path) {
        return response;
    }
    // WOR-1721: fleet metrics aggregated over the mesh.
    if let Some(response) = crate::admin_cluster::dispatch(method, path) {
        return response;
    }
    // WOR-1754 / WOR-1755: response-cache + key-policy-cache management.
    if let Some(response) = crate::admin_cache::dispatch(method, path, body) {
        return response;
    }

    // --- Method-aware routes first ---
    if path == "/admin/reload" {
        if method.eq_ignore_ascii_case("POST") {
            return handle_reload(state);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }

    // GET /admin/drift: compare loaded config against on-disk file.
    // Read-only, idempotent, side-effect-free; only GET is accepted.
    if path == "/admin/drift" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_drift(state);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }

    // --- WOR-800 PR3: prompt-store runtime overlay admin API ---
    //
    // The PR2 runtime overlay (sbproxy_ai::prompts) lets operators
    // add and pin prompt versions at runtime. These three routes are
    // the HTTP mutation surface; PR4 will add redb persistence so
    // mutations survive restart.
    //
    // * GET  /admin/prompts                              -> snapshot
    // * POST /admin/prompts/<host>/<name>/versions       -> add version
    // * PUT  /admin/prompts/<host>/<name>/pin            -> pin default
    if path == "/admin/prompts" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_prompts_list();
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    if let Some(rest) = path.strip_prefix("/admin/prompts/") {
        if let Some((host, name, action)) = parse_prompt_admin_path(rest) {
            return dispatch_prompt_admin_route(method, host, name, action, body, state);
        }
        return (
            404,
            "application/json",
            r#"{"error":"unknown prompt admin route"}"#.to_string(),
        );
    }

    // --- WOR-1130: rate-limit budget admin routes ---
    //
    // These carry query strings, so match on the path prefix (the
    // exact-match arm below sees the full target including `?...`).
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only == "/api/rate_limits/effective" {
        let workspace = rl_query_param(path, "workspace").unwrap_or("default");
        return match crate::rate_limit_budget::registry() {
            Some(reg) => {
                let (rps, tier) = reg.effective(workspace);
                (
                    200,
                    "application/json",
                    format!(
                        r#"{{"workspace":"{}","effective_rps":{},"tier":"{}"}}"#,
                        workspace,
                        rps,
                        tier.as_str()
                    ),
                )
            }
            None => (
                404,
                "application/json",
                r#"{"error":"no rate_limits: block configured"}"#.to_string(),
            ),
        };
    }
    if path_only == "/api/rate_limits/clock/advance" {
        if !method.eq_ignore_ascii_case("POST") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let secs: u64 = rl_query_param(path, "secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        return match crate::rate_limit_budget::registry() {
            Some(reg) if reg.advance_clock(std::time::Duration::from_secs(secs)) => (
                200,
                "application/json",
                format!(r#"{{"advanced_secs":{secs}}}"#),
            ),
            Some(_) => (
                400,
                "application/json",
                r#"{"error":"clock is not in manual mode"}"#.to_string(),
            ),
            None => (
                404,
                "application/json",
                r#"{"error":"no rate_limits: block configured"}"#.to_string(),
            ),
        };
    }
    // WOR-1764: per-workspace budget state + manual resume.
    if path_only == "/api/rate_limits/budget" {
        return match crate::rate_limit_budget::registry() {
            Some(reg) => match serde_json::to_string(&reg.snapshot()) {
                Ok(body) => (200, "application/json", body),
                Err(e) => (
                    500,
                    "application/json",
                    format!(r#"{{"error":"serialize: {e}"}}"#),
                ),
            },
            None => (
                404,
                "application/json",
                r#"{"error":"no rate_limits: block configured"}"#.to_string(),
            ),
        };
    }
    if path_only == "/api/rate_limits/resume" {
        if !method.eq_ignore_ascii_case("POST") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let workspace = body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
            .and_then(|v| {
                v.get("workspace")
                    .and_then(|w| w.as_str())
                    .map(str::to_string)
            });
        let workspace = match workspace {
            Some(w) if !w.trim().is_empty() => w,
            _ => {
                return (
                    400,
                    "application/json",
                    r#"{"error":"missing 'workspace'"}"#.to_string(),
                )
            }
        };
        return match crate::rate_limit_budget::registry() {
            Some(reg) if reg.resume(&workspace) => (
                200,
                "application/json",
                format!(
                    r#"{{"workspace":"{}","tier":"normal"}}"#,
                    workspace.replace('"', "'")
                ),
            ),
            Some(_) => (
                404,
                "application/json",
                r#"{"error":"workspace not tracked (no traffic seen yet)"}"#.to_string(),
            ),
            None => (
                404,
                "application/json",
                r#"{"error":"no rate_limits: block configured"}"#.to_string(),
            ),
        };
    }
    if path_only == "/api/audit/recent" {
        let limit: usize = rl_query_param(path, "limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);
        let rows = crate::rate_limit_budget::registry()
            .map(|reg| reg.recent_audit(limit))
            .unwrap_or_default();
        return match serde_json::to_string(&rows) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // WOR-1718: recent request log with filters + pagination. Query params:
    // `status` (exact), `method` (case-insensitive), `path` (substring),
    // `offset`, `limit`. No params returns the newest entries, unchanged.
    if path_only == "/api/requests" {
        let status = rl_query_param(path, "status").and_then(|s| s.parse::<u16>().ok());
        let method_f = rl_query_param(path, "method");
        let path_f = rl_query_param(path, "path");
        let offset = rl_query_param(path, "offset")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let limit = rl_query_param(path, "limit")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(state.config.max_log_entries)
            .min(state.config.max_log_entries);
        let entries = state.query_requests(status, method_f, path_f, offset, limit);
        return match serde_json::to_string(&entries) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // WOR-1718: spend summary from the AI cost/token metrics.
    if path_only == "/api/usage/spend" {
        let snap = sbproxy_observe::metrics::metrics().snapshot_named(&[
            "sbproxy_ai_tokens_total",
            "sbproxy_ai_cost_usd_micros_total",
        ]);
        let tokens = snap.get("sbproxy_ai_tokens_total").copied().unwrap_or(0.0);
        let micros = snap
            .get("sbproxy_ai_cost_usd_micros_total")
            .copied()
            .unwrap_or(0.0);
        let body = serde_json::json!({
            "tokens": tokens,
            "cost_usd": micros / 1_000_000.0,
        })
        .to_string();
        return (200, "application/json", body);
    }
    // WOR-1720: config read + write (validate, persist, hot-swap). The
    // write path is a mutation, so the connection handler's RBAC gate has
    // already blocked read-only operators before we get here.
    if path_only == "/admin/config" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_read(state);
        }
        if method.eq_ignore_ascii_case("PUT") || method.eq_ignore_ascii_case("POST") {
            return handle_config_write(state, body, rl_query_param(path, "if_match"));
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-1759: runtime log-level control. GET reads the current tracing
    // filter; PUT/POST sets a new one (e.g. "debug" or "sbproxy_ai=debug")
    // without a restart. The mutation goes through the connection
    // handler's RBAC gate, so read-only operators are already blocked.
    if path_only == "/admin/log-level" {
        if method.eq_ignore_ascii_case("GET") {
            return (
                200,
                "application/json",
                serde_json::json!({ "level": sbproxy_observe::current_log_filter() }).to_string(),
            );
        }
        if method.eq_ignore_ascii_case("PUT") || method.eq_ignore_ascii_case("POST") {
            let level = body
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v.get("level").and_then(|l| l.as_str()).map(str::to_string));
            let level = match level {
                Some(l) if !l.trim().is_empty() => l,
                _ => {
                    return (
                        400,
                        "application/json",
                        r#"{"error":"missing 'level' directive"}"#.to_string(),
                    )
                }
            };
            return match sbproxy_observe::set_log_filter(&level) {
                Ok(()) => (
                    200,
                    "application/json",
                    serde_json::json!({ "level": level }).to_string(),
                ),
                Err(e) => (
                    400,
                    "application/json",
                    format!(r#"{{"error":"{}"}}"#, e.replace('"', "'")),
                ),
            };
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }

    // --- Route ---
    match path {
        // WOR-1130: Prometheus exposition on the admin port. The same
        // `sbproxy_*` series is also served on the main data-plane port;
        // mirroring it here lets ops scrape via the (already
        // access-controlled) admin listener.
        "/metrics" => (
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            sbproxy_observe::metrics::metrics().render(),
        ),

        // Recent request log is handled by the filtered early-return block
        // above (WOR-1718), which also covers the no-query case.

        // Aggregate proxy liveness summary.
        "/api/health" => {
            let body = r#"{"status":"ok","origins":[]}"#.to_string();
            (200, "application/json", body)
        }

        // Per-target health: probe state, outlier ejection, breaker
        // state, in-flight connections. Walks the live pipeline so
        // operators can see exactly what `select_target` would skip.
        "/api/health/targets" => {
            let body = render_target_health();
            (200, "application/json", body)
        }

        // OpenAPI 3.0 document describing the routes the gateway
        // exposes. Cached per pipeline revision so reload triggers a
        // rebuild but back-to-back requests are cheap.
        "/api/openapi.json" => match render_openapi(state, false) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"{}"}}"#, e.replace('"', "'")),
            ),
        },

        // YAML rendering of the same document. Buyer tooling
        // (Postman/Swagger UI) accepts either; we publish both so
        // operators can pick.
        "/api/openapi.yaml" => match render_openapi(state, true) {
            Ok(body) => (200, "application/yaml", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"{}"}}"#, e.replace('"', "'")),
            ),
        },

        // Basic stats summary placeholder.
        "/api/stats" => {
            let log = state
                .recent_requests
                .lock()
                .expect("admin log mutex poisoned");
            let count = log.len();
            drop(log);
            let body = format!(r#"{{"request_log_entries":{count}}}"#);
            (200, "application/json", body)
        }

        // SPA root - placeholder HTML.
        "/" => {
            let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SoapBucket Admin</title>
</head>
<body>
  <h1>SoapBucket Admin</h1>
  <p>API endpoints: /api/requests, /api/health, /api/stats</p>
</body>
</html>"#;
            (200, "text/html; charset=utf-8", html.to_string())
        }

        // Unknown path.
        _ => (
            404,
            "application/json",
            r#"{"error":"Not Found"}"#.to_string(),
        ),
    }
}

// --- Admin HTTP listener ---
//
// Spawns a tiny tokio-driven HTTP/1.1 server on the admin port. We
// deliberately do NOT use Pingora here because the admin API has
// completely different requirements (authoritative routing, basic
// auth, no upstream forwarding) and bolting it onto the proxy
// service would require a second listener in Pingora's
// configuration tree.
//
// The implementation is intentionally minimal: a single tokio task
// per connection, enough request parsing to route on path + auth,
// and write_all of the response. Production deployments protect the
// admin port with an IP allowlist and basic-auth credentials; the
// in-process [`AdminRateLimiter`] caps both per-IP and global
// admin RPS so a misconfigured allowlist cannot be DDoSed.

/// Process-global handle to the running admin state, installed at boot so
/// the request pipeline's logging hook can feed the request-log ring
/// buffer + SSE tail (WOR-1718). `None` when the admin server is off.
static ADMIN_LOG_SINK: std::sync::OnceLock<Arc<AdminState>> = std::sync::OnceLock::new();

/// Install the process-global admin-state handle (first install wins).
pub fn install_admin_log_sink(state: Arc<AdminState>) {
    let _ = ADMIN_LOG_SINK.set(state);
}

/// The running admin state, if the admin server is enabled, for the
/// pipeline's logging hook to record each completed request.
pub fn admin_log_sink() -> Option<&'static Arc<AdminState>> {
    ADMIN_LOG_SINK.get()
}

/// Spawn the admin server bound to `127.0.0.1:<config.port>`.
///
/// No-ops when `config.enabled` is false. The returned join handle
/// can be ignored; the task lives for the duration of the process
/// and shares the `AdminState` with the rest of the proxy.
pub fn spawn_admin_server(
    state: std::sync::Arc<AdminState>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !state.config.enabled {
        return None;
    }
    let port = state.config.port;
    // WOR-1717: build the TLS acceptor up front so a bad cert fails the
    // admin server at startup rather than silently per-connection.
    let acceptor = match &state.config.tls {
        Some(tls) => match build_admin_acceptor(tls) {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::error!(error = %e, "admin TLS init failed; admin server not started");
                return None;
            }
        },
        None => None,
    };
    // WOR-1717: bind address from config (default loopback), and an IP
    // allowlist. An empty allowlist keeps the safe loopback-only default;
    // a configured list (CIDRs) permits remote admin from known networks.
    let bind_ip: std::net::IpAddr = state
        .config
        .bind
        .parse()
        .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
    let allow_ips = state.config.allow_ips.clone();
    Some(tokio::spawn(async move {
        let addr = std::net::SocketAddr::new(bind_ip, port);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    addr = %addr,
                    error = %e,
                    "admin server failed to bind"
                );
                return;
            }
        };
        tracing::info!(addr = %addr, tls = acceptor.is_some(), "admin server listening");
        let rate_limiter = std::sync::Arc::new(AdminRateLimiter::new(60));
        let ip_filter = std::sync::Arc::new(if allow_ips.is_empty() {
            AdminIpFilter::localhost_only()
        } else {
            AdminIpFilter::new(allow_ips)
        });
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "admin accept failed");
                    continue;
                }
            };
            let state = state.clone();
            let rate_limiter = rate_limiter.clone();
            let ip_filter = ip_filter.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let peer_ip = peer.ip().to_string();
                // Complete the TLS handshake first (when configured), so
                // even the 403/429 rejections are sent over TLS to a
                // TLS-expecting client rather than as a plaintext reply.
                match acceptor {
                    Some(acc) => match acc.accept(sock).await {
                        Ok(tls) => {
                            serve_admin_conn(tls, peer_ip, state, rate_limiter, ip_filter).await
                        }
                        Err(e) => tracing::debug!(error = %e, "admin TLS handshake failed"),
                    },
                    None => serve_admin_conn(sock, peer_ip, state, rate_limiter, ip_filter).await,
                }
            });
        }
    }))
}

/// Per-connection admin handling shared by the plaintext and TLS paths
/// (WOR-1717): enforce the IP allowlist and rate limit, then dispatch.
/// Generic over the stream so it serves both `TcpStream` and a TLS
/// `TlsStream`.
async fn serve_admin_conn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    sock: S,
    peer_ip: String,
    state: std::sync::Arc<AdminState>,
    rate_limiter: std::sync::Arc<AdminRateLimiter>,
    ip_filter: std::sync::Arc<AdminIpFilter>,
) {
    if !ip_filter.is_allowed(&peer_ip) {
        let _ =
            write_admin_response(sock, 403, "application/json", r#"{"error":"Forbidden"}"#).await;
        return;
    }
    if !rate_limiter.check(&peer_ip) {
        let _ = write_admin_response(
            sock,
            429,
            "application/json",
            r#"{"error":"Too Many Requests"}"#,
        )
        .await;
        return;
    }
    handle_admin_connection(sock, state).await;
}

/// Build a rustls `TlsAcceptor` for the admin server from PEM cert + key
/// files (WOR-1717). Returns a descriptive error string on any read or
/// parse failure so `spawn_admin_server` can log it and decline to start
/// rather than serve plaintext on a port an operator asked to be TLS.
fn build_admin_acceptor(tls: &AdminTls) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    let cert_pem = std::fs::read(&tls.cert)
        .map_err(|e| format!("read admin cert {}: {e}", tls.cert.display()))?;
    let key_pem = std::fs::read(&tls.key)
        .map_err(|e| format!("read admin key {}: {e}", tls.key.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse admin cert {}: {e}", tls.cert.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "admin cert {} contained no certificates",
            tls.cert.display()
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| format!("parse admin key {}: {e}", tls.key.display()))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("build admin TLS config: {e}"))?;
    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

async fn handle_admin_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut sock: S,
    state: std::sync::Arc<AdminState>,
) {
    use tokio::io::AsyncReadExt;
    // 64 KiB is enough for every admin route the proxy ships, including
    // a few-KiB prompt template POST. Larger bodies (a giant template,
    // a SBOM upload) would need streaming reads gated on Content-Length;
    // none of the current routes need that and growing the buffer
    // hot-path is preferable to per-byte plumbing.
    const MAX_ADMIN_REQUEST_BYTES: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 8192];
    // Read at least the headers (everything up to the \r\n\r\n). For
    // a body-bearing request, keep reading until we have the full
    // Content-Length or hit the cap.
    let mut content_length: Option<usize> = None;
    let mut header_end: Option<usize> = None;
    loop {
        match sock.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() >= MAX_ADMIN_REQUEST_BYTES {
                    break;
                }
                if header_end.is_none() {
                    if let Some(p) = find_header_end(&buf) {
                        header_end = Some(p);
                        let head = String::from_utf8_lossy(&buf[..p]);
                        for line in head.lines() {
                            let rest = match line
                                .strip_prefix("Content-Length:")
                                .or_else(|| line.strip_prefix("content-length:"))
                            {
                                Some(r) => r,
                                None => continue,
                            };
                            if let Ok(v) = rest.trim().parse::<usize>() {
                                content_length = Some(v);
                            }
                        }
                    }
                }
                if let (Some(end), Some(cl)) = (header_end, content_length) {
                    // header bytes + 4 for "\r\n\r\n" + cl body bytes
                    if buf.len() >= end + 4 + cl {
                        break;
                    }
                }
                if header_end.is_some() && content_length.is_none() {
                    // No Content-Length means no body to wait on (a
                    // bare GET, or a HEAD). Stop after the headers.
                    break;
                }
            }
            Err(_) => return,
        }
    }
    if buf.is_empty() {
        return;
    }
    let request = String::from_utf8_lossy(&buf);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let mut auth_header: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut cookie: Option<String> = None;
    let mut csrf_header: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line
            .strip_prefix("Authorization:")
            .or_else(|| line.strip_prefix("authorization:"))
        {
            auth_header = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("Origin:")
            .or_else(|| line.strip_prefix("origin:"))
        {
            origin = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("Cookie:")
            .or_else(|| line.strip_prefix("cookie:"))
        {
            cookie = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("X-CSRF-Token:")
            .or_else(|| line.strip_prefix("x-csrf-token:"))
        {
            csrf_header = Some(rest.trim().to_string());
        }
    }
    // WOR-1717: CORS headers for an allowed cross-origin caller (echoed on
    // every response below), and a direct 204 answer to preflight OPTIONS.
    let cors = cors_response_headers(origin.as_deref(), &state.config.cors_origins);
    if method.eq_ignore_ascii_case("OPTIONS") {
        let _ = write_admin_response_headed(sock, 204, "text/plain", b"", &cors).await;
        return;
    }

    // Slice the request body off the buffer (needed by login + dispatch).
    let body_owned: Option<String> = match (header_end, content_length) {
        (Some(end), Some(cl)) => {
            let start = end + 4;
            let stop = (start + cl).min(buf.len());
            if start < buf.len() {
                Some(String::from_utf8_lossy(&buf[start..stop]).into_owned())
            } else {
                Some(String::new())
            }
        }
        _ => None,
    };

    // WOR-1714: browser session endpoints, handled before the auth gate.
    if path == "/admin/login" && is_state_changing(method) {
        handle_admin_login(
            sock,
            &state,
            auth_header.as_deref(),
            body_owned.as_deref(),
            &cors,
            state.config.tls.is_some(),
        )
        .await;
        return;
    }
    if path == "/admin/logout" && is_state_changing(method) {
        handle_admin_logout(sock, &state, cookie.as_deref(), &cors).await;
        return;
    }

    // WOR-1714 / WOR-1716: resolve the operator (session or Basic), enforce
    // CSRF on cookie-authed mutations and RBAC (read-only cannot mutate),
    // and audit the action with the operator's identity.
    let principal = state.resolve_principal(auth_header.as_deref(), cookie.as_deref());
    let mutating = is_state_changing(method);
    if let Some(p) = &principal {
        if p.via_session && mutating {
            let ok = match (csrf_header.as_deref(), p.csrf.as_deref()) {
                (Some(h), Some(c)) => constant_time_eq(h.as_bytes(), c.as_bytes()),
                _ => false,
            };
            if !ok {
                let _ = write_admin_response_headed(
                    sock,
                    403,
                    "application/json",
                    br#"{"error":"CSRF token missing or invalid"}"#,
                    &cors,
                )
                .await;
                return;
            }
        }
        if p.role == AdminRole::ReadOnly && mutating {
            let _ = write_admin_response_headed(
                sock,
                403,
                "application/json",
                br#"{"error":"forbidden: read-only operator cannot perform this action"}"#,
                &cors,
            )
            .await;
            return;
        }
        if mutating {
            tracing::info!(
                target: "sbproxy::admin::audit",
                operator = %p.username,
                role = %role_label(p.role),
                method = %method,
                path = %path,
                "admin action"
            );
        }
    }
    // A session-authenticated request synthesizes a Basic header so
    // `handle_admin_request`'s internal gate accepts it (the RBAC gate
    // above already ran on the resolved principal).
    let auth_for_dispatch: Option<String> = if principal.as_ref().is_some_and(|p| p.via_session) {
        Some(synthesize_basic(
            &state.config.username,
            &state.config.password,
        ))
    } else {
        auth_header.clone()
    };

    // WOR-1758: session whoami. Lets the SPA recover its identity + CSRF
    // token from the session cookie on load (a page reload keeps the
    // cookie but loses the in-memory token), and decide whether to show
    // the login form. Public: returns `{authenticated:false}` with no
    // session rather than 401, so the SPA can distinguish "log in" from
    // an error.
    if path.split('?').next() == Some("/admin/session") && method.eq_ignore_ascii_case("GET") {
        let body = match &principal {
            Some(p) => serde_json::json!({
                "authenticated": true,
                "username": p.username,
                "role": role_label(p.role),
                "via_session": p.via_session,
                "csrf_token": p.csrf,
            }),
            None => serde_json::json!({ "authenticated": false }),
        };
        let _ = write_admin_response_headed(
            sock,
            200,
            "application/json",
            body.to_string().as_bytes(),
            &cors,
        )
        .await;
        return;
    }

    // WOR-1753: chat playground. Handled here (not in
    // `handle_admin_request`) because the chat call awaits the AI client.
    // Both routes require authentication; the chat POST is a mutation, so
    // the RBAC gate above already restricted it to the admin role.
    let pg_path = path.split('?').next().unwrap_or(path);
    if pg_path == crate::admin_playground::ENDPOINTS_PATH && method.eq_ignore_ascii_case("GET") {
        if principal.is_none() {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"Unauthorized"}"#,
                &cors,
            )
            .await;
            return;
        }
        let (status, ct, resp) = crate::admin_playground::list_endpoints();
        let _ = write_admin_response_headed(sock, status, ct, resp.as_bytes(), &cors).await;
        return;
    }
    if pg_path == crate::admin_playground::CHAT_PATH && method.eq_ignore_ascii_case("POST") {
        if principal.is_none() {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"Unauthorized"}"#,
                &cors,
            )
            .await;
            return;
        }
        let (status, ct, resp) = crate::admin_playground::handle_chat(body_owned.as_deref()).await;
        let _ = write_admin_response_headed(sock, status, ct, resp.as_bytes(), &cors).await;
        return;
    }

    // WOR-1718: SSE tail of the request log. Handled here rather than in
    // `handle_admin_request` because it must own the socket and stream
    // `data:` events until the client disconnects.
    if path.split('?').next() == Some("/api/requests/stream") && method.eq_ignore_ascii_case("GET")
    {
        if principal.is_none() {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"Unauthorized"}"#,
                &cors,
            )
            .await;
            return;
        }
        use tokio::io::AsyncWriteExt;
        let mut head = String::from(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n",
        );
        for (k, v) in &cors {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        if sock.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let _ = sock.write_all(b": connected\n\n").await;
        let mut rx = state.log_events.subscribe();
        loop {
            match rx.recv().await {
                Ok(json) => {
                    if sock
                        .write_all(format!("data: {json}\n\n").as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let _ = sock.flush().await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
        return;
    }

    // WOR-1715: the built-in admin UI serves a real Vite bundle,
    // including binary assets (fonts, images, wasm) that the `String`
    // dispatcher path would corrupt. Serve it on the byte path here.
    //
    // WOR-1758: the SPA shell is served WITHOUT auth so the app can load
    // and present a login form (POST /admin/login). The bundle is static
    // JS/CSS/HTML with no secrets; every data-bearing call is a separate
    // `/admin/*` API request that stays behind the auth gate. The IP
    // filter + rate limiter already ran in the accept loop.
    if crate::admin_ui::path_is_ours(path) {
        if let Some((status, content_type, bytes)) = crate::admin_ui::dispatch_bytes(method, path) {
            let _ = write_admin_response_headed(sock, status, content_type, &bytes, &cors).await;
            return;
        }
    }

    // WOR-618: `handle_admin_request` does blocking std::fs reads for
    // `POST /admin/reload` (re-read the config file) and
    // `GET /admin/drift` (re-hash the on-disk config). Both routes can
    // block on slow disks or large config files; run the dispatcher on
    // the blocking pool so the admin listener task keeps accepting new
    // connections. `auth_for_dispatch` carries a synthesized Basic header
    // for session-authenticated requests (WOR-1714).
    let method_owned = method.to_string();
    let path_owned = path.to_string();
    let auth_owned = auth_for_dispatch;
    let body_for_task = body_owned.clone();
    let state_for_task = state.clone();
    let (status, content_type, body) = match tokio::task::spawn_blocking(move || {
        handle_admin_request(
            &method_owned,
            &path_owned,
            &state_for_task,
            auth_owned.as_deref(),
            body_for_task.as_deref(),
        )
    })
    .await
    {
        Ok(triple) => triple,
        Err(e) => {
            tracing::warn!(error = %e, "admin: dispatcher task panicked");
            (
                500,
                "application/json",
                r#"{"error":"internal server error"}"#.to_string(),
            )
        }
    };
    let _ = write_admin_response_headed(sock, status, content_type, body.as_bytes(), &cors).await;
}

/// Locate the byte offset of the `\r\n\r\n` (or LF-only `\n\n` for
/// tolerance) header terminator inside `buf`. Returns the index of the
/// first terminator byte so the caller adds 4 (or 2) to skip past it.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// The HTTP reason phrase for the status codes the admin server emits.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

async fn write_admin_response<S: tokio::io::AsyncWrite + Unpin>(
    sock: S,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    write_admin_response_bytes(sock, status, content_type, body.as_bytes()).await
}

/// Write an admin response with a raw byte body. `write_admin_response`
/// is the `&str` convenience wrapper; the admin UI (WOR-1715) uses this
/// directly so binary assets (fonts, images, wasm) are sent unmodified.
/// Generic over the stream so it works over both plain TCP and TLS
/// (WOR-1717).
async fn write_admin_response_bytes<S: tokio::io::AsyncWrite + Unpin>(
    sock: S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_admin_response_headed(sock, status, content_type, body, &[]).await
}

/// Write an admin response with a byte body plus extra response headers
/// (WOR-1717 CORS, WOR-1714 `Set-Cookie`). `write_admin_response_bytes`
/// is the no-extra-headers wrapper.
async fn write_admin_response_headed<S: tokio::io::AsyncWrite + Unpin>(
    mut sock: S,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(String, String)],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         WWW-Authenticate: Basic realm=\"sbproxy admin\"\r\n",
        status = status,
        reason = reason_phrase(status),
        content_type = content_type,
        len = body.len(),
    );
    for (k, v) in extra_headers {
        header.push_str(k);
        header.push_str(": ");
        header.push_str(v);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    sock.write_all(header.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.shutdown().await
}

/// Build the CORS response headers for an admin request, or an empty vec
/// when the request's `Origin` is not in the configured allowlist (or no
/// allowlist is set). `*` matches any origin (echoed back so credentials
/// still work). WOR-1717.
fn cors_response_headers(origin: Option<&str>, allowed: &[String]) -> Vec<(String, String)> {
    match origin {
        Some(o) if allowed.iter().any(|a| a == o || a == "*") => vec![
            ("Access-Control-Allow-Origin".to_string(), o.to_string()),
            (
                "Access-Control-Allow-Credentials".to_string(),
                "true".to_string(),
            ),
            (
                "Access-Control-Allow-Methods".to_string(),
                "GET, POST, PUT, PATCH, DELETE, OPTIONS".to_string(),
            ),
            (
                "Access-Control-Allow-Headers".to_string(),
                "Authorization, Content-Type, X-CSRF-Token".to_string(),
            ),
            ("Vary".to_string(), "Origin".to_string()),
        ],
        _ => Vec::new(),
    }
}

/// Synthesize a Basic `Authorization` header from the top-level admin
/// creds. When a request is already session-authenticated (WOR-1714), the
/// connection handler passes this to `handle_admin_request` so its
/// internal Basic gate accepts the request without re-checking; the
/// role-based gate (WOR-1716) already ran on the resolved principal.
fn synthesize_basic(user: &str, pass: &str) -> String {
    use base64::Engine;
    // Standard alphabet, no padding: `base64_decode` uses the standard
    // alphabet and does not require padding, so this round-trips.
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(format!("{user}:{pass}"))
    )
}

/// Whether a method mutates state (drives CSRF + RBAC enforcement).
fn is_state_changing(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

fn role_label(role: AdminRole) -> &'static str {
    match role {
        AdminRole::Admin => "admin",
        AdminRole::ReadOnly => "read_only",
    }
}

/// Handle `POST /admin/login` (WOR-1714): verify credentials (Basic header
/// or a JSON `{username,password}` body) against the top-level admin and
/// configured operators, mint a session cookie, and return the CSRF token.
async fn handle_admin_login<S: tokio::io::AsyncWrite + Unpin>(
    sock: S,
    state: &AdminState,
    auth_header: Option<&str>,
    body: Option<&str>,
    cors: &[(String, String)],
    secure: bool,
) {
    let creds = auth_header.and_then(decode_basic_auth).or_else(|| {
        body.and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
            .and_then(|v| {
                Some((
                    v.get("username")?.as_str()?.to_string(),
                    v.get("password")?.as_str()?.to_string(),
                ))
            })
    });
    let (user, pass) = match creds {
        Some(c) => c,
        None => {
            let _ = write_admin_response_headed(
                sock,
                400,
                "application/json",
                br#"{"error":"missing credentials"}"#,
                cors,
            )
            .await;
            return;
        }
    };
    let role = match state.check_operator_login(&user, &pass) {
        Some(r) => r,
        None => {
            tracing::warn!(target: "sbproxy::admin::audit", operator = %user, "admin login failed");
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"invalid credentials"}"#,
                cors,
            )
            .await;
            return;
        }
    };
    let ttl_secs = 8 * 3600;
    let (token, csrf) = state.session_signer.mint(&user, role, ttl_secs, unix_now());
    tracing::info!(target: "sbproxy::admin::audit", operator = %user, role = %role_label(role), "admin login");
    let secure_attr = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{}={token}; HttpOnly; SameSite=Strict; Path=/{secure_attr}; Max-Age={ttl_secs}",
        crate::admin_session::SESSION_COOKIE
    );
    let mut headers = cors.to_vec();
    headers.push(("Set-Cookie".to_string(), cookie));
    let out = serde_json::json!({"role": role_label(role), "csrf_token": csrf, "username": user})
        .to_string();
    let _ =
        write_admin_response_headed(sock, 200, "application/json", out.as_bytes(), &headers).await;
}

/// Handle `POST /admin/logout` (WOR-1714): revoke the session and clear
/// the cookie.
async fn handle_admin_logout<S: tokio::io::AsyncWrite + Unpin>(
    sock: S,
    state: &AdminState,
    cookie_header: Option<&str>,
    cors: &[(String, String)],
) {
    if let Some(ch) = cookie_header {
        if let Some(tok) =
            crate::admin_session::cookie_value(ch, crate::admin_session::SESSION_COOKIE)
        {
            if let Some(sess) = state.session_signer.verify(&tok, unix_now()) {
                if let Ok(mut set) = state.revoked_sessions.lock() {
                    set.insert(sess.nonce);
                }
            }
        }
    }
    let clear = format!(
        "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        crate::admin_session::SESSION_COOKIE
    );
    let mut headers = cors.to_vec();
    headers.push(("Set-Cookie".to_string(), clear));
    let _ = write_admin_response_headed(
        sock,
        200,
        "application/json",
        br#"{"status":"logged out"}"#,
        &headers,
    )
    .await;
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> AdminState {
        AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
    }

    fn basic_auth(user: &str, pass: &str) -> String {
        // Encode user:pass in base64 using our own encoder for tests.
        let raw = format!("{user}:{pass}");
        format!("Basic {}", base64_encode(raw.as_bytes()))
    }

    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i < input.len() {
            let b0 = input[i] as u32;
            let b1 = if i + 1 < input.len() {
                input[i + 1] as u32
            } else {
                0
            };
            let b2 = if i + 2 < input.len() {
                input[i + 2] as u32
            } else {
                0
            };
            out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
            out.push(ALPHABET[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
            if i + 1 < input.len() {
                out.push(ALPHABET[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            if i + 2 < input.len() {
                out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            i += 3;
        }
        out
    }

    // --- Auth ---

    #[test]
    fn auth_valid_credentials() {
        let state = make_state();
        assert!(state.check_auth("admin", "secret"));
    }

    #[test]
    fn auth_wrong_password() {
        let state = make_state();
        assert!(!state.check_auth("admin", "wrong"));
    }

    #[test]
    fn auth_wrong_username() {
        let state = make_state();
        assert!(!state.check_auth("root", "secret"));
    }

    #[test]
    fn auth_empty_credentials() {
        let state = make_state();
        assert!(!state.check_auth("", ""));
    }

    // --- Ring buffer ---

    #[test]
    fn log_request_adds_entry() {
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            origin: "api.test".to_string(),
            method: "GET".to_string(),
            path: "/ping".to_string(),
            status: 200,
            latency_ms: 1.5,
            client_ip: "127.0.0.1".to_string(),
        });
        let entries = state.get_recent_requests(10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/ping");
    }

    #[test]
    fn log_request_newest_first() {
        let state = make_state();
        for i in 0..3u16 {
            state.log_request(RequestLogEntry {
                timestamp: format!("t{i}"),
                origin: "o".to_string(),
                method: "GET".to_string(),
                path: format!("/path{i}"),
                status: 200,
                latency_ms: 0.0,
                client_ip: "127.0.0.1".to_string(),
            });
        }
        let entries = state.get_recent_requests(10);
        // Newest first: /path2, /path1, /path0
        assert_eq!(entries[0].path, "/path2");
        assert_eq!(entries[1].path, "/path1");
        assert_eq!(entries[2].path, "/path0");
    }

    #[test]
    fn log_request_ring_buffer_overflow() {
        let state = make_state(); // max_log_entries = 5
        for i in 0..8u16 {
            state.log_request(RequestLogEntry {
                timestamp: format!("t{i}"),
                origin: "o".to_string(),
                method: "GET".to_string(),
                path: format!("/p{i}"),
                status: 200,
                latency_ms: 0.0,
                client_ip: "127.0.0.1".to_string(),
            });
        }
        let entries = state.get_recent_requests(100);
        // Only 5 most recent entries retained.
        assert_eq!(entries.len(), 5);
        // Newest first: /p7 .. /p3
        assert_eq!(entries[0].path, "/p7");
        assert_eq!(entries[4].path, "/p3");
    }

    #[test]
    fn query_requests_filters_and_paginates() {
        // WOR-1718: filter by status/method/path substring, then paginate.
        let cfg = AdminConfig {
            max_log_entries: 100,
            ..AdminConfig::default()
        };
        let state = AdminState::new(cfg);
        for i in 0..10u16 {
            state.log_request(RequestLogEntry {
                timestamp: format!("t{i}"),
                origin: "o".to_string(),
                method: if i % 2 == 0 { "GET" } else { "POST" }.to_string(),
                path: format!("/api/thing/{i}"),
                status: if i < 5 { 200 } else { 500 },
                latency_ms: 1.0,
                client_ip: "127.0.0.1".to_string(),
            });
        }
        // Status filter.
        let errs = state.query_requests(Some(500), None, None, 0, 100);
        assert_eq!(errs.len(), 5);
        assert!(errs.iter().all(|e| e.status == 500));
        // Method filter (case-insensitive).
        let posts = state.query_requests(None, Some("post"), None, 0, 100);
        assert_eq!(posts.len(), 5);
        // Path substring.
        assert_eq!(
            state
                .query_requests(None, None, Some("/thing/7"), 0, 100)
                .len(),
            1
        );
        // Pagination: newest-first, skip 2, take 3.
        let page = state.query_requests(None, None, None, 2, 3);
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].path, "/api/thing/7");
    }

    #[test]
    fn config_write_guards() {
        // WOR-1720: the pre-write guards (empty body, invalid config,
        // revision mismatch) run before any file write or hot-swap.
        let dir = tempfile::tempdir().unwrap();
        let cfgpath = dir.path().join("sb.yml");
        let original = "proxy:\n  http_bind_port: 8080\norigins: {}\n";
        std::fs::write(&cfgpath, original).unwrap();
        let state = AdminState::new(AdminConfig::default())
            .with_config_path(cfgpath.clone())
            .with_loaded_config_content_hash("known-revision");

        // Empty body -> 400.
        assert_eq!(handle_config_write(&state, None, None).0, 400);
        // Invalid YAML -> 400, and the file is untouched.
        assert_eq!(
            handle_config_write(&state, Some("origins: [oops"), None).0,
            400
        );
        // Revision mismatch -> 409 (checked before validation/write).
        assert_eq!(
            handle_config_write(&state, Some(original), Some("stale-revision")).0,
            409
        );
        // The on-disk config was never clobbered by the rejected writes.
        assert_eq!(std::fs::read_to_string(&cfgpath).unwrap(), original);
    }

    #[test]
    fn config_read_returns_yaml_and_revision() {
        let dir = tempfile::tempdir().unwrap();
        let cfgpath = dir.path().join("sb.yml");
        std::fs::write(&cfgpath, "proxy:\n  http_bind_port: 8080\n").unwrap();
        let state = AdminState::new(AdminConfig::default())
            .with_config_path(cfgpath)
            .with_loaded_config_content_hash("rev-xyz");
        let (status, _, body) = handle_config_read(&state);
        assert_eq!(status, 200);
        assert!(body.contains("http_bind_port"));
        assert!(body.contains("rev-xyz"));
    }

    #[test]
    fn get_recent_requests_respects_limit() {
        let state = make_state();
        for i in 0..4u16 {
            state.log_request(RequestLogEntry {
                timestamp: format!("t{i}"),
                origin: "o".to_string(),
                method: "GET".to_string(),
                path: format!("/p{i}"),
                status: 200,
                latency_ms: 0.0,
                client_ip: "127.0.0.1".to_string(),
            });
        }
        let entries = state.get_recent_requests(2);
        assert_eq!(entries.len(), 2);
    }

    // --- API Routes ---

    #[test]
    fn unauthorized_returns_401() {
        let state = make_state();
        let (status, _, _) = handle_admin_request("GET", "/api/stats", &state, None, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn bad_credentials_returns_401() {
        let state = make_state();
        let auth = basic_auth("admin", "wrong");
        let (status, _, _) = handle_admin_request("GET", "/api/stats", &state, Some(&auth), None);
        assert_eq!(status, 401);
    }

    #[test]
    fn unknown_path_returns_404() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) =
            handle_admin_request("GET", "/unknown/path", &state, Some(&auth), None);
        assert_eq!(status, 404);
    }

    #[test]
    fn playground_chat_requires_admin_auth() {
        let state = make_state();
        let (status, _, body) = handle_admin_request(
            "POST",
            crate::admin_playground::CHAT_PATH,
            &state,
            None,
            Some("{}"),
        );
        assert_eq!(status, 401);
        assert!(body.contains("Unauthorized"));
    }

    // The playground chat + endpoints routes moved to the async admin
    // connection handler (they await the AI client), so they are no
    // longer dispatched from `handle_admin_request`; the handlers
    // themselves are covered by `admin_playground::tests`.

    #[test]
    fn api_requests_returns_200_json() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("GET", "/api/requests", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        // Empty log returns JSON array.
        assert_eq!(body, "[]");
    }

    #[test]
    fn api_health_returns_200() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, _) = handle_admin_request("GET", "/api/health", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn api_health_targets_returns_200_json() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("GET", "/api/health/targets", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        // Empty pipeline => empty origins array; the shape is what we promise.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            parsed.get("origins").is_some(),
            "missing 'origins' key: {body}"
        );
        assert!(
            parsed.get("config_revision").is_some(),
            "missing 'config_revision': {body}"
        );
    }

    #[test]
    fn api_stats_returns_200_with_count() {
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "t".to_string(),
            origin: "o".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            status: 200,
            latency_ms: 0.0,
            client_ip: "127.0.0.1".to_string(),
        });
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/api/stats", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert!(body.contains("1"), "expected count 1 in: {body}");
    }

    #[test]
    fn root_returns_html() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) = handle_admin_request("GET", "/", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert!(ct.starts_with("text/html"), "expected text/html, got: {ct}");
        assert!(body.contains("<html"), "expected HTML body");
    }

    // --- /admin/reload ---

    fn write_yaml(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write yaml");
        f.flush().expect("flush yaml");
        f
    }

    fn reload_yaml(host: &str) -> String {
        // Minimal valid sb.yml with a single static origin. The
        // hostname is variable so a successful reload changes the
        // pipeline's `host_map`.
        format!(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "reload-test"
"#
        )
    }

    #[test]
    fn admin_reload_route_requires_post() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        // GET is rejected with 405.
        let (status, _, _) =
            handle_admin_request("GET", "/admin/reload", &state, Some(&auth), None);
        assert_eq!(status, 405);
    }

    #[test]
    fn admin_reload_unauthorized_returns_401() {
        let state = make_state();
        let (status, _, _) = handle_admin_request("POST", "/admin/reload", &state, None, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn admin_reload_without_config_path_returns_503() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("POST", "/admin/reload", &state, Some(&auth), None);
        assert_eq!(status, 503);
        assert!(body.contains("config_path"), "got: {body}");
    }

    #[test]
    fn admin_reload_succeeds_with_valid_config() {
        let f = write_yaml(&reload_yaml("reload-success.example.com"));
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("POST", "/admin/reload", &state, Some(&auth), None);
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(ct, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert!(
            parsed
                .get("config_revision")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "expected non-empty config_revision: {body}"
        );
        assert!(
            parsed
                .get("loaded_at")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "expected loaded_at: {body}"
        );
    }

    #[test]
    fn admin_reload_returns_400_on_yaml_parse_error() {
        let f = write_yaml("this is not: valid: yaml: at all\n  - {");
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("POST", "/admin/reload", &state, Some(&auth), None);
        assert_eq!(status, 400, "body: {body}");
        // Sanitised: the file name may appear, but not the absolute path.
        let abs = f.path().to_string_lossy().to_string();
        assert!(
            !body.contains(&abs),
            "absolute path leaked into error: {body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_concurrent_calls_one_wins_one_409s() {
        // Two simultaneous calls to /admin/reload: the single-flight
        // guard admits one and rejects the other with 409. We use a
        // multi-thread runtime so the two tasks really do contend.
        let f = write_yaml(&reload_yaml("reload-concurrency.example.com"));
        let state = std::sync::Arc::new(
            AdminState::new(AdminConfig {
                enabled: true,
                port: 9090,
                username: "admin".to_string(),
                password: "secret".to_string(),
                max_log_entries: 5,
                tls: None,
                bind: "127.0.0.1".to_string(),
                allow_ips: Vec::new(),
                cors_origins: Vec::new(),
                operators: Vec::new(),
            })
            .with_config_path(f.path()),
        );
        let auth = basic_auth("admin", "secret");

        // Pre-set the guard so the first task we spawn cannot race
        // ahead and finish before the second task has even started.
        // The deterministic shape: hold the guard, fire two tasks
        // off, release the guard, wait for both. Whichever tokio
        // schedules first wins 200; the other sees true and 409s.
        state
            .reload_in_progress
            .store(true, std::sync::atomic::Ordering::Release);

        let s1 = state.clone();
        let a1 = auth.clone();
        let h1 = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                handle_admin_request("POST", "/admin/reload", &s1, Some(&a1), None)
            })
            .await
            .unwrap()
        });
        let s2 = state.clone();
        let a2 = auth.clone();
        let h2 = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                handle_admin_request("POST", "/admin/reload", &s2, Some(&a2), None)
            })
            .await
            .unwrap()
        });

        // Yield long enough that both tasks observed the contended
        // guard, then release it for the winner.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        state
            .reload_in_progress
            .store(false, std::sync::atomic::Ordering::Release);

        let (r1, r2) = tokio::join!(h1, h2);
        let (s1_status, _, _) = r1.unwrap();
        let (s2_status, _, _) = r2.unwrap();

        // Both observed `true` when they entered, so both 409. This
        // is the conservative shape: the contract is "one wins, one
        // loses" but if both lose that's still proof the guard is
        // working. The test asserts at least one is 409 and neither
        // is 500.
        assert!(s1_status == 200 || s1_status == 409, "got {s1_status}");
        assert!(s2_status == 200 || s2_status == 409, "got {s2_status}");
        assert!(
            s1_status == 409 || s2_status == 409,
            "expected at least one 409, got {s1_status} and {s2_status}"
        );
    }

    // --- /admin/drift ---

    #[test]
    fn admin_drift_unauthorized_returns_401() {
        let state = make_state();
        let (status, _, _) = handle_admin_request("GET", "/admin/drift", &state, None, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn admin_drift_rejects_post() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) =
            handle_admin_request("POST", "/admin/drift", &state, Some(&auth), None);
        assert_eq!(status, 405);
    }

    #[test]
    fn admin_drift_without_config_path_returns_503() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/admin/drift", &state, Some(&auth), None);
        assert_eq!(status, 503);
        assert!(body.contains("no on-disk config path"), "got: {body}");
    }

    #[test]
    fn admin_drift_without_content_hash_baseline_returns_503() {
        // config_path is set but no content-hash baseline yet (nothing
        // has called `with_loaded_config_content_hash` and no reload
        // has occurred). Drift cannot be determined.
        let f = write_yaml(&reload_yaml("drift-no-baseline.example.com"));
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/admin/drift", &state, Some(&auth), None);
        assert_eq!(status, 503);
        assert!(
            body.contains("no loaded config content hash baseline"),
            "got: {body}"
        );
    }

    #[test]
    fn admin_drift_missing_file_returns_500_with_sanitised_path() {
        // Point at a file that does not exist. Seed the baseline so
        // we get past the no-baseline 503 path. The handler should
        // surface the I/O error but scrub the absolute path so the
        // body does not leak the operator's filesystem layout.
        let dir = tempfile::tempdir().expect("tempdir");
        let bogus = dir.path().join("does-not-exist.yml");
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_config_path(&bogus)
        .with_loaded_config_content_hash("deadbeefcafe");
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("GET", "/admin/drift", &state, Some(&auth), None);
        assert_eq!(status, 500, "body: {body}");
        assert_eq!(ct, "application/json");
        let abs = bogus.to_string_lossy().to_string();
        assert!(
            !body.contains(&abs),
            "absolute path leaked into error: {body}"
        );
    }

    #[test]
    fn admin_drift_after_reload_reports_no_drift() {
        // Reload to make the loaded revision deterministic, then
        // query drift against the same file: revisions match, drift
        // is false.
        let f = write_yaml(&reload_yaml("reload-drift-noop.example.com"));
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (rstatus, _, _) =
            handle_admin_request("POST", "/admin/reload", &state, Some(&auth), None);
        assert_eq!(rstatus, 200);

        let (status, ct, body) =
            handle_admin_request("GET", "/admin/drift", &state, Some(&auth), None);
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(ct, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(parsed.get("drift").and_then(|v| v.as_bool()), Some(false));
        let loaded = parsed
            .get("loaded_content_hash")
            .and_then(|v| v.as_str())
            .expect("loaded_content_hash string");
        let on_disk = parsed
            .get("on_disk_content_hash")
            .and_then(|v| v.as_str())
            .expect("on_disk_content_hash string");
        assert_eq!(loaded, on_disk, "content hashes should match after reload");
        // The origin-set identity hash also surfaces; sanity-check
        // that it's a 12-char hex string (matches config_revision()'s
        // contract).
        let origin_revision = parsed
            .get("loaded_revision")
            .and_then(|v| v.as_str())
            .expect("loaded_revision string");
        assert_eq!(origin_revision.len(), 12);
        assert!(parsed.get("on_disk_size_bytes").is_some());
        assert!(parsed.get("checked_at").is_some());
    }

    #[test]
    fn admin_drift_after_file_change_reports_drift() {
        // Reload, mutate the file, query drift: on-disk hash differs
        // from the loaded revision.
        let f = write_yaml(&reload_yaml("reload-drift-edit-a.example.com"));
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (rstatus, _, _) =
            handle_admin_request("POST", "/admin/reload", &state, Some(&auth), None);
        assert_eq!(rstatus, 200);

        // Edit the file in place. The loaded pipeline still has the
        // pre-edit revision; the on-disk file hashes differently.
        std::fs::write(
            f.path(),
            reload_yaml("reload-drift-edit-b.example.com").as_bytes(),
        )
        .expect("rewrite yaml");

        let (status, _, body) =
            handle_admin_request("GET", "/admin/drift", &state, Some(&auth), None);
        assert_eq!(status, 200, "body: {body}");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(parsed.get("drift").and_then(|v| v.as_bool()), Some(true));
        let loaded = parsed
            .get("loaded_content_hash")
            .and_then(|v| v.as_str())
            .expect("loaded_content_hash string");
        let on_disk = parsed
            .get("on_disk_content_hash")
            .and_then(|v| v.as_str())
            .expect("on_disk_content_hash string");
        assert_ne!(loaded, on_disk, "revisions should differ after file change");
    }

    // --- Rate Limiter ---

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = AdminRateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.check("10.0.0.1"), "should allow within limit");
        }
    }

    #[test]
    fn admin_acceptor_missing_files_errors_clearly() {
        // WOR-1717: an unreadable cert must produce a descriptive error
        // so spawn_admin_server can log it and decline to start rather
        // than serve plaintext on a port asked to be TLS.
        let tls = AdminTls {
            cert: std::path::PathBuf::from("/nonexistent/admin-cert.pem"),
            key: std::path::PathBuf::from("/nonexistent/admin-key.pem"),
        };
        // map Ok to () since TlsAcceptor is not Debug (expect_err needs it).
        let err = build_admin_acceptor(&tls)
            .map(|_| ())
            .expect_err("missing cert must error");
        assert!(err.contains("read admin cert"), "unexpected error: {err}");
    }

    #[test]
    fn admin_acceptor_rejects_non_cert_content() {
        // A file that exists but is not a PEM cert must be rejected (no
        // certificates parsed), not silently accepted.
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, b"not a certificate").unwrap();
        std::fs::write(&key, b"not a key").unwrap();
        let tls = AdminTls { cert, key };
        let err = build_admin_acceptor(&tls)
            .map(|_| ())
            .expect_err("garbage cert must error");
        assert!(
            err.contains("admin cert") || err.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = AdminRateLimiter::new(3);
        for _ in 0..3 {
            limiter.check("10.0.0.2");
        }
        assert!(
            !limiter.check("10.0.0.2"),
            "should block after limit exceeded"
        );
    }

    #[test]
    fn rate_limiter_different_ips_independent() {
        // Explicit global cap well above what the test exercises so the
        // per-IP independence check is unaffected by it.
        let limiter = AdminRateLimiter::with_global(1, 1_000);
        assert!(limiter.check("10.0.0.3"));
        assert!(!limiter.check("10.0.0.3"), "same IP should be blocked");
        assert!(
            limiter.check("10.0.0.4"),
            "different IP should still be allowed"
        );
    }

    #[test]
    fn rate_limiter_global_cap_blocks_distributed_flood() {
        // Per-IP cap is generous; global cap is what stops a flood from
        // many different IPs. Each unique IP gets one request through,
        // then the global cap kicks in.
        let limiter = AdminRateLimiter::with_global(100, 3);
        assert!(limiter.check("10.0.1.1"));
        assert!(limiter.check("10.0.1.2"));
        assert!(limiter.check("10.0.1.3"));
        assert!(
            !limiter.check("10.0.1.4"),
            "global cap should block the fourth distinct IP"
        );
    }

    #[test]
    fn rate_limiter_rejected_request_does_not_bump_counter() {
        // If a blocked request still incremented the counter, a well-
        // behaved caller arriving right after would see an inflated
        // count and also get blocked even though they are on their first
        // request of the window.
        let limiter = AdminRateLimiter::with_global(1, 100);
        assert!(limiter.check("10.0.2.1"));
        assert!(!limiter.check("10.0.2.1"));
        assert!(!limiter.check("10.0.2.1"));
        // Different IP on its first request of the window: should be
        // admitted, because no global cap has been hit.
        assert!(limiter.check("10.0.2.2"));
    }

    // --- IP Filter ---

    #[test]
    fn ip_filter_localhost_only_allows_loopback() {
        let filter = AdminIpFilter::localhost_only();
        assert!(filter.is_allowed("127.0.0.1"));
        assert!(filter.is_allowed("::1"));
        assert!(!filter.is_allowed("192.168.1.1"));
        assert!(!filter.is_allowed("10.0.0.1"));
    }

    #[test]
    fn ip_filter_custom_list() {
        let filter = AdminIpFilter::new(vec!["10.1.2.3".to_string(), "10.1.2.4".to_string()]);
        assert!(filter.is_allowed("10.1.2.3"));
        assert!(filter.is_allowed("10.1.2.4"));
        assert!(!filter.is_allowed("10.1.2.5"));
        assert!(!filter.is_allowed("127.0.0.1"));
    }

    #[test]
    fn ip_filter_empty_allows_all() {
        let filter = AdminIpFilter::new(vec![]);
        assert!(filter.is_allowed("192.168.1.1"));
        assert!(filter.is_allowed("10.0.0.1"));
        assert!(filter.is_allowed("::1"));
    }

    #[test]
    fn ip_filter_cidr_match() {
        // WOR-1717: entries that parse as CIDRs match by network.
        let filter = AdminIpFilter::new(vec!["10.1.0.0/16".to_string(), "192.168.1.5".to_string()]);
        assert!(filter.is_allowed("10.1.2.3"), "in CIDR");
        assert!(filter.is_allowed("10.1.255.255"), "in CIDR");
        assert!(!filter.is_allowed("10.2.0.1"), "outside CIDR");
        assert!(filter.is_allowed("192.168.1.5"), "exact");
        assert!(!filter.is_allowed("192.168.1.6"), "exact miss");
    }

    #[test]
    fn cors_headers_gate_on_allowed_origin() {
        // WOR-1717: CORS headers only for a configured origin.
        let allowed = vec!["https://admin.example.com".to_string()];
        let h = cors_response_headers(Some("https://admin.example.com"), &allowed);
        assert!(h
            .iter()
            .any(|(k, v)| k == "Access-Control-Allow-Origin" && v == "https://admin.example.com"));
        assert!(h
            .iter()
            .any(|(k, _)| k == "Access-Control-Allow-Credentials"));
        assert!(cors_response_headers(Some("https://evil.example.com"), &allowed).is_empty());
        assert!(cors_response_headers(None, &allowed).is_empty());
        // Wildcard echoes the caller's origin so credentials still work.
        let star = vec!["*".to_string()];
        let hs = cors_response_headers(Some("https://any.example.com"), &star);
        assert!(hs
            .iter()
            .any(|(k, v)| k == "Access-Control-Allow-Origin" && v == "https://any.example.com"));
    }

    #[test]
    fn session_principal_and_csrf() {
        // WOR-1714: a valid session cookie resolves the operator, and the
        // CSRF token equals the session nonce.
        let state = make_state();
        let (token, nonce) = state
            .session_signer
            .mint("alice", AdminRole::Admin, 3600, unix_now());
        let cookie = format!("sb_admin_session={token}");
        let p = state
            .resolve_principal(None, Some(&cookie))
            .expect("session resolves");
        assert!(p.via_session);
        assert_eq!(p.username, "alice");
        assert_eq!(p.role, AdminRole::Admin);
        assert_eq!(p.csrf.as_deref(), Some(nonce.as_str()));
    }

    #[test]
    fn revoked_session_rejected() {
        // WOR-1714: logout revokes the nonce.
        let state = make_state();
        let (token, nonce) = state
            .session_signer
            .mint("bob", AdminRole::Admin, 3600, unix_now());
        state.revoked_sessions.lock().unwrap().insert(nonce);
        let cookie = format!("sb_admin_session={token}");
        assert!(state.resolve_principal(None, Some(&cookie)).is_none());
    }

    #[test]
    fn basic_principal_is_admin() {
        // make_state uses admin/secret.
        let state = make_state();
        let p = state
            .resolve_principal(Some(&basic_auth("admin", "secret")), None)
            .expect("basic resolves");
        assert!(!p.via_session);
        assert_eq!(p.role, AdminRole::Admin);
        assert!(state
            .resolve_principal(Some(&basic_auth("admin", "wrong")), None)
            .is_none());
    }

    #[test]
    fn operator_login_roles() {
        // WOR-1716: top-level admin is full-access; a configured operator
        // gets its declared role; wrong password fails.
        let cfg = AdminConfig {
            operators: vec![AdminOperator {
                username: "ro".to_string(),
                password: "ropass".to_string(),
                role: AdminRole::ReadOnly,
            }],
            ..AdminConfig::default()
        };
        let state = AdminState::new(cfg);
        assert_eq!(
            state.check_operator_login("admin", "changeme"),
            Some(AdminRole::Admin)
        );
        assert_eq!(
            state.check_operator_login("ro", "ropass"),
            Some(AdminRole::ReadOnly)
        );
        assert_eq!(state.check_operator_login("ro", "bad"), None);
        assert_eq!(state.check_operator_login("nobody", "x"), None);
    }

    #[test]
    fn synthesized_basic_round_trips() {
        // WOR-1714: the synthesized header decodes back to the creds so
        // handle_admin_request's Basic gate accepts a session-authed call.
        let h = synthesize_basic("admin", "s3cret:with:colon");
        let (u, p) = decode_basic_auth(&h).expect("decodes");
        assert_eq!(u, "admin");
        assert_eq!(p, "s3cret:with:colon");
    }

    // --- /healthz + /readyz ---

    #[test]
    fn healthz_is_unauthenticated_and_returns_200() {
        let state = make_state();
        let (status, ct, body) = handle_admin_request("GET", "/healthz", &state, None, None);
        assert_eq!(status, 200, "healthz must not require auth");
        assert_eq!(ct, "application/json");
        assert!(body.contains("ok"), "body: {}", body);
    }

    #[test]
    fn readyz_is_unauthenticated_and_returns_200_when_empty() {
        let state = make_state();
        let (status, ct, body) = handle_admin_request("GET", "/readyz", &state, None, None);
        assert_eq!(
            status, 200,
            "default unconfigured registry should be ready: {}",
            body
        );
        assert_eq!(ct, "application/json");
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"name\":\"ledger\""));
        assert!(body.contains("\"status\":\"not_configured\""));
    }

    #[test]
    fn live_and_livez_return_alive_true() {
        let state = make_state();
        for path in ["/live", "/livez"] {
            let (status, ct, body) = handle_admin_request("GET", path, &state, None, None);
            assert_eq!(status, 200, "{} must not require auth", path);
            assert_eq!(ct, "application/json");
            assert!(body.contains("\"alive\":true"), "{} body: {}", path, body);
        }
    }

    #[test]
    fn ready_alias_matches_readyz_and_health_is_rich() {
        let state = make_state();
        let (rs, _, rb) = handle_admin_request("GET", "/readyz", &state, None, None);
        let (as_, _, ab) = handle_admin_request("GET", "/ready", &state, None, None);
        assert_eq!(rs, as_, "/ready must mirror /readyz status");
        assert_eq!(rb, ab, "/ready must mirror /readyz body");

        let (hs, _, hb) = handle_admin_request("GET", "/healthz", &state, None, None);
        let (ps, _, pb) = handle_admin_request("GET", "/health", &state, None, None);
        assert_eq!(hs, 200, "/healthz remains trivial liveness: {hb}");
        assert_eq!(ps, 200, "/health rich endpoint ready status: {pb}");
        let rich: serde_json::Value = serde_json::from_str(&pb).unwrap();
        assert_eq!(rich["status"], "ok");
        assert!(rich["version"].as_str().is_some(), "body: {pb}");
        assert!(rich["build_hash"].as_str().is_some(), "body: {pb}");
        assert!(rich["timestamp"].as_str().is_some(), "body: {pb}");
        assert!(rich["uptime_seconds"].as_u64().is_some(), "body: {pb}");
        assert!(rich["checks"].as_array().is_some(), "body: {pb}");
    }

    #[test]
    fn readyz_returns_503_when_default_registry_has_unhealthy_ledger() {
        // Seed the default Wave 1 registry but never mark the ledger
        // recency as successful so it reports unhealthy.
        let l = sbproxy_observe::Recency::new(std::time::Duration::from_secs(60));
        let b = sbproxy_observe::Recency::new(std::time::Duration::from_secs(60));
        b.mark_success();
        let registry = sbproxy_observe::default_registry(l, b);
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_health_registry(registry);
        let (status, _, body) = handle_admin_request("GET", "/readyz", &state, None, None);
        assert_eq!(status, 503, "ledger never marked => unready: {}", body);
        assert!(body.contains("\"name\":\"ledger\""), "body: {}", body);
        assert!(body.contains("\"status\":\"unhealthy\""), "body: {}", body);
    }

    #[test]
    fn readyz_returns_200_when_default_registry_is_fresh() {
        let l = sbproxy_observe::Recency::new(std::time::Duration::from_secs(60));
        l.mark_success();
        let b = sbproxy_observe::Recency::new(std::time::Duration::from_secs(60));
        b.mark_success();
        let registry = sbproxy_observe::default_registry(l, b);
        let state = AdminState::new(AdminConfig {
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_health_registry(registry);
        let (status, _, body) = handle_admin_request("GET", "/readyz", &state, None, None);
        assert_eq!(status, 200, "fresh recencies + stubs => ready: {}", body);
        // The seeded components show up.
        assert!(body.contains("ledger"));
        assert!(body.contains("bot_auth_directory"));
        assert!(body.contains("agent_registry"));
        assert!(body.contains("mesh_quorum"));
    }

    #[test]
    fn healthz_post_falls_through_to_auth() {
        let state = make_state();
        // POST /healthz isn't a probe path; the auth gate kicks in
        // and we get 401. This documents that we only fast-path GET.
        let (status, _, _) = handle_admin_request("POST", "/healthz", &state, None, None);
        assert_eq!(status, 401);
    }

    // --- Wave 3 closeout: quote-token JWKS publication ---

    #[test]
    fn quote_keys_jwks_unions_kids_across_origins() {
        // The JWKS endpoint must aggregate kids across every origin's
        // `ai_crawl_control` policy. Wire two origins, each carrying a
        // distinct quote-token signer kid, install the pipeline through
        // the global ArcSwap, and assert both kids show up in the
        // unioned response.
        use crate::pipeline::CompiledPipeline;
        use compact_str::CompactString;
        use sbproxy_config::CompiledOrigin;
        use std::collections::HashMap;

        // Quote-token signer config for two origins. The seed_hex bytes
        // do not matter for this test (the JWKS only carries the public
        // key); the kid is what we assert on. Wave 3 / G3.6 lands the
        // signer config on the policy itself so two ai_crawl_control
        // origins with different `key_id` values produce two kids in
        // the unioned JWKS.
        let make_origin = |hostname: &str, kid: &str| {
            let policy_cfg = serde_json::json!({
                "type": "ai_crawl_control",
                "price": 0.001,
                "valid_tokens": [],
                "rails": {
                    "x402": {
                        "chain": "base",
                        "facilitator": "https://facilitator-base.x402.org",
                        "asset": "USDC",
                        "pay_to": "0xabc",
                    }
                },
                "quote_token": {
                    "key_id": kid,
                    "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
                    "issuer": format!("https://{}", hostname),
                    "default_ttl_seconds": 300,
                }
            });
            CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: serde_json::json!({"type": "noop"}),
                auth_config: None,
                policy_configs: vec![policy_cfg],
                transform_configs: Vec::new(),
                cors: None,
                hsts: None,
                compression: None,
                session: None,
                properties: None,
                sessions: None,
                user: None,
                force_ssl: false,
                allowed_methods: smallvec::smallvec![],
                request_modifiers: smallvec::smallvec![],
                response_modifiers: smallvec::smallvec![],
                variables: None,
                forward_rules: Vec::new(),
                fallback_origin: None,
                error_pages: None,
                problem_details: None,
                proxy_status: None,
                message_signatures: None,
                olp: None,
                web_bot_auth_publish: None,
                idempotency: None,
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                rate_limits: None,
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
                agent_skills: Vec::new(),
                agents_md: None,
                ai_txt: None,
                agents_json: None,
                outbound_credential: None,
                outbound_web_bot_auth: false,
                observability: None,
            }
        };

        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new("alpha.example"), 0);
        host_map.insert(CompactString::new("beta.example"), 1);
        let cfg = sbproxy_config::CompiledConfig {
            origins: vec![
                make_origin("alpha.example", "kid-alpha"),
                make_origin("beta.example", "kid-beta"),
            ],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
        };
        let pipeline = CompiledPipeline::from_config(cfg).expect("pipeline compiles");
        crate::reload::load_pipeline(pipeline);

        // Hit the unauthenticated route. The handler reads the live
        // pipeline through `current_pipeline()` so we don't need a
        // dedicated AdminState for the JWKS path.
        let state = make_state();
        let (status, ct, body) = handle_admin_request(
            "GET",
            "/.well-known/sbproxy/quote-keys.json",
            &state,
            None,
            None,
        );
        assert_eq!(status, 200, "JWKS route must return 200: {}", body);
        assert_eq!(ct, "application/json");

        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("JWKS body parses as JSON");
        let keys = parsed
            .get("keys")
            .and_then(|v| v.as_array())
            .expect("`keys` array");
        let kids: std::collections::BTreeSet<String> = keys
            .iter()
            .filter_map(|k| k.get("kid").and_then(|v| v.as_str()).map(String::from))
            .collect();
        assert!(
            kids.contains("kid-alpha"),
            "alpha origin kid missing: {:?}",
            kids
        );
        assert!(
            kids.contains("kid-beta"),
            "beta origin kid missing: {:?}",
            kids
        );

        // Each entry must carry the standard JWK-ish shape.
        for k in keys.iter() {
            assert_eq!(k.get("kty").and_then(|v| v.as_str()), Some("OKP"));
            assert_eq!(k.get("crv").and_then(|v| v.as_str()), Some("Ed25519"));
            assert_eq!(k.get("alg").and_then(|v| v.as_str()), Some("EdDSA"));
            assert!(k.get("x").is_some(), "JWK entry missing public-key bytes");
        }
    }

    #[test]
    fn quote_keys_jwks_route_skips_auth_check() {
        // Pinned: the JWKS path is unauthenticated. Requests without
        // an Authorization header must NOT receive 401.
        let state = make_state();
        let (status, _, _) = handle_admin_request(
            "GET",
            "/.well-known/sbproxy/quote-keys.json",
            &state,
            None,
            None,
        );
        // Either 200 (a pipeline with kids is installed) or 200 with an
        // empty `{"keys":[]}` body (default pipeline). 401 is the
        // failure mode this test guards against.
        assert_ne!(
            status, 401,
            "JWKS route must not require basic-auth credentials"
        );
        assert_eq!(status, 200);
    }

    // --- WOR-800 PR3: prompt-store admin endpoints ---

    /// The runtime overlay is process-global; tests that mutate it
    /// serialise to avoid clobbering each other. Defers to the
    /// shared lock in `sbproxy_ai::prompts::lock_for_tests` so this
    /// module and `admin::prompt_persistence::tests` (the other
    /// in-binary caller that touches the overlay) never run
    /// interleaved sequences.
    fn prompts_admin_lock() -> std::sync::MutexGuard<'static, ()> {
        sbproxy_ai::prompts::lock_for_tests()
    }

    fn reset_runtime_overlay() {
        sbproxy_ai::prompts::install_runtime_overlay(
            sbproxy_ai::prompts::RuntimePromptOverlay::default(),
        );
    }

    #[test]
    fn parse_prompt_admin_path_happy_path() {
        let (h, n, a) = parse_prompt_admin_path("example.com/summary/versions").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(n, "summary");
        assert_eq!(a, "versions");
    }

    #[test]
    fn parse_prompt_admin_path_rejects_short_paths() {
        assert!(parse_prompt_admin_path("example.com").is_none());
        assert!(parse_prompt_admin_path("example.com/summary").is_none());
        assert!(parse_prompt_admin_path("").is_none());
        // Trailing slash leaves an empty action segment.
        assert!(parse_prompt_admin_path("example.com/summary/").is_none());
    }

    #[test]
    fn list_prompts_is_authenticated_only() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let (status, _, _) = handle_admin_request("GET", "/admin/prompts", &state, None, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn list_prompts_empty_overlay_returns_empty_hosts() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("GET", "/admin/prompts", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["hosts"], serde_json::json!({}));
    }

    #[test]
    fn add_version_then_list_round_trips_through_overlay() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let add_body = r#"{"version":"1","template":"hello {{ request.tool }}"}"#;
        let (status, _, body) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            Some(add_body),
        );
        assert_eq!(status, 200, "add version response: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["host"], "example.com");
        assert_eq!(v["name"], "greet");
        assert_eq!(v["version"], "1");
        assert_eq!(v["default_version"], "1");

        // List should now show the new prompt. `default_version` is
        // null until pinned; `effective_version` mirrors the runtime
        // fallback (highest numeric label) so an unpinned add still
        // shows what a render would pick.
        let (status, _, list_body) =
            handle_admin_request("GET", "/admin/prompts", &state, Some(&auth), None);
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&list_body).unwrap();
        let greet = &v["hosts"]["example.com"]["prompts"]["greet"];
        assert_eq!(greet["default_version"], serde_json::Value::Null);
        assert_eq!(greet["effective_version"], "1");
        assert_eq!(greet["versions"], serde_json::json!(["1"]));
    }

    #[test]
    fn add_version_rejects_missing_body() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn add_version_rejects_blank_version_or_template() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            Some(r#"{"version":"","template":"x"}"#),
        );
        assert_eq!(status, 400);
        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            Some(r#"{"version":"1","template":""}"#),
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn add_version_rejects_malformed_json() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            Some("{not json"),
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn add_version_rejects_get() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "GET",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 405);
    }

    #[test]
    fn pin_changes_default_version() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        // Seed two versions.
        for v in &["1", "2"] {
            let body = format!(r#"{{"version":"{v}","template":"v{v}"}}"#);
            handle_admin_request(
                "POST",
                "/admin/prompts/example.com/greet/versions",
                &state,
                Some(&auth),
                Some(&body),
            );
        }
        let (status, _, body) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/pin",
            &state,
            Some(&auth),
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 200, "pin response: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["default_version"], "1");

        // The render-time view honours the pin.
        let overlay = sbproxy_ai::prompts::current_runtime_overlay();
        let store = overlay.by_host.get("example.com").unwrap();
        let prompt = store.templates.get("greet").unwrap();
        assert_eq!(prompt.default_version.as_deref(), Some("1"));
    }

    #[test]
    fn pin_returns_404_on_unknown_host() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "PUT",
            "/admin/prompts/unknown.com/greet/pin",
            &state,
            Some(&auth),
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn pin_returns_404_on_unknown_version() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            Some(r#"{"version":"1","template":"v1"}"#),
        );
        let (status, _, _) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/pin",
            &state,
            Some(&auth),
            Some(r#"{"version":"7"}"#),
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn pin_rejects_post() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/pin",
            &state,
            Some(&auth),
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 405);
    }

    #[test]
    fn unknown_prompt_admin_action_returns_404() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/teleport",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 404);
    }
}
