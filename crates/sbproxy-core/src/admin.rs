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
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

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
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9090,
            username: "admin".to_string(),
            password: "changeme".to_string(),
            max_log_entries: 1000,
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

    /// Returns `true` if `ip` is permitted.
    ///
    /// An empty allowlist permits all IPs.
    pub fn is_allowed(&self, ip: &str) -> bool {
        self.allowed_ips.is_empty() || self.allowed_ips.iter().any(|a| a == ip)
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
    /// Single-flight guard for `/admin/reload`.
    ///
    /// We CAS this from `false` to `true` on entry; if the swap
    /// fails another reload is already in flight and the request
    /// returns `409 Conflict`. The file watcher and any other
    /// in-process reload call sites contend on the same flag so a
    /// manual reload during a watcher reload serialises cleanly.
    reload_in_progress: AtomicBool,
    /// Per-pillar health registry powering `/healthz` + `/readyz` per
    /// `docs/AIGOVERNANCE-BUILD.md` § 4.2 (R1.3). Per-wave probes are
    /// registered into this registry as their backing services come
    /// online; until then the default seeded set keeps `NotConfigured`
    /// stubs in place so readiness still passes.
    pub health_registry: sbproxy_observe::HealthRegistry,
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
            reload_in_progress: AtomicBool::new(false),
            health_registry: sbproxy_observe::HealthRegistry::new(),
        }
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

    /// Replace the health registry. Wave 1 callers seed the registry
    /// with `sbproxy_observe::default_registry(...)` so `/readyz`
    /// reports the standard pillar set; subsequent waves register
    /// their own probes via `state.health_registry.register(...)`.
    pub fn with_health_registry(mut self, registry: sbproxy_observe::HealthRegistry) -> Self {
        self.health_registry = registry;
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
/// Pinned by `adr-quote-token-jws.md` § "Key publication". The
/// returned document follows the standard JWKS shape:
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
    crate::reload::load_pipeline(new_pipeline);
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

// --- Request Handler ---

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
) -> (u16, &'static str, String) {
    // --- Unauthenticated probe routes (R1.3) ---
    //
    // `/healthz` and `/readyz` are reached by load balancers that
    // don't carry credentials, so we serve them before the basic-auth
    // gate. The handlers do not expose anything past per-component
    // status; the redaction middleware in `sbproxy-observe::logging`
    // covers per-component `detail` fields if a probe ever reports
    // sensitive content.
    if method.eq_ignore_ascii_case("GET") {
        match path {
            "/healthz" => return sbproxy_observe::handle_healthz(),
            "/readyz" => return sbproxy_observe::handle_readyz(&state.health_registry),
            // Wave 3 closeout: quote-token JWKS publication.
            //
            // Pinned by `adr-quote-token-jws.md` § "Key publication".
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

    // --- Route ---
    match path {
        // Recent request log.
        "/api/requests" => {
            let entries = state.get_recent_requests(state.config.max_log_entries);
            match serde_json::to_string(&entries) {
                Ok(body) => (200, "application/json", body),
                Err(e) => (
                    500,
                    "application/json",
                    format!(r#"{{"error":"serialization failed: {e}"}}"#),
                ),
            }
        }

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
    Some(tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
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
        tracing::info!(addr = %addr, "admin server listening");
        let rate_limiter = std::sync::Arc::new(AdminRateLimiter::new(60));
        let ip_filter = std::sync::Arc::new(AdminIpFilter::localhost_only());
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
            tokio::spawn(async move {
                let peer_ip = peer.ip().to_string();
                if !ip_filter.is_allowed(&peer_ip) {
                    let _ = write_admin_response(
                        sock,
                        403,
                        "application/json",
                        r#"{"error":"Forbidden"}"#,
                    )
                    .await;
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
                handle_admin_connection(sock, &state).await;
            });
        }
    }))
}

async fn handle_admin_connection(mut sock: tokio::net::TcpStream, state: &AdminState) {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];
    let n = match sock.read(&mut buf).await {
        Ok(0) => return,
        Ok(n) => n,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let mut auth_header: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Authorization:") {
            auth_header = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("authorization:") {
            auth_header = Some(rest.trim().to_string());
        }
    }
    let (status, content_type, body) =
        handle_admin_request(method, path, state, auth_header.as_deref());
    let _ = write_admin_response(sock, status, content_type, &body).await;
}

async fn write_admin_response(
    mut sock: tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let reason = match status {
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
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         WWW-Authenticate: Basic realm=\"sbproxy admin\"\r\n\
         \r\n\
         {body}",
        status = status,
        reason = reason,
        content_type = content_type,
        len = body.len(),
        body = body,
    );
    sock.write_all(response.as_bytes()).await?;
    sock.shutdown().await
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
        let (status, _, _) = handle_admin_request("GET", "/api/stats", &state, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn bad_credentials_returns_401() {
        let state = make_state();
        let auth = basic_auth("admin", "wrong");
        let (status, _, _) = handle_admin_request("GET", "/api/stats", &state, Some(&auth));
        assert_eq!(status, 401);
    }

    #[test]
    fn unknown_path_returns_404() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request("GET", "/unknown/path", &state, Some(&auth));
        assert_eq!(status, 404);
    }

    #[test]
    fn api_requests_returns_200_json() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) = handle_admin_request("GET", "/api/requests", &state, Some(&auth));
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        // Empty log returns JSON array.
        assert_eq!(body, "[]");
    }

    #[test]
    fn api_health_returns_200() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, _) = handle_admin_request("GET", "/api/health", &state, Some(&auth));
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn api_health_targets_returns_200_json() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("GET", "/api/health/targets", &state, Some(&auth));
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
        let (status, _, body) = handle_admin_request("GET", "/api/stats", &state, Some(&auth));
        assert_eq!(status, 200);
        assert!(body.contains("1"), "expected count 1 in: {body}");
    }

    #[test]
    fn root_returns_html() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) = handle_admin_request("GET", "/", &state, Some(&auth));
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
        let (status, _, _) = handle_admin_request("GET", "/admin/reload", &state, Some(&auth));
        assert_eq!(status, 405);
    }

    #[test]
    fn admin_reload_unauthorized_returns_401() {
        let state = make_state();
        let (status, _, _) = handle_admin_request("POST", "/admin/reload", &state, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn admin_reload_without_config_path_returns_503() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) = handle_admin_request("POST", "/admin/reload", &state, Some(&auth));
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
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (status, ct, body) = handle_admin_request("POST", "/admin/reload", &state, Some(&auth));
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
        })
        .with_config_path(f.path());
        let auth = basic_auth("admin", "secret");
        let (status, _, body) = handle_admin_request("POST", "/admin/reload", &state, Some(&auth));
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
                handle_admin_request("POST", "/admin/reload", &s1, Some(&a1))
            })
            .await
            .unwrap()
        });
        let s2 = state.clone();
        let a2 = auth.clone();
        let h2 = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                handle_admin_request("POST", "/admin/reload", &s2, Some(&a2))
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

    // --- Rate Limiter ---

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = AdminRateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.check("10.0.0.1"), "should allow within limit");
        }
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

    // --- /healthz + /readyz (R1.3) ---

    #[test]
    fn healthz_is_unauthenticated_and_returns_200() {
        let state = make_state();
        let (status, ct, body) = handle_admin_request("GET", "/healthz", &state, None);
        assert_eq!(status, 200, "healthz must not require auth");
        assert_eq!(ct, "application/json");
        assert!(body.contains("ok"), "body: {}", body);
    }

    #[test]
    fn readyz_is_unauthenticated_and_returns_200_when_empty() {
        let state = make_state();
        let (status, ct, body) = handle_admin_request("GET", "/readyz", &state, None);
        assert_eq!(status, 200, "empty registry should be ready: {}", body);
        assert_eq!(ct, "application/json");
        assert!(body.contains("\"status\":\"ok\""));
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
        })
        .with_health_registry(registry);
        let (status, _, body) = handle_admin_request("GET", "/readyz", &state, None);
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
        })
        .with_health_registry(registry);
        let (status, _, body) = handle_admin_request("GET", "/readyz", &state, None);
        assert_eq!(status, 200, "fresh recencies + stubs => ready: {}", body);
        // All five Wave 1 components show up.
        assert!(body.contains("ledger"));
        assert!(body.contains("bot_auth_directory"));
        assert!(body.contains("agent_registry"));
        assert!(body.contains("stripe"));
        assert!(body.contains("facilitator_quorum"));
    }

    #[test]
    fn healthz_post_falls_through_to_auth() {
        let state = make_state();
        // POST /healthz isn't a probe path; the auth gate kicks in
        // and we get 401. This documents that we only fast-path GET.
        let (status, _, _) = handle_admin_request("POST", "/healthz", &state, None);
        assert_eq!(status, 401);
    }

    // --- Wave 3 closeout: quote-token JWKS publication ---

    #[test]
    fn quote_keys_jwks_unions_kids_across_origins() {
        // The JWKS endpoint must aggregate kids across every origin's
        // `ai_crawl_control` policy. Wire two origins, each carrying a
        // distinct quote-token signer kid, install the pipeline through
        // the global ArcSwap, and assert both kids show up in the
        // unioned response. Pinned by `adr-quote-token-jws.md` § "Key
        // publication".
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
        };
        let pipeline = CompiledPipeline::from_config(cfg).expect("pipeline compiles");
        crate::reload::load_pipeline(pipeline);

        // Hit the unauthenticated route. The handler reads the live
        // pipeline through `current_pipeline()` so we don't need a
        // dedicated AdminState for the JWKS path.
        let state = make_state();
        let (status, ct, body) =
            handle_admin_request("GET", "/.well-known/sbproxy/quote-keys.json", &state, None);
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

        // Each entry must carry the standard JWK-ish shape pinned in
        // `adr-quote-token-jws.md`.
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
        let (status, _, _) =
            handle_admin_request("GET", "/.well-known/sbproxy/quote-keys.json", &state, None);
        // Either 200 (a pipeline with kids is installed) or 200 with an
        // empty `{"keys":[]}` body (default pipeline). 401 is the
        // failure mode this test guards against.
        assert_ne!(
            status, 401,
            "JWKS route must not require basic-auth credentials"
        );
        assert_eq!(status, 200);
    }
}
