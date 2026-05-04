//! Request context builder for CEL evaluation.
//!
//! Builds a [`CelContext`] from HTTP request data, populating the standard
//! namespaces that sbproxy CEL expressions can reference:
//!
//! - `request` - method, path, host, headers, query, scheme
//! - `connection` - remote_ip
//! - `jwt.claims` - decoded JWT claims when an `Authorization: Bearer`
//!   header carries a structurally-valid JWT. Decoded only; signature
//!   verification belongs to the JwtAuth provider.

use std::collections::HashMap;

use base64::Engine;
use http::HeaderMap;

use super::{CelContext, CelValue};

/// Build a CEL context from HTTP request data.
///
/// Populates the `request` and `connection` namespaces used by sbproxy's
/// CEL expressions for conditional routing, access control, and policy
/// decisions.
///
/// # Namespaces
///
/// - `request.method` - HTTP method (GET, POST, etc.)
/// - `request.path` - Request URI path
/// - `request.host` - Hostname from the request
/// - `request.headers` - Map of header name to value (lowercase keys)
/// - `request.query` - Raw query string (if present)
/// - `request.scheme` - URL scheme (if provided)
/// - `request.time` - Current request time as Unix epoch seconds (integer)
/// - `request.unix_nanos` - Current request time as Unix epoch nanoseconds (integer)
/// - `connection.remote_ip` - Client IP address (if known)
pub fn build_request_context(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    query: Option<&str>,
    client_ip: Option<&str>,
    hostname: &str,
) -> CelContext {
    let mut ctx = CelContext::new();

    // --- request namespace ---
    let mut request = HashMap::new();
    request.insert("method".to_string(), CelValue::String(method.to_string()));
    request.insert("path".to_string(), CelValue::String(path.to_string()));
    request.insert("host".to_string(), CelValue::String(hostname.to_string()));

    // Build headers map with lowercase keys (HTTP headers are case-insensitive,
    // but CEL field access is case-sensitive, so we normalize to lowercase).
    let mut hdrs = HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            // http::HeaderName is already lowercase
            hdrs.insert(key.as_str().to_string(), CelValue::String(v.to_string()));
        }
    }
    request.insert("headers".to_string(), CelValue::Map(hdrs));

    // Always set request.query so size(request.query) works even without a query string.
    let q_str = query.unwrap_or("");
    request.insert("query".to_string(), CelValue::String(q_str.to_string()));

    // --- request.time / request.unix_nanos ---
    // Wall-clock at the moment the CEL context is built. Exposed as
    // integers so expressions can compare against epoch-second or
    // epoch-nanosecond literals without bringing in a date library.
    let (unix_secs, unix_nanos) =
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.as_nanos() as i64),
            Err(_) => (0, 0),
        };
    request.insert("time".to_string(), CelValue::Int(unix_secs));
    request.insert("unix_nanos".to_string(), CelValue::Int(unix_nanos));

    ctx.set("request", CelValue::Map(request));

    // --- connection namespace ---
    let mut connection = HashMap::new();
    if let Some(ip) = client_ip {
        connection.insert("remote_ip".to_string(), CelValue::String(ip.to_string()));
    }
    ctx.set("connection", CelValue::Map(connection));

    // --- jwt namespace ---
    // Populate `jwt.claims` from `Authorization: Bearer <jwt>` when the
    // token's payload segment decodes as JSON. We do not verify the
    // signature here. CEL is consuming the token as data (e.g. for
    // rate-limit keys, route gating); JwtAuth still owns the security
    // boundary on a separate code path.
    let mut jwt = HashMap::new();
    if let Some(claims) = extract_jwt_claims(headers) {
        jwt.insert("claims".to_string(), CelValue::Map(claims));
    } else {
        jwt.insert("claims".to_string(), CelValue::Map(HashMap::new()));
    }
    ctx.set("jwt", CelValue::Map(jwt));

    ctx
}

/// Agent-class fields exposed to CEL (G1.4). The caller (proxy
/// pipeline) owns the strings and passes a borrowed view so the
/// scripting layer avoids cloning. Empty / `None` fields render as
/// the zero value (`""`) so expressions can call
/// `size(request.agent_id) > 0` without first probing.
#[derive(Debug, Default, Clone, Copy)]
pub struct AgentClassView<'a> {
    /// Resolved agent identifier (`human`, `anonymous`, `unknown`,
    /// or a catalog `id` like `openai-gptbot`).
    pub agent_id: Option<&'a str>,
    /// Operator display name (`OpenAI`, `Google`, ...).
    pub agent_vendor: Option<&'a str>,
    /// Operator-stated purpose (`training`, `search`, `assistant`, ...).
    pub agent_purpose: Option<&'a str>,
    /// Diagnostic stamp for which signal in the resolver chain matched
    /// (`bot_auth`, `rdns`, `user_agent`, `anonymous_bot_auth`, `fallback`).
    pub agent_id_source: Option<&'a str>,
    /// Forward-confirmed reverse-DNS hostname when the rDNS path matched.
    pub agent_rdns_hostname: Option<&'a str>,
}

/// Stamp the [`AgentClassView`] under both `request.agent_*` keys and
/// a top-level `agent` namespace.
///
/// We expose the values under `request.*` (matching the brief of
/// "expose to CEL: bind `request.agent_class`, `request.agent_id`")
/// and also under the dedicated `agent` namespace so future
/// per-agent expressions can scope cleanly:
///
/// - `request.agent_id` (alias `agent.id`)
/// - `request.agent_class` (alias `agent.id`; equal to agent_id by
///   the ADR contract: the catalog id IS the class)
/// - `request.agent_vendor` (alias `agent.vendor`)
/// - `request.agent_purpose` (alias `agent.purpose`)
/// - `request.agent_id_source` (alias `agent.source`)
/// - `request.agent_rdns_hostname` (alias `agent.rdns_hostname`)
pub fn populate_agent_class_namespace(ctx: &mut CelContext, view: &AgentClassView<'_>) {
    let id = view.agent_id.unwrap_or("");
    let vendor = view.agent_vendor.unwrap_or("");
    let purpose = view.agent_purpose.unwrap_or("");
    let source = view.agent_id_source.unwrap_or("");
    let rdns = view.agent_rdns_hostname.unwrap_or("");

    // Splice the agent fields into the existing `request` map so
    // existing CEL expressions that index `request.headers`, etc.,
    // keep working alongside the new keys.
    let request_var = ctx
        .variables
        .remove("request")
        .unwrap_or_else(|| CelValue::Map(HashMap::new()));
    let mut request_map = match request_var {
        CelValue::Map(m) => m,
        _ => HashMap::new(),
    };
    request_map.insert("agent_id".to_string(), CelValue::String(id.to_string()));
    request_map.insert("agent_class".to_string(), CelValue::String(id.to_string()));
    request_map.insert(
        "agent_vendor".to_string(),
        CelValue::String(vendor.to_string()),
    );
    request_map.insert(
        "agent_purpose".to_string(),
        CelValue::String(purpose.to_string()),
    );
    request_map.insert(
        "agent_id_source".to_string(),
        CelValue::String(source.to_string()),
    );
    request_map.insert(
        "agent_rdns_hostname".to_string(),
        CelValue::String(rdns.to_string()),
    );
    ctx.set("request", CelValue::Map(request_map));

    // Also expose under top-level `agent` for cleaner expressions.
    let mut agent = HashMap::new();
    agent.insert("id".to_string(), CelValue::String(id.to_string()));
    agent.insert("class".to_string(), CelValue::String(id.to_string()));
    agent.insert("vendor".to_string(), CelValue::String(vendor.to_string()));
    agent.insert("purpose".to_string(), CelValue::String(purpose.to_string()));
    agent.insert("source".to_string(), CelValue::String(source.to_string()));
    agent.insert(
        "rdns_hostname".to_string(),
        CelValue::String(rdns.to_string()),
    );
    ctx.set("agent", CelValue::Map(agent));
}

/// Borrowed view over the three Wave 4 aipref axes the CEL context
/// exposes (G4.9). The caller (typically `sbproxy-modules` or
/// `sbproxy-core`) owns the parsed signal and constructs this view to
/// avoid pulling the `sbproxy-modules` crate into `sbproxy-extension`'s
/// dependency graph (the two crates are siblings).
#[derive(Debug, Default, Clone, Copy)]
pub struct AiprefView {
    /// `train`: whether the resource may be used for AI model training.
    pub train: bool,
    /// `search`: whether the resource may be indexed for search.
    pub search: bool,
    /// `ai-input`: whether the resource may be used as model input
    /// (inference / RAG).
    pub ai_input: bool,
}

impl AiprefView {
    /// Default-permissive view: every axis `true`. Used when the
    /// request had no `aipref` header or the header was malformed
    /// (A4.1's "absence of a signal is not a signal" rule).
    pub fn permissive() -> Self {
        Self {
            train: true,
            search: true,
            ai_input: true,
        }
    }
}

/// Populate the `request.aipref` namespace with the parsed aipref
/// signal from the inbound request header (Wave 4 / G4.9).
///
/// CEL expressions read `request.aipref.train`,
/// `request.aipref.search`, and `request.aipref.ai_input` as booleans
/// to gate AI-use opt-outs. When the request had no `aipref` header
/// or the header was malformed, the caller passes `None` and every
/// axis defaults to `true` (default-permissive) per A4.1's "absence
/// of a signal is not a signal" contract.
///
/// Idempotent: re-invoking with a different signal overwrites the
/// previous values so request-time and response-time evaluations can
/// share one CEL context.
pub fn populate_aipref_namespace(ctx: &mut CelContext, aipref: Option<&AiprefView>) {
    let view = aipref.copied().unwrap_or_else(AiprefView::permissive);

    let mut aipref_map = HashMap::with_capacity(4);
    aipref_map.insert("train".to_string(), CelValue::Bool(view.train));
    aipref_map.insert("search".to_string(), CelValue::Bool(view.search));
    aipref_map.insert("ai_input".to_string(), CelValue::Bool(view.ai_input));
    // Also expose the hyphenated alias so expressions can read
    // either `request.aipref.ai_input` (canonical Rust naming) or
    // `request.aipref["ai-input"]` if a future engine supports it.
    aipref_map.insert("ai-input".to_string(), CelValue::Bool(view.ai_input));

    let request_var = ctx
        .variables
        .remove("request")
        .unwrap_or_else(|| CelValue::Map(HashMap::new()));
    let mut request_map = match request_var {
        CelValue::Map(m) => m,
        _ => HashMap::new(),
    };
    request_map.insert("aipref".to_string(), CelValue::Map(aipref_map));
    ctx.set("request", CelValue::Map(request_map));
}

// --- Wave 5 / G5.1 KYA verifier namespace ---

/// Borrowed view over the Wave 5 / G5.1 KYA verifier verdict exposed
/// to CEL under `request.kya`. The caller (`sbproxy-core`) owns the
/// strings on the `RequestContext` KYA fields.
///
/// Empty / `None` fields render as the zero value (`""` for strings,
/// `0` for `kyab_balance.amount`) so expressions can call
/// `request.kya.verdict == "missing"` without first probing for
/// presence.
#[derive(Debug, Default, Clone, Copy)]
pub struct KyaVerdictView<'a> {
    /// Verdict label as defined by `KyaVerdict::metric_label` on the
    /// enterprise verifier. One of: `"verified"`, `"missing"`,
    /// `"expired"`, `"revoked"`, `"invalid"`,
    /// `"directory_unavailable"`. `None` when no KYA hook ran.
    pub verdict: Option<&'a str>,
    /// Resolved agent identifier (mirrors `request.agent_id` for the
    /// KYA case). Empty when the verdict is not `"verified"`.
    pub agent_id: Option<&'a str>,
    /// KYA agent vendor (e.g. `"skyfire"`).
    pub vendor: Option<&'a str>,
    /// KYA spec version (e.g. `"v1"`).
    pub kya_version: Option<&'a str>,
    /// KYAB advisory balance (smallest currency unit).
    pub kyab_balance: Option<u64>,
}

/// Populate the `request.kya` namespace with the verdict produced by
/// the enterprise KYA verifier (Wave 5 / G5.1).
///
/// CEL expressions read `request.kya.verdict` (string) to gate routes
/// without owning the verifier itself. The pipeline calls this once
/// per request after the resolver chain runs; downstream policy
/// evaluation reads through the same map.
///
/// When the KYA hook never ran (no enterprise binary, or no
/// `auth.kya:` block), every field renders as the zero value so a
/// policy expression like `request.kya.verdict != "missing"` evaluates
/// to `true` (the expression sees `""` rather than the literal
/// `"missing"`). Operators that want "no hook ran" to count as
/// "missing" must spell that out: `request.kya.verdict == "missing"`.
///
/// Idempotent: re-invoking with a different verdict overwrites the
/// previous fields so request-time and response-time evaluations can
/// share one CEL context.
pub fn populate_kya_namespace(ctx: &mut CelContext, view: &KyaVerdictView<'_>) {
    let mut kya_map = HashMap::with_capacity(5);
    kya_map.insert(
        "verdict".to_string(),
        CelValue::String(view.verdict.unwrap_or("").to_string()),
    );
    kya_map.insert(
        "agent_id".to_string(),
        CelValue::String(view.agent_id.unwrap_or("").to_string()),
    );
    kya_map.insert(
        "vendor".to_string(),
        CelValue::String(view.vendor.unwrap_or("").to_string()),
    );
    kya_map.insert(
        "kya_version".to_string(),
        CelValue::String(view.kya_version.unwrap_or("").to_string()),
    );
    let mut balance_map = HashMap::with_capacity(1);
    // KYAB balance is advisory; the proxy never settles against it.
    // Render `amount` as `Int(0)` when absent so a CEL expression like
    // `request.kya.kyab_balance.amount > 100` short-circuits cleanly
    // for unsigned tokens.
    balance_map.insert(
        "amount".to_string(),
        CelValue::Int(view.kyab_balance.unwrap_or(0) as i64),
    );
    kya_map.insert("kyab_balance".to_string(), CelValue::Map(balance_map));

    let request_var = ctx
        .variables
        .remove("request")
        .unwrap_or_else(|| CelValue::Map(HashMap::new()));
    let mut request_map = match request_var {
        CelValue::Map(m) => m,
        _ => HashMap::new(),
    };
    request_map.insert("kya".to_string(), CelValue::Map(kya_map));
    ctx.set("request", CelValue::Map(request_map));
}

// --- Wave 5 / A5.2 ML classifier namespace ---

/// Borrowed view over the Wave 5 / A5.2 ML agent classifier verdict
/// exposed to CEL under `request.ml_classification`.
///
/// Empty / `None` fields render as the zero value so expressions can
/// call `request.ml_classification.class == "human"` without first
/// probing for presence.
#[derive(Debug, Default, Clone, Copy)]
pub struct MlClassificationView<'a> {
    /// Class label: `"human"`, `"llm-agent"`, `"scraper"`, `"unknown"`.
    /// `None` when no classifier ran.
    pub class: Option<&'a str>,
    /// Top-class softmax probability in `[0.0, 1.0]`.
    pub confidence: Option<f32>,
    /// Stable identifier of the loaded weights (e.g. `"ml-agent-v1"`).
    pub model_version: Option<&'a str>,
    /// Schema version the feature builder produced for this verdict.
    pub feature_schema_version: Option<u32>,
}

/// Populate the `request.ml_classification` namespace with the verdict
/// produced by the enterprise ML agent classifier (Wave 5 / A5.2).
///
/// CEL expressions read:
///
/// - `request.ml_classification.class` - one of `"human"`,
///   `"llm-agent"`, `"scraper"`, `"unknown"`, or `""` when no
///   classifier ran.
/// - `request.ml_classification.confidence` - `f64` in `[0.0, 1.0]`.
/// - `request.ml_classification.model_version` - string.
/// - `request.ml_classification.feature_schema_version` - integer.
///
/// Idempotent: re-invoking with a different verdict overwrites the
/// previous fields.
pub fn populate_ml_namespace(ctx: &mut CelContext, view: &MlClassificationView<'_>) {
    let mut ml_map = HashMap::with_capacity(4);
    ml_map.insert(
        "class".to_string(),
        CelValue::String(view.class.unwrap_or("").to_string()),
    );
    ml_map.insert(
        "confidence".to_string(),
        CelValue::Float(view.confidence.unwrap_or(0.0) as f64),
    );
    ml_map.insert(
        "model_version".to_string(),
        CelValue::String(view.model_version.unwrap_or("").to_string()),
    );
    ml_map.insert(
        "feature_schema_version".to_string(),
        CelValue::Int(view.feature_schema_version.unwrap_or(0) as i64),
    );

    let request_var = ctx
        .variables
        .remove("request")
        .unwrap_or_else(|| CelValue::Map(HashMap::new()));
    let mut request_map = match request_var {
        CelValue::Map(m) => m,
        _ => HashMap::new(),
    };
    request_map.insert("ml_classification".to_string(), CelValue::Map(ml_map));
    ctx.set("request", CelValue::Map(request_map));
}

/// Borrowed view over the Wave 5 / G5.3 TLS fingerprint exposed to
/// CEL under `request.tls`. The caller (`sbproxy-core`) owns the
/// strings on `RequestContext.tls_fingerprint`.
///
/// Empty / `None` fields render as the zero value (`""` for strings,
/// `false` for `trustworthy`) so expressions can call
/// `size(request.tls.ja4) > 0` without first probing for presence.
#[derive(Debug, Default, Clone, Copy)]
pub struct TlsFingerprintView<'a> {
    /// JA3 fingerprint (32-char hex) or `None`.
    pub ja3: Option<&'a str>,
    /// JA4 fingerprint (FoxIO format) or `None`.
    pub ja4: Option<&'a str>,
    /// JA4H HTTP fingerprint or `None`.
    pub ja4h: Option<&'a str>,
    /// Whether the fingerprint reflects the actual client (per-origin
    /// CIDR resolution; default `false` per A5.1).
    pub trustworthy: bool,
}

/// Stamp the [`TlsFingerprintView`] under `request.tls.*`.
///
/// Exposed bindings (Wave 5 / G5.3, A5.1 §"Scripting surface"):
///
/// - `request.tls.ja3` - 32-char hex string or `""`.
/// - `request.tls.ja4` - JA4 structured prefix string or `""`.
/// - `request.tls.ja4h` - HTTP fingerprint string or `""`.
/// - `request.tls.trustworthy` - boolean.
///
/// Idempotent: re-invoking overwrites the previous values so
/// request- and response-time CEL evaluations can share one context.
pub fn populate_tls_namespace(ctx: &mut CelContext, view: &TlsFingerprintView<'_>) {
    let mut tls_map = HashMap::with_capacity(4);
    tls_map.insert(
        "ja3".to_string(),
        CelValue::String(view.ja3.unwrap_or("").to_string()),
    );
    tls_map.insert(
        "ja4".to_string(),
        CelValue::String(view.ja4.unwrap_or("").to_string()),
    );
    tls_map.insert(
        "ja4h".to_string(),
        CelValue::String(view.ja4h.unwrap_or("").to_string()),
    );
    tls_map.insert("trustworthy".to_string(), CelValue::Bool(view.trustworthy));

    let request_var = ctx
        .variables
        .remove("request")
        .unwrap_or_else(|| CelValue::Map(HashMap::new()));
    let mut request_map = match request_var {
        CelValue::Map(m) => m,
        _ => HashMap::new(),
    };
    request_map.insert("tls".to_string(), CelValue::Map(tls_map));
    ctx.set("request", CelValue::Map(request_map));
}

/// Wave 8 envelope dimensions exposed to CEL. Borrowed view so the
/// caller's RequestContext owns the strings and the CEL builder
/// avoids cloning. Empty / `None` fields render as the zero value
/// (`""`, `{}`) so expressions can call `size(envelope.user_id) > 0`
/// without first probing for presence.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvelopeView<'a> {
    /// Resolved user identifier per `adr-user-id.md`.
    pub user_id: Option<&'a str>,
    /// Source label for `user_id` (`header`, `jwt`, `forward_auth`).
    pub user_id_source: Option<&'a str>,
    /// Session identifier per `adr-session-id.md`.
    pub session_id: Option<&'a str>,
    /// Parent session identifier (caller-supplied chain).
    pub parent_session_id: Option<&'a str>,
    /// Tenant scope per `adr-event-envelope.md`.
    pub workspace_id: Option<&'a str>,
    /// Custom properties captured per `adr-custom-properties.md`.
    pub properties: Option<&'a std::collections::BTreeMap<String, String>>,
}

/// Stamp the Wave 8 envelope namespace onto a CEL context. Idempotent:
/// callers may invoke once for both request- and response-time CEL
/// evaluation, or call again to overwrite fields if the envelope
/// resolved later in the pipeline.
///
/// # Namespace
///
/// - `envelope.user_id` - resolved user identifier (string, may be `""`)
/// - `envelope.user_id_source` - origin of `user_id` (`header`, `jwt`, ...)
/// - `envelope.session_id` - session identifier (string, may be `""`)
/// - `envelope.parent_session_id` - parent session identifier
/// - `envelope.workspace_id` - tenant scope
/// - `envelope.properties` - map of caller-supplied properties
pub fn populate_envelope_namespace(ctx: &mut CelContext, envelope: &EnvelopeView<'_>) {
    let mut env = HashMap::new();
    env.insert(
        "user_id".to_string(),
        CelValue::String(envelope.user_id.unwrap_or("").to_string()),
    );
    env.insert(
        "user_id_source".to_string(),
        CelValue::String(envelope.user_id_source.unwrap_or("").to_string()),
    );
    env.insert(
        "session_id".to_string(),
        CelValue::String(envelope.session_id.unwrap_or("").to_string()),
    );
    env.insert(
        "parent_session_id".to_string(),
        CelValue::String(envelope.parent_session_id.unwrap_or("").to_string()),
    );
    env.insert(
        "workspace_id".to_string(),
        CelValue::String(envelope.workspace_id.unwrap_or("").to_string()),
    );
    let props_map: HashMap<String, CelValue> = envelope
        .properties
        .map(|p| {
            p.iter()
                .map(|(k, v)| (k.clone(), CelValue::String(v.clone())))
                .collect()
        })
        .unwrap_or_default();
    env.insert("properties".to_string(), CelValue::Map(props_map));
    ctx.set("envelope", CelValue::Map(env));
}

/// Decode the claims segment of `Authorization: Bearer <jwt>`. Returns
/// `None` when no header, no Bearer prefix, fewer than three segments,
/// invalid base64, or non-object JSON. **Does not verify the signature.**
fn extract_jwt_claims(headers: &HeaderMap) -> Option<HashMap<String, CelValue>> {
    let raw = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))?;
    let raw = raw.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    parts.next()?; // signature must exist as a third segment

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let object = value.as_object()?;

    let mut out = HashMap::with_capacity(object.len());
    for (k, v) in object {
        out.insert(k.clone(), json_to_cel(v));
    }
    Some(out)
}

fn json_to_cel(value: &serde_json::Value) -> CelValue {
    use serde_json::Value as J;
    match value {
        J::Null => CelValue::Null,
        J::Bool(b) => CelValue::Bool(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                CelValue::Float(f)
            } else {
                CelValue::String(n.to_string())
            }
        }
        J::String(s) => CelValue::String(s.clone()),
        J::Array(items) => CelValue::List(items.iter().map(json_to_cel).collect()),
        J::Object(map) => {
            let mut out = HashMap::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), json_to_cel(v));
            }
            CelValue::Map(out)
        }
    }
}

/// Build a CEL context from HTTP request and response data.
///
/// Includes everything from [`build_request_context`] plus response-specific
/// namespaces for assertion evaluation and response-time policy checks.
///
/// # Additional namespaces
///
/// - `response.status` - HTTP status code (integer)
/// - `response.headers` - Map of response header name to value (lowercase keys)
/// - `response.body_size` - Response body size in bytes (if known)
#[allow(clippy::too_many_arguments)]
pub fn build_response_context(
    method: &str,
    path: &str,
    request_headers: &HeaderMap,
    query: Option<&str>,
    client_ip: Option<&str>,
    hostname: &str,
    response_status: u16,
    response_headers: &HeaderMap,
    body_size: Option<usize>,
) -> CelContext {
    let mut ctx = build_request_context(method, path, request_headers, query, client_ip, hostname);

    // --- response namespace ---
    let mut response = HashMap::new();
    response.insert("status".to_string(), CelValue::Int(response_status as i64));

    let mut resp_hdrs = HashMap::new();
    for (key, value) in response_headers.iter() {
        if let Ok(v) = value.to_str() {
            resp_hdrs.insert(key.as_str().to_string(), CelValue::String(v.to_string()));
        }
    }
    response.insert("headers".to_string(), CelValue::Map(resp_hdrs));

    if let Some(size) = body_size {
        response.insert("body_size".to_string(), CelValue::Int(size as i64));
    }

    ctx.set("response", CelValue::Map(response));

    ctx
}

/// Extend an existing CelContext with additional custom variables.
///
/// Useful for adding origin-specific or workspace-specific context on top
/// of the base request context.
pub fn extend_context(ctx: &mut CelContext, name: &str, values: HashMap<String, CelValue>) {
    ctx.set(name, CelValue::Map(values));
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cel::CelEngine;

    fn sample_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-api-key", "secret-key-123".parse().unwrap());
        headers.insert("authorization", "Bearer tok_abc".parse().unwrap());
        headers
    }

    #[test]
    fn test_build_request_context_method() {
        let headers = sample_headers();
        let ctx = build_request_context(
            "POST",
            "/api/v1/users",
            &headers,
            None,
            None,
            "api.example.com",
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.method == "POST""#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_build_request_context_path() {
        let headers = HeaderMap::new();
        let ctx = build_request_context("GET", "/health", &headers, None, None, "localhost");
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.path == "/health""#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_build_request_context_host() {
        let headers = HeaderMap::new();
        let ctx = build_request_context("GET", "/", &headers, None, None, "example.com");
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.host == "example.com""#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_build_request_context_headers() {
        let headers = sample_headers();
        let ctx = build_request_context("GET", "/", &headers, None, None, "example.com");
        let engine = CelEngine::new();

        // Header access by name
        assert!(engine
            .eval_bool_source(
                r#"request.headers["content-type"] == "application/json""#,
                &ctx,
            )
            .unwrap());

        // Dot notation for simple header names (no hyphens in key)
        assert!(engine
            .eval_bool_source(r#"request.headers["x-api-key"] == "secret-key-123""#, &ctx,)
            .unwrap());
    }

    #[test]
    fn test_build_request_context_query() {
        let headers = HeaderMap::new();
        let ctx = build_request_context(
            "GET",
            "/search",
            &headers,
            Some("q=rust&limit=10"),
            None,
            "example.com",
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.query.contains("rust")"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_build_request_context_client_ip() {
        let headers = HeaderMap::new();
        let ctx = build_request_context(
            "GET",
            "/",
            &headers,
            None,
            Some("192.168.1.100"),
            "example.com",
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"connection.remote_ip == "192.168.1.100""#, &ctx,)
            .unwrap());
    }

    #[test]
    fn test_complex_request_expression() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer admin-token".parse().unwrap());
        let ctx = build_request_context(
            "DELETE",
            "/api/v1/users/42",
            &headers,
            None,
            Some("10.0.0.1"),
            "api.example.com",
        );
        let engine = CelEngine::new();

        // Compound condition: must be DELETE to admin API with auth header
        let result = engine
            .eval_bool_source(
                r#"request.method == "DELETE" && request.path.startsWith("/api/") && request.headers["authorization"].startsWith("Bearer ")"#,
                &ctx,
            )
            .unwrap();
        assert!(result);
    }

    // --- jwt namespace tests ---

    /// Encode a JSON object as the payload segment of a stub JWT. Returns
    /// `header.payload.signature` with stub header and signature segments.
    fn stub_jwt(payload: &serde_json::Value) -> String {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload_bytes = serde_json::to_vec(payload).unwrap();
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
        format!("{}.{}.x", header, body)
    }

    #[test]
    fn jwt_claims_populated_from_authorization_bearer() {
        let token = stub_jwt(
            &serde_json::json!({"sub": "alice", "tenant_id": "acme", "scope": ["read", "write"]}),
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let ctx = build_request_context("GET", "/", &headers, None, None, "api.example.com");

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"jwt.claims.sub == "alice""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"jwt.claims.tenant_id == "acme""#, &ctx)
            .unwrap());
    }

    #[test]
    fn jwt_claims_empty_when_no_authorization_header() {
        let headers = HeaderMap::new();
        let ctx = build_request_context("GET", "/", &headers, None, None, "api.example.com");
        let engine = CelEngine::new();
        // Indexing into an empty map for a missing key yields the absence
        // case CEL surfaces; the simpler smoke test is that the namespace
        // exists and is empty.
        assert!(engine
            .eval_bool_source(r#"size(jwt.claims) == 0"#, &ctx)
            .unwrap());
    }

    #[test]
    fn jwt_claims_empty_when_token_is_malformed() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer not.a.jwt!@#".parse().unwrap());
        let ctx = build_request_context("GET", "/", &headers, None, None, "api.example.com");
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"size(jwt.claims) == 0"#, &ctx)
            .unwrap());
    }

    #[test]
    fn jwt_claims_empty_for_non_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let ctx = build_request_context("GET", "/", &headers, None, None, "api.example.com");
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"size(jwt.claims) == 0"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_extend_context() {
        let headers = HeaderMap::new();
        let mut ctx = build_request_context("GET", "/", &headers, None, None, "example.com");

        let mut origin = HashMap::new();
        origin.insert(
            "name".to_string(),
            CelValue::String("backend-a".to_string()),
        );
        origin.insert("weight".to_string(), CelValue::Int(80));
        extend_context(&mut ctx, "origin", origin);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"origin.name == "backend-a" && origin.weight > 50"#, &ctx)
            .unwrap());
    }

    // --- build_response_context tests ---

    #[test]
    fn test_response_context_status() {
        let req_headers = sample_headers();
        let resp_headers = HeaderMap::new();
        let ctx = build_response_context(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"response.status == 200"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_response_context_status_error() {
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let ctx = build_response_context(
            "POST",
            "/api/submit",
            &req_headers,
            None,
            None,
            "example.com",
            500,
            &resp_headers,
            None,
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"response.status >= 500"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_response_context_headers() {
        let req_headers = HeaderMap::new();
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("content-type", "application/json".parse().unwrap());
        resp_headers.insert("x-request-id", "abc-123".parse().unwrap());
        let ctx = build_response_context(
            "GET",
            "/",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(
                r#"response.headers["content-type"] == "application/json""#,
                &ctx,
            )
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"response.headers["x-request-id"] == "abc-123""#, &ctx,)
            .unwrap());
    }

    #[test]
    fn test_response_context_body_size() {
        let req_headers = HeaderMap::new();
        let resp_headers = HeaderMap::new();
        let ctx = build_response_context(
            "GET",
            "/",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            Some(4096),
        );
        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"response.body_size == 4096"#, &ctx)
            .unwrap());
    }

    #[test]
    fn request_time_namespace_is_populated() {
        let headers = HeaderMap::new();
        let ctx = build_request_context("GET", "/", &headers, None, None, "example.com");
        let engine = CelEngine::new();

        // request.time is a positive epoch-second integer.
        assert!(engine
            .eval_bool_source(r#"request.time > 0"#, &ctx)
            .unwrap());
        // request.unix_nanos is a positive epoch-nanosecond integer.
        assert!(engine
            .eval_bool_source(r#"request.unix_nanos > 0"#, &ctx)
            .unwrap());
        // unix_nanos is at least 1e9 times larger than time.
        assert!(engine
            .eval_bool_source(r#"request.unix_nanos >= request.time * 1000000000"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_response_context_includes_request_data() {
        let mut req_headers = HeaderMap::new();
        req_headers.insert("authorization", "Bearer tok".parse().unwrap());
        let resp_headers = HeaderMap::new();
        let ctx = build_response_context(
            "POST",
            "/api/v1/users",
            &req_headers,
            Some("page=1"),
            Some("10.0.0.1"),
            "api.example.com",
            201,
            &resp_headers,
            None,
        );
        let engine = CelEngine::new();
        // Request data is still accessible
        assert!(engine
            .eval_bool_source(r#"request.method == "POST""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.host == "api.example.com""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"connection.remote_ip == "10.0.0.1""#, &ctx)
            .unwrap());
        // Combined request + response expression
        assert!(engine
            .eval_bool_source(
                r#"request.method == "POST" && response.status == 201"#,
                &ctx,
            )
            .unwrap());
    }

    #[test]
    fn envelope_namespace_round_trips_strings_and_properties() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let mut props = std::collections::BTreeMap::new();
        props.insert("environment".to_string(), "prod".to_string());
        let env = EnvelopeView {
            user_id: Some("user_42"),
            user_id_source: Some("header"),
            session_id: Some("01H..."),
            parent_session_id: None,
            workspace_id: Some("ws_a"),
            properties: Some(&props),
        };
        populate_envelope_namespace(&mut ctx, &env);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"envelope.user_id == "user_42""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"envelope.user_id_source == "header""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"envelope.workspace_id == "ws_a""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"envelope.properties.environment == "prod""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"size(envelope.parent_session_id) == 0"#, &ctx)
            .unwrap());
    }

    #[test]
    fn envelope_namespace_defaults_to_empty_strings() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        populate_envelope_namespace(&mut ctx, &EnvelopeView::default());

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(
                r#"envelope.user_id == "" && envelope.workspace_id == """#,
                &ctx
            )
            .unwrap());
    }

    // --- AgentClassView (G1.4) tests ---

    #[test]
    fn agent_class_namespace_round_trips_under_request_and_agent_keys() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = AgentClassView {
            agent_id: Some("openai-gptbot"),
            agent_vendor: Some("OpenAI"),
            agent_purpose: Some("training"),
            agent_id_source: Some("user_agent"),
            agent_rdns_hostname: Some("crawl-1.gptbot.openai.com"),
        };
        populate_agent_class_namespace(&mut ctx, &view);

        let engine = CelEngine::new();
        // Brief "expose to CEL: bind request.agent_class, request.agent_id".
        assert!(engine
            .eval_bool_source(r#"request.agent_id == "openai-gptbot""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.agent_class == "openai-gptbot""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.agent_vendor == "OpenAI""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.agent_purpose == "training""#, &ctx)
            .unwrap());
        // Cleaner top-level alias for new expressions.
        assert!(engine
            .eval_bool_source(r#"agent.id == "openai-gptbot""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"agent.source == "user_agent""#, &ctx)
            .unwrap());
        // Existing request fields still readable.
        assert!(engine
            .eval_bool_source(r#"request.method == "GET""#, &ctx)
            .unwrap());
    }

    #[test]
    fn agent_class_namespace_defaults_to_empty_strings_for_human() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        populate_agent_class_namespace(&mut ctx, &AgentClassView::default());

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(
                r#"request.agent_id == "" && agent.id == "" && agent.vendor == """#,
                &ctx
            )
            .unwrap());
    }

    // --- AiprefView (G4.9) tests ---

    #[test]
    fn aipref_namespace_round_trips_a_concrete_signal() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = AiprefView {
            train: false,
            search: true,
            ai_input: false,
        };
        populate_aipref_namespace(&mut ctx, Some(&view));

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.aipref.train == false"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.aipref.search == true"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.aipref.ai_input == false"#, &ctx)
            .unwrap());
    }

    #[test]
    fn aipref_namespace_defaults_permissive_when_signal_absent() {
        // No `aipref:` header -> default-permissive (every axis true)
        // per A4.1's "absence of a signal is not a signal" rule.
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        populate_aipref_namespace(&mut ctx, None);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.aipref.train == true"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.aipref.search == true"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.aipref.ai_input == true"#, &ctx)
            .unwrap());
    }

    // --- TlsFingerprintView (G5.3) tests ---

    #[test]
    fn tls_namespace_exposes_ja3_ja4_ja4h_and_trustworthy() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = TlsFingerprintView {
            ja3: Some("773a820ef18383c8533e03ddcebf348b"),
            ja4: Some("t13d1516h2_8daaf6152771"),
            ja4h: Some("abc123def456"),
            trustworthy: true,
        };
        populate_tls_namespace(&mut ctx, &view);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(
                r#"request.tls.ja3 == "773a820ef18383c8533e03ddcebf348b""#,
                &ctx
            )
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.tls.ja4 == "t13d1516h2_8daaf6152771""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.tls.ja4h == "abc123def456""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.tls.trustworthy == true"#, &ctx)
            .unwrap());
    }

    #[test]
    fn tls_namespace_defaults_render_as_empty_strings_and_false() {
        // Empty view (no fingerprint captured) - expressions still
        // evaluate without nil errors.
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        populate_tls_namespace(&mut ctx, &TlsFingerprintView::default());

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"size(request.tls.ja4) == 0"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.tls.trustworthy == false"#, &ctx)
            .unwrap());
    }

    // --- KyaVerdictView (G5.1) tests ---

    #[test]
    fn kya_namespace_round_trips_a_verified_token() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = KyaVerdictView {
            verdict: Some("verified"),
            agent_id: Some("openai-gptbot"),
            vendor: Some("skyfire"),
            kya_version: Some("v1"),
            kyab_balance: Some(1000),
        };
        populate_kya_namespace(&mut ctx, &view);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.kya.verdict == "verified""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.kya.agent_id == "openai-gptbot""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.kya.vendor == "skyfire""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.kya.kya_version == "v1""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.kya.kyab_balance.amount == 1000"#, &ctx)
            .unwrap());
    }

    #[test]
    fn kya_namespace_renders_missing_verdict_when_no_token_presented() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = KyaVerdictView {
            verdict: Some("missing"),
            ..Default::default()
        };
        populate_kya_namespace(&mut ctx, &view);

        let engine = CelEngine::new();
        // Pin the test ignore-reason claim:
        //   "request.kya.verdict != \"missing\""
        // resolves to false when the verifier ran and reported missing.
        assert!(engine
            .eval_bool_source(r#"request.kya.verdict == "missing""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.kya.agent_id == """#, &ctx)
            .unwrap());
    }

    #[test]
    fn kya_namespace_defaults_render_as_empty_strings_when_hook_did_not_run() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        populate_kya_namespace(&mut ctx, &KyaVerdictView::default());

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"size(request.kya.verdict) == 0"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.kya.kyab_balance.amount == 0"#, &ctx)
            .unwrap());
    }

    // --- MlClassificationView (A5.2) tests ---

    #[test]
    fn ml_namespace_round_trips_a_human_verdict() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = MlClassificationView {
            class: Some("human"),
            confidence: Some(0.97),
            model_version: Some("ml-agent-v1"),
            feature_schema_version: Some(1),
        };
        populate_ml_namespace(&mut ctx, &view);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.ml_classification.class == "human""#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.ml_classification.confidence > 0.9"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(
                r#"request.ml_classification.model_version == "ml-agent-v1""#,
                &ctx
            )
            .unwrap());
        assert!(engine
            .eval_bool_source(
                r#"request.ml_classification.feature_schema_version == 1"#,
                &ctx
            )
            .unwrap());
    }

    #[test]
    fn ml_namespace_round_trips_an_llm_agent_verdict() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        let view = MlClassificationView {
            class: Some("llm-agent"),
            confidence: Some(0.78),
            model_version: Some("ml-agent-v1"),
            feature_schema_version: Some(1),
        };
        populate_ml_namespace(&mut ctx, &view);

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"request.ml_classification.class == "llm-agent""#, &ctx)
            .unwrap());
    }

    #[test]
    fn ml_namespace_defaults_render_as_empty_strings_when_classifier_disabled() {
        let mut ctx = build_request_context("GET", "/", &HeaderMap::new(), None, None, "h.com");
        populate_ml_namespace(&mut ctx, &MlClassificationView::default());

        let engine = CelEngine::new();
        assert!(engine
            .eval_bool_source(r#"size(request.ml_classification.class) == 0"#, &ctx)
            .unwrap());
        assert!(engine
            .eval_bool_source(r#"request.ml_classification.confidence == 0.0"#, &ctx)
            .unwrap());
    }
}
