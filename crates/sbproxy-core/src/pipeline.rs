//! Compiled pipeline: config + instantiated module enums + enterprise hooks.
//!
//! [`CompiledPipeline`] bridges the gap between `sbproxy-config` (which stores
//! JSON `serde_json::Value` blobs) and `sbproxy-modules` (which defines typed
//! `Action` / `Auth` / `Policy` enums). It holds a `CompiledConfig` alongside
//! parallel vecs of compiled module instances indexed by origin position:
//! index `N` in `actions` corresponds to index `N` in `config.origins`.
//!
//! In addition to the compiled modules, a `CompiledPipeline` owns:
//! * an optional shared `CacheStore` (from `sbproxy-cache`) for the
//!   response cache: Redis when `config.l2_store` is set, in-memory LRU
//!   otherwise,
//! * an enterprise [`Hooks`](crate::hooks::Hooks) bundle of optional traits
//!   that OSS leaves as `None` and enterprise populates via the
//!   [`EnterpriseStartupHook`](crate::hooks::EnterpriseStartupHook) pattern.
//!
//! This struct lives in `sbproxy-core` to avoid a circular dependency:
//! config -> modules -> config would be circular, but core depends on both.

use std::collections::HashMap;
use std::sync::Arc;

use sbproxy_cache::{
    CacheReserveBackend, CacheStore, FsReserve, MemoryCacheStore, MemoryReserve, RedisCacheStore,
    RedisReserve,
};
use sbproxy_config::{CompiledConfig, Parameter, RequestModifierConfig};
use sbproxy_modules::compile::{compile_action, compile_auth, compile_policy, compile_transform};
use sbproxy_modules::transform::{CompiledTransform, TransformConfig};
use sbproxy_modules::{Action, Auth, BotDetection, Policy, ThreatProtection};

use crate::router::HostRouter;

// --- Forward Rule types ---

/// One parsed segment of a `Template` path matcher.
///
/// Literal segments must match exactly. `Param` segments capture a single
/// path segment under the given name, optionally validated against a regex
/// constraint. `CatchAll` captures the remainder of the path (all segments
/// after this point) and may only appear as the final segment.
#[derive(Debug)]
pub enum TemplateSegment {
    /// A literal path segment that must match exactly.
    Literal(String),
    /// A named `{name}` segment with an optional regex constraint
    /// (e.g. `{id:[0-9]+}`).
    Param {
        /// The captured parameter name.
        name: String,
        /// Optional per-segment regex constraint anchored at both ends.
        constraint: Option<regex::Regex>,
    },
    /// A `{*name}` catch-all segment that captures the rest of the path.
    /// Only valid as the final segment.
    CatchAll(String),
}

/// A compiled OpenAPI-style path template (e.g. `/users/{id}/posts/{*rest}`).
///
/// Matching walks the segments in O(n) where n is the number of path
/// segments; per-segment regex constraints are only evaluated when the
/// segment is explicitly constrained, so unconstrained templates pay no
/// regex cost on the hot path.
#[derive(Debug)]
pub struct PathTemplate {
    /// Original template string (preserved for OpenAPI emission, debug
    /// logging, and error messages).
    pub raw: String,
    /// Parsed segment list. `CatchAll` may only appear as the final entry.
    pub segments: Vec<TemplateSegment>,
}

impl PathTemplate {
    /// Compile a template string into a [`PathTemplate`].
    ///
    /// Errors when:
    /// - a segment uses unbalanced braces
    /// - a constraint regex fails to compile
    /// - a `{*name}` catch-all is not the final segment
    pub fn compile(template: &str) -> anyhow::Result<Self> {
        let raw = template.to_string();
        let trimmed = template.strip_prefix('/').unwrap_or(template);
        let parts: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };
        let mut segments = Vec::with_capacity(parts.len());
        let last_idx = parts.len().saturating_sub(1);
        for (i, part) in parts.iter().enumerate() {
            let seg = parse_template_segment(part, i == last_idx)?;
            if matches!(seg, TemplateSegment::CatchAll(_)) && i != last_idx {
                anyhow::bail!("catch-all segment must be last in template '{}'", template);
            }
            segments.push(seg);
        }
        Ok(PathTemplate { raw, segments })
    }

    /// Match the given path against this template, returning captured params
    /// on a successful match.
    pub fn match_path(&self, path: &str) -> Option<HashMap<String, String>> {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        // An empty path == "/" -> zero parts. Splitting an empty string yields
        // [""] which would break length compares, so guard explicitly.
        let parts: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };

        // Catch-all loosens the length constraint to ">= segments-1" since
        // the final segment soaks up everything else. Without one we need
        // an exact length match.
        let has_catch_all = matches!(self.segments.last(), Some(TemplateSegment::CatchAll(_)));
        if has_catch_all {
            if parts.len() < self.segments.len() - 1 {
                return None;
            }
        } else if parts.len() != self.segments.len() {
            return None;
        }

        let mut captured: HashMap<String, String> = HashMap::new();
        for (idx, seg) in self.segments.iter().enumerate() {
            match seg {
                TemplateSegment::Literal(lit) => {
                    if parts.get(idx).copied() != Some(lit.as_str()) {
                        return None;
                    }
                }
                TemplateSegment::Param { name, constraint } => {
                    let value = parts.get(idx).copied()?;
                    if let Some(re) = constraint {
                        if !re.is_match(value) {
                            return None;
                        }
                    }
                    captured.insert(name.clone(), value.to_string());
                }
                TemplateSegment::CatchAll(name) => {
                    // Splice the remainder back together with '/' so the
                    // captured value reads naturally (e.g. "css/site.css"
                    // not ["css", "site.css"]).
                    let rest = parts[idx..].join("/");
                    captured.insert(name.clone(), rest);
                    break;
                }
            }
        }
        Some(captured)
    }
}

fn parse_template_segment(part: &str, _is_last: bool) -> anyhow::Result<TemplateSegment> {
    // Literals: no leading '{' means we treat the whole segment as a literal.
    // Mid-segment '{' is rejected as malformed since we do not support
    // mixed-content segments (e.g. "users-{id}") - this keeps emission
    // unambiguous and lines up with OpenAPI 3.0 path-template semantics.
    if !part.starts_with('{') {
        if part.contains('{') || part.contains('}') {
            anyhow::bail!("mixed literal/param segments are not supported: '{}'", part);
        }
        return Ok(TemplateSegment::Literal(part.to_string()));
    }
    let inner = part
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| {
            anyhow::anyhow!("malformed template segment '{}': unbalanced braces", part)
        })?;

    // Catch-all: leading '*' marks the rest of the path.
    if let Some(name) = inner.strip_prefix('*') {
        if name.is_empty() {
            anyhow::bail!("catch-all segment '{}' missing name", part);
        }
        return Ok(TemplateSegment::CatchAll(name.to_string()));
    }

    // Named param with optional constraint: split on the first ':'.
    let (name, constraint) = match inner.split_once(':') {
        Some((n, pat)) => {
            // Anchor the regex at both ends so a constraint like `[0-9]+`
            // doesn't match a path segment that merely *contains* digits.
            let anchored = format!("^(?:{})$", pat);
            let re = regex::Regex::new(&anchored).map_err(|e| {
                anyhow::anyhow!("invalid constraint regex in segment '{}': {}", part, e)
            })?;
            (n, Some(re))
        }
        None => (inner, None),
    };
    if name.is_empty() {
        anyhow::bail!("named segment '{}' missing param name", part);
    }
    Ok(TemplateSegment::Param {
        name: name.to_string(),
        constraint,
    })
}

/// A single path-matching rule within a forward rule.
///
/// Variants are ordered cheapest-first on the hot path. `Prefix` and
/// `Exact` are byte comparisons. `Template` walks segments and only
/// evaluates regex when a segment is explicitly constrained. `Regex`
/// pays the full regex cost per match and is the escape hatch for
/// patterns the template syntax cannot express.
pub enum PathMatch {
    /// Matches if the request path starts with this prefix.
    Prefix(String),
    /// Matches if the request path equals this exactly.
    Exact(String),
    /// OpenAPI-style template (named segments, catch-all, optional
    /// per-segment regex constraints).
    Template(PathTemplate),
    /// Whole-path regex. Named captures are exposed as path params.
    Regex(regex::Regex),
}

impl PathMatch {
    /// Check whether the given request path matches this rule.
    ///
    /// Retained for callers that only need the boolean. Prefer
    /// [`Self::match_with_params`] to also surface captured path params
    /// on the request context.
    pub fn matches(&self, path: &str) -> bool {
        self.match_with_params(path).is_some()
    }

    /// Match the path and return any captured params.
    ///
    /// Returns `Some(map)` on a successful match, where `map` is empty
    /// for `Prefix`/`Exact` rules (which capture nothing). Returns
    /// `None` when the path does not match.
    pub fn match_with_params(&self, path: &str) -> Option<HashMap<String, String>> {
        match self {
            PathMatch::Prefix(p) => {
                if path.starts_with(p.as_str()) {
                    Some(HashMap::new())
                } else {
                    None
                }
            }
            PathMatch::Exact(e) => {
                if path == e.as_str() {
                    Some(HashMap::new())
                } else {
                    None
                }
            }
            PathMatch::Template(t) => t.match_path(path),
            PathMatch::Regex(re) => {
                let caps = re.captures(path)?;
                let mut map = HashMap::new();
                for name in re.capture_names().flatten() {
                    if let Some(m) = caps.name(name) {
                        map.insert(name.to_string(), m.as_str().to_string());
                    }
                }
                Some(map)
            }
        }
    }
}

/// Match a request header by exact value or value prefix.
///
/// Header name lookup is case-insensitive (per RFC 7230). Value comparison
/// is case-sensitive. Choose `Equals` for exact match, `Prefix` for value
/// prefix.
pub enum HeaderMatch {
    /// Header must exist and its value must equal `value` exactly.
    Equals {
        /// Header name (case-insensitive lookup).
        name: String,
        /// Expected value.
        value: String,
    },
    /// Header must exist and its value must start with `prefix`.
    Prefix {
        /// Header name (case-insensitive lookup).
        name: String,
        /// Required value prefix.
        prefix: String,
    },
}

impl HeaderMatch {
    /// Test the matcher against a Pingora-style header map.
    pub fn matches(&self, headers: &http::HeaderMap) -> bool {
        match self {
            HeaderMatch::Equals { name, value } => headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|got| got == value)
                .unwrap_or(false),
            HeaderMatch::Prefix { name, prefix } => headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|got| got.starts_with(prefix.as_str()))
                .unwrap_or(false),
        }
    }
}

/// Match a query string parameter by exact value or by mere presence.
pub enum QueryMatch {
    /// Parameter must be present and equal `value`.
    Equals {
        /// Query parameter name (case-sensitive).
        name: String,
        /// Expected value.
        value: String,
    },
    /// Parameter must merely be present.
    Present {
        /// Query parameter name (case-sensitive).
        name: String,
    },
}

impl QueryMatch {
    /// Test the matcher against a raw URI query string (e.g. `a=1&b=2`).
    pub fn matches(&self, query: Option<&str>) -> bool {
        let Some(q) = query else {
            return false;
        };
        for pair in q.split('&') {
            let mut it = pair.splitn(2, '=');
            let key = it.next().unwrap_or("");
            let val = it.next().unwrap_or("");
            match self {
                QueryMatch::Equals { name, value } => {
                    if key == name && val == value {
                        return true;
                    }
                }
                QueryMatch::Present { name } => {
                    if key == name {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// One AND-grouped match entry inside a forward rule's `rules:` list.
///
/// Every present matcher (`path`, `header`, `query`) must succeed for the
/// entry to fire. The enclosing list of entries is ORed: any matching entry
/// triggers the rule.
pub struct MatcherEntry {
    /// Path matcher (any of prefix / exact / template / regex).
    pub path: Option<PathMatch>,
    /// Header matcher.
    pub header: Option<HeaderMatch>,
    /// Query parameter matcher.
    pub query: Option<QueryMatch>,
}

impl MatcherEntry {
    /// Evaluate this entry against the incoming request.
    ///
    /// Returns the captured path params (possibly empty) when every present
    /// matcher passes. Returns `None` when any present matcher fails or when
    /// the entry has no matchers at all.
    pub fn match_request(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Option<HashMap<String, String>> {
        let any_present = self.path.is_some() || self.header.is_some() || self.query.is_some();
        if !any_present {
            return None;
        }
        let captured = if let Some(p) = &self.path {
            p.match_with_params(path)?
        } else {
            HashMap::new()
        };
        if let Some(h) = &self.header {
            if !h.matches(headers) {
                return None;
            }
        }
        if let Some(q) = &self.query {
            if !q.matches(query) {
                return None;
            }
        }
        Some(captured)
    }
}

/// A compiled forward rule: match conditions + inline origin action + request modifiers.
pub struct CompiledForwardRule {
    /// AND-grouped matcher entries evaluated in order. Entries are ORed: the
    /// first entry whose every present matcher passes wins.
    pub matchers: Vec<MatcherEntry>,
    /// Action executed when the rule matches.
    pub action: Action,
    /// Request modifiers applied before the action runs.
    pub request_modifiers: Vec<RequestModifierConfig>,
    /// OpenAPI 3.0 Parameter Object declarations carried verbatim from
    /// config. Consumed by OpenAPI emission to populate `parameters[]`
    /// on emitted operations; available for future runtime validation
    /// of captured params.
    pub parameters: Vec<Parameter>,
}

/// A compiled fallback origin: triggers and the fallback action.
pub struct CompiledFallback {
    /// Trigger on upstream connection error / timeout.
    pub on_error: bool,
    /// Trigger on these upstream HTTP status codes.
    pub on_status: Vec<u16>,
    /// Add an X-Fallback-Trigger debug header to the response.
    pub add_debug_header: bool,
    /// The fallback action to serve.
    pub action: Action,
}

/// Admission settings for the Cache Reserve cold tier.
///
/// Pre-extracted from `proxy.cache_reserve` so the request path can
/// gate every reserve write on three cheap checks (sample roll, TTL
/// floor, size ceiling) without re-walking the YAML schema struct.
#[derive(Debug, Clone, Copy)]
pub struct ReserveAdmission {
    /// Fraction of writes mirrored to the reserve.
    pub sample_rate: f64,
    /// Minimum TTL (seconds) an entry must carry to be admitted.
    pub min_ttl: u64,
    /// Upper bound on the body size of an admitted entry. `0`
    /// disables the cap.
    pub max_size_bytes: u64,
}

impl ReserveAdmission {
    /// Returns true when the entry passes the size and TTL gates.
    /// Sample-rate is rolled separately by the caller so the random
    /// draw can be skipped when the other gates already reject.
    pub fn admits(&self, ttl_secs: u64, body_len: usize) -> bool {
        if ttl_secs < self.min_ttl {
            return false;
        }
        if self.max_size_bytes > 0 && (body_len as u64) > self.max_size_bytes {
            return false;
        }
        true
    }
}

/// Build the OSS Cache Reserve backend from the YAML config block.
///
/// Returns `(None, None)` when the block is absent, disabled, or
/// targets an enterprise backend the OSS pipeline does not know how
/// to instantiate. Failures during construction (e.g. an invalid
/// Redis URL) are logged at `warn` level and surfaced as `(None, None)`
/// so a misconfigured reserve degrades to plain hot-cache behavior
/// rather than failing the whole config load.
fn build_cache_reserve(
    cfg: &Option<sbproxy_config::CacheReserveConfig>,
) -> (
    Option<Arc<dyn CacheReserveBackend>>,
    Option<ReserveAdmission>,
) {
    let Some(cfg) = cfg.as_ref() else {
        return (None, None);
    };
    if !cfg.enabled {
        return (None, None);
    }
    let Some(backend) = cfg.backend.as_ref() else {
        tracing::warn!("cache_reserve.enabled = true but no backend configured; ignoring");
        return (None, None);
    };
    let admission = ReserveAdmission {
        sample_rate: cfg.sample_rate.clamp(0.0, 1.0),
        min_ttl: cfg.min_ttl,
        max_size_bytes: cfg.max_size_bytes,
    };
    let built: Option<Arc<dyn CacheReserveBackend>> = match backend {
        sbproxy_config::CacheReserveBackendConfig::Memory => Some(Arc::new(MemoryReserve::new())),
        sbproxy_config::CacheReserveBackendConfig::Filesystem { path } => {
            Some(Arc::new(FsReserve::new(path)))
        }
        sbproxy_config::CacheReserveBackendConfig::Redis {
            redis_url,
            key_prefix,
        } => match RedisReserve::new(
            redis_url,
            key_prefix
                .clone()
                .unwrap_or_else(|| "sbproxy:reserve:".to_string()),
        ) {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!(error = %e, "cache_reserve redis backend init failed; reserve disabled");
                None
            }
        },
        sbproxy_config::CacheReserveBackendConfig::Other => {
            tracing::warn!(
                "cache_reserve backend type is unknown to OSS; if this is an enterprise backend, the enterprise startup hook should attach it"
            );
            None
        }
    };
    if built.is_some() {
        (built, Some(admission))
    } else {
        (None, None)
    }
}

/// TLS-fingerprint capture mode (Wave 5 day-6 Item 3).
///
/// `passive` and `sidecar` are wire-equivalent today; the OSS path
/// captures fingerprints exclusively from the sidecar header pattern
/// because Pingora 0.8 does not surface the raw ClientHello bytes. The
/// distinct names are reserved so a future native-capture implementation
/// can flip to `passive` without an operator-visible config change.
/// `disabled` short-circuits the capture path even when sidecar headers
/// arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprintMode {
    /// Capture fingerprints natively from the TLS handshake (reserved
    /// for a future implementation; behaves like `sidecar` today).
    Passive,
    /// Capture fingerprints from sidecar-injected request headers.
    /// Requires `proxy.trusted_proxies` to cover the sidecar's source
    /// range so the sidecar headers cannot be forged by a downstream
    /// client.
    #[default]
    Sidecar,
    /// No capture. Sidecar TLS-fingerprint headers are stripped on
    /// ingress regardless of `proxy.trusted_proxies`.
    Disabled,
}

/// TLS-fingerprint capture configuration (Wave 5 day-6 Item 3).
///
/// Lifted onto [`CompiledPipeline`] from the
/// `proxy.extensions.tls_fingerprint` block (canonical) or the legacy
/// `features.tls_fingerprint` shape (rewritten by the day-6 Item 2
/// migration). Default: `disabled`, no headers honoured, no capture.
///
/// ## Schema
///
/// ```yaml
/// proxy:
///   extensions:
///     tls_fingerprint:
///       enabled: true
///       mode: sidecar
///       sidecar_header_allowlist:
///         - x-forwarded-ja3
///         - x-forwarded-ja4
///         - x-forwarded-ja4h
///         - x-forwarded-ja4s
/// ```
///
/// `enabled: false` is equivalent to omitting the block. `mode` is
/// `sidecar` by default. `sidecar_header_allowlist` is the operator-
/// supplied set of trust-bounded sidecar headers; the canonical
/// `x-sbproxy-tls-*` family is always honoured (see the request
/// entry hook). The allowlist is the operator's escape hatch for
/// CDN-specific header names (`x-forwarded-ja4` is Cloudflare and
/// Fastly's spelling).
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct TlsFingerprintConfig {
    /// Master switch. `false` (the default) disables the capture path
    /// entirely.
    #[serde(default)]
    pub enabled: bool,
    /// Capture mode. See [`TlsFingerprintMode`] for semantics.
    #[serde(default)]
    pub mode: TlsFingerprintMode,
    /// Additional sidecar header names the request entry hook will
    /// read JA3 / JA4 / JA4H / JA4S values from. Honoured only when
    /// the immediate TCP peer is in `proxy.trusted_proxies`.
    #[serde(default)]
    pub sidecar_header_allowlist: Vec<String>,
    /// Per-origin trustworthy CIDR ranges (clients seen as the direct
    /// TCP peer get `request.tls.trustworthy = true`). When unset the
    /// request entry hook defaults `trustworthy` based on whether the
    /// sidecar marked the value true.
    #[serde(default)]
    pub trustworthy_client_cidrs: Vec<String>,
    /// CIDR ranges flagged as untrusted (e.g. CDN egress pools). When
    /// the resolved client IP falls in this set the captured
    /// fingerprint is marked `trustworthy = false` even when the
    /// sidecar reported it as trustworthy.
    #[serde(default)]
    pub untrusted_client_cidrs: Vec<String>,
}

impl TlsFingerprintConfig {
    /// Build a [`TlsFingerprintConfig`] from the parsed
    /// `proxy.extensions.tls_fingerprint` YAML block. Returns
    /// `Default::default()` (disabled) when the block is absent or
    /// malformed; a parse failure logs a warning rather than failing
    /// the whole compile.
    pub fn from_extensions(
        extensions: &std::collections::HashMap<String, serde_yaml::Value>,
    ) -> Self {
        let Some(block) = extensions.get("tls_fingerprint") else {
            return Self::default();
        };
        match serde_yaml::from_value::<TlsFingerprintConfig>(block.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "proxy.extensions.tls_fingerprint failed to parse; capture disabled",
                );
                Self::default()
            }
        }
    }

    /// Pre-parsed view of [`Self::trustworthy_client_cidrs`]. Invalid
    /// entries are dropped with a warn log. Empty when the field is
    /// unset, equivalent to "no trust list".
    pub fn trustworthy_cidrs(&self) -> Vec<ipnetwork::IpNetwork> {
        self.trustworthy_client_cidrs
            .iter()
            .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                Ok(n) => Some(n),
                Err(e) => {
                    tracing::warn!(
                        cidr = %s,
                        error = %e,
                        "ignoring invalid trustworthy_client_cidrs entry",
                    );
                    None
                }
            })
            .collect()
    }

    /// Pre-parsed view of [`Self::untrusted_client_cidrs`]. Invalid
    /// entries are dropped with a warn log.
    pub fn untrusted_cidrs(&self) -> Vec<ipnetwork::IpNetwork> {
        self.untrusted_client_cidrs
            .iter()
            .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                Ok(n) => Some(n),
                Err(e) => {
                    tracing::warn!(
                        cidr = %s,
                        error = %e,
                        "ignoring invalid untrusted_client_cidrs entry",
                    );
                    None
                }
            })
            .collect()
    }

    /// Whether the named header should be honoured as a trust-bounded
    /// sidecar TLS-fingerprint signal. Always honours the canonical
    /// `x-sbproxy-tls-*` family; defers to
    /// [`Self::sidecar_header_allowlist`] for everything else. Matches
    /// case-insensitively.
    pub fn header_allowed(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "x-sbproxy-tls-ja3"
                | "x-sbproxy-tls-ja4"
                | "x-sbproxy-tls-ja4h"
                | "x-sbproxy-tls-ja4s"
                | "x-sbproxy-tls-trustworthy"
        ) {
            return true;
        }
        self.sidecar_header_allowlist
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&lower))
    }
}

/// A compiled config with its module instances ready for request processing.
///
/// Each vec is parallel to `config.origins` - index N in `actions` corresponds
/// to index N in `config.origins`. This avoids per-request JSON parsing.
pub struct CompiledPipeline {
    /// The underlying compiled config (origins, host_map, server settings).
    pub config: CompiledConfig,
    /// Bloom filter + HashMap router for fast hostname lookup.
    pub router: HostRouter,
    /// Compiled action for each origin (parallel to config.origins).
    pub actions: Vec<Action>,
    /// Compiled auth for each origin (None if no auth configured).
    pub auths: Vec<Option<Auth>>,
    /// Compiled policies for each origin (may be empty).
    pub policies: Vec<Vec<Policy>>,
    /// Compiled transforms for each origin (may be empty).
    pub transforms: Vec<Vec<CompiledTransform>>,
    /// Compiled forward rules for each origin (may be empty).
    pub forward_rules: Vec<Vec<CompiledForwardRule>>,
    /// Compiled fallback origin for each origin (None if not configured).
    pub fallbacks: Vec<Option<CompiledFallback>>,
    /// Compiled bot detection for each origin (None if not configured).
    pub bot_detections: Vec<Option<BotDetection>>,
    /// Compiled threat protection for each origin (None if not configured).
    pub threat_protections: Vec<Option<ThreatProtection>>,
    /// Shared response cache backend.
    ///
    /// Points at a Redis-backed store when `CompiledConfig.l2_store` is set,
    /// otherwise at an in-process `MemoryCacheStore`. A single backend is
    /// shared by all origins; per-origin `ResponseCacheConfig` gates whether
    /// the cache is actually used for that origin.
    pub cache_store: Option<Arc<dyn CacheStore>>,
    /// Optional Cache Reserve cold-tier backend.
    ///
    /// Built from the top-level `cache_reserve:` block. When `Some`, the
    /// request path consults the reserve on hot-cache misses, promotes
    /// reserve hits back into the hot tier, and writes evicted entries
    /// into the reserve subject to admission control. When `None`, the
    /// cache path runs unchanged.
    pub cache_reserve: Option<Arc<dyn CacheReserveBackend>>,
    /// Settings carried alongside [`Self::cache_reserve`] (sample
    /// rate, min TTL, max object size). Cached here so the request
    /// path doesn't have to re-walk `config.server.cache_reserve` on
    /// every put.
    pub cache_reserve_admission: Option<ReserveAdmission>,
    /// Enterprise hooks bundle.
    ///
    /// All fields default to `None` in OSS builds. Enterprise registers
    /// implementations (classifier, semantic cache, etc.) via the
    /// `EnterpriseStartupHook` pattern. Request-path code invokes these
    /// optionally and no-ops when they are `None`.
    pub hooks: crate::hooks::Hooks,
    /// Pre-parsed CIDRs from `proxy.trusted_proxies`. When the immediate
    /// TCP peer's IP falls inside one of these networks, the proxy honors
    /// the inbound `X-Forwarded-For` / `X-Real-IP` / `Forwarded` headers
    /// and recovers the real client IP from them. Otherwise those headers
    /// are stripped on ingress (they cannot be trusted).
    pub trusted_proxy_cidrs: Vec<ipnetwork::IpNetwork>,
    /// TLS fingerprint capture configuration (Wave 5 day-6 Item 3).
    ///
    /// Lifted from `proxy.extensions.tls_fingerprint` (or the migrated
    /// legacy `features.tls_fingerprint` shape, see Wave 5 day-6 Item
    /// 2). When `enabled = false` (the default), the request entry
    /// hook ignores sidecar TLS-fingerprint headers entirely so an
    /// operator's deployment that lacks a TLS-terminating sidecar does
    /// not pay the parse cost.
    pub tls_fingerprint_config: TlsFingerprintConfig,
    /// Opt-in switch for raw CSP-report logging.
    ///
    /// CSP reports may carry URLs with embedded credentials, session
    /// IDs, or tokens; the structured log path always redacts them. An
    /// operator who needs the raw payload (e.g. for forensic analysis
    /// in an isolated environment) sets
    /// `proxy.extensions.page_shield.raw_report_log: true` to also
    /// emit the unredacted body at debug level. Default `false`.
    pub page_shield_raw_report_log: bool,
    /// Per-tenant allowlist of private CIDRs that upstream URLs are
    /// permitted to resolve to.
    ///
    /// Lifted from `proxy.extensions.upstream.allow_private_cidrs`,
    /// which accepts a list of CIDR strings (`"10.0.0.0/8"`,
    /// `"169.254.0.0/16"`). Empty by default, in which case any
    /// upstream URL that resolves to a private / loopback / link-local
    /// IP is rejected before `HttpPeer` construction. Used by the
    /// SSRF guard in `upstream_peer`.
    pub upstream_allow_private_cidrs: Vec<ipnetwork::IpNetwork>,
    /// Short hex tag identifying the loaded config revision. Webhooks
    /// and alerts include this so receivers can tell when the config
    /// changed underneath them. Recomputed on every hot reload.
    pub config_revision: String,
    /// Shared DNS resolver used by `service_discovery`-enabled
    /// upstreams. One refresher backs every origin so resolutions
    /// are not duplicated when several origins point at the same
    /// hostname.
    pub dns_resolver: Arc<sbproxy_platform::RefreshingResolver>,
}

impl Default for CompiledPipeline {
    fn default() -> Self {
        let config = CompiledConfig::default();
        let router = HostRouter::new(&config);
        Self {
            config,
            router,
            actions: Vec::new(),
            auths: Vec::new(),
            policies: Vec::new(),
            transforms: Vec::new(),
            forward_rules: Vec::new(),
            fallbacks: Vec::new(),
            bot_detections: Vec::new(),
            threat_protections: Vec::new(),
            cache_store: None,
            cache_reserve: None,
            cache_reserve_admission: None,
            hooks: crate::hooks::Hooks::default(),
            trusted_proxy_cidrs: Vec::new(),
            tls_fingerprint_config: TlsFingerprintConfig::default(),
            page_shield_raw_report_log: false,
            upstream_allow_private_cidrs: Vec::new(),
            config_revision: String::new(),
            dns_resolver: Arc::new(sbproxy_platform::RefreshingResolver::new()),
        }
    }
}

impl CompiledPipeline {
    /// Compile a config into a full pipeline with modules instantiated.
    ///
    /// Iterates over every origin in the config, compiling its action,
    /// auth, and policy JSON values into typed enum variants. Fails if
    /// any origin has an invalid or unrecognized module config.
    pub fn from_config(config: CompiledConfig) -> anyhow::Result<Self> {
        let mut actions = Vec::with_capacity(config.origins.len());
        let mut auths = Vec::with_capacity(config.origins.len());
        let mut policies = Vec::with_capacity(config.origins.len());
        let mut transforms = Vec::with_capacity(config.origins.len());
        let mut forward_rules = Vec::with_capacity(config.origins.len());
        let mut fallbacks = Vec::with_capacity(config.origins.len());
        let mut bot_detections = Vec::with_capacity(config.origins.len());
        let mut threat_protections = Vec::with_capacity(config.origins.len());

        for origin in &config.origins {
            // Compile action (required for every origin).
            let action = compile_action(&origin.action_config)?;
            actions.push(action);

            // Compile auth (optional per origin).
            let auth = match &origin.auth_config {
                Some(cfg) => Some(compile_auth(cfg)?),
                None => None,
            };
            auths.push(auth);

            // Compile policies (zero or more per origin).
            // After compilation, attach the cluster-shared L2 store (if any) to
            // each RateLimit policy so it can use Redis-backed counters.
            let mut origin_policies: Vec<Policy> = origin
                .policy_configs
                .iter()
                .map(compile_policy)
                .collect::<anyhow::Result<Vec<_>>>()?;
            if config.l2_store.is_some() {
                let store = config.l2_store.clone();
                let origin_id = origin.origin_id.as_str();
                for p in origin_policies.iter_mut() {
                    if let Policy::RateLimit(rl) = p {
                        // take+replace: with_store consumes self and returns Self.
                        let taken = std::mem::replace(
                            rl,
                            sbproxy_modules::RateLimitPolicy::from_config(serde_json::json!({
                                "requests_per_second": 10.0
                            }))?,
                        );
                        *rl = taken.with_store(store.clone(), origin_id);
                    }
                }
            }
            policies.push(origin_policies);

            // Compile transforms (zero or more per origin).
            let origin_transforms: Vec<CompiledTransform> = origin
                .transform_configs
                .iter()
                .filter_map(|cfg| {
                    // Parse wrapper config to check disabled flag and extract metadata.
                    let wrapper: TransformConfig = match serde_json::from_value(cfg.clone()) {
                        Ok(w) => w,
                        Err(e) => {
                            return Some(Err(anyhow::anyhow!("invalid transform config: {}", e)))
                        }
                    };
                    if wrapper.disabled {
                        return None;
                    }
                    let transform = match compile_transform(cfg) {
                        Ok(t) => t,
                        Err(e) => return Some(Err(e)),
                    };
                    Some(Ok(CompiledTransform {
                        transform,
                        content_types: wrapper.content_types,
                        fail_on_error: wrapper.fail_on_error,
                        max_body_size: wrapper.max_body_size,
                    }))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            transforms.push(origin_transforms);

            // Compile forward rules (zero or more per origin).
            let origin_fwd_rules = compile_forward_rules(&origin.forward_rules)?;
            forward_rules.push(origin_fwd_rules);

            // Compile fallback origin (optional per origin).
            let fallback = compile_fallback(&origin.fallback_origin)?;
            fallbacks.push(fallback);

            // Compile bot detection (optional per origin).
            let bot = match &origin.bot_detection {
                Some(cfg) => Some(BotDetection::from_config(cfg.clone())?),
                None => None,
            };
            bot_detections.push(bot);

            // Compile threat protection (optional per origin).
            let threat = match &origin.threat_protection {
                Some(cfg) => Some(ThreatProtection::from_config(cfg.clone())?),
                None => None,
            };
            threat_protections.push(threat);
        }

        let router = HostRouter::new(&config);

        // --- Shared response cache backend ---
        //
        // Pick Redis when the top-level `l2_cache` block is set, otherwise
        // fall back to an in-process LRU. The cache is only created when
        // at least one origin has `response_cache.enabled = true`; this
        // avoids allocating a store for configs that don't use caching.
        let any_cache_enabled = config
            .origins
            .iter()
            .any(|o| o.response_cache.as_ref().is_some_and(|c| c.enabled));
        let cache_store: Option<Arc<dyn CacheStore>> = if any_cache_enabled {
            match config.l2_store.clone() {
                Some(kv) => Some(Arc::new(RedisCacheStore::new(kv))),
                None => {
                    // Take the largest configured max_size across origins
                    // so the shared memory cache can fit all of them.
                    let max = config
                        .origins
                        .iter()
                        .filter_map(|o| o.response_cache.as_ref())
                        .map(|c| c.max_size)
                        .max()
                        .unwrap_or(10_000);
                    Some(Arc::new(MemoryCacheStore::new(max)))
                }
            }
        } else {
            None
        };

        // --- Cache Reserve cold tier ---
        //
        // Built from the top-level `cache_reserve:` block. The OSS
        // backends (memory / filesystem / redis) are instantiated here;
        // unknown / enterprise backends drop through to `None` with a
        // warning so the enterprise startup hook can swap in its own
        // implementation post-compile.
        let (cache_reserve, cache_reserve_admission) =
            build_cache_reserve(&config.server.cache_reserve);

        // Pre-parse trusted_proxies CIDRs once at compile time so the
        // request path can do a constant-time membership check.
        let trusted_proxy_cidrs: Vec<ipnetwork::IpNetwork> = config
            .server
            .trusted_proxies
            .iter()
            .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                Ok(net) => Some(net),
                Err(e) => {
                    tracing::warn!(cidr = %s, error = %e, "ignoring invalid trusted_proxies CIDR");
                    None
                }
            })
            .collect();

        // Hash a stable view of the loaded origin set so webhook
        // receivers can tell which config revision fired the event. We
        // use the host_map (which is sorted hostnames) plus origin
        // count so the revision changes whenever the routable surface
        // changes; we don't need byte-perfect fidelity, only "different
        // when the config differs."
        let mut keyed: Vec<(&compact_str::CompactString, &usize)> =
            config.host_map.iter().collect();
        keyed.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        let mut buf = Vec::with_capacity(keyed.len() * 32);
        buf.extend_from_slice(format!("origins:{}\n", config.origins.len()).as_bytes());
        for (host, idx) in keyed {
            buf.extend_from_slice(host.as_bytes());
            buf.push(b'=');
            buf.extend_from_slice(idx.to_string().as_bytes());
            buf.push(b'\n');
        }
        let config_revision = crate::identity::config_revision(&buf);

        // Wave 5 day-6 Item 3: lift TLS-fingerprint config off
        // proxy.extensions[tls_fingerprint] (which the day-6 Item 2
        // migration also fills from legacy features.tls_fingerprint).
        let tls_fingerprint_config =
            TlsFingerprintConfig::from_extensions(&config.server.extensions);

        // --- Page Shield raw-report opt-in ---
        // CSP reports default to redacted-only structured logs. The
        // operator can opt into raw-body capture for forensics.
        let page_shield_raw_report_log = config
            .server
            .extensions
            .get("page_shield")
            .and_then(|v| v.get("raw_report_log"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // --- SSRF private-CIDR allowlist ---
        // Operators that intentionally target a private network
        // (corporate VPN, mesh sidecar, internal registry) opt in
        // explicitly. Invalid CIDRs are warn-logged and dropped.
        let upstream_allow_private_cidrs: Vec<ipnetwork::IpNetwork> = config
            .server
            .extensions
            .get("upstream")
            .and_then(|v| v.get("allow_private_cidrs"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|entry| entry.as_str())
                    .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                        Ok(n) => Some(n),
                        Err(e) => {
                            tracing::warn!(
                                cidr = %s,
                                error = %e,
                                "ignoring invalid upstream.allow_private_cidrs entry",
                            );
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let pipeline = Self {
            config,
            router,
            actions,
            auths,
            policies,
            transforms,
            forward_rules,
            fallbacks,
            bot_detections,
            threat_protections,
            cache_store,
            cache_reserve,
            cache_reserve_admission,
            hooks: crate::hooks::Hooks::default(),
            trusted_proxy_cidrs,
            tls_fingerprint_config,
            page_shield_raw_report_log,
            upstream_allow_private_cidrs,
            config_revision,
            dns_resolver: Arc::new(sbproxy_platform::RefreshingResolver::new()),
        };
        // Spawn active health-check probes for any load_balancer
        // target that has `health_check:` configured. Best-effort: if
        // we are not running inside a Tokio runtime (e.g. unit tests),
        // the call is a no-op.
        pipeline.start_background_tasks();
        Ok(pipeline)
    }

    /// Start background tasks owned by the pipeline.
    ///
    /// Currently this only covers the active health-check probes on
    /// `Action::LoadBalancer` targets, but it is the seam any future
    /// pipeline-scoped task (e.g. periodic cache eviction sweeps,
    /// dynamic blocklist refresh) will plug into.
    fn start_background_tasks(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        for action in &self.actions {
            if let sbproxy_modules::Action::LoadBalancer(lb) = action {
                lb.spawn_health_probes();
            }
        }
    }

    /// Construct a minimal empty pipeline for unit tests.
    ///
    /// All vectors are empty, the router is built from an empty config, and
    /// hooks default to `None`. Intended only for tests that need to assert
    /// invariants on a freshly constructed pipeline without compiling any
    /// origins.
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self::default()
    }

    /// Resolve a hostname to an origin index.
    ///
    /// Uses the bloom filter to fast-reject unknown hostnames before
    /// falling through to the HashMap lookup.
    pub fn resolve_origin(&self, hostname: &str) -> Option<usize> {
        self.router.resolve(hostname)
    }
}

// --- Forward rule / fallback compilation helpers ---

/// Compile a list of forward rule JSON values into typed forward rules.
fn compile_forward_rules(
    raw_rules: &[serde_json::Value],
) -> anyhow::Result<Vec<CompiledForwardRule>> {
    let mut compiled = Vec::with_capacity(raw_rules.len());
    for rule_val in raw_rules {
        let fwd = compile_single_forward_rule(rule_val)?;
        compiled.push(fwd);
    }
    Ok(compiled)
}

/// Compile a single forward rule from its JSON representation.
///
/// Expected structure:
/// ```yaml
/// rules:
///   - path:
///       prefix: /api/
///   - path:
///       exact: /health
///   - path:
///       template: /users/{id}/posts/{post_id}
///   - path:
///       template: /static/{*rest}
///   - path:
///       regex: '^/v(?P<version>\d+)/items'
/// origin:
///   action:
///     type: proxy
///     url: http://...
///   request_modifiers:
///     - headers:
///         set:
///           X-Routed-To: api-backend
/// ```
///
/// When more than one of `prefix`/`exact`/`template`/`regex` is set on the
/// same `path` block, precedence is `template` > `regex` > `exact` >
/// `prefix`. The shorthand `match: <prefix>` field is always treated as a
/// prefix match.
fn compile_single_forward_rule(val: &serde_json::Value) -> anyhow::Result<CompiledForwardRule> {
    let rules_arr = val
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("forward rule missing 'rules' array"))?;

    // `serde_json::to_value` on `RawForwardRule` emits `null` for absent
    // optional fields (because the struct uses `#[serde(default)]` rather
    // than `skip_serializing_if`). Treat both `None` and `Value::Null` as
    // "field absent" so the compiler is forgiving on the wire format.
    let mut matchers: Vec<MatcherEntry> = Vec::with_capacity(rules_arr.len());
    for rule in rules_arr {
        let path = compile_path_matcher(rule)?;
        let header = compile_header_matcher(non_null(rule.get("header")))?;
        let query = compile_query_matcher(non_null(rule.get("query")))?;
        if path.is_some() || header.is_some() || query.is_some() {
            matchers.push(MatcherEntry {
                path,
                header,
                query,
            });
        }
    }

    // Parse the inline origin config.
    let origin_obj = val
        .get("origin")
        .ok_or_else(|| anyhow::anyhow!("forward rule missing 'origin' object"))?;

    // The action is nested under origin.action.
    let action_config = origin_obj
        .get("action")
        .ok_or_else(|| anyhow::anyhow!("forward rule origin missing 'action'"))?;
    let action = compile_action(action_config)?;

    // Parse request modifiers (optional).
    // Supports both Rust format ({ headers: { set: ... } }) and Go format
    // ({ type: "header", set: { ... } }). The Go format is normalized to Rust format.
    let request_modifiers: Vec<RequestModifierConfig> =
        if let Some(mods) = origin_obj.get("request_modifiers") {
            if let Some(arr) = mods.as_array() {
                arr.iter().map(normalize_request_modifier).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

    // Rule-level OpenAPI parameter declarations. Optional; absent
    // entirely when the rule is described only by prefix/exact paths.
    let parameters: Vec<Parameter> = match val.get("parameters") {
        Some(p) => serde_json::from_value(p.clone())
            .map_err(|e| anyhow::anyhow!("invalid 'parameters' in forward rule: {}", e))?,
        None => Vec::new(),
    };

    Ok(CompiledForwardRule {
        matchers,
        action,
        request_modifiers,
        parameters,
    })
}

/// Treat `Some(Value::Null)` as `None` so `serde_json::to_value` round-trips
/// of optional matcher fields do not look "present" downstream.
fn non_null(v: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
    match v {
        Some(serde_json::Value::Null) => None,
        other => other,
    }
}

/// Compile the `path:` block of a single matcher entry, plus the `match:`
/// shorthand. Returns the most expressive matcher present (template, regex,
/// exact, prefix; in that priority). When both `path:` and `match:` are
/// present, `path:` wins because it is the canonical form.
fn compile_path_matcher(rule: &serde_json::Value) -> anyhow::Result<Option<PathMatch>> {
    if let Some(path_obj) = rule.get("path") {
        if let Some(template) = path_obj.get("template").and_then(|v| v.as_str()) {
            return Ok(Some(PathMatch::Template(PathTemplate::compile(template)?)));
        }
        if let Some(pattern) = path_obj.get("regex").and_then(|v| v.as_str()) {
            let re = regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("invalid forward-rule regex '{}': {}", pattern, e))?;
            return Ok(Some(PathMatch::Regex(re)));
        }
        if let Some(exact) = path_obj.get("exact").and_then(|v| v.as_str()) {
            return Ok(Some(PathMatch::Exact(exact.to_string())));
        }
        if let Some(prefix) = path_obj.get("prefix").and_then(|v| v.as_str()) {
            return Ok(Some(PathMatch::Prefix(prefix.to_string())));
        }
    }
    if let Some(match_str) = rule.get("match").and_then(|v| v.as_str()) {
        return Ok(Some(PathMatch::Prefix(match_str.to_string())));
    }
    Ok(None)
}

/// Compile the `header:` block of a single matcher entry. Accepts
/// `{ name, value }` (exact) or `{ name, prefix }` (value prefix).
fn compile_header_matcher(val: Option<&serde_json::Value>) -> anyhow::Result<Option<HeaderMatch>> {
    let Some(obj) = val else {
        return Ok(None);
    };
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("forward-rule header matcher missing 'name'"))?
        .to_string();
    if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
        return Ok(Some(HeaderMatch::Equals {
            name,
            value: value.to_string(),
        }));
    }
    if let Some(prefix) = obj.get("prefix").and_then(|v| v.as_str()) {
        return Ok(Some(HeaderMatch::Prefix {
            name,
            prefix: prefix.to_string(),
        }));
    }
    Err(anyhow::anyhow!(
        "forward-rule header matcher '{}' needs 'value' or 'prefix'",
        name
    ))
}

/// Compile the `query:` block of a single matcher entry. Accepts
/// `{ name, value }` (exact) or just `{ name }` (presence-only).
fn compile_query_matcher(val: Option<&serde_json::Value>) -> anyhow::Result<Option<QueryMatch>> {
    let Some(obj) = val else {
        return Ok(None);
    };
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("forward-rule query matcher missing 'name'"))?
        .to_string();
    if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
        return Ok(Some(QueryMatch::Equals {
            name,
            value: value.to_string(),
        }));
    }
    Ok(Some(QueryMatch::Present { name }))
}

/// Compile a fallback origin from its JSON representation (if present).
///
/// Expected structure:
/// ```yaml
/// fallback_origin:
///   on_error: true
///   on_status: [502, 503, 504]
///   add_debug_header: true
///   origin:
///     action:
///       type: static
///       status_code: 200
///       json_body: { ... }
/// ```
fn compile_fallback(raw: &Option<serde_json::Value>) -> anyhow::Result<Option<CompiledFallback>> {
    let val = match raw {
        Some(v) => v,
        None => return Ok(None),
    };

    let on_error = val
        .get("on_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let on_status: Vec<u16> = val
        .get("on_status")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default();

    let add_debug_header = val
        .get("add_debug_header")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let origin_obj = val
        .get("origin")
        .ok_or_else(|| anyhow::anyhow!("fallback_origin missing 'origin' object"))?;

    let action_config = origin_obj
        .get("action")
        .ok_or_else(|| anyhow::anyhow!("fallback origin missing 'action'"))?;
    let action = compile_action(action_config)?;

    Ok(Some(CompiledFallback {
        on_error,
        on_status,
        add_debug_header,
        action,
    }))
}

/// Normalize a request modifier from either Go format or Rust format.
///
/// Go format: `{ type: "header", set: { "X-Foo": "bar" } }`
/// Rust format: `{ headers: { set: { "X-Foo": "bar" } } }`
///
/// The Go format is converted to Rust format before deserialization.
/// Default (empty) request modifier config used as a fallback when deserialization fails.
fn default_request_modifier() -> RequestModifierConfig {
    RequestModifierConfig {
        headers: None,
        url: None,
        query: None,
        method: None,
        body: None,
        lua_script: None,
        js_script: None,
    }
}

fn normalize_request_modifier(val: &serde_json::Value) -> RequestModifierConfig {
    // If it already has a `headers` field, it's in Rust format.
    if val.get("headers").is_some() {
        return serde_json::from_value(val.clone()).unwrap_or_else(|_| default_request_modifier());
    }

    // Check for Go format: { type: "header", set: { ... }, add: { ... }, remove/delete: [...] }
    if val.get("type").and_then(|v| v.as_str()) == Some("header") {
        let set = val.get("set").cloned().unwrap_or(serde_json::json!({}));
        let add = val.get("add").cloned().unwrap_or(serde_json::json!({}));
        let remove = val
            .get("remove")
            .or_else(|| val.get("delete"))
            .cloned()
            .unwrap_or(serde_json::json!([]));
        let normalized = serde_json::json!({
            "headers": {
                "set": set,
                "add": add,
                "remove": remove,
            }
        });
        return serde_json::from_value(normalized).unwrap_or_else(|_| default_request_modifier());
    }

    // Fallback: try direct deserialization (handles url, query, method, body modifier types).
    serde_json::from_value(val.clone()).unwrap_or_else(|_| default_request_modifier())
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use std::collections::HashMap;

    fn make_config(
        hostname: &str,
        action: serde_json::Value,
        auth: Option<serde_json::Value>,
        policies: Vec<serde_json::Value>,
    ) -> CompiledConfig {
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        CompiledConfig {
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                workspace_id: CompactString::default(),
                action_config: action,
                auth_config: auth,
                policy_configs: policies,
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
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        }
    }

    #[test]
    fn pipeline_from_proxy_config() {
        let config = make_config(
            "api.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.actions.len(), 1);
        assert_eq!(pipeline.actions[0].action_type(), "proxy");
        assert!(pipeline.auths[0].is_none());
        assert!(pipeline.policies[0].is_empty());
    }

    #[test]
    fn pipeline_with_auth_and_policies() {
        let config = make_config(
            "secure.example.com",
            serde_json::json!({"type": "static", "body": "ok"}),
            Some(serde_json::json!({"type": "api_key", "api_keys": ["key1"]})),
            vec![serde_json::json!({
                "type": "rate_limiting",
                "requests_per_second": 10.0,
                "burst": 5
            })],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.actions[0].action_type(), "static");
        assert!(pipeline.auths[0].is_some());
        assert_eq!(pipeline.auths[0].as_ref().unwrap().auth_type(), "api_key");
        assert_eq!(pipeline.policies[0].len(), 1);
        assert_eq!(pipeline.policies[0][0].policy_type(), "rate_limiting");
    }

    #[test]
    fn pipeline_resolve_origin() {
        let config = make_config(
            "test.example.com",
            serde_json::json!({"type": "noop"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.resolve_origin("test.example.com"), Some(0));
        assert_eq!(pipeline.resolve_origin("unknown.com"), None);
    }

    #[test]
    fn pipeline_invalid_action_errors() {
        let config = make_config(
            "bad.example.com",
            serde_json::json!({"type": "unknown_action_type"}),
            None,
            vec![],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    #[test]
    fn pipeline_invalid_auth_errors() {
        let config = make_config(
            "bad.example.com",
            serde_json::json!({"type": "noop"}),
            Some(serde_json::json!({"type": "nonexistent_auth"})),
            vec![],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    #[test]
    fn pipeline_invalid_policy_errors() {
        let config = make_config(
            "bad.example.com",
            serde_json::json!({"type": "noop"}),
            None,
            vec![serde_json::json!({"type": "nonexistent_policy"})],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    fn make_config_with_transforms(
        hostname: &str,
        action: serde_json::Value,
        transforms: Vec<serde_json::Value>,
    ) -> CompiledConfig {
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        CompiledConfig {
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                workspace_id: CompactString::default(),
                action_config: action,
                auth_config: None,
                policy_configs: Vec::new(),
                transform_configs: transforms,
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
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        }
    }

    #[test]
    fn pipeline_with_transforms() {
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            vec![
                serde_json::json!({"type": "json", "set": {"injected": true}, "remove": ["secret"]}),
                serde_json::json!({"type": "noop"}),
            ],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.transforms.len(), 1); // One origin.
        assert_eq!(pipeline.transforms[0].len(), 2); // Two transforms.
        assert_eq!(pipeline.transforms[0][0].transform.transform_type(), "json");
        assert_eq!(pipeline.transforms[0][1].transform.transform_type(), "noop");
        // Default metadata values.
        assert!(!pipeline.transforms[0][0].fail_on_error);
        assert_eq!(pipeline.transforms[0][0].max_body_size, 10 * 1024 * 1024);
        assert!(pipeline.transforms[0][0].content_types.is_empty());
    }

    #[test]
    fn pipeline_disabled_transforms_are_skipped() {
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "noop"}),
            vec![
                serde_json::json!({"type": "json", "set": {"a": 1}}),
                serde_json::json!({"type": "noop", "disabled": true}),
                serde_json::json!({"type": "json", "remove": ["x"], "fail_on_error": true, "max_body_size": 512}),
            ],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        // The disabled noop should be filtered out, leaving 2 transforms.
        assert_eq!(pipeline.transforms[0].len(), 2);
        assert_eq!(pipeline.transforms[0][0].transform.transform_type(), "json");
        assert_eq!(pipeline.transforms[0][1].transform.transform_type(), "json");
        assert!(pipeline.transforms[0][1].fail_on_error);
        assert_eq!(pipeline.transforms[0][1].max_body_size, 512);
    }

    #[test]
    fn pipeline_invalid_transform_errors() {
        let config = make_config_with_transforms(
            "bad.example.com",
            serde_json::json!({"type": "noop"}),
            vec![serde_json::json!({"type": "unknown_transform_type"})],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    #[test]
    fn pipeline_no_transforms_gives_empty_vec() {
        let config = make_config(
            "api.example.com",
            serde_json::json!({"type": "noop"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.transforms.len(), 1); // One origin.
        assert!(pipeline.transforms[0].is_empty()); // No transforms.
    }

    #[test]
    fn pipeline_default_is_empty() {
        let pipeline = CompiledPipeline::default();
        assert!(pipeline.actions.is_empty());
        assert!(pipeline.auths.is_empty());
        assert!(pipeline.policies.is_empty());
        assert!(pipeline.transforms.is_empty());
        assert!(pipeline.forward_rules.is_empty());
        assert!(pipeline.fallbacks.is_empty());
        assert!(pipeline.config.origins.is_empty());
    }

    #[test]
    fn compiled_pipeline_has_hooks_field_defaulting_to_none() {
        let pipeline = CompiledPipeline::empty_for_test();
        assert!(pipeline.hooks.startup.is_none());
        assert!(pipeline.hooks.prompt_classifier.is_none());
        assert!(pipeline.hooks.intent_detection.is_none());
        assert!(pipeline.hooks.quality_scoring.is_none());
        assert!(pipeline.hooks.stream_safety.is_none());
        assert!(pipeline.hooks.semantic_lookup.is_none());
        assert!(pipeline.hooks.stream_cache_recorder.is_none());
    }

    #[test]
    fn pipeline_compiles_forward_rules() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "routing.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api-backend
          action:
            type: proxy
            url: http://127.0.0.1:18888/echo
      - rules:
          - path:
              exact: /health
        origin:
          id: health-static
          action:
            type: static
            status_code: 200
            content_type: application/json
            json_body:
              status: healthy
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        assert_eq!(pipeline.forward_rules.len(), 1); // One origin.
        assert_eq!(pipeline.forward_rules[0].len(), 2); // Two forward rules.

        // First rule: prefix /api/ -> proxy action
        let rule0 = &pipeline.forward_rules[0][0];
        assert_eq!(rule0.matchers.len(), 1);
        let path0 = rule0.matchers[0].path.as_ref().expect("path matcher");
        assert!(path0.matches("/api/users"));
        assert!(!path0.matches("/health"));
        assert_eq!(rule0.action.action_type(), "proxy");

        // Second rule: exact /health -> static action
        let rule1 = &pipeline.forward_rules[0][1];
        assert_eq!(rule1.matchers.len(), 1);
        let path1 = rule1.matchers[0].path.as_ref().expect("path matcher");
        assert!(path1.matches("/health"));
        assert!(!path1.matches("/health/"));
        assert_eq!(rule1.action.action_type(), "static");
    }

    #[test]
    fn pipeline_compiles_fallback_origin() {
        let yaml = r#"
origins:
  "fb.test":
    action:
      type: proxy
      url: http://127.0.0.1:19999
    fallback_origin:
      on_error: true
      on_status: [502, 503, 504]
      add_debug_header: true
      origin:
        id: fb-fallback
        action:
          type: static
          status_code: 200
          content_type: application/json
          json_body:
            source: fallback
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        assert_eq!(pipeline.fallbacks.len(), 1);
        let fb = pipeline.fallbacks[0].as_ref().unwrap();
        assert!(fb.on_error);
        assert_eq!(fb.on_status, vec![502, 503, 504]);
        assert!(fb.add_debug_header);
        assert_eq!(fb.action.action_type(), "static");
    }

    #[test]
    fn pipeline_no_forward_rules_or_fallback() {
        let config = make_config(
            "simple.test",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert!(pipeline.forward_rules[0].is_empty());
        assert!(pipeline.fallbacks[0].is_none());
    }
    #[test]
    fn pipeline_forward_rule_request_modifiers_are_applied() {
        // Verifies that forward rule request modifiers (e.g., X-Routed-To) are
        // correctly compiled and can be applied to a HeaderMap.
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "fwdlocal.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888/echo
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api-route
          hostname: api-route
          workspace_id: test
          version: "1.0.0"
          action:
            type: proxy
            url: http://127.0.0.1:18888/echo
          request_modifiers:
            - headers:
                set:
                  X-Routed-To: api-backend
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        let fwd = &pipeline.forward_rules[0];
        assert_eq!(fwd.len(), 1);
        assert!(!fwd[0].request_modifiers.is_empty());

        // Simulate applying modifiers to a header map.
        let mut headers = http::HeaderMap::new();
        sbproxy_middleware::modifiers::apply_request_modifiers(
            &fwd[0].request_modifiers,
            &mut headers,
        );
        assert_eq!(
            headers.get("x-routed-to").map(|v| v.to_str().unwrap()),
            Some("api-backend"),
            "X-Routed-To header should be set by forward rule modifier"
        );
    }

    // --- Path matcher tests ---

    #[test]
    fn template_matches_named_segments() {
        let t = PathTemplate::compile("/users/{id}/posts/{post_id}").unwrap();
        let captured = t.match_path("/users/42/posts/abc").unwrap();
        assert_eq!(captured.get("id").map(String::as_str), Some("42"));
        assert_eq!(captured.get("post_id").map(String::as_str), Some("abc"));
    }

    #[test]
    fn template_rejects_wrong_segment_count() {
        let t = PathTemplate::compile("/users/{id}").unwrap();
        assert!(t.match_path("/users/42/extra").is_none());
        assert!(t.match_path("/users").is_none());
    }

    #[test]
    fn template_literal_segments_must_match() {
        let t = PathTemplate::compile("/users/{id}/posts").unwrap();
        assert!(t.match_path("/users/42/posts").is_some());
        assert!(t.match_path("/users/42/comments").is_none());
    }

    #[test]
    fn template_catch_all_captures_remainder() {
        let t = PathTemplate::compile("/static/{*rest}").unwrap();
        let captured = t.match_path("/static/css/site.css").unwrap();
        assert_eq!(
            captured.get("rest").map(String::as_str),
            Some("css/site.css")
        );

        // Catch-all may match zero remaining segments too.
        let captured = t.match_path("/static").unwrap();
        assert_eq!(captured.get("rest").map(String::as_str), Some(""));
    }

    #[test]
    fn template_catch_all_must_be_last() {
        let err = PathTemplate::compile("/static/{*rest}/extra").unwrap_err();
        assert!(err.to_string().contains("catch-all"));
    }

    #[test]
    fn template_constraint_passes_only_when_regex_matches() {
        let t = PathTemplate::compile("/users/{id:[0-9]+}").unwrap();
        assert!(t.match_path("/users/42").is_some());
        assert!(
            t.match_path("/users/abc").is_none(),
            "constraint should reject non-numeric id"
        );
    }

    #[test]
    fn template_invalid_constraint_errors_at_compile() {
        let err = PathTemplate::compile("/x/{id:[}").unwrap_err();
        assert!(err.to_string().contains("invalid constraint regex"));
    }

    #[test]
    fn template_mixed_literal_param_segment_rejected() {
        let err = PathTemplate::compile("/users-{id}").unwrap_err();
        assert!(err.to_string().contains("mixed"));
    }

    #[test]
    fn path_match_template_via_match_with_params() {
        let pm = PathMatch::Template(PathTemplate::compile("/users/{id}").unwrap());
        let params = pm.match_with_params("/users/42").unwrap();
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
        assert!(pm.match_with_params("/orders/42").is_none());
    }

    #[test]
    fn path_match_regex_named_captures() {
        let re = regex::Regex::new(r"^/v(?P<version>\d+)/items").unwrap();
        let pm = PathMatch::Regex(re);
        let params = pm.match_with_params("/v3/items/123").unwrap();
        assert_eq!(params.get("version").map(String::as_str), Some("3"));
    }

    #[test]
    fn path_match_prefix_returns_empty_params() {
        let pm = PathMatch::Prefix("/api/".to_string());
        let params = pm.match_with_params("/api/users").unwrap();
        assert!(params.is_empty());
        assert!(pm.match_with_params("/health").is_none());
    }

    #[test]
    fn path_match_exact_returns_empty_params() {
        let pm = PathMatch::Exact("/health".to_string());
        let params = pm.match_with_params("/health").unwrap();
        assert!(params.is_empty());
        assert!(pm.match_with_params("/health/").is_none());
    }

    #[test]
    fn pipeline_compiles_template_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "tmpl.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              template: /users/{id}/posts/{post_id}
        origin:
          id: posts
          action:
            type: proxy
            url: http://127.0.0.1:18888/posts
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let path = rule.matchers[0].path.as_ref().expect("path matcher");
        let params = path
            .match_with_params("/users/42/posts/abc")
            .expect("template should match");
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
        assert_eq!(params.get("post_id").map(String::as_str), Some("abc"));
    }

    #[test]
    fn pipeline_propagates_rule_parameters() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "params.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              template: /users/{id}
        parameters:
          - name: id
            in: path
            required: true
            description: Numeric user identifier
            schema:
              type: integer
              format: int64
          - name: include
            in: query
            required: false
            schema:
              type: string
        origin:
          id: users-api
          action:
            type: proxy
            url: http://127.0.0.1:18888/users
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.parameters.len(), 2);
        assert_eq!(rule.parameters[0].name, "id");
        assert_eq!(
            rule.parameters[0].location,
            sbproxy_config::ParameterLocation::Path
        );
        assert!(rule.parameters[0].required);
        assert_eq!(
            rule.parameters[0].description.as_deref(),
            Some("Numeric user identifier")
        );
        assert_eq!(
            rule.parameters[0]
                .schema
                .get("type")
                .and_then(|v| v.as_str()),
            Some("integer")
        );
        assert_eq!(rule.parameters[1].name, "include");
        assert_eq!(
            rule.parameters[1].location,
            sbproxy_config::ParameterLocation::Query
        );
    }

    #[test]
    fn pipeline_compiles_regex_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "rx.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              regex: '^/v(?P<version>[0-9]+)/items'
        origin:
          id: versioned
          action:
            type: proxy
            url: http://127.0.0.1:18888/items
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let path = rule.matchers[0].path.as_ref().expect("path matcher");
        let params = path
            .match_with_params("/v3/items/abc")
            .expect("regex should match");
        assert_eq!(params.get("version").map(String::as_str), Some("3"));
    }

    #[test]
    fn pipeline_compiles_header_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "h.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - header:
              name: X-Tenant
              value: foo
        origin:
          id: tenant-foo
          action:
            type: proxy
            url: http://127.0.0.1:18889
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("foo"));
        let captured = rule.matchers[0].match_request("/anything", None, &headers);
        assert!(captured.is_some(), "header match should fire");

        let mut other = http::HeaderMap::new();
        other.insert("x-tenant", http::HeaderValue::from_static("bar"));
        assert!(rule.matchers[0]
            .match_request("/anything", None, &other)
            .is_none());
    }

    #[test]
    fn pipeline_compiles_query_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "q.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - query:
              name: env
              value: staging
        origin:
          id: q-staging
          action:
            type: proxy
            url: http://127.0.0.1:18890
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let headers = http::HeaderMap::new();
        assert!(rule.matchers[0]
            .match_request("/anything", Some("env=staging&x=1"), &headers)
            .is_some());
        assert!(rule.matchers[0]
            .match_request("/anything", Some("env=prod"), &headers)
            .is_none());
        assert!(rule.matchers[0]
            .match_request("/anything", None, &headers)
            .is_none());
    }

    #[test]
    fn pipeline_path_and_header_are_anded() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "and.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
            header:
              name: X-Beta
              value: "true"
        origin:
          id: beta
          action:
            type: proxy
            url: http://127.0.0.1:18891
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let mut beta = http::HeaderMap::new();
        beta.insert("x-beta", http::HeaderValue::from_static("true"));
        let mut not_beta = http::HeaderMap::new();
        not_beta.insert("x-beta", http::HeaderValue::from_static("false"));

        // Both must hold.
        assert!(rule.matchers[0]
            .match_request("/api/x", None, &beta)
            .is_some());
        // Path matches, header wrong: AND fails.
        assert!(rule.matchers[0]
            .match_request("/api/x", None, &not_beta)
            .is_none());
        // Header matches, path wrong: AND fails.
        assert!(rule.matchers[0]
            .match_request("/web/x", None, &beta)
            .is_none());
    }

    #[test]
    fn pipeline_compiles_header_prefix() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "hp.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - header:
              name: Authorization
              prefix: "Bearer "
        origin:
          id: bearer
          action:
            type: proxy
            url: http://127.0.0.1:18892
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let mut bearer = http::HeaderMap::new();
        bearer.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer abc123"),
        );
        let mut basic = http::HeaderMap::new();
        basic.insert("authorization", http::HeaderValue::from_static("Basic xyz"));
        assert!(rule.matchers[0].match_request("/", None, &bearer).is_some());
        assert!(rule.matchers[0].match_request("/", None, &basic).is_none());
    }
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    #[test]
    fn normalize_go_header_modifier() {
        let val = serde_json::json!({
            "type": "header",
            "set": {
                "X-Routed-To": "api-backend"
            }
        });
        let config = normalize_request_modifier(&val);
        assert!(config.headers.is_some(), "headers should be Some");
        let headers = config.headers.unwrap();
        assert_eq!(
            headers.set.get("X-Routed-To").map(|s| s.as_str()),
            Some("api-backend")
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Load the case-09 forward-rules fixture relative to the crate root.
    ///
    /// The `e2e/` directory lives alongside this crate and is populated
    /// out-of-band (historically via a symlink to the Go repo's fixtures).
    /// If the fixture is not present we skip the test rather than panic so
    /// CI environments without the fixtures still pass.
    #[test]
    fn load_case09_forward_rules() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../e2e/cases/09-forwarding-rules/sb.yml");
        let Ok(yaml) = std::fs::read_to_string(&fixture) else {
            eprintln!(
                "skipping load_case09_forward_rules: fixture missing at {}",
                fixture.display()
            );
            return;
        };
        let config = sbproxy_config::compile_config(&yaml).unwrap();
        let origin = config.resolve_origin("routing.test").unwrap();
        assert!(
            !origin.forward_rules.is_empty(),
            "forward_rules should not be empty"
        );
        assert_eq!(origin.forward_rules.len(), 3, "should have 3 forward rules");

        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert!(!pipeline.forward_rules.is_empty());
        let fwd = &pipeline.forward_rules[0];
        assert_eq!(fwd.len(), 3, "compiled should have 3 forward rules");

        // Check first rule has request modifier
        assert!(
            !fwd[0].request_modifiers.is_empty(),
            "first rule should have modifiers"
        );
        let modifier = &fwd[0].request_modifiers[0];
        assert!(modifier.headers.is_some(), "modifier should have headers");
        let headers = modifier.headers.as_ref().unwrap();
        assert_eq!(
            headers.set.get("X-Routed-To").map(|s| s.as_str()),
            Some("api-backend")
        );
    }

    // --- Wave 5 day-6 Item 3: TlsFingerprintConfig roundtrip tests ---

    #[test]
    fn tls_fingerprint_config_default_is_disabled() {
        let cfg = TlsFingerprintConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.mode, TlsFingerprintMode::Sidecar);
        assert!(cfg.sidecar_header_allowlist.is_empty());
    }

    #[test]
    fn tls_fingerprint_config_round_trips_from_extensions_block() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: sidecar
      sidecar_header_allowlist:
        - x-forwarded-ja3
        - x-forwarded-ja4
      trustworthy_client_cidrs:
        - 127.0.0.0/8
      untrusted_client_cidrs:
        - 173.245.48.0/20
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let tls = TlsFingerprintConfig::from_extensions(&cfg.server.extensions);
        assert!(tls.enabled);
        assert_eq!(tls.mode, TlsFingerprintMode::Sidecar);
        assert_eq!(tls.sidecar_header_allowlist.len(), 2);
        assert!(tls.header_allowed("x-forwarded-ja3"));
        assert!(tls.header_allowed("X-Forwarded-JA4"));
        assert!(!tls.header_allowed("x-evil"));
        // Canonical headers always allowed.
        assert!(tls.header_allowed("x-sbproxy-tls-ja3"));
        assert!(tls.header_allowed("X-SBProxy-TLS-Trustworthy"));
        let trustworthy_cidrs = tls.trustworthy_cidrs();
        assert_eq!(trustworthy_cidrs.len(), 1);
        let untrusted_cidrs = tls.untrusted_cidrs();
        assert_eq!(untrusted_cidrs.len(), 1);
    }

    #[test]
    fn tls_fingerprint_config_lifts_legacy_features_block() {
        // Day-6 Item 2 + Item 3 together: a legacy
        // features.tls_fingerprint block is migrated and the typed
        // config picks it up.
        let yaml = r#"
proxy:
  http_bind_port: 8080
features:
  tls_fingerprint:
    enabled: true
    sidecar_header_allowlist:
      - x-forwarded-ja4
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let tls = TlsFingerprintConfig::from_extensions(&cfg.server.extensions);
        assert!(tls.enabled);
        assert!(tls.header_allowed("x-forwarded-ja4"));
    }

    #[test]
    fn tls_fingerprint_config_threads_onto_compiled_pipeline() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: passive
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let pipeline = CompiledPipeline::from_config(cfg).expect("compile pipeline");
        assert!(pipeline.tls_fingerprint_config.enabled);
        assert_eq!(
            pipeline.tls_fingerprint_config.mode,
            TlsFingerprintMode::Passive,
        );
    }

    #[test]
    fn tls_fingerprint_config_disabled_mode_blocks_capture() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: disabled
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let pipeline = CompiledPipeline::from_config(cfg).expect("compile pipeline");
        assert_eq!(
            pipeline.tls_fingerprint_config.mode,
            TlsFingerprintMode::Disabled,
        );
    }

    #[test]
    fn tls_fingerprint_config_invalid_block_falls_through_to_default() {
        // A malformed extensions block must not abort compile_config.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: not-a-bool
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let tls = TlsFingerprintConfig::from_extensions(&cfg.server.extensions);
        // Default => disabled (safe).
        assert!(!tls.enabled);
    }
}
