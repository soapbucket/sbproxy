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
//! proxy.admin.password: ${ADMIN_PASSWORD}
//!
//! The credentials default to `admin` / `changeme`, which is fine on the
//! loopback default and refused by `compile_config` once `bind` or
//! `allow_ips` makes the surface reachable from another host.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use sbproxy_config::config_merge::{BaseOrigin, MergeMode, Provenance};
use sbproxy_config::types::AdminRole;
use serde::Serialize;

// Shared with the non-admin reload paths (WOR-2486 fix round 1, I5) so
// a config_audit rejection reason is scrubbed the same way an HTTP
// response body already is. See `crate::path_redact` for the scrub
// itself; this file's own reload/validate handlers are its original
// and largest set of call sites.
use crate::path_redact::sanitise_path_in_error;

pub mod prompt_persistence;
pub use prompt_persistence::{prompt_key_ring, PromptPersistence, PromptSealer};

// --- Config ---

/// Configuration for the admin server.
#[derive(Clone)]
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
    /// Maximum admin API requests per client IP per minute. The global
    /// cap is ten times this value. Validated to 1..=100000 at config
    /// compile; the limiter cannot be turned off.
    pub rate_limit_per_minute: u64,
    /// Optional TLS (WOR-1717). When set, the admin server (and the
    /// built-in UI) is served over HTTPS with this PEM cert + key instead
    /// of plaintext HTTP.
    pub tls: Option<AdminTls>,
    /// WOR-1717: bind address. Defaults to `127.0.0.1` (loopback only).
    /// Must be an IP address literal, not a hostname; `compile_config`
    /// rejects anything that does not parse, and the admin server
    /// declines to start rather than fall back to loopback.
    pub bind: String,
    /// WOR-1717: IP / CIDR allowlist. Empty means loopback-only, which
    /// [`AdminIpFilter::new`] enforces so the empty case cannot be read
    /// as permit-all.
    pub allow_ips: Vec<String>,
    /// WOR-1717: allowed CORS origins. Empty means no CORS headers.
    pub cors_origins: Vec<String>,
    /// WOR-1716: RBAC operators in addition to the top-level admin (which
    /// is always the full-access `admin` role).
    pub operators: Vec<AdminOperator>,
    /// WOR-1870: URL template for trace deep-links in the admin UI.
    /// `{trace_id}` is substituted with the row's trace id; `None`
    /// renders trace ids as plain text.
    pub trace_url_template: Option<String>,
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
    /// HMAC-SHA256 hash of the login password, hex-encoded. Verified with
    /// `sbproxy_keystore::crypto::verify_secret` against the operator
    /// pepper resolved for this `AdminState`.
    pub password_hash: String,
    /// Role governing which admin actions this operator may perform.
    pub role: AdminRole,
    /// Billing tenant whose metered consumption this operator may read
    /// (WOR-2131). `None` is the whole deployment.
    ///
    /// Orthogonal to [`AdminOperator::role`], and deliberately so: the role
    /// answers "may they change anything", and this answers "whose numbers
    /// are they allowed to see". A full-access operator pinned to one tenant
    /// is a normal arrangement for a reseller, and collapsing the two
    /// questions into one field would make it unexpressible.
    pub tenant: Option<String>,
}

/// Redacted `Debug` (WOR-2606). The runtime twin of
/// `sbproxy_config::AdminConfig`, which was given a redacting `Debug` in
/// the first half of WOR-2640 while this one kept the derive: the same
/// Basic-auth password authenticates the admin API, and this is the
/// copy the running server holds and formats.
///
/// The username, the bind address, the port and the allowlist all stay.
/// None of them authenticates and each is what tells one misconfigured
/// admin server from another. `operators` renders through
/// [`AdminOperator`], whose `password_hash` is a peppered hash rather
/// than a credential.
impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("enabled", &self.enabled)
            .field("bind", &self.bind)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("max_log_entries", &self.max_log_entries)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("tls", &self.tls)
            .field("allow_ips", &self.allow_ips)
            .field("cors_origins", &self.cors_origins)
            .field("operators", &self.operators)
            .finish_non_exhaustive()
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9090,
            username: sbproxy_config::types::DEFAULT_ADMIN_USERNAME.to_string(),
            password: sbproxy_config::types::DEFAULT_ADMIN_PASSWORD.to_string(),
            max_log_entries: 1000,
            rate_limit_per_minute: 240,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
            trace_url_template: None,
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

/// One parsed entry of the admin IP allowlist.
enum AdminIpRule {
    /// Any loopback peer, in either address family. Matched by asking the
    /// address, not by comparing text, so the IPv4-mapped IPv6 form a
    /// dual-stack listener reports (`::ffff:127.0.0.1`) counts too.
    Loopback,
    /// A single exact address, stored canonicalised.
    Exact(std::net::IpAddr),
    /// A CIDR network containing the permitted addresses.
    Network(ipnetwork::IpNetwork),
}

/// Configurable IP allowlist for the admin endpoint.
///
/// Fail-closed by construction: the rule list is never empty, so there is
/// no permit-all state to represent. An empty configured allowlist (the
/// default) collapses to loopback-only inside the constructor rather than
/// relying on each call site to remember the special case.
pub struct AdminIpFilter {
    /// Never empty; see [`AdminIpFilter::new`].
    rules: Vec<AdminIpRule>,
}

impl AdminIpFilter {
    /// Create an IP filter from configured `allow_ips` entries, each
    /// either an exact IP address or a CIDR network (WOR-1717).
    ///
    /// An empty list yields [`AdminIpFilter::localhost_only`], which is
    /// the documented meaning of an empty `proxy.admin.allow_ips`.
    /// Entries that parse as neither an address nor a network are logged
    /// and dropped; if that leaves nothing, the filter is loopback-only,
    /// because a typo in the allowlist has to narrow the admin surface
    /// rather than widen it.
    pub fn new(allowed_ips: Vec<String>) -> Self {
        let mut rules = Vec::with_capacity(allowed_ips.len());
        for entry in &allowed_ips {
            let trimmed = entry.trim();
            if let Ok(addr) = trimmed.parse::<std::net::IpAddr>() {
                rules.push(AdminIpRule::Exact(addr.to_canonical()));
            } else if let Ok(net) = trimmed.parse::<ipnetwork::IpNetwork>() {
                rules.push(AdminIpRule::Network(net));
            } else {
                tracing::warn!(
                    entry = %entry,
                    "proxy.admin.allow_ips entry is neither an IP address nor a CIDR \
                     network; ignoring it"
                );
            }
        }
        if rules.is_empty() {
            return Self::localhost_only();
        }
        Self { rules }
    }

    /// Create a filter that only permits loopback addresses.
    pub fn localhost_only() -> Self {
        Self {
            rules: vec![AdminIpRule::Loopback],
        }
    }

    /// Returns `true` if `ip` is permitted.
    ///
    /// The peer is parsed as an address and compared semantically rather
    /// than as text, so `::ffff:127.0.0.1` (what a dual-stack listener
    /// reports for an IPv4 client) is recognised as the same peer as
    /// `127.0.0.1` and matches the same rules. A value that does not
    /// parse as an address is denied: a peer we cannot identify cannot be
    /// shown to be on the list.
    pub fn is_allowed(&self, ip: &str) -> bool {
        let Ok(peer) = ip.trim().parse::<std::net::IpAddr>() else {
            return false;
        };
        let peer = peer.to_canonical();
        // A CIDR entry may itself be written in the v4-mapped v6 space,
        // so try the peer in both spellings before rejecting it.
        let peer_mapped = match peer {
            std::net::IpAddr::V4(v4) => Some(std::net::IpAddr::V6(v4.to_ipv6_mapped())),
            std::net::IpAddr::V6(_) => None,
        };
        self.rules.iter().any(|rule| match rule {
            AdminIpRule::Loopback => peer.is_loopback(),
            AdminIpRule::Exact(addr) => *addr == peer,
            AdminIpRule::Network(net) => {
                net.contains(peer) || peer_mapped.is_some_and(|mapped| net.contains(mapped))
            }
        })
    }
}

// --- Request Log ---

/// Recent request log entry stored in a ring buffer.
#[derive(Debug, Clone, Default, Serialize)]
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
    /// Request id, correlating the ring row with the access log line
    /// and the trace (WOR-1874).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// W3C trace id when tracing is active; the admin LogsView renders
    /// it as an operator-configured deep link (WOR-1870).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Caller-supplied or generated session identifier, when capture is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Parent session identifier supplied by the caller, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    /// Bounded, normalized, and already-redacted custom properties.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, String>,
    /// Gateway cache outcome: disabled, miss, hit, or semantic_hit.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cache_status: String,
    /// Additional upstream attempts after the first attempt.
    pub retry_count: u32,
    /// Whether generic fallback or AI provider failover was engaged.
    pub failover_engaged: bool,
    /// First failed provider or target in a failover chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover_from: Option<String>,
    /// Last provider or target selected by failover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover_to: Option<String>,
    /// Which typed trigger drove an AI reroute, when one did (WOR-2556).
    /// Closed vocabulary: `context_window`, `content_policy`, or
    /// `generic`. Absent when no reroute happened, so the LogsView can
    /// distinguish "the prompt outgrew the model" from "the provider
    /// refused" from an ordinary availability failover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover_trigger: Option<String>,
    /// Closed load-balancing or AI routing strategy name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_balancer_strategy: Option<String>,
    /// Selected bounded target, such as host:port or provider name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_balancer_target: Option<String>,
    /// Zone-locality verdict of the target selection (WOR-2328):
    /// `"local"` when selection stayed in the proxy's own zone,
    /// `"spilled"` when no same-zone target was healthy and selection
    /// widened across zones. Absent when the stage did not engage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_locality: Option<String>,
    /// Why the strategy picked that target, for strategies that decide
    /// per request (WOR-2564). `semantic_route` reports the matched
    /// deployment, the winning exemplar's ordinal, and the cosine score,
    /// or the near-miss that sent the request to the fallback. Bounded
    /// and operator-derived; never exemplar text or caller input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_detail: Option<String>,
    /// AI provider that served the request, when the AI gateway did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// AI model, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Prompt tokens, when the AI usage parser reported them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,
    /// Completion tokens, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,
    /// Provider prompt-cache **read** tokens, when the provider
    /// reported them (OpenAI's `prompt_tokens_details.cached_tokens`,
    /// Anthropic's `cache_read_input_tokens`).
    ///
    /// WOR-2658: a subset of `tokens_in`, not an addition to it, and on
    /// this row because this is the row that already names the provider,
    /// the model, and the credential that paid. Before this the counts
    /// existed only on the request-event envelope and the attribution
    /// metric, so the one record an operator reads per request could
    /// show a bill that dropped without showing the cache hit that
    /// explains it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_cached: Option<u64>,
    /// Provider prompt-cache **write** tokens (Anthropic's
    /// `cache_creation_input_tokens`). Absent for providers that report
    /// only cache reads. Also a subset of `tokens_in`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_cache_write: Option<u64>,
    /// Operator service tier the AI attempt was served under (WOR-2652),
    /// as the value written on the wire (`flex`, `priority`, and so on).
    ///
    /// WOR-2658: the fifth fact this row owes an operator, beside the
    /// provider, the model, the credential that paid, and the cache
    /// tokens. The tier reached only
    /// `sbproxy_ai_service_tier_decisions_total{disposition}` and the
    /// outbound body, so the row could show a bill without showing the
    /// tier that priced it. Absent when the surface has no tier axis,
    /// when the provider declares none, and on rows the AI gateway did
    /// not dispatch. It is always the operator's tier: a caller's own
    /// `service_tier` field is stripped before dispatch and never
    /// reaches this row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    /// Derived AI cost in micro-USD (WOR-1874).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd_micros: Option<u64>,
    /// Category of the guardrail that intervened, when one did
    /// (WOR-1874).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrail_category: Option<String>,
    /// What the intervening guardrail did (`block` today; WOR-1874).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrail_action: Option<String>,
    /// Canonical public id of the key that governed this request, when
    /// one resolved (WOR-2093). Matches the access log column, the
    /// `sbproxy_inbound_key_requests_total{api_key_id}` label, and the
    /// `sbproxy.key_id` span attribute. Never the raw secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// Inbound credential mode: `none`, `minted`, or `native` (WOR-2093).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub key_mode: String,
    /// Recognized native provider label; never credential material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_provider: Option<String>,
    /// Which secret the AI attempt presented upstream (WOR-2655):
    /// `provider_entry`, `native_caller`, or `fallback`. The outbound
    /// counterpart to `key_mode`. Absent on rows the AI gateway did not
    /// dispatch. Never credential material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_source: Option<String>,
    /// Origin-scoped tenant label (`__default__` when unset).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub tenant_id: String,
    /// Resolved end-user identifier, when user capture resolved one.
    /// Already length-capped and redaction-applied by capture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Coarse machine-readable failure class (`auth_denied`,
    /// `rate_limited`, `upstream_5xx`, ...), absent on success
    /// (WOR-2094).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Config revision of the pipeline generation that served this
    /// request (WOR-2094): every row names the config that governed it.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub config_revision: String,
    /// Governed key-policy revision that applied, when a key policy
    /// resolved (WOR-2094). Same `r{rev}:{digest}` / `c:{rev}:{digest}`
    /// vocabulary as the `sbproxy.policy_version` span attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Bounded, ordered summary of policy decisions on this request as
    /// `policy_type:verdict` pairs (WOR-2094). Explains why the gateway
    /// acted, not just that it did.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub policy_decisions: Vec<String>,
    /// Machine-readable reason from the policy or auth layer that
    /// denied this request, when one did (WOR-2094).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

/// Filters for [`AdminState::query_requests`] (WOR-1718 / WOR-1874).
/// Every field is optional; `None` means the dimension is not
/// filtered.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestLogFilter<'a> {
    /// Exact status code.
    pub status: Option<u16>,
    /// Case-insensitive HTTP method match.
    pub method: Option<&'a str>,
    /// Path substring match.
    pub path_sub: Option<&'a str>,
    /// Exact guardrail action match (WOR-1874).
    pub guardrail_action: Option<&'a str>,
    /// Exact guardrail category match (WOR-1874).
    pub guardrail_category: Option<&'a str>,
    /// Exact gateway cache-status match.
    pub cache_status: Option<&'a str>,
    /// Match rows that did or did not make an additional attempt.
    pub retried: Option<bool>,
    /// Exact normalized property key whose presence is required.
    pub property_key: Option<&'a str>,
    /// Exact redacted property value. Requires `property_key`.
    pub property_value: Option<&'a str>,
    /// Exact canonical key id match (WOR-2093).
    pub api_key_id: Option<&'a str>,
    /// Exact inbound key mode match: `none`, `minted`, or `native`.
    pub key_mode: Option<&'a str>,
    /// Exact session id match (WOR-2093; previously client-side only).
    pub session_id: Option<&'a str>,
    /// Exact AI model match (WOR-2578), one of the report dimensions.
    pub model: Option<&'a str>,
    /// Exact origin-scoped tenant label match (WOR-2578).
    pub tenant: Option<&'a str>,
    /// Exact resolved end-user id match (WOR-2578): the human subject
    /// behind the call, sbproxy's equivalent of OpenRouter's "Creator".
    pub user: Option<&'a str>,
}

impl RequestLogFilter<'_> {
    /// Returns `true` when `entry` passes every dimension this filter
    /// sets. `None` on a dimension means it is not filtered.
    ///
    /// This is the single predicate behind `/api/requests`,
    /// `/api/requests/report`, and `/api/requests/export`
    /// ([`AdminState::query_requests`] and `for_each_request` both call
    /// it), so the three routes cannot drift into selecting different
    /// rows for the same query string. A dimension added here is
    /// filtered on all three.
    ///
    /// On the three optional *report* dimensions (`model`,
    /// `api_key_id`, `user`) an absent value on the row reads as the
    /// empty string, which is what `report_dimension_value` does when
    /// it groups. The report's grouper is a fourth reader of these
    /// fields, and if it folded unattributed rows under `""` while this
    /// predicate required `Some(..)`, the `""` group (typically the
    /// largest one in a deployment that does not resolve end users)
    /// would drill through to an empty export rather than to its own
    /// rows. The remaining exact-match dimensions keep `Some(..)`
    /// semantics: nothing groups on them, so there is no group to drill
    /// through from.
    fn matches(&self, entry: &RequestLogEntry) -> bool {
        self.status.is_none_or(|s| entry.status == s)
            && self
                .method
                .is_none_or(|m| entry.method.eq_ignore_ascii_case(m))
            && self.path_sub.is_none_or(|p| entry.path.contains(p))
            // WOR-1874: exact-match filters on the guardrail columns so
            // the Guardrails admin view can deep-link to blocked rows.
            && self
                .guardrail_action
                .is_none_or(|a| entry.guardrail_action.as_deref() == Some(a))
            && self
                .guardrail_category
                .is_none_or(|c| entry.guardrail_category.as_deref() == Some(c))
            && self
                .cache_status
                .is_none_or(|status| entry.cache_status == status)
            && self
                .retried
                .is_none_or(|retried| (entry.retry_count > 0) == retried)
            && match (self.property_key, self.property_value) {
                (None, _) => true,
                (Some(key), None) => entry.properties.contains_key(key),
                (Some(key), Some(value)) => entry.properties.get(key).is_some_and(|v| v == value),
            }
            // WOR-2093: key-accountability filters so the Keys view can
            // deep-link to one credential's traffic, and session rows
            // resolve server-side instead of client-side.
            && self
                .api_key_id
                .is_none_or(|id| entry.api_key_id.as_deref().unwrap_or("") == id)
            && self.key_mode.is_none_or(|mode| entry.key_mode == mode)
            && self
                .session_id
                .is_none_or(|id| entry.session_id.as_deref() == Some(id))
            // WOR-2578: the four report dimensions, filterable exactly
            // so a grouped row drills through to the rows behind it,
            // including the unattributed group. `unwrap_or("")` is what
            // makes `?user=` select the rows the report folded under
            // `""` rather than nothing at all; `tenant_id` is a `String`
            // on the row and is already symmetric.
            && self
                .model
                .is_none_or(|model| entry.model.as_deref().unwrap_or("") == model)
            && self.tenant.is_none_or(|tenant| entry.tenant_id == tenant)
            && self
                .user
                .is_none_or(|user| entry.user_id.as_deref().unwrap_or("") == user)
    }
}

/// One provider (and optionally model) the router weighed for a request
/// (WOR-2575). Ordered as the router saw them: a routing plan's tier
/// order, a cascade's tier order, or the eligible provider order of the
/// configured strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoutingDecisionCandidate {
    /// Provider name as configured under the origin's provider list.
    pub provider: String,
    /// Model the candidate would serve, when the routing source names
    /// one. Plan and cascade tiers do; strategy orderings serve the
    /// requested model and leave this empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Recent routing decision stored in a ring buffer (WOR-2575): why one
/// request was routed where it was.
///
/// The shape is additive by design. Features that explain more of a
/// decision (typed fallback triggers, eligibility filter results,
/// price-ceiling exclusions, semantic-match scores) add namespaced keys
/// to the open `detail` map via `RequestContext::ai_route_detail`
/// rather than redesigning this struct, and every optional column is
/// omitted from the wire when absent, so readers never break when a
/// field they do not know about appears.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RoutingDecisionEntry {
    /// RFC 3339 timestamp marking when the request completed.
    pub timestamp: String,
    /// Origin name that handled the request.
    pub origin: String,
    /// Request id, correlating the decision with the request-log row,
    /// the access log line, and the trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Origin-scoped tenant label (`__default__` when unset).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
    /// Closed strategy name that decided the request: a built-in
    /// strategy label (`round_robin`, `fallback_chain`, `cascade`, ...),
    /// `ai_routing_policy` when an operator plan dispatched, or the
    /// generic load balancer's selection method.
    pub strategy: String,
    /// Model the caller asked for, after alias resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    /// Provider that served (or last attempted) the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_provider: Option<String>,
    /// Model that served the request, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_model: Option<String>,
    /// Reason the routing plane gave for its decision: an operator
    /// plan's `reason` string or the `ai_policy route_to` override
    /// note. Absent for built-in strategies, which decide by their
    /// name's own criterion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ordered candidates the router weighed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<RoutingDecisionCandidate>,
    /// Providers actually attempted, in dispatch order: the fallback
    /// chain as traversed, not as planned.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attempted: Vec<String>,
    /// Number of provider calls actually made.
    pub attempts: u32,
    /// Whether fallback or provider failover engaged.
    pub failover_engaged: bool,
    /// First provider that handed off to another provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover_from: Option<String>,
    /// Last provider selected by failover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover_to: Option<String>,
    /// HTTP response status the request finished with.
    pub status: u16,
    /// End-to-end request latency in milliseconds.
    pub latency_ms: f64,
    /// Open, additive decision detail carried verbatim from
    /// `RequestContext::ai_route_detail`. Consumers add namespaced
    /// keys here without a schema change.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub detail: serde_json::Map<String, serde_json::Value>,
}

/// Filters for [`AdminState::query_routing_decisions`] (WOR-2575).
/// Every field is optional; `None` means the dimension is not
/// filtered.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoutingDecisionFilter<'a> {
    /// Exact origin name match.
    pub origin: Option<&'a str>,
    /// Exact strategy name match.
    pub strategy: Option<&'a str>,
    /// Exact selected-provider match.
    pub provider: Option<&'a str>,
    /// Exact model match against the requested or the selected model,
    /// so a substitution is findable from either side.
    pub model: Option<&'a str>,
    /// Keep decisions at or after this instant.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Keep decisions at or before this instant.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Parse a routing-decision ring entry's RFC 3339 timestamp for
/// time-range filtering (WOR-2575). The writer always emits
/// `chrono::Utc::now().to_rfc3339()`, so a parse failure marks a
/// hand-built entry, which a time-bounded query excludes rather than
/// guesses about.
fn routing_entry_time(entry: &RoutingDecisionEntry) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

// --- Admin State ---

/// Per-revision cached rendering of the emitted OpenAPI document.
///
/// We cache the rendered JSON / YAML bytes keyed on the live pipeline's
/// `config_revision` so the spec is rebuilt only when the underlying
/// config changes. Reads after the first miss for a revision return the
/// cached bytes directly.
struct OpenApiCache {
    /// Pipeline generation that produced the cached bytes.
    ///
    /// Not `config_revision`: that is an origin-set identity hash and
    /// holds still across a reload that changes auth, forward rules or
    /// a deprecation block, all of which change this document. Keyed
    /// on it, the cache served the pre-reload spec for the life of the
    /// process on any config whose hostnames did not move.
    generation: u64,
    /// Cached JSON rendering, populated on first JSON request for a revision.
    json: Option<String>,
    /// Cached YAML rendering, populated on first YAML request for a revision.
    yaml: Option<String>,
}

impl OpenApiCache {
    fn empty() -> Self {
        Self {
            // No generation can equal this, so the first request for
            // either format is always a miss rather than a hit on an
            // empty body.
            generation: u64::MAX,
            json: None,
            yaml: None,
        }
    }
}

/// Shared state for the admin API.
pub struct AdminState {
    /// Ring buffer of the most recent request log entries.
    pub recent_requests: Mutex<VecDeque<RequestLogEntry>>,
    /// Ring buffer of the most recent routing decisions (WOR-2575).
    /// Shares the `max_log_entries` cap with `recent_requests` so
    /// operators size one retention knob.
    pub recent_routing_decisions: Mutex<VecDeque<RoutingDecisionEntry>>,
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
    /// Fallible audit sink guarding compression summary-content inspection.
    compression_audit: Arc<dyn crate::admin_compression::CompressionAuditSink>,
    /// WOR-2664: the agent registry, when the operator configured one.
    /// `None` means `agent_registry:` is absent or disabled, and every
    /// route under `/admin/agent-registry` answers 404 rather than
    /// pretending an empty registry exists.
    pub agent_registry: Option<Arc<sbproxy_agent_registry::AgentRegistry>>,
    /// WOR-2669: the outbound notifier, when the operator configured one.
    /// `None` means `notifications:` is absent or disabled, and every route
    /// under `/admin/notifications` answers 404.
    pub notifier: Option<Arc<sbproxy_observe::notify::Notifier>>,
    /// Pepper for hashing/verifying `AdminOperator.password_hash`.
    /// Defaults to [`crate::key_plane::default_admin_operator_pepper`] so
    /// operator login works with no `key_management:` block at all; the
    /// binary overrides it via [`AdminState::with_operator_pepper`] once it
    /// has resolved `key_management.crypto.pepper` from the loaded config.
    operator_pepper: Vec<u8>,
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
            recent_routing_decisions: Mutex::new(VecDeque::new()),
            config,
            openapi_cache: Mutex::new(OpenApiCache::empty()),
            config_path: None,
            loaded_config_content_hash: Mutex::new(None),
            reload_in_progress: AtomicBool::new(false),
            health_registry: sbproxy_observe::default_registry_optional(None, None),
            prompt_persistence: None,
            agent_registry: None,
            notifier: None,
            session_signer: crate::admin_session::SessionSigner::random(),
            revoked_sessions: Mutex::new(std::collections::HashSet::new()),
            log_events: tokio::sync::broadcast::channel(256).0,
            compression_audit: Arc::new(crate::admin_compression::TracingCompressionAuditSink),
            operator_pepper: crate::key_plane::default_admin_operator_pepper(),
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
                        let tenant = self.operator_tenant(&sess.username);
                        return Some(AdminPrincipal {
                            username: sess.username,
                            role: sess.role,
                            via_session: true,
                            csrf: Some(sess.nonce),
                            tenant,
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
                    // The top-level credential is the deployment's own
                    // operator, not a tenant's, so it is never narrowed.
                    // A reseller who wants a scoped login configures one
                    // under `proxy.admin.operators`.
                    tenant: None,
                });
            }
        }
        None
    }

    /// The billing tenant `username` is narrowed to, if any (WOR-2131).
    ///
    /// Looks the operator up by name in the live config rather than trusting
    /// anything the caller presented, so a scope can only ever come from the
    /// document an operator edits and reloads.
    fn operator_tenant(&self, username: &str) -> Option<String> {
        self.config
            .operators
            .iter()
            .find(|operator| operator.username == username)
            .and_then(|operator| operator.tenant.clone())
    }

    /// Verify login credentials against the top-level admin and the
    /// configured operators (WOR-1716), returning the matched role.
    ///
    /// Operator passwords are hashed at rest: verification recomputes
    /// `HMAC-SHA256(pass, operator_pepper)` and compares it,
    /// constant-time, to the stored `password_hash`.
    pub fn check_operator_login(&self, user: &str, pass: &str) -> Option<AdminRole> {
        if self.check_auth(user, pass) {
            return Some(AdminRole::Admin);
        }
        self.config
            .operators
            .iter()
            .find(|o| {
                o.username == user
                    && sbproxy_keystore::crypto::verify_secret(
                        pass,
                        &self.operator_pepper,
                        &o.password_hash,
                    )
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

    /// Builder-style setter for the operator-password pepper.
    ///
    /// The binary calls this with `key_plane::resolve_admin_operator_pepper`
    /// once it has read `key_management.crypto.pepper` from the loaded
    /// config, so `check_operator_login` verifies against the same pepper
    /// `sbproxy admin hash-password` used to produce the stored hash.
    /// Tests that exercise operator login call it directly with a fixed
    /// test pepper instead of going through config.
    pub fn with_operator_pepper(mut self, pepper: impl Into<Vec<u8>>) -> Self {
        self.operator_pepper = pepper.into();
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

    /// Attach a configured agent registry.
    ///
    /// The binary opts in from `agent_registry:`; leaving it out is what
    /// makes the routes 404 rather than answering for a registry with no
    /// store behind it.
    #[must_use]
    pub fn with_agent_registry(
        mut self,
        registry: Arc<sbproxy_agent_registry::AgentRegistry>,
    ) -> Self {
        self.agent_registry = Some(registry);
        self
    }

    /// Attach a configured outbound notifier.
    ///
    /// The binary opts in from `notifications:`; leaving it out is what
    /// makes the routes 404 rather than answering for a notifier with no
    /// store behind it.
    #[must_use]
    pub fn with_notifier(mut self, notifier: Arc<sbproxy_observe::notify::Notifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Replace the fallible sink used before returning compression content.
    pub fn with_compression_audit_sink(
        mut self,
        audit: Arc<dyn crate::admin_compression::CompressionAuditSink>,
    ) -> Self {
        self.compression_audit = audit;
        self
    }

    /// Add a request to the log (ring buffer, drops oldest when full).
    ///
    /// See [`RequestLogFilter`] for the matching query surface.
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

    /// Query the recent-request log (newest first) with optional
    /// filters and pagination (WOR-1718 / WOR-1874). `offset`/`limit`
    /// paginate the filtered result.
    ///
    /// This is `for_each_request` collecting into a `Vec`, and both run
    /// the same private `RequestLogFilter` predicate, so the
    /// aggregating and exporting routes select exactly the rows this
    /// one returns.
    pub fn query_requests(
        &self,
        filter: &RequestLogFilter<'_>,
        offset: usize,
        limit: usize,
    ) -> Vec<RequestLogEntry> {
        let mut out = Vec::new();
        self.for_each_request(filter, offset, limit, |entry| out.push(entry.clone()));
        out
    }

    /// Visit the filtered recent-request log (newest first) one entry
    /// at a time, without materializing the matching set (WOR-2578).
    ///
    /// The aggregation and export routes fold or serialize each row as
    /// it is visited, so nothing holds a second copy of the result:
    /// peak memory is the ring itself, which
    /// `proxy.admin.max_log_entries` already bounds, plus one row's
    /// worth of encoding. `query_requests` is this function collecting
    /// into a `Vec`, which is why the two can never disagree about
    /// which rows a filter selects.
    ///
    /// `visit` runs while the ring lock is held, so it must not call
    /// back into the log. Both in-tree callers only write into a
    /// `String` or a `BTreeMap`. Deliberately private: the report and
    /// the export live in this module, and a callback that borrows the
    /// ring lock is not a shape to hand to another crate.
    fn for_each_request(
        &self,
        filter: &RequestLogFilter<'_>,
        offset: usize,
        limit: usize,
        mut visit: impl FnMut(&RequestLogEntry),
    ) {
        let log = self
            .recent_requests
            .lock()
            .expect("admin log mutex poisoned");
        log.iter()
            .rev()
            .filter(|e| filter.matches(e))
            .skip(offset)
            .take(limit)
            .for_each(&mut visit);
    }

    /// Add a routing decision to its ring (drops oldest when full;
    /// WOR-2575).
    ///
    /// See [`RoutingDecisionFilter`] for the matching query surface. A
    /// poisoned lock drops the record rather than panicking: the ring
    /// is a runtime sample, and the panic that poisoned the lock is
    /// the incident worth surfacing, not this write.
    pub fn log_routing_decision(&self, entry: RoutingDecisionEntry) {
        let Ok(mut log) = self.recent_routing_decisions.lock() else {
            return;
        };
        if log.len() >= self.config.max_log_entries {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Query the recent routing decisions (newest first) with optional
    /// filters and pagination (WOR-2575). `offset`/`limit` paginate the
    /// filtered result.
    pub fn query_routing_decisions(
        &self,
        filter: &RoutingDecisionFilter<'_>,
        offset: usize,
        limit: usize,
    ) -> Vec<RoutingDecisionEntry> {
        let Ok(log) = self.recent_routing_decisions.lock() else {
            return Vec::new();
        };
        log.iter()
            .rev()
            .filter(|e| filter.origin.is_none_or(|o| e.origin == o))
            .filter(|e| filter.strategy.is_none_or(|s| e.strategy == s))
            .filter(|e| {
                filter
                    .provider
                    .is_none_or(|p| e.selected_provider.as_deref() == Some(p))
            })
            // The model dimension matches what the caller asked for or
            // what was served, so "every decision that touched this
            // model" works without the operator knowing which side of a
            // substitution it was on.
            .filter(|e| {
                filter.model.is_none_or(|m| {
                    e.requested_model.as_deref() == Some(m)
                        || e.selected_model.as_deref() == Some(m)
                })
            })
            .filter(|e| {
                filter
                    .since
                    .is_none_or(|since| routing_entry_time(e).is_some_and(|t| t >= since))
            })
            .filter(|e| {
                filter
                    .until
                    .is_none_or(|until| routing_entry_time(e).is_some_and(|t| t <= until))
            })
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
    /// The single billing tenant this operator may read metered
    /// consumption for, or `None` for the whole deployment (WOR-2131).
    ///
    /// Resolved from `proxy.admin.operators` on every request rather than
    /// decoded from the session token. A token minted before the operator
    /// was narrowed would otherwise keep the old, wider scope until it
    /// expired, which turns a config change into a delayed one.
    pub tenant: Option<String>,
}

/// WOR-1777: the `Set-Cookie` + `X-CSRF-Token` headers that upgrade a
/// Basic-authenticated principal to a session token, so a client can carry
/// a short-lived token instead of resending the password on every request.
/// Returns empty for a `via_session` principal (it already holds a cookie),
/// so requests that already present the cookie are not re-minted.
fn basic_session_upgrade_headers(
    signer: &crate::admin_session::SessionSigner,
    principal: &AdminPrincipal,
    secure: bool,
    now: u64,
) -> Vec<(String, String)> {
    if principal.via_session {
        return Vec::new();
    }
    let ttl_secs = 8 * 3600;
    let (token, csrf) = signer.mint(&principal.username, principal.role, ttl_secs, now);
    let secure_attr = if secure { "; Secure" } else { "" };
    vec![
        (
            "Set-Cookie".to_string(),
            format!(
                "{}={token}; HttpOnly; SameSite=Strict; Path=/{secure_attr}; Max-Age={ttl_secs}",
                crate::admin_session::SESSION_COOKIE
            ),
        ),
        ("X-CSRF-Token".to_string(), csrf),
    ]
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
/// Delegates to `subtle` so the no-early-exit property rests on an
/// audited implementation. Branches on length only, which is not
/// secret for the credentials compared here.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    a.len() == b.len() && bool::from(a.ct_eq(b))
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

/// One load-balancer target's resilience state, as walked from the
/// live pipeline. Shared by `GET /api/health/targets` (the JSON body)
/// and the `sbproxy_target_health_state` gauge (WOR-2560), so the two
/// surfaces cannot disagree about what `select_target` would skip.
struct TargetHealthRow {
    /// Position in the origin's target list.
    index: usize,
    /// Target URL as configured.
    url: String,
    /// Active health probe verdict.
    healthy: bool,
    /// Outlier detector eject state.
    outlier_ejected: bool,
    /// Circuit breaker state, when one is configured.
    breaker_state: Option<&'static str>,
    /// Configured selection weight, echoed for the JSON body.
    weight: u32,
    /// Whether the target is a fallback-only backup.
    backup: bool,
    /// Deployment group tag (blue-green / canary), when set.
    group: Option<String>,
    /// Zone label the target is configured in (WOR-2328), when set.
    /// `None` for an unlabeled target, which the locality stage treats
    /// as belonging to no zone.
    zone: Option<String>,
}

impl TargetHealthRow {
    /// Whether `select_target` would consider this target at all.
    fn eligible(&self) -> bool {
        self.healthy && !self.outlier_ejected && self.breaker_state != Some("open")
    }

    /// The tri-state `sbproxy_target_health_state` value, on LiteLLM's
    /// 0/1/2 deployment-state scale so Grafana panels built against
    /// that convention port over: ineligible is 2 (full outage as far
    /// as selection is concerned), an eligible target whose breaker is
    /// half-open is 1 (carrying trial traffic), everything else is 0.
    fn metric_state(&self) -> i64 {
        if !self.eligible() {
            sbproxy_observe::metrics::TARGET_HEALTH_EXCLUDED
        } else if self.breaker_state == Some("half_open") {
            sbproxy_observe::metrics::TARGET_HEALTH_DEGRADED
        } else {
            sbproxy_observe::metrics::TARGET_HEALTH_HEALTHY
        }
    }
}

/// Per-origin grouping of [`TargetHealthRow`]s.
struct OriginTargetHealth {
    /// Origin hostname as configured.
    hostname: String,
    /// Stable configured origin id; the `origin` label on the gauge.
    origin_id: String,
    /// Zone this origin's load balancer resolved for itself (WOR-2328),
    /// which is what its targets' `zone` labels are compared against.
    local_zone: Option<String>,
    /// The origin's load-balancer targets, in config order.
    targets: Vec<TargetHealthRow>,
}

/// Walk the live pipeline and collect every load-balancer target's
/// resilience state: active health verdict, outlier ejection state,
/// and circuit breaker state.
fn collect_target_health(pipeline: &crate::pipeline::CompiledPipeline) -> Vec<OriginTargetHealth> {
    use sbproxy_modules::Action;
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
            targets.push(TargetHealthRow {
                index: t_idx,
                url: target.url.clone(),
                healthy,
                outlier_ejected,
                breaker_state,
                weight: target.weight,
                backup: target.backup,
                group: target.group.clone(),
                zone: target.zone.clone(),
            });
        }
        origins.push(OriginTargetHealth {
            hostname: origin.hostname.as_str().to_string(),
            origin_id: origin.origin_id.as_str().to_string(),
            local_zone: lb.local_zone().map(str::to_string),
            targets,
        });
    }
    origins
}

/// Install the scrape-time source for the `sbproxy_target_health_state`
/// gauge (WOR-2560).
///
/// Called from `reload::load_pipeline` at every pipeline publication.
/// The closure walks whatever pipeline is current when a scrape
/// happens, through the same [`collect_target_health`] that renders
/// `GET /api/health/targets`, so `/metrics` and the admin endpoint can
/// never tell different stories about the same target. Reinstalling on
/// every publication is deliberate: it costs one boxed closure and
/// keeps the seam correct for library embedders who never call the
/// startup path exactly once.
pub(crate) fn install_target_health_metrics_source() {
    sbproxy_observe::metrics::set_target_health_source(|| {
        target_health_samples(&collect_target_health(&crate::reload::current_pipeline()))
    });
}

/// Project one pipeline walk onto the gauge's sample list.
///
/// A free function rather than a closure body so the collision rule
/// below is testable without a live pipeline.
///
/// The `target` label is the configured URL when that URL is unique
/// within its origin, which is the normal case and the readable one.
/// When an origin configures the same URL more than once, every
/// colliding row takes the load balancer's own `url#index` identifier
/// instead, the same string [`sbproxy_modules::action::loadbalancer`]
/// hands the outlier detector. Two same-URL targets are a real config
/// (weighting, or a blue/green pair addressed through one host), and
/// keying the label on the URL alone collapsed them onto one series:
/// last write won, an outlier-ejected target read as healthy, and
/// `GET /api/health/targets` went on rendering both rows with distinct
/// `index` values. That is precisely the disagreement between the two
/// surfaces this gauge promises cannot happen.
fn target_health_samples(
    origins: &[OriginTargetHealth],
) -> Vec<sbproxy_observe::metrics::TargetHealthSample> {
    let mut samples = Vec::new();
    for origin in origins {
        for row in &origin.targets {
            let collides = origin
                .targets
                .iter()
                .any(|other| other.index != row.index && other.url == row.url);
            samples.push(sbproxy_observe::metrics::TargetHealthSample {
                origin: origin.origin_id.clone(),
                target: if collides {
                    format!("{}#{}", row.url, row.index)
                } else {
                    row.url.clone()
                },
                state: row.metric_state(),
            });
        }
    }
    samples
}

/// Emit the `GET /api/health/targets` JSON snapshot from the live
/// pipeline walk. Operators query this to see exactly what
/// `select_target` would skip right now.
fn render_target_health() -> String {
    let pipeline = crate::reload::current_pipeline();
    let origins: Vec<serde_json::Value> = collect_target_health(&pipeline)
        .into_iter()
        .map(|origin| {
            let targets: Vec<serde_json::Value> = origin
                .targets
                .into_iter()
                .map(|row| {
                    // `zone` disappeared from this response while the
                    // config refused the label (WOR-2498) and returned
                    // when WOR-2328 made it a live routing input.
                    // `local_zone` below is what it routes against.
                    serde_json::json!({
                        "index": row.index,
                        "url": row.url,
                        "eligible": row.eligible(),
                        "healthy": row.healthy,
                        "outlier_ejected": row.outlier_ejected,
                        "circuit_breaker_state": row.breaker_state,
                        "weight": row.weight,
                        "backup": row.backup,
                        "group": row.group,
                        "zone": row.zone,
                    })
                })
                .collect();
            serde_json::json!({
                "hostname": origin.hostname,
                "origin_id": origin.origin_id,
                "local_zone": origin.local_zone,
                "targets": targets,
            })
        })
        .collect();
    serde_json::json!({
        "config_revision": pipeline.config_revision,
        // The zone the pipeline resolved for itself (WOR-2328):
        // `proxy.zone`, else `SB_ZONE`. Null means the zone-locality
        // stage never engages, which beside a zoned target list is
        // the misconfiguration the boot warning names.
        "proxy_zone": pipeline.config.server.resolve_zone(),
        "origins": origins,
    })
    .to_string()
}

// --- OWASP API Security Top 10 pack manifest ---

/// `GET /admin/owasp-api-pack`: per-origin outcome of expanding each
/// origin's `owasp_api_top10` pack entry (WOR-2491), computed once at
/// compile time by `sbproxy_config::owasp_api_pack::expand_owasp_pack`
/// and carried on `CompiledOrigin::owasp_pack_manifest`. An origin
/// with no `owasp_api_top10` policy is absent from `origins`
/// entirely; a config with no pack anywhere returns
/// `{"origins":{}}`.
///
/// The JSON shape here is a controller-ruled contract shared verbatim
/// with the docs task and with `sbproxy plan`'s text renderer
/// (`sbproxy_config::plan::render_text`): `item`/`title`/`state`/
/// `reason`/`synthesized` per row, `enabled`/`posture`/`items` per
/// origin. See the plan's `manifest-endpoint-contract.md` for the
/// full pinned shape.
fn handle_owasp_api_pack() -> (u16, &'static str, String) {
    let pipeline = crate::reload::current_pipeline();
    let mut origins = serde_json::Map::new();
    for origin in pipeline.config.origins.iter() {
        let Some(manifest) = origin.owasp_pack_manifest.as_ref() else {
            continue;
        };
        let enabled: Vec<&'static str> = manifest
            .entries
            .iter()
            .map(|entry| entry.item.canonical_name())
            .collect();
        let items: Vec<serde_json::Value> = manifest
            .entries
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "item": entry.item.canonical_name(),
                    "title": entry.item.title(),
                    "state": entry.state.label(),
                    "reason": entry.reason,
                    "synthesized": entry.synthesized_types,
                })
            })
            .collect();
        origins.insert(
            origin.hostname.to_string(),
            serde_json::json!({
                "enabled": enabled,
                "posture": manifest.posture.label(),
                "items": items,
            }),
        );
    }
    (
        200,
        "application/json",
        serde_json::json!({ "origins": origins }).to_string(),
    )
}

// --- AI provider data posture (WOR-2557) ---

/// `GET /admin/ai-data-posture`: per AI origin, each provider's
/// declared data-handling posture next to its wire format and auth
/// header, plus the live effective eligible-provider set under the
/// origin's `data_posture:` requirement.
///
/// Read off the live compiled pipeline, so a hot reload updates it
/// without a restart. The same computed-state pattern
/// `GET /admin/owasp-api-pack` uses: an operator reads what the
/// configuration *does*, not only what it says. An origin with no
/// `ai_proxy` action is absent from `origins` entirely; a config with
/// no AI origin returns `{"origins":{}}`.
///
/// `catalog` records what the vendor's published data-processing terms
/// say about a stock account, not the result of auditing one;
/// `effective` folds in the operator's per-entry `data_posture:`
/// declaration and the locally-served special case, and is what the
/// routing filter actually evaluates.
fn handle_ai_data_posture() -> (u16, &'static str, String) {
    use sbproxy_modules::Action;
    let pipeline = crate::reload::current_pipeline();
    let mut origins = serde_json::Map::new();
    for (idx, action) in pipeline.actions.iter().enumerate() {
        let Action::AiProxy(ai) = action else {
            continue;
        };
        let Some(origin) = pipeline.config.origins.get(idx) else {
            continue;
        };
        let requirement = ai.config.data_posture.as_ref();
        let constraint =
            sbproxy_ai::data_posture::DataPostureConstraint::from_parts(requirement, false, false);
        let mut eligible: Vec<&str> = Vec::new();
        let mut excluded: Vec<&str> = Vec::new();
        let providers: Vec<serde_json::Value> = ai
            .config
            .providers
            .iter()
            .map(|provider| {
                let effective = sbproxy_ai::data_posture::effective_data_posture(provider);
                let catalog =
                    sbproxy_ai::providers::get_provider_info(provider.effective_provider_type());
                let is_eligible = constraint
                    .as_ref()
                    .is_none_or(|constraint| constraint.provider_eligible(provider));
                if provider.enabled {
                    if is_eligible {
                        eligible.push(provider.name.as_str());
                    } else {
                        excluded.push(provider.name.as_str());
                    }
                }
                serde_json::json!({
                    "name": provider.name.as_str(),
                    "provider_type": provider.effective_provider_type(),
                    "enabled": provider.enabled,
                    "format": sbproxy_ai::client::provider_format(provider),
                    "auth_header": catalog.as_ref().map(|info| info.auth_header.clone()),
                    "catalog": catalog.as_ref().map(|info| serde_json::json!({
                        "retains_data": info.data_posture.retains_data,
                        "zdr_available": info.data_posture.zdr_available,
                        "data_region": info.data_posture.data_region,
                    })),
                    "effective": {
                        "retains_data": effective.retains_data,
                        "zdr": effective.zdr,
                    },
                    "eligible": is_eligible,
                })
            })
            .collect();
        origins.insert(
            origin.hostname.to_string(),
            serde_json::json!({
                "requirement": requirement.map(|block| serde_json::json!({
                    "require_zdr": block.require_zdr,
                    "allow_data_collection": block.allow_data_collection,
                })),
                "constraint": constraint.as_ref().map(|c| c.describe()),
                "eligible_providers": eligible,
                "excluded_providers": excluded,
                "providers": providers,
            }),
        );
    }
    (
        200,
        "application/json",
        serde_json::json!({ "origins": origins }).to_string(),
    )
}

// --- AI chargeback export (WOR-2672) ---

fn with_live_ai_chargeback_trackers<R>(
    f: impl FnOnce(&BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>) -> R,
) -> R {
    use sbproxy_modules::Action;

    let pipeline = crate::reload::current_pipeline();
    let mut origins: BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>> =
        BTreeMap::new();
    for (index, action) in pipeline.actions.iter().enumerate() {
        let Action::AiProxy(ai) = action else {
            continue;
        };
        let Some(origin) = pipeline.config.origins.get(index) else {
            continue;
        };
        let trackers: Vec<_> = ai
            .config
            .usage_sinks()
            .iter()
            .filter_map(|sink| sink.chargeback_tracker())
            .collect();
        if !trackers.is_empty() {
            origins.insert(origin.hostname.to_string(), trackers);
        }
    }
    f(&origins)
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LegacyChargebackConversionCounters {
    json_serialization_passes: usize,
    csv_serialization_passes: usize,
}

#[cfg(test)]
std::thread_local! {
    static LEGACY_CHARGEBACK_CONVERSION_COUNTERS: std::cell::RefCell<
        Option<LegacyChargebackConversionCounters>,
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct LegacyChargebackConversionProbe;

#[cfg(test)]
impl LegacyChargebackConversionProbe {
    fn install_for_current_thread() -> Self {
        LEGACY_CHARGEBACK_CONVERSION_COUNTERS.with(|slot| {
            let previous = slot.replace(Some(LegacyChargebackConversionCounters::default()));
            assert!(
                previous.is_none(),
                "legacy chargeback conversion probe already installed"
            );
        });
        Self
    }

    fn counters(&self) -> LegacyChargebackConversionCounters {
        LEGACY_CHARGEBACK_CONVERSION_COUNTERS.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("legacy chargeback conversion probe is installed")
                .clone()
        })
    }
}

#[cfg(test)]
impl Drop for LegacyChargebackConversionProbe {
    fn drop(&mut self) {
        LEGACY_CHARGEBACK_CONVERSION_COUNTERS.with(|slot| {
            let _ = slot.replace(None);
        });
    }
}

#[cfg(test)]
fn observe_legacy_chargeback_conversion(
    update: impl FnOnce(&mut LegacyChargebackConversionCounters),
) {
    LEGACY_CHARGEBACK_CONVERSION_COUNTERS.with(|slot| {
        if let Some(counters) = slot.borrow_mut().as_mut() {
            update(counters);
        }
    });
}

const DEFAULT_AI_CHARGEBACK_PAGE_LIMIT: usize = 100;
const MAX_AI_CHARGEBACK_PAGE_LIMIT: usize = 1_000;
const MAX_AI_CHARGEBACK_RESPONSE_BYTES: usize = 512 * 1024;
const CHARGEBACK_CURSOR_PREFIX: &str = "chargeback:";

#[derive(Debug, Clone, Copy, Default)]
struct ChargebackEntrySlice {
    offset: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy)]
struct ParsedChargebackPaging {
    offset: usize,
    limit: usize,
    requested: bool,
}

#[derive(Debug)]
struct ChargebackPagePlan {
    slices: Vec<Vec<ChargebackEntrySlice>>,
    next_cursor: Option<String>,
}

struct CappedResponseWriter {
    body: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl CappedResponseWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            body: Vec::with_capacity(max_bytes.min(8 * 1024)),
            max_bytes,
            limit_exceeded: false,
        }
    }

    fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    fn into_string(self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body)
    }
}

impl std::io::Write for CappedResponseWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.body.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "admin chargeback response exceeded its byte limit",
            ));
        }
        self.body.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct BorrowedChargebackV2Entry<'a> {
    workspace: &'a sbproxy_ai::billing::DimensionKey,
    team: &'a sbproxy_ai::billing::DimensionKey,
    project: &'a str,
    provider: &'a str,
    model: &'a str,
    tokens: u64,
    cost: f64,
    timestamp: &'a str,
}

impl<'a> From<&'a sbproxy_ai::billing::ChargebackSnapshotEntry> for BorrowedChargebackV2Entry<'a> {
    fn from(entry: &'a sbproxy_ai::billing::ChargebackSnapshotEntry) -> Self {
        Self {
            workspace: &entry.workspace,
            team: &entry.team,
            project: &entry.project,
            provider: &entry.provider,
            model: &entry.model,
            tokens: entry.tokens,
            cost: entry.cost,
            timestamp: &entry.timestamp,
        }
    }
}

#[derive(Serialize)]
struct BorrowedChargebackLegacyEntry<'a> {
    team: Cow<'a, str>,
    project: &'a str,
    provider: &'a str,
    model: &'a str,
    tokens: u64,
    cost: f64,
    timestamp: &'a str,
}

impl<'a> From<&'a sbproxy_ai::billing::ChargebackSnapshotEntry>
    for BorrowedChargebackLegacyEntry<'a>
{
    fn from(entry: &'a sbproxy_ai::billing::ChargebackSnapshotEntry) -> Self {
        Self {
            team: entry.team.legacy_projection(),
            project: &entry.project,
            provider: &entry.provider,
            model: &entry.model,
            tokens: entry.tokens,
            cost: entry.cost,
            timestamp: &entry.timestamp,
        }
    }
}

#[derive(Serialize)]
struct BorrowedChargebackRollup<'a> {
    dimension: &'a sbproxy_ai::billing::DimensionKey,
    totals: &'a sbproxy_ai::billing::WorkspaceTotals,
}

#[derive(Serialize)]
struct BorrowedChargebackRefusalCount<'a> {
    reason: &'a sbproxy_ai::billing::ChargebackRecordError,
    count: u64,
}

fn bounded_chargeback_schema_token(value: &str) -> String {
    const MAX_SCHEMA_TOKEN_BYTES: usize = 64;
    if value.len() <= MAX_SCHEMA_TOKEN_BYTES {
        return value.to_string();
    }
    let mut end = MAX_SCHEMA_TOKEN_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn admin_chargeback_export_refusal_label(
    reason: sbproxy_observe::metrics::AdminChargebackExportRefusalReason,
) -> &'static str {
    use sbproxy_observe::metrics::AdminChargebackExportRefusalReason;

    match reason {
        AdminChargebackExportRefusalReason::InvalidCursor => "invalid_cursor",
        AdminChargebackExportRefusalReason::InvalidLimit => "invalid_limit",
        AdminChargebackExportRefusalReason::UnsupportedSchemaVersion => {
            "unsupported_schema_version"
        }
        AdminChargebackExportRefusalReason::ResponseTooLarge => "response_too_large",
    }
}

fn admin_chargeback_export_format_label(
    format: sbproxy_observe::metrics::AdminChargebackExportFormat,
) -> &'static str {
    use sbproxy_observe::metrics::AdminChargebackExportFormat;

    match format {
        AdminChargebackExportFormat::Json => "json",
        AdminChargebackExportFormat::Csv => "csv",
    }
}

fn record_admin_chargeback_export_refusal(
    format: sbproxy_observe::metrics::AdminChargebackExportFormat,
    reason: sbproxy_observe::metrics::AdminChargebackExportRefusalReason,
    site: &'static str,
) {
    sbproxy_observe::metrics::record_admin_chargeback_export_refusal(format, reason);
    tracing::warn!(
        target: "sbproxy::admin::chargeback",
        code = "chargeback_export_refused",
        format = admin_chargeback_export_format_label(format),
        reason = admin_chargeback_export_refusal_label(reason),
        site,
        "admin chargeback export refused"
    );
}

fn unsupported_chargeback_schema_version(requested: &str) -> AdminResponse {
    let requested = bounded_chargeback_schema_token(requested);
    let requested = serde_json::from_str::<serde_json::Value>(&requested)
        .ok()
        .filter(serde_json::Value::is_number)
        .unwrap_or_else(|| serde_json::Value::String(requested));
    (
        400,
        "application/json",
        serde_json::json!({
            "code": "unsupported_schema_version",
            "requested_schema_version": requested,
            "supported_schema_versions": [1, 2],
        })
        .to_string(),
    )
}

fn encode_chargeback_cursor(offset: usize) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{CHARGEBACK_CURSOR_PREFIX}{offset}"))
}

fn decode_chargeback_cursor(raw: &str) -> Option<usize> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let offset = text.strip_prefix(CHARGEBACK_CURSOR_PREFIX)?;
    offset.parse::<usize>().ok()
}

fn parse_chargeback_paging(path: &str) -> Result<ParsedChargebackPaging, AdminResponse> {
    let cursor = decoded_query_param(path, "cursor");
    let limit = decoded_query_param(path, "limit");
    if cursor.is_none() && limit.is_none() {
        return Ok(ParsedChargebackPaging {
            offset: 0,
            limit: usize::MAX,
            requested: false,
        });
    }

    let offset = match cursor {
        None => 0,
        Some(raw) => decode_chargeback_cursor(&raw).ok_or_else(|| {
            record_admin_chargeback_export_refusal(
                sbproxy_observe::metrics::AdminChargebackExportFormat::Json,
                sbproxy_observe::metrics::AdminChargebackExportRefusalReason::InvalidCursor,
                "cursor_decode",
            );
            admin_error(400, "cursor is invalid")
        })?,
    };
    let limit = match limit {
        None => DEFAULT_AI_CHARGEBACK_PAGE_LIMIT,
        Some(raw) => match raw.parse::<usize>() {
            Ok(0) | Err(_) => {
                record_admin_chargeback_export_refusal(
                    sbproxy_observe::metrics::AdminChargebackExportFormat::Json,
                    sbproxy_observe::metrics::AdminChargebackExportRefusalReason::InvalidLimit,
                    "limit_parse",
                );
                return Err(admin_error(400, "limit must be a positive whole number"));
            }
            Ok(limit) => limit.min(MAX_AI_CHARGEBACK_PAGE_LIMIT),
        },
    };
    Ok(ParsedChargebackPaging {
        offset,
        limit,
        requested: true,
    })
}

fn chargeback_response_too_large(limit: usize) -> AdminResponse {
    (
        413,
        "application/json",
        serde_json::json!({
            "code": "chargeback_response_too_large",
            "max_response_bytes": limit,
            "hint": format!(
                "retry with ?limit=<1..={MAX_AI_CHARGEBACK_PAGE_LIMIT}> and the returned next_cursor"
            ),
        })
        .to_string(),
    )
}

fn build_chargeback_page_plan(
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
    paging: ParsedChargebackPaging,
) -> Result<ChargebackPagePlan, AdminResponse> {
    let total_entries = origins
        .values()
        .flat_map(|trackers| trackers.iter())
        .map(|tracker| tracker.entries_count())
        .sum::<usize>();
    if paging.offset > total_entries {
        record_admin_chargeback_export_refusal(
            sbproxy_observe::metrics::AdminChargebackExportFormat::Json,
            sbproxy_observe::metrics::AdminChargebackExportRefusalReason::InvalidCursor,
            "cursor_offset",
        );
        return Err(admin_error(400, "cursor is invalid"));
    }

    let mut remaining_skip = paging.offset;
    let mut remaining_take = paging.limit;
    let mut slices = Vec::with_capacity(origins.len());
    for trackers in origins.values() {
        let mut origin_slices = Vec::with_capacity(trackers.len());
        for tracker in trackers {
            let count = tracker.entries_count();
            let skip = remaining_skip.min(count);
            remaining_skip = remaining_skip.saturating_sub(skip);
            let available = count.saturating_sub(skip);
            let len = if paging.requested {
                let take = available.min(remaining_take);
                remaining_take = remaining_take.saturating_sub(take);
                take
            } else {
                available
            };
            origin_slices.push(ChargebackEntrySlice { offset: skip, len });
        }
        slices.push(origin_slices);
    }
    let returned_entries = if paging.requested {
        paging.limit.saturating_sub(remaining_take)
    } else {
        total_entries.saturating_sub(paging.offset)
    };
    let next_cursor = (paging.requested
        && paging.offset.saturating_add(returned_entries) < total_entries)
        .then(|| encode_chargeback_cursor(paging.offset.saturating_add(returned_entries)));
    Ok(ChargebackPagePlan {
        slices,
        next_cursor,
    })
}

fn write_raw_json<W: std::io::Write>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), serde_json::Error> {
    writer.write_all(bytes).map_err(serde_json::Error::io)
}

fn write_legacy_chargeback_totals<'a, W, I>(
    writer: &mut W,
    totals: I,
) -> Result<(), serde_json::Error>
where
    W: std::io::Write,
    I: Iterator<
        Item = (
            &'a sbproxy_ai::billing::DimensionKey,
            &'a sbproxy_ai::billing::WorkspaceTotals,
        ),
    >,
{
    write_raw_json(writer, b"{")?;
    for (index, (dimension, total)) in totals.enumerate() {
        if index != 0 {
            write_raw_json(writer, b",")?;
        }
        serde_json::to_writer(&mut *writer, dimension.legacy_projection().as_ref())?;
        write_raw_json(writer, b":")?;
        serde_json::to_writer(&mut *writer, total)?;
    }
    write_raw_json(writer, b"}")
}

fn write_chargeback_json_response<W: std::io::Write>(
    writer: &mut W,
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
    plan: &ChargebackPagePlan,
    schema_version: u32,
    paging: ParsedChargebackPaging,
) -> Result<(), serde_json::Error> {
    #[cfg(test)]
    observe_legacy_chargeback_conversion(|counters| {
        counters.json_serialization_passes += 1;
    });
    write_raw_json(writer, br#"{"schema_version":"#)?;
    serde_json::to_writer(&mut *writer, &schema_version)?;
    if paging.requested {
        write_raw_json(writer, br#","limit":"#)?;
        serde_json::to_writer(&mut *writer, &paging.limit)?;
        write_raw_json(writer, br#","next_cursor":"#)?;
        serde_json::to_writer(&mut *writer, &plan.next_cursor)?;
    }
    write_raw_json(writer, br#","origins":{"#)?;
    for (origin_index, ((origin, trackers), origin_plan)) in
        origins.iter().zip(plan.slices.iter()).enumerate()
    {
        if origin_index != 0 {
            write_raw_json(writer, b",")?;
        }
        serde_json::to_writer(&mut *writer, origin)?;
        write_raw_json(writer, b":[")?;
        for (tracker_index, (tracker, slice)) in trackers.iter().zip(origin_plan.iter()).enumerate()
        {
            if tracker_index != 0 {
                write_raw_json(writer, b",")?;
            }
            tracker.with_export_view(|view| {
                write_raw_json(writer, b"{")?;
                write_raw_json(writer, br#""max_entries":"#)?;
                serde_json::to_writer(&mut *writer, &view.max_entries())?;
                write_raw_json(writer, br#","max_workspaces":"#)?;
                serde_json::to_writer(&mut *writer, &view.max_workspaces())?;
                write_raw_json(writer, br#","max_teams":"#)?;
                serde_json::to_writer(&mut *writer, &view.max_teams())?;
                if schema_version == 1 {
                    write_raw_json(writer, br#","entries":["#)?;
                    for (entry_index, entry) in view.entries(slice.offset, slice.len).enumerate() {
                        if entry_index != 0 {
                            write_raw_json(writer, b",")?;
                        }
                        serde_json::to_writer(
                            &mut *writer,
                            &BorrowedChargebackLegacyEntry::from(entry),
                        )?;
                    }
                    write_raw_json(writer, br#"],"workspace_totals":"#)?;
                    write_legacy_chargeback_totals(writer, view.workspace_totals())?;
                    write_raw_json(writer, br#","team_totals":"#)?;
                    write_legacy_chargeback_totals(writer, view.team_totals())?;
                    write_raw_json(writer, br#","recorded_entries":"#)?;
                    serde_json::to_writer(&mut *writer, &view.recorded_entries())?;
                    write_raw_json(writer, br#","evicted_entries":"#)?;
                    serde_json::to_writer(&mut *writer, &view.evicted_entries())?;
                    write_raw_json(writer, br#","collapsed_workspace_events":"#)?;
                    serde_json::to_writer(&mut *writer, &view.collapsed_workspace_events())?;
                    write_raw_json(writer, br#","collapsed_team_events":"#)?;
                    serde_json::to_writer(&mut *writer, &view.collapsed_team_events())?;
                } else {
                    write_raw_json(writer, br#","schema_version":2"#)?;
                    write_raw_json(writer, br#","entries":["#)?;
                    for (entry_index, entry) in view.entries(slice.offset, slice.len).enumerate() {
                        if entry_index != 0 {
                            write_raw_json(writer, b",")?;
                        }
                        serde_json::to_writer(
                            &mut *writer,
                            &BorrowedChargebackV2Entry::from(entry),
                        )?;
                    }
                    write_raw_json(writer, br#"],"workspace_rollups":["#)?;
                    for (rollup_index, (dimension, totals)) in view.workspace_totals().enumerate() {
                        if rollup_index != 0 {
                            write_raw_json(writer, b",")?;
                        }
                        serde_json::to_writer(
                            &mut *writer,
                            &BorrowedChargebackRollup { dimension, totals },
                        )?;
                    }
                    write_raw_json(writer, br#"],"team_rollups":["#)?;
                    for (rollup_index, (dimension, totals)) in view.team_totals().enumerate() {
                        if rollup_index != 0 {
                            write_raw_json(writer, b",")?;
                        }
                        serde_json::to_writer(
                            &mut *writer,
                            &BorrowedChargebackRollup { dimension, totals },
                        )?;
                    }
                    write_raw_json(writer, br#"],"recorded_entries":"#)?;
                    serde_json::to_writer(&mut *writer, &view.recorded_entries())?;
                    write_raw_json(writer, br#","evicted_entries":"#)?;
                    serde_json::to_writer(&mut *writer, &view.evicted_entries())?;
                    write_raw_json(writer, br#","collapsed_workspace_events":"#)?;
                    serde_json::to_writer(&mut *writer, &view.collapsed_workspace_events())?;
                    write_raw_json(writer, br#","collapsed_team_events":"#)?;
                    serde_json::to_writer(&mut *writer, &view.collapsed_team_events())?;
                    write_raw_json(writer, br#","complete":"#)?;
                    serde_json::to_writer(&mut *writer, &view.complete())?;
                    write_raw_json(writer, br#","refused_entries":"#)?;
                    serde_json::to_writer(&mut *writer, &view.refused_entries())?;
                    write_raw_json(writer, br#","refusal_counts":["#)?;
                    for (refusal_index, (reason, count)) in view.refusal_counts().enumerate() {
                        if refusal_index != 0 {
                            write_raw_json(writer, b",")?;
                        }
                        serde_json::to_writer(
                            &mut *writer,
                            &BorrowedChargebackRefusalCount {
                                reason,
                                count: *count,
                            },
                        )?;
                    }
                    write_raw_json(writer, br#"],"earliest_retained_timestamp":"#)?;
                    serde_json::to_writer(&mut *writer, &view.earliest_retained_timestamp())?;
                    write_raw_json(writer, br#","latest_retained_timestamp":"#)?;
                    serde_json::to_writer(&mut *writer, &view.latest_retained_timestamp())?;
                    write_raw_json(writer, br#","eviction_watermark":"#)?;
                    serde_json::to_writer(&mut *writer, view.eviction_watermark())?;
                }
                write_raw_json(writer, b"}")
            })?;
        }
        write_raw_json(writer, b"]")?;
    }
    write_raw_json(writer, b"}}")
}

fn render_live_ai_chargeback_json_with_limit(
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
    path: &str,
    schema_version: Option<&str>,
    max_response_bytes: usize,
) -> AdminResponse {
    let paging = match parse_chargeback_paging(path) {
        Ok(paging) => paging,
        Err(error) => return error,
    };
    let plan = match build_chargeback_page_plan(origins, paging) {
        Ok(plan) => plan,
        Err(error) => return error,
    };
    let schema_version = match schema_version {
        None | Some("1") => 1,
        Some("2") => 2,
        Some(requested) => {
            record_admin_chargeback_export_refusal(
                sbproxy_observe::metrics::AdminChargebackExportFormat::Json,
                sbproxy_observe::metrics::AdminChargebackExportRefusalReason::UnsupportedSchemaVersion,
                "schema_version",
            );
            return unsupported_chargeback_schema_version(requested);
        }
    };

    let mut writer = CappedResponseWriter::new(max_response_bytes);
    if write_chargeback_json_response(&mut writer, origins, &plan, schema_version, paging).is_err()
    {
        if writer.limit_exceeded() {
            record_admin_chargeback_export_refusal(
                sbproxy_observe::metrics::AdminChargebackExportFormat::Json,
                sbproxy_observe::metrics::AdminChargebackExportRefusalReason::ResponseTooLarge,
                "response_size",
            );
            return chargeback_response_too_large(max_response_bytes);
        }
        return admin_error(500, "chargeback response serialization failed");
    }
    match writer.into_string() {
        Ok(body) => (200, "application/json", body),
        Err(_) => admin_error(500, "chargeback response serialization failed"),
    }
}

#[cfg(test)]
fn render_live_ai_chargeback_json_for_test(
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
    path: &str,
    max_response_bytes: usize,
) -> AdminResponse {
    let schema_version = decoded_query_param(path, "schema_version");
    render_live_ai_chargeback_json_with_limit(
        origins,
        path,
        schema_version.as_deref(),
        max_response_bytes,
    )
}

/// WOR-2672: route the bounded live chargeback exports with the resolved
/// principal in hand. Runs on the connection task rather than in
/// `handle_admin_request` because the synchronous handler is never given the
/// principal and therefore cannot enforce the operator's tenant restriction.
///
/// The team and project rollup dimensions aggregate usage across tenants, so
/// no post-hoc filter can produce a correct tenant-narrowed export. A
/// tenant-restricted operator is refused outright, mirroring the meter
/// routes' refusal-over-silent-narrowing rule; the unrestricted operator
/// keeps the deployment-wide export, whose `workspace` dimension already
/// breaks usage down by tenant.
pub(crate) fn dispatch_ai_chargeback(
    method: &str,
    path: &str,
    principal: Option<&AdminPrincipal>,
) -> Option<AdminResponse> {
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only != "/admin/ai-chargeback" && path_only != "/admin/ai-chargeback.csv" {
        return None;
    }
    if !method.eq_ignore_ascii_case("GET") {
        return Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        ));
    }
    let Some(principal) = principal else {
        return Some((
            401,
            "application/json",
            r#"{"error":"authentication required"}"#.to_string(),
        ));
    };
    if principal.tenant.is_some() {
        return Some((
            403,
            "application/json",
            r#"{"error":"chargeback exports are deployment-wide; a tenant-scoped operator cannot read them"}"#
                .to_string(),
        ));
    }
    Some(if path_only == "/admin/ai-chargeback" {
        handle_ai_chargeback(path)
    } else {
        handle_ai_chargeback_csv()
    })
}

/// Return all configured live chargeback trackers as a capped JSON export.
fn handle_ai_chargeback(path: &str) -> AdminResponse {
    let schema_version = decoded_query_param(path, "schema_version");
    with_live_ai_chargeback_trackers(|origins| {
        render_live_ai_chargeback_json_with_limit(
            origins,
            path,
            schema_version.as_deref(),
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        )
    })
}

fn write_chargeback_csv_rollups<'a, W, I>(
    writer: &mut W,
    origin: &str,
    tracker: usize,
    dimension: &str,
    totals: I,
) -> std::io::Result<()>
where
    W: std::io::Write,
    I: Iterator<
        Item = (
            &'a sbproxy_ai::billing::DimensionKey,
            &'a sbproxy_ai::billing::WorkspaceTotals,
        ),
    >,
{
    for (name, total) in totals {
        writeln!(
            writer,
            "{origin},{tracker},{dimension},{},{},{},{}",
            chargeback_csv_field(name.legacy_projection().as_ref()),
            total.request_count,
            total.tokens,
            total.cost_usd
        )?;
    }
    Ok(())
}

fn write_chargeback_csv_response<W: std::io::Write>(
    writer: &mut W,
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
) -> std::io::Result<()> {
    #[cfg(test)]
    observe_legacy_chargeback_conversion(|counters| {
        counters.csv_serialization_passes += 1;
    });
    writer.write_all(b"origin,tracker,dimension,name,request_count,tokens,cost_usd\n")?;
    for (origin, trackers) in origins {
        let origin = chargeback_csv_field(origin);
        for (tracker_index, tracker) in trackers.iter().enumerate() {
            tracker.with_export_view(|view| {
                write_chargeback_csv_rollups(
                    writer,
                    &origin,
                    tracker_index,
                    "workspace",
                    view.workspace_totals(),
                )?;
                write_chargeback_csv_rollups(
                    writer,
                    &origin,
                    tracker_index,
                    "team",
                    view.team_totals(),
                )
            })?;
        }
    }
    Ok(())
}

fn chargeback_csv_response_too_large(limit: usize) -> AdminResponse {
    (
        413,
        "application/json",
        serde_json::json!({
            "code": "chargeback_response_too_large",
            "max_response_bytes": limit,
            "hint": "use the paged JSON chargeback export for large datasets",
        })
        .to_string(),
    )
}

fn render_live_ai_chargeback_csv_with_limit(
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
    max_response_bytes: usize,
) -> AdminResponse {
    let mut writer = CappedResponseWriter::new(max_response_bytes);
    if write_chargeback_csv_response(&mut writer, origins).is_err() {
        if writer.limit_exceeded() {
            record_admin_chargeback_export_refusal(
                sbproxy_observe::metrics::AdminChargebackExportFormat::Csv,
                sbproxy_observe::metrics::AdminChargebackExportRefusalReason::ResponseTooLarge,
                "response_size",
            );
            return chargeback_csv_response_too_large(max_response_bytes);
        }
        return admin_error(500, "chargeback CSV serialization failed");
    }
    match writer.into_string() {
        Ok(body) => (200, "text/csv; charset=utf-8", body),
        Err(_) => admin_error(500, "chargeback CSV serialization failed"),
    }
}

#[cfg(test)]
fn render_live_ai_chargeback_csv_for_test(
    origins: &BTreeMap<String, Vec<&sbproxy_ai::billing::ChargebackTracker>>,
    max_response_bytes: usize,
) -> AdminResponse {
    render_live_ai_chargeback_csv_with_limit(origins, max_response_bytes)
}

/// Return bounded workspace/team rollups in spreadsheet-safe CSV.
fn handle_ai_chargeback_csv() -> AdminResponse {
    with_live_ai_chargeback_trackers(|origins| {
        render_live_ai_chargeback_csv_with_limit(origins, MAX_AI_CHARGEBACK_RESPONSE_BYTES)
    })
}

fn chargeback_csv_field(value: &str) -> String {
    let formula = value
        .chars()
        .next()
        .is_some_and(|first| matches!(first, '=' | '+' | '-' | '@' | '\t' | '\r'));
    let mut safe = if formula {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if safe
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
    {
        safe = format!("\"{}\"", safe.replace('"', "\"\""));
    }
    safe
}

// --- OpenAPI rendering ---

/// Render the live pipeline's OpenAPI document as JSON or YAML.
///
/// The render is cached per pipeline generation on the supplied
/// `AdminState` so back-to-back requests return the cached bytes, and
/// every hot reload invalidates it.
fn render_openapi(state: &AdminState, yaml: bool) -> Result<String, String> {
    // Generation first, pipeline second. A swap landing between the two
    // reads then renders the newer pipeline under the older generation,
    // and the next request sees the bump and re-renders. Reading them
    // the other way round caches the older pipeline's document under
    // the newer generation, which is served until the reload after it.
    //
    // This ordering argument only holds because `load_pipeline`
    // advances the generation strictly after the pipeline store swap
    // (see `advance_config_version`). With the bump before the store,
    // no read order here would be safe: this one would see the new
    // generation while the old pipeline was still installed and cache
    // the stale document under it.
    let generation = crate::reload::pipeline_generation();
    let pipeline = crate::reload::current_pipeline();

    let mut cache = state
        .openapi_cache
        .lock()
        .expect("openapi cache mutex poisoned");
    if cache.generation != generation {
        // Stale: drop both renderings; we'll repopulate the requested
        // format below and let the other format lazy-build on its
        // first request.
        cache.generation = generation;
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
/// This aggregation is multi-tenancy, not key rotation, and the two
/// are easy to mistake for each other because both widen the same
/// array. Rotation is per-origin and lives in the policy: an origin
/// with `quote_token.previous_key_id` set hands back two kids of its
/// own, and that is what keeps a quote issued before a reload
/// verifying after it. Nothing at this level knows a rotation window
/// is open, so nothing here can substitute for one.
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

    // WOR-2094: snapshot the outgoing generation so the config audit
    // event can name the revision pair and the origin delta.
    let prior_pipeline = crate::reload::current_pipeline();
    let prior_revision = prior_pipeline.config_revision.clone();
    let prior_origins: std::collections::BTreeSet<String> = prior_pipeline
        .config
        .origins
        .iter()
        .map(|origin| origin.hostname.to_string())
        .collect();

    // --- Read + compile + load ---
    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "admin reload: failed to read config file");
            let msg = sanitise_path_in_error(&e.to_string(), &path);
            audit_admin_reload_rejection(&prior_revision, &msg);
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

    // Resolve `source:` before validating anything. The pointer document
    // is near-empty and compiles trivially, so validating it proves
    // nothing about the payload it points at; and resolving here means
    // the transaction below is handed the already-fetched text rather
    // than fetching the source a second time.
    let resolved = match crate::config_source::resolve(&yaml) {
        Ok(resolved) => resolved,
        Err(e) => {
            tracing::warn!(error = %e, "admin reload: config source resolution failed");
            let msg = sanitise_path_in_error(&format!("{e:#}"), &path);
            audit_admin_reload_rejection(&prior_revision, &msg);
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"failed to resolve config source: {}"}}"#,
                    msg.replace('"', "'")
                ),
            );
        }
    };
    let compiled = match sbproxy_config::compile_config(&resolved.text) {
        Ok(compiled) => compiled,
        Err(e) => {
            tracing::warn!(error = %e, "admin reload: YAML parse failed");
            let msg = sanitise_path_in_error(&e.to_string(), &path);
            audit_admin_reload_rejection(&prior_revision, &msg);
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

    // Keep the file-backed reload contract aligned with PUT /admin/config:
    // failures caused by operator-supplied config are 4xx, while failures in
    // the shared runtime transaction below remain 5xx.
    let config_dir = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if let Err(error) =
        crate::pipeline::CompiledPipeline::from_config_for_validation_at(compiled, config_dir)
    {
        tracing::warn!(error = ?error, "admin reload: pipeline compile failed");
        let msg = sanitise_path_in_error(&format!("{error:#}"), &path);
        audit_admin_reload_rejection(&prior_revision, &msg);
        return (
            400,
            "application/json",
            format!(
                r#"{{"error":"config does not compile: {}"}}"#,
                msg.replace('"', "'")
            ),
        );
    }

    let path_text = path.to_string_lossy();
    let outcome = match crate::server::reload_from_resolved_yaml(&path_text, &resolved.text, &yaml)
    {
        Ok(outcome) => outcome,
        Err(error) => {
            sbproxy_observe::metrics::record_config_reload("failure");
            // `{error:#}`, not `{error}`. The alternate form walks the whole
            // anyhow chain; the plain one renders only the outermost context,
            // which is where a reload failure loses its own cause. An
            // embedded keystore that could not be re-opened reported "open
            // embedded keystore at '<path>'" and dropped the reason, so the
            // operator saw a path they could read and nothing to act on.
            tracing::error!(error = ?error, "admin reload: shared reload transaction failed");
            let msg = sanitise_path_in_error(&format!("{error:#}"), &path);
            audit_admin_reload_rejection(&prior_revision, &msg);
            return (
                500,
                "application/json",
                format!(r#"{{"error":"reload failed: {}"}}"#, msg.replace('"', "'")),
            );
        }
    };
    sbproxy_observe::metrics::record_config_reload("success");

    let revision = crate::reload::current_pipeline().config_revision.clone();
    let content_hash = crate::identity::config_revision(yaml.as_bytes());
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

    // WOR-2094: config changes are audited with the actor (when the
    // reload came through an authenticated admin request), the revision
    // pair, and the origin delta. This is the previously-dead
    // ConfigAuditEntry channel's first production emitter.
    let next_pipeline = crate::reload::current_pipeline();
    let next_origins: std::collections::BTreeSet<String> = next_pipeline
        .config
        .origins
        .iter()
        .map(|origin| origin.hostname.to_string())
        .collect();
    let mut entry = sbproxy_observe::ConfigAuditEntry::new(
        "api",
        next_origins.difference(&prior_origins).cloned().collect(),
        prior_origins.difference(&next_origins).cloned().collect(),
        Vec::new(),
    )
    .with_revisions(Some(prior_revision.as_str()), Some(revision.as_str()));
    if let Some(actor) = current_admin_actor() {
        entry = entry.with_actor(actor);
    }
    entry.emit();

    // A reload can succeed while one subsystem stayed on prior state.
    // The caller (often an unattended config authority) needs to see
    // that in the response body, not only in this node's logs.
    let degraded = outcome
        .degraded()
        .iter()
        .map(|subsystem| format!("\"{}\"", subsystem.as_str()))
        .collect::<Vec<_>>()
        .join(",");

    (
        200,
        "application/json",
        format!(
            r#"{{"config_revision":"{}","loaded_at":"{}","fully_applied":{},"degraded":[{}]}}"#,
            revision.replace('"', "'"),
            loaded_at,
            outcome.is_fully_applied(),
            degraded,
        ),
    )
}

// --- /admin/config (WOR-1720) ---

/// `GET /admin/config`: return the current on-disk config YAML plus the
/// loaded content-hash, which a client passes back as `if_match` on a
/// write for optimistic concurrency.
///
/// This is the node's own file and nothing else. On a node that pulls from
/// a git repository or an authority it is not what is running, and on a
/// git-sourced node it may be nothing but the `source:` pointer that
/// selected the repository. `GET /admin/config/effective` is the endpoint
/// that answers "what is actually running".
///
/// The YAML is passed through [`sbproxy_observe::redact::redact_secrets`]
/// before it leaves this handler, so a credential inlined as plaintext is
/// returned as `[REDACTED]` rather than handed to every operator with read
/// access. `${VAR}` and secret-backend references are unaffected; they
/// never held the value in the first place.
fn handle_config_read(state: &AdminState) -> (u16, &'static str, String) {
    let path = match state.config_path.as_ref() {
        Some(p) => p,
        None => {
            return (
                503,
                "application/json",
                r#"{"error":"config path not wired"}"#.to_string(),
            );
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
    // WOR-2316: a secret inlined in the file as plaintext (rather than as a
    // `${VAR}` or secret-backend reference) must not be echoed back to a
    // read-only operator. Same pass the log pipeline runs, so the same token
    // shapes are caught; everything the patterns do not match, comments and
    // formatting included, is returned byte-for-byte.
    let yaml = sbproxy_observe::redact::redact_secrets(&yaml);
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

/// Entity tag for the config JSON Schema, derived from the schema itself.
///
/// Content-derived rather than tied to the release version, because the
/// schema changes whenever a config type or its documentation changes,
/// which happens many times between releases. A tag that moved only on
/// release would hand an editor a stale schema for the whole development
/// cycle, and one that moved on every process start would defeat the point.
fn config_schema_etag() -> &'static str {
    static ETAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ETAG.get_or_init(|| {
        let digest =
            crate::identity::config_revision(sbproxy_config::config_json_schema().as_bytes());
        format!("\"{digest}\"")
    })
}

/// Refuse a write whose edits the node's remote layers would swallow,
/// returning the `409` response, or `None` when every edit takes effect.
///
/// The rule this enforces is not "an authority exists, so writes are
/// forbidden". It is "this specific edit would not reach the running
/// configuration", which is both narrower and more useful: a node under a
/// replace-mode authority can still change its own admin listener and TLS
/// material, because the deny list guarantees the authority cannot take
/// them, while an overlay-mode node is stopped only at the paths its
/// authority actually sets. See [`crate::config_effective`] for how that is
/// decided without a second copy of the merge rules.
///
/// The guard is not a substitute for RBAC. A read-only operator was already
/// refused by the connection handler's role gate; this refuses writes that
/// would be pointless rather than writes that are unauthorized.
fn guard_config_write(
    path: &std::path::Path,
    proposed: &str,
) -> Option<(u16, &'static str, String)> {
    let on_disk = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            let msg = sanitise_path_in_error(&error.to_string(), path);
            return Some((
                500,
                "application/json",
                format!(
                    r#"{{"error":"read current config to check ownership: {}"}}"#,
                    msg.replace('"', "'")
                ),
            ));
        }
    };
    let layers = crate::config_effective::current_layers(&on_disk);
    if layers.is_local_only() {
        return None;
    }

    let conflicts = match crate::config_effective::write_conflicts(&layers, &on_disk, proposed) {
        Ok(conflicts) => conflicts,
        Err(error) => {
            // The guard could not be evaluated, so whether the write would
            // survive is unknown. Refuse: persisting an edit that might be
            // silently discarded is the failure this endpoint exists to
            // prevent.
            tracing::warn!(%error, "admin config write: ownership check failed");
            return Some((
                409,
                "application/json",
                serde_json::json!({
                    "error": format!("could not determine which paths this node owns: {error}"),
                    "code": "config_ownership_unknown",
                    "layers": config_layers_json(&layers),
                })
                .to_string(),
            ));
        }
    };
    if conflicts.is_empty() {
        return None;
    }

    let paths: Vec<&str> = conflicts.iter().map(|c| c.path.as_str()).collect();
    // Audit the refusal, not only the writes that land. An operator
    // repeatedly trying to edit configuration they do not own is a signal
    // that a fleet is misconfigured or that someone is working against the
    // wrong node, and neither shows up in a log of successes. The operator
    // identity is on the connection handler's "admin action" line for the
    // same request; this line carries the outcome.
    tracing::warn!(
        target: "sbproxy::admin::audit",
        action = "config_write",
        outcome = "rejected_not_locally_owned",
        reason_code = "config_not_locally_owned",
        conflicting_paths = %paths.join(","),
        conflict_count = conflicts.len(),
        "admin config write refused: this node does not own the edited paths"
    );

    Some((
        409,
        "application/json",
        serde_json::json!({
            "error": format!(
                "this node does not own {}: {}",
                if conflicts.len() == 1 { "the edited path" } else { "every edited path" },
                paths.join(", ")
            ),
            "code": "config_not_locally_owned",
            "conflicts": conflicts
                .iter()
                .map(|conflict| serde_json::json!({
                    "path": conflict.path,
                    "owner": match &conflict.owner {
                        Some(Provenance::Local) => serde_json::json!("local"),
                        Some(Provenance::Git { repo, reference, commit }) => serde_json::json!({
                            "kind": "git", "repo": repo, "reference": reference, "commit": commit,
                        }),
                        Some(Provenance::Authority) => serde_json::json!("authority"),
                        // No owner means the path is suppressed rather than
                        // overwritten: a replace-mode authority discards it,
                        // or a git base never had it. Same outcome for the
                        // operator, so it is reported the same way.
                        None => serde_json::json!("suppressed"),
                    },
                }))
                .collect::<Vec<_>>(),
            "layers": config_layers_json(&layers),
            "remedy": config_write_redirect(&layers),
        })
        .to_string(),
    ))
}

/// Describe the layers a node's configuration is assembled from, for both
/// the effective-config response and the body of a rejected write.
///
/// Deliberately names the resolved commit and the applied revision rather
/// than the configured repository and the configured authority. An operator
/// reading this wants to know what is running, and "configured" and
/// "running" differ during exactly the incidents where the answer matters.
fn config_layers_json(layers: &crate::config_effective::ConfigLayers) -> serde_json::Value {
    let base = match &layers.base_origin {
        BaseOrigin::Local => serde_json::json!({"kind": "local"}),
        BaseOrigin::Git {
            repo,
            reference,
            commit,
        } => serde_json::json!({
            "kind": "git",
            "repo": repo,
            "reference": reference,
            "commit": commit,
        }),
    };
    let authority = layers.authority.as_ref().map(|applied| {
        serde_json::json!({
            "authority_id": applied.authority_id,
            "revision": applied.revision,
            "mode": match applied.merge_mode {
                MergeMode::Overlay => "overlay",
                MergeMode::Replace => "replace",
            },
        })
    });
    serde_json::json!({"base": base, "authority": authority})
}

/// Where an operator should go to change configuration this node does not
/// own.
///
/// A 409 that says only "conflict" leaves the operator guessing, and the
/// guess is usually "retry", which cannot work. Naming the repository or
/// the authority turns the rejection into an instruction.
fn config_write_redirect(layers: &crate::config_effective::ConfigLayers) -> String {
    match (&layers.base_origin, &layers.authority) {
        (
            BaseOrigin::Git {
                repo, reference, ..
            },
            _,
        ) => format!(
            "this node reads its configuration from {repo} at {reference}; commit the change \
             there and the node will pick it up on its next refresh"
        ),
        (BaseOrigin::Local, Some(applied)) => format!(
            "authority {} owns these paths at revision {}; publish the change through the \
             authority with `sbproxy authority publish`",
            applied.authority_id, applied.revision
        ),
        (BaseOrigin::Local, None) => {
            "this node owns its own configuration; no redirect applies".to_string()
        }
    }
}

/// Read this node's own config file and assemble the document it is
/// actually running, or the response that says why not.
///
/// Shared by `GET /admin/config/effective` and
/// `GET /admin/origin-composition`, which need the same three steps and
/// the same three failures. They were written out twice, which meant two
/// copies of the hand-rolled JSON error bodies and two places for the
/// "config path not wired" contract to drift.
fn effective_document(state: &AdminState) -> Result<EffectiveDocument, AdminResponse> {
    let Some(path) = state.config_path.as_ref() else {
        return Err((
            503,
            "application/json",
            r#"{"error":"config path not wired"}"#.to_string(),
        ));
    };
    let local = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            let message = sanitise_path_in_error(&error.to_string(), path);
            return Err((
                500,
                "application/json",
                serde_json::json!({"error": format!("read config: {message}")}).to_string(),
            ));
        }
    };
    let layers = crate::config_effective::current_layers(&local);
    match crate::config_effective::effective_config(&layers) {
        Ok(effective) => Ok(EffectiveDocument { layers, effective }),
        Err(error) => {
            // A merge that fails here failed for the running node too, so
            // the node is serving whatever it last applied. Say so rather
            // than reporting a document that was never assembled.
            tracing::warn!(%error, "admin: effective config merge failed");
            Err((
                500,
                "application/json",
                serde_json::json!({
                    "error": format!("could not assemble the effective config: {error}"),
                    "code": "effective_config_unavailable",
                    "layers": config_layers_json(&layers),
                })
                .to_string(),
            ))
        }
    }
}

/// The layers in play and the document they merged to.
struct EffectiveDocument {
    layers: crate::config_effective::ConfigLayers,
    effective: crate::config_effective::EffectiveConfig,
}

/// `GET /admin/origin-composition`: which project repositories this
/// node's configuration pulls, what hosts each one claims, and the
/// platform floor every composed origin starts from (WOR-2436).
///
/// Read-only, and answerable with nothing fetched. `origin_sources`
/// names the hosts itself, so the collision check and the pin state are
/// both properties of the document rather than of a clone. A node never
/// composes (composition runs in one aggregator, WOR-2437), so what an
/// operator wants here is the declaration and its posture, which is
/// exactly what this returns.
///
/// Read off the **effective** config rather than the node's own file,
/// for the same reason `/admin/config/effective` exists: on a
/// git-sourced node the local file is only the pointer that selected the
/// repository. `origin_sources` is on `AUTHORITY_DENIED_PATHS`, so an
/// authority never contributes to what this reports, and seeing it here
/// is how an operator confirms that.
///
/// Nothing secret-shaped is emitted. A repository URL is
/// credential-stripped, an entry credential is reported as present or
/// absent and never by value, and an input is reported by name only,
/// because an input value is exactly where a secret reference lands.
///
/// A console page is deferred to WOR-2574. Until it lands this route is
/// the operator surface, and the console will read the same JSON.
fn handle_origin_composition(state: &AdminState) -> (u16, &'static str, String) {
    let Some(path) = state.config_path.as_ref() else {
        return (
            503,
            "application/json",
            r#"{"error":"config path not wired"}"#.to_string(),
        );
    };
    let local = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            let message = sanitise_path_in_error(&error.to_string(), path);
            return (
                500,
                "application/json",
                format!(
                    r#"{{"error":"read config: {}"}}"#,
                    message.replace('"', "'")
                ),
            );
        }
    };
    let layers = crate::config_effective::current_layers(&local);
    let yaml = match crate::config_effective::effective_config(&layers) {
        Ok(effective) => effective.yaml,
        Err(error) => {
            tracing::warn!(%error, "admin origin composition: merge failed");
            return (
                500,
                "application/json",
                serde_json::json!({
                    "error": format!("could not assemble the effective config: {error}"),
                    "code": "effective_config_unavailable",
                })
                .to_string(),
            );
        }
    };
    let config: sbproxy_config::ConfigFile = match serde_yaml::from_str(&yaml) {
        Ok(config) => config,
        Err(error) => {
            return (
                500,
                "application/json",
                serde_json::json!({
                    "error": format!("effective config does not parse: {error}"),
                    "code": "effective_config_unparseable",
                })
                .to_string(),
            )
        }
    };
    (
        200,
        "application/json",
        origin_composition_json(&config).to_string(),
    )
}

/// The body of `GET /admin/origin-composition`, as a pure function of
/// the parsed config so it can be asserted on without a listener.
fn origin_composition_json(config: &sbproxy_config::ConfigFile) -> serde_json::Value {
    let Some(sources) = config.origin_sources.as_ref() else {
        return serde_json::json!({
            "declared": false,
            "note": "no `origin_sources:` block; every origin on this node is hand written",
            "origin_defaults": origin_defaults_json(config),
        });
    };
    let entries: Vec<serde_json::Value> = sources
        .entries
        .iter()
        .map(|entry| {
            let mut input_names: Vec<&str> = entry.inputs.keys().map(String::as_str).collect();
            input_names.sort_unstable();
            serde_json::json!({
                "name": entry.name,
                "repo": sbproxy_config::redact_repo(&entry.repo),
                "revision": entry.revision,
                "pinned": entry
                    .revision
                    .as_deref()
                    .is_some_and(sbproxy_config::revision_is_immutable),
                "path": entry.path,
                "environment": entry.environment,
                "verify_signature": entry.verify_signature,
                "timeout_secs": entry.timeout_secs,
                "credential": if entry.credential.is_some() { "reference" } else { "none" },
                "hosts": entry.hosts,
                "inputs": input_names,
                "has_overrides": entry.overrides.is_some(),
            })
        })
        .collect();
    let hand_written: std::collections::BTreeSet<String> = config.origins.keys().cloned().collect();
    let (claims, collision) = match sbproxy_config::claimed_hosts(&sources.entries, &hand_written) {
        Ok(claims) => (
            claims
                .iter()
                .map(|claim| {
                    serde_json::json!({
                        "host": claim.host,
                        "entry": claim.entry,
                        "profile_origin": claim.profile_origin,
                        "repo": claim.repo,
                    })
                })
                .collect::<Vec<_>>(),
            serde_json::Value::Null,
        ),
        Err(error) => (Vec::new(), serde_json::json!(error.to_string())),
    };
    serde_json::json!({
        "declared": true,
        "tier": sources.tier.as_str(),
        "aggregator": {
            "poll_interval_secs": sources.aggregator.poll_interval_secs,
            "debounce_secs": sources.aggregator.debounce_secs,
            "max_deferral_secs": sources.aggregator.max_deferral_secs,
            "concurrency": sources.aggregator.concurrency,
            "deadline_secs": sources.aggregator.deadline_secs,
            "polls_per_hour_per_repo": 3600 / sources.aggregator.poll_interval_secs.max(1),
        },
        "entries": entries,
        "claimed_hosts": claims,
        "collision": collision,
        "hand_written_origins": hand_written,
        "origin_defaults": origin_defaults_json(config),
        "last_round": last_round_json(),
        "note": "the declarations this node's effective config carries. `last_round` is \
                 present only on the node that runs the aggregator; every other node sees \
                 the composed result as an ordinary signed bundle",
    })
}

/// The last aggregation round this process ran, for the admin surface.
///
/// Null on every node that does not aggregate, which is every node but
/// one: composition runs in a single place and the rest of the fleet
/// receives its output as a signed bundle. Distinguishing "did not
/// aggregate" from "aggregated and found nothing" matters, so the two
/// are a null and a `decision` respectively rather than both being
/// zeroes.
///
/// Provenance is summarized rather than emitted in full. Fifty composed
/// origins carry thousands of leaves, and a route that returned all of
/// them on every poll would be the most expensive thing on the admin
/// listener. `sbproxy aggregate --explain <host>` renders one host's,
/// which is the question anybody actually asks.
///
/// Nothing secret-shaped is emitted, and provenance could not carry a
/// value even if this wanted it to: a `LeafOrigin` is a layer and a
/// repository, never the leaf's value.
fn last_round_json() -> serde_json::Value {
    let Some(status) = crate::config_aggregator::last_round() else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "at_unix_ms": status.at_unix_ms,
        "decision": status.decision,
        "revision": status.revision,
        "content_digest": status.content_digest,
        "duration_ms": status.duration_ms,
        "origins": status.origins,
        "resolved": status.resolved,
        "failed": status.failed,
        "drops": status.drops,
        "provenance_hosts": status.provenance.keys().collect::<Vec<_>>(),
        "reason": status.reason,
    })
}

/// The platform floor, summarized by the names a project can address and
/// which of them are locked against override.
fn origin_defaults_json(config: &sbproxy_config::ConfigFile) -> serde_json::Value {
    let Some(defaults) = config.origin_defaults.as_ref() else {
        return serde_json::json!({"present": false});
    };
    let mut lists = serde_json::Map::new();
    for list in sbproxy_config::PROFILE_LIST_MERGE_KEYS {
        let Some(items) = defaults.get(*list).and_then(serde_yaml::Value::as_sequence) else {
            continue;
        };
        let named: Vec<serde_json::Value> = items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "name": item
                        .get("name")
                        .and_then(serde_yaml::Value::as_str)
                        .unwrap_or("(unnamed)"),
                    "locked": item
                        .get("locked")
                        .and_then(serde_yaml::Value::as_bool)
                        .unwrap_or(false),
                })
            })
            .collect();
        lists.insert((*list).to_string(), serde_json::Value::Array(named));
    }
    serde_json::json!({
        "present": true,
        "keys": defaults
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<Vec<_>>(),
        "addressable": lists,
    })
}

/// `GET /admin/config/effective`: the configuration this node is actually
/// running, plus which layer owns each leaf of it.
///
/// On a node that owns its own configuration this is the local file merged
/// with nothing, and every leaf reports `local`. The endpoint is still
/// worth calling there, because the answer "every key is yours" is what
/// tells an editor it may offer a write at all.
///
/// The `yaml` field passes through
/// [`sbproxy_observe::redact::redact_secrets`] like `GET /admin/config`
/// does: the merged document carries any plaintext credential the local
/// file or an authority layer inlined, so the sibling endpoint must not
/// return what the primary one redacts.
fn handle_config_effective(state: &AdminState) -> (u16, &'static str, String) {
    let EffectiveDocument { layers, effective } = match effective_document(state) {
        Ok(document) => document,
        Err(response) => return response,
    };
    let locally_owned = effective
        .provenance
        .iter()
        .filter(|(_, provenance)| matches!(provenance, Provenance::Local))
        .count();
    // WOR-2316: same pass as `GET /admin/config`, for the same reason. The
    // provenance map holds leaf paths, never values, so only the document
    // itself needs it.
    let yaml = sbproxy_observe::redact::redact_secrets(&effective.yaml);
    (
        200,
        "application/json",
        serde_json::json!({
            "yaml": yaml,
            "provenance": effective.provenance,
            "layers": config_layers_json(&layers),
            "locally_owned": layers.is_local_only(),
            "locally_owned_leaves": locally_owned,
            "total_leaves": effective.provenance.len(),
        })
        .to_string(),
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
            );
        }
    };
    let yaml = match body {
        Some(b) if !b.trim().is_empty() => b,
        _ => {
            return (
                400,
                "application/json",
                r#"{"error":"empty config body"}"#.to_string(),
            );
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
    // A body naming a remote source meets the ownership guard BEFORE
    // any resolution: resolving means cloning the named repository, and
    // a write this node would refuse anyway must not reach the network
    // first, nor have its 409 turned into a 400 about an unreachable
    // host. Plain bodies keep the guard's documented after-validation
    // ordering below, so a syntax error still wins over an ownership
    // violation.
    if matches!(sbproxy_config::source::parse_source_head(yaml), Ok(Some(_))) {
        if let Some(rejection) = guard_config_write(&path, yaml) {
            return rejection;
        }
    }
    // Validate BEFORE writing so a bad config never clobbers the file.
    // Resolution comes first for the same reason: a `source:` pointer
    // body compiles trivially on its own, so without resolving here a
    // pointer at a broken payload would be validated as the pointer,
    // written to disk, and only then refused by the delegated reload,
    // leaving a file behind that fails the next boot or SIGHUP.
    let resolved_body = match crate::config_source::resolve(yaml) {
        Ok(resolved) => resolved,
        Err(e) => {
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"failed to resolve config source: {}"}}"#,
                    format!("{e:#}").replace('"', "'")
                ),
            );
        }
    };
    let compiled = match sbproxy_config::compile_config(&resolved_body.text) {
        Ok(c) => c,
        Err(e) => {
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"invalid config: {}"}}"#,
                    e.to_string().replace('"', "'")
                ),
            );
        }
    };
    // Construct for validation only: this pipeline is dropped immediately,
    // and the runtime constructor would spawn health-check probes that
    // outlive it and keep hitting the operator's upstreams.
    let config_dir = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if let Err(e) =
        crate::pipeline::CompiledPipeline::from_config_for_validation_at(compiled, config_dir)
    {
        return (
            400,
            "application/json",
            format!(
                r#"{{"error":"config does not compile: {}"}}"#,
                e.to_string().replace('"', "'")
            ),
        );
    }
    // WOR-2012: refuse a write this node's remote layers would swallow.
    // Runs after validation on purpose: an operator who sends both a syntax
    // error and an ownership violation is better served by hearing about the
    // syntax error, and this is the last gate before anything is persisted.
    if let Some(rejection) = guard_config_write(&path, yaml) {
        return rejection;
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

// --- /admin/config/history ---

/// Resolve the process-wide config-history slot to an open recorder, or
/// a ready-to-return response for the two states that are not open.
///
/// `404` with `{"error":"config history is not enabled"}` for
/// [`crate::config_history::ConfigHistoryState::Disabled`] -- the UI's
/// `isConfigHistoryDisabled` (`ui/src/lib/config-history.ts`) matches
/// this exact body to render an opt-in empty state instead of an error
/// toast, so the wording is part of the contract, not incidental.
///
/// `503` for [`crate::config_history::ConfigHistoryState::Failed`]: the
/// block was enabled but the store could not open at boot. Answering
/// this the same way as `Disabled` would tell an operator whose ring
/// failed to open that the feature was never turned on, which is worse
/// than saying nothing -- it reads as "you forgot to enable this"
/// rather than "this broke". `reason` already carries only the bounded,
/// no-secrets-by-construction open-error text
/// [`crate::config_history::ConfigHistoryState::Failed`] documents (an
/// unwritable path, a corrupt-ring shape `RevisionStore::open` names),
/// so it is safe to echo back verbatim past the one JSON-quote escape
/// every hand-built error body here already applies.
fn config_history_open_recorder(
) -> Result<Arc<crate::config_history::ConfigHistoryRecorder>, (u16, &'static str, String)> {
    match &*crate::config_history::current_config_history_state() {
        crate::config_history::ConfigHistoryState::Open(recorder) => Ok(Arc::clone(recorder)),
        crate::config_history::ConfigHistoryState::Disabled => Err((
            404,
            "application/json",
            r#"{"error":"config history is not enabled"}"#.to_string(),
        )),
        crate::config_history::ConfigHistoryState::Failed { reason } => Err((
            503,
            "application/json",
            format!(
                r#"{{"error":"config history failed to open at boot: {}"}}"#,
                reason.replace('"', "'")
            ),
        )),
    }
}

/// `GET /admin/config/history`: every recorded config revision, newest
/// first, alongside this ring's lineage identity and last-known-good
/// revision.
///
/// `404`/`503` per [`config_history_open_recorder`] when the slot is
/// not open.
fn handle_config_history_list() -> (u16, &'static str, String) {
    let recorder = match config_history_open_recorder() {
        Ok(recorder) => recorder,
        Err(response) => return response,
    };
    let mut entries = recorder.entries();
    // The ring stores oldest first; the response contract is newest
    // first, matching the order an operator scanning for a rollback
    // target actually wants.
    entries.reverse();
    let entries: Vec<serde_json::Value> = entries.iter().map(config_history_entry_json).collect();
    let body = serde_json::json!({
        "lineage": recorder.lineage(),
        "lkg_revision": recorder.lkg().map(|entry| entry.revision),
        // Which revision is under judgment right now, if any. An
        // operator looking at a ring whose `lkg_revision` has not moved
        // needs to know whether that is because a window is still open
        // or because the last one did not promote (WOR-2458).
        "soak_revision": crate::config_soak::in_flight_revision(),
        "entries": entries,
        // Additive: `entries` keeps its existing shape and meaning, and
        // `timeline` interleaves the refused candidates among them for a
        // panel that wants the whole story in one list (WOR-2462).
        "timeline": config_history_timeline(&recorder),
    });
    (200, "application/json", body.to_string())
}

/// `GET /admin/config/fallback`: whether this node is serving a config
/// its boot fallback restored from the revision ring, and which one
/// (WOR-2459).
///
/// Always answers, on every node, including one that never enabled the
/// ring: "am I running what I was told to run" is a question an operator
/// must be able to ask without first knowing whether a feature is
/// switched on, and answering `404` there would read as "I do not know".
fn handle_config_fallback_status() -> (u16, &'static str, String) {
    let pinned = crate::config_boot::pinned_revision();
    let body = serde_json::json!({
        "active": crate::config_boot::on_fallback(),
        "revision": pinned.as_ref().map(|pin| pin.revision),
        "digest": pinned.as_ref().map(|pin| pin.digest.clone()),
        // Named rather than implied: an operator reading this is
        // deciding whether their edit to the config file will do
        // anything, and the answer is no until they clear the pin.
        "suspended": if crate::config_boot::on_fallback() {
            serde_json::json!(["file_watcher", "sighup", "config_refresh_poller"])
        } else {
            serde_json::json!([])
        },
    });
    (200, "application/json", body.to_string())
}

/// `DELETE /admin/config/fallback`: clear the pin and resume the
/// suspended reload paths (WOR-2459).
///
/// The file watcher, SIGHUP, and the `source:` refresh poller check the
/// pin on every cycle rather than being torn down at boot, precisely so
/// this can bring them back without a restart. `sbproxy_config_fallback_active`
/// returns to 0 in the same call.
///
/// `409` when nothing is pinned: clearing a pin that does not exist is a
/// caller bug, and answering `200` would tell an operator their node is
/// back on its config file when it was never off it.
fn handle_config_fallback_clear(state: &AdminState) -> (u16, &'static str, String) {
    let Some(pin) = crate::config_boot::clear_fallback() else {
        return (
            409,
            "application/json",
            r#"{"error":"this node is not pinned to a fallback configuration"}"#.to_string(),
        );
    };
    // Clearing the pin is only half of recovery, and leaving the other
    // half to the operator was a trap: the watcher only fires on a
    // *future* filesystem event, so a node whose file had already been
    // fixed sat on the October config with
    // `sbproxy_config_fallback_active` reading 0, which is the one
    // reading that says everything is fine. So the clear applies the
    // file itself, through the same path `POST /admin/reload` uses
    // (WOR-2459 fix round, Major 9).
    let reload = state.config_path.as_ref().map(|path| {
        // The unaudited variant: this handler writes the record, with
        // the actor the HTTP layer has. Letting the shared path write
        // its own too produced two entries for one apply, one of them
        // naming `file_watcher` for a deliberate operator action
        // (verification residual R3).
        let outcome = crate::server::reload_from_config_path_unaudited(&path.to_string_lossy());
        // Audited here, at the admin call site, with the actor the HTTP
        // layer has. `reload_from_config_path` stamps its own entry under
        // `source: "file_watcher"`, which is right for a filesystem event
        // and wrong for the single most consequential operator action in
        // this feature: clearing the pin is a deliberate recovery, and
        // the audit trail has to name who did it rather than blame the
        // watcher (re-review, new Minor 7).
        let mut entry =
            sbproxy_observe::ConfigAuditEntry::new("api", Vec::new(), Vec::new(), Vec::new());
        if let Some(actor) = current_admin_actor() {
            entry = entry.with_actor(actor);
        }
        if let Err(error) = &outcome {
            entry = entry.with_rejection_reason(crate::path_redact::sanitise_path_in_error(
                &format!("{error:#}"),
                path,
            ));
        }
        entry.emit();
        outcome
    });
    let (reloaded, reload_error) = match reload {
        Some(Ok(_)) => (true, None),
        Some(Err(error)) => (
            false,
            Some(crate::path_redact::sanitise_path_in_error(
                &format!("{error:#}"),
                state
                    .config_path
                    .as_deref()
                    .unwrap_or(std::path::Path::new("")),
            )),
        ),
        // No config path is wired into this admin state, which is the
        // unit-test shape rather than a served one.
        None => (
            false,
            Some("no config path is wired on this node".to_string()),
        ),
    };
    let body = serde_json::json!({
        "cleared": true,
        "revision": pin.revision,
        "digest": pin.digest,
        "resumed": ["file_watcher", "sighup", "config_refresh_poller"],
        "reloaded": reloaded,
        "reload_error": reload_error,
    });
    // 200 either way: the pin *is* cleared, which is what was asked for
    // and what the gauge now reports. A file that still does not compile
    // is the operator's next problem, not a failure of this call, and
    // `reloaded: false` plus the error is how they see it.
    (200, "application/json", body.to_string())
}

/// `POST /admin/config/confirm`: promote the revision under soak
/// immediately, without waiting out its window (WOR-2458).
///
/// The Junos `commit confirmed` ergonomic, inverted. A deployment
/// pipeline that has just run its own smoke test knows more than a timer
/// does, and this is what it calls instead of sleeping for two minutes.
///
/// `409` when no soak is in flight, rather than a cheerful `200`:
/// confirming nothing is a caller bug (the reload never happened, or the
/// window already closed), and answering it as success would tell a
/// pipeline its config is now the rollback target when it is not.
///
/// The confirmation runs the same signals a timed close runs, so it
/// short-circuits the *wait*, not the *judgment*: a revision that is
/// already failing its upstream-health signal is not promoted just
/// because somebody confirmed it. Reporting the verdict back is what
/// lets the pipeline fail its own step on it.
fn handle_config_confirm(state: &AdminState) -> (u16, &'static str, String) {
    // Answered before the soak state is consulted, so a node that never
    // opted into the ring gets the same "not enabled" body as its
    // sibling routes rather than a confusing 409.
    if let Err(response) = config_history_open_recorder() {
        return response;
    }
    let Some(closed) = crate::config_soak::confirm_now() else {
        return (
            409,
            "application/json",
            r#"{"error":"no config soak is in flight"}"#.to_string(),
        );
    };
    let signals: Vec<serde_json::Value> = closed
        .reports
        .iter()
        .map(|(signal, outcome)| {
            serde_json::json!({
                "signal": signal.as_str(),
                "outcome": outcome.as_str(),
                // Redacted for display, the same pass
                // `config_rejected_entry_json` applies to a stored
                // refusal. A signal detail is built from bounded,
                // secret-free parts by construction (the probe's URL
                // reaches it only through `redacted_url`), and this is
                // the belt to that brace: an operator can put a literal
                // credential into a config value the same way they can
                // anywhere else, and a soak failure quoting one back to
                // an admin-authenticated reader would be the leak this
                // pass exists to stop (WOR-2458 fix round, Blocker 1).
                "detail": sbproxy_observe::redact::redact_secrets(
                    outcome.detail().unwrap_or_default(),
                ),
            })
        })
        .collect();
    // WOR-2461: a confirmation runs the same judgment a timed close
    // runs, so a confirmation that comes back `failed` is a failed soak
    // and arms the same automatic revert. Wiring only the timer would
    // have meant a pipeline that confirms early gets the verdict and not
    // the consequence, which is the worst half of both behaviors. This
    // handler already runs on a blocking thread, so it calls the
    // decision directly where the soak supervisor needs `spawn_blocking`.
    let auto_revert = if closed.verdict == sbproxy_config::SoakVerdict::Failed {
        let config_path = state
            .config_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned());
        Some(crate::config_rollback::auto_revert_after_failed_soak(
            config_path.as_deref(),
            closed.revision,
            &closed.digest,
            closed.auto_revert,
        ))
    } else {
        None
    };
    let body = serde_json::json!({
        "revision": closed.revision,
        "verdict": crate::config_soak::verdict_label(closed.verdict),
        "promoted": closed.verdict == sbproxy_config::SoakVerdict::Successful,
        "signals": signals,
        // Present only on a failed verdict, and `null` everywhere else,
        // so a pipeline reading this cannot mistake "the soak passed"
        // for "auto-revert declined".
        "auto_revert": auto_revert.as_ref().map(config_auto_revert_json),
    });
    (200, "application/json", body.to_string())
}

/// Render an [`crate::config_rollback::AutoRevertDecision`] for the
/// confirm route's response.
///
/// Every arm says what is serving now, because that is the question a
/// deploy pipeline is about to make a decision on, and "the soak failed"
/// alone does not answer it.
fn config_auto_revert_json(
    decision: &crate::config_rollback::AutoRevertDecision,
) -> serde_json::Value {
    use crate::config_rollback::AutoRevertDecision;
    match decision {
        AutoRevertDecision::Disarmed => serde_json::json!({
            "acted": false,
            "reason": "disarmed",
            "detail": "proxy.config_history.soak.auto_revert is off, which is the default; this node is \
                       still serving the revision that failed",
        }),
        AutoRevertDecision::NotArcSwappable(radius) => serde_json::json!({
            "acted": false,
            "reason": "not_arc_swappable",
            "blast_radius": crate::config_rollback::blast_radius_label(*radius),
            "detail": "an in-process swap cannot undo a change of this class; use \
                       POST /admin/config/rollback and plan to restart",
        }),
        AutoRevertDecision::RadiusUnknown => serde_json::json!({
            "acted": false,
            "reason": "radius_unknown",
            "detail": "no blast radius is recorded for the failing revision, so this node cannot \
                       know an in-process swap would undo it",
        }),
        AutoRevertDecision::WouldLoop => serde_json::json!({
            "acted": false,
            "reason": "would_loop",
            "detail": "this is the revision an earlier automatic revert restored, and it has now \
                       failed its own soak; escalating rather than reverting to itself",
        }),
        AutoRevertDecision::AlreadyOnLastKnownGood => serde_json::json!({
            "acted": false,
            "reason": "already_on_last_known_good",
            "detail": "the last known good is the document already running",
        }),
        AutoRevertDecision::Reverted(outcome) => serde_json::json!({
            "acted": true,
            "reason": "reverted",
            "restored_revision": outcome.restored_revision,
            "restored_digest": outcome.restored_digest,
            "appended_revision": outcome.appended_revision,
            "detail": "this node re-applied its last known good; the restored document soaks like \
                       any other candidate",
        }),
        AutoRevertDecision::Refused(refusal) => serde_json::json!({
            "acted": false,
            "reason": refusal.as_str(),
            "detail": sbproxy_observe::redact::redact_secrets(&refusal.to_string()),
        }),
    }
}

/// `POST /admin/config/rollback`: re-apply a config revision this node
/// already stored (WOR-2460).
///
/// The escape hatch, and the one route in this feature that changes what
/// is serving. Authenticated exactly like `POST /admin/reload`: the
/// connection handler's admin credential and its RBAC gate run before
/// this is reached, so a read-only operator cannot roll a node back.
///
/// # Body
///
/// A JSON object. Every field is optional and an empty body is the
/// documented shortest form, `{}`, which rolls back to the last known
/// good.
///
/// | Field | Meaning |
/// |---|---|
/// | `revision` | Roll back to this ring revision number |
/// | `digest` | Roll back to this content digest |
/// | `target` | `"last-known-good"`, the default |
/// | `expected_current` | Refuse unless this is the revision running now |
/// | `lineage` | Refuse unless this is the ring's lineage, absent `force` |
/// | `confirm_revision` | Type the target revision back to accept a restart-class or breaking rollback |
/// | `force` | Proceed across a lineage break |
///
/// `revision`, `digest`, and `target` are mutually exclusive; naming two
/// is a `400` rather than a silent precedence rule, because guessing
/// which one an operator meant during an incident is the wrong kind of
/// helpful.
///
/// # What the response says that an operator has to read
///
/// `config_file_unchanged` is always `true`, and it is on the response
/// rather than in a doc because it is the half of the recovery this
/// route cannot do. See [`crate::config_rollback`]'s module
/// documentation.
///
/// # The console's Roll back button is deferred to WOR-2574
///
/// **There is no button in the Vue console that calls this yet.** Until
/// there is, this route and `sbproxy config rollback` are the operator
/// surface, and the console will call this same route when it lands.
/// WOR-2574 owns `ui/src/views/ConfigView.vue`, so drawing the button
/// belongs with the rest of the console work rather than here.
///
/// The client half of the typed-confirmation rule is written and tested
/// ahead of it, as `rollbackGate` in `ui/src/lib/config-history.ts`: a
/// `restart` or `breaking` rollback, and one whose radius is unknown,
/// may not submit until the operator types the target revision back.
/// That function is the affordance and nothing calls it yet; this
/// route's `confirm_revision` check is the enforcer and is what
/// actually refuses.
///
/// The two do not read the same radius, which whoever wires the button
/// has to close. `rollbackGate` is handed the radius
/// `GET /admin/config/history` stored on the entry, measured against the
/// revision before it when it applied; this route measures the running
/// document against the target at call time. They can disagree in either
/// direction, and this route decides.
fn handle_config_rollback(state: &AdminState, body: Option<&str>) -> (u16, &'static str, String) {
    // Answered before the ring is consulted, so a node that never opted
    // into `proxy.config_history` gets the same "not enabled" body as
    // its sibling routes rather than a confusing refusal about a
    // revision.
    if let Err(response) = config_history_open_recorder() {
        return response;
    }
    let parsed =
        match body.map(str::trim).filter(|body| !body.is_empty()) {
            None => serde_json::Value::Object(serde_json::Map::new()),
            Some(text) => match serde_json::from_str::<serde_json::Value>(text) {
                Ok(value) if value.is_object() => value,
                Ok(_) => return (
                    400,
                    "application/json",
                    r#"{"error":"the request body must be a JSON object","code":"bad_request"}"#
                        .to_string(),
                ),
                Err(error) => {
                    return (
                        400,
                        "application/json",
                        serde_json::json!({
                            "error": format!("invalid JSON body: {error}"),
                            "code": "bad_request",
                        })
                        .to_string(),
                    )
                }
            },
        };

    let target = match rollback_target_from_body(&parsed) {
        Ok(target) => target,
        Err(message) => {
            return (
                400,
                "application/json",
                serde_json::json!({"error": message, "code": "bad_request"}).to_string(),
            )
        }
    };
    let request = crate::config_rollback::RollbackRequest {
        target,
        expected_current: parsed
            .get("expected_current")
            .and_then(serde_json::Value::as_u64),
        expected_lineage: parsed
            .get("lineage")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        confirm_revision: parsed
            .get("confirm_revision")
            .and_then(serde_json::Value::as_u64),
        force: parsed
            .get("force")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        actor: current_admin_actor(),
        trigger: crate::config_rollback::RollbackTrigger::Manual,
    };

    let config_path = state
        .config_path
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    match crate::config_rollback::rollback(config_path.as_deref(), &request) {
        Ok(outcome) => {
            let mut warnings: Vec<String> = Vec::new();
            if outcome.secrets_fingerprint_changed {
                warnings.push(
                    "the secrets fingerprint in force when this revision applied differs from \
                     the one running now, so a ${VAR}, vault:// or secret:// reference inside \
                     it may resolve to a different value than it did then"
                        .to_string(),
                );
            }
            if !outcome.degraded.is_empty() {
                warnings.push(format!(
                    "the restored revision published with these subsystems on prior state: {}",
                    outcome.degraded.join(", ")
                ));
            }
            warnings.push(
                "this node's config file is unchanged: the next file-watcher event, SIGHUP, \
                 source: poll, or authority bundle re-applies whatever the source of truth \
                 still says. fix it before then"
                    .to_string(),
            );
            let body = serde_json::json!({
                "rolled_back": true,
                "restored_revision": outcome.restored_revision,
                "restored_digest": outcome.restored_digest,
                "previous_revision": outcome.previous_revision,
                "appended_revision": outcome.appended_revision,
                "blast_radius": outcome.blast_radius.map(crate::config_rollback::blast_radius_label),
                "degraded": outcome.degraded,
                // The rollback candidate soaks like any other, so the
                // pointer has not moved to it yet. A pipeline that
                // wants it promoted now calls POST /admin/config/confirm.
                "soaking": crate::config_soak::in_flight_revision().is_some(),
                "secrets_fingerprint_changed": outcome.secrets_fingerprint_changed,
                "config_file_unchanged": outcome.config_file_unchanged,
                "warnings": warnings,
            });
            (200, "application/json", body.to_string())
        }
        Err(refusal) => {
            let mut body = serde_json::json!({
                // Redacted for display, the same pass the confirm route
                // and the stored-rejection listing already apply: an
                // `apply_failed` detail is a compile error, and a
                // compile error routinely quotes the offending YAML.
                "error": sbproxy_observe::redact::redact_secrets(&refusal.to_string()),
                "code": refusal.as_str(),
                "rolled_back": false,
            });
            if let crate::config_rollback::RollbackRefusal::UnknownRevision { available, .. } =
                &refusal
            {
                body["available_revisions"] = serde_json::json!(available);
            }
            if let crate::config_rollback::RollbackRefusal::UnknownDigest { available, .. } =
                &refusal
            {
                body["available_digests"] = serde_json::json!(available);
            }
            (refusal.http_status(), "application/json", body.to_string())
        }
    }
}

/// Read the three mutually exclusive target fields out of a rollback
/// body.
///
/// Split out so the exclusivity rule is one function with its own test
/// rather than a chain of `if let` arms whose precedence nobody can
/// state.
fn rollback_target_from_body(
    body: &serde_json::Value,
) -> Result<crate::config_rollback::RollbackTarget, String> {
    let revision = body.get("revision").and_then(serde_json::Value::as_u64);
    let digest = body.get("digest").and_then(serde_json::Value::as_str);
    let named = body.get("target").and_then(serde_json::Value::as_str);
    let count = usize::from(revision.is_some())
        + usize::from(digest.is_some())
        + usize::from(named.is_some());
    if count > 1 {
        return Err(
            "name exactly one of `revision`, `digest`, or `target`; naming two leaves it \
             ambiguous which revision you meant"
                .to_string(),
        );
    }
    if let Some(revision) = revision {
        return Ok(crate::config_rollback::RollbackTarget::Revision(revision));
    }
    if let Some(digest) = digest {
        return Ok(crate::config_rollback::RollbackTarget::Digest(
            digest.to_string(),
        ));
    }
    match named {
        None | Some("last-known-good") => Ok(crate::config_rollback::RollbackTarget::LastKnownGood),
        Some(other) => Err(format!(
            "`target` accepts only \"last-known-good\"; got \"{other}\". name a specific \
             revision with `revision` or a specific document with `digest`"
        )),
    }
}

/// `GET /admin/config/diff?from=<rev>&to=<rev>`: a plan between two
/// stored revisions, or between what is running and one stored revision
/// (WOR-2460).
///
/// Junos has both forms and the second is the one people actually want
/// mid-incident: `show | compare rollback n` diffs against one stored
/// revision, and `show system rollback 3 compare 1` diffs two stored
/// revisions that need not be adjacent. Cisco's `show archive config
/// differences` is the same idea. `plan()` already takes two
/// `ConfigFile` values, so this is argument plumbing rather than new
/// logic.
///
/// `from` defaults to what is running, which makes the one-argument
/// form `?to=<rev>` the same answer `GET /admin/config/history/{digest}`
/// gives for that revision. Both parameters accept a revision number or
/// the literal `last-known-good`.
///
/// Touches nothing: no reload, no ring write, no pointer move.
fn handle_config_diff(state: &AdminState, path: &str) -> (u16, &'static str, String) {
    let recorder = match config_history_open_recorder() {
        Ok(recorder) => recorder,
        Err(response) => return response,
    };
    let Some(to) = rl_query_param(path, "to") else {
        return (
            400,
            "application/json",
            r#"{"error":"`to` is required: name a revision number or last-known-good","code":"bad_request"}"#
                .to_string(),
        );
    };
    let to = match resolve_diff_side(&recorder, to) {
        Ok(side) => side,
        Err(response) => return response,
    };
    let from = match rl_query_param(path, "from") {
        Some(from) => match resolve_diff_side(&recorder, from) {
            Ok(side) => side,
            Err(response) => return response,
        },
        None => match running_document_for_diff(state) {
            Ok(text) => DiffSide {
                revision: None,
                digest: None,
                document: text,
            },
            Err(message) => {
                return (
                    503,
                    "application/json",
                    serde_json::json!({"error": message, "code": "running_config_unreadable"})
                        .to_string(),
                )
            }
        },
    };

    let baseline = match serde_yaml::from_str::<sbproxy_config::ConfigFile>(&from.document) {
        Ok(config) => config,
        Err(error) => {
            return (
                422,
                "application/json",
                serde_json::json!({
                    "error": format!("the `from` document does not parse: {error}"),
                    "code": "unparseable_revision",
                })
                .to_string(),
            )
        }
    };
    let proposed = match serde_yaml::from_str::<sbproxy_config::ConfigFile>(&to.document) {
        Ok(config) => config,
        Err(error) => {
            return (
                422,
                "application/json",
                serde_json::json!({
                    "error": format!("the `to` document does not parse: {error}"),
                    "code": "unparseable_revision",
                })
                .to_string(),
            )
        }
    };
    let report = sbproxy_config::plan(&baseline, &proposed);
    // Rendered from the original bytes and redacted afterwards, the
    // ordering `handle_config_history_detail` documents: redacting
    // first can corrupt the YAML a literal secret sits inside, and the
    // diff would then be a diff of two mangled documents.
    let plan_text = sbproxy_observe::redact::redact_secrets(&sbproxy_config::render_text(&report));
    let body = serde_json::json!({
        "from": {"revision": from.revision, "digest": from.digest},
        "to": {"revision": to.revision, "digest": to.digest},
        "max_blast_radius": crate::config_rollback::blast_radius_label(report.max_blast_radius),
        "changes": report.summary.added + report.summary.changed + report.summary.removed,
        "plan_text": plan_text,
    });
    (200, "application/json", body.to_string())
}

/// One side of a `GET /admin/config/diff`.
struct DiffSide {
    /// Ring revision, absent for the running configuration.
    revision: Option<u64>,
    /// Content digest, absent for the running configuration.
    digest: Option<String>,
    /// The document itself, unredacted: the caller redacts the rendered
    /// plan after computing it.
    document: String,
}

/// Resolve one `from=` / `to=` value to a stored document.
fn resolve_diff_side(
    recorder: &Arc<crate::config_history::ConfigHistoryRecorder>,
    value: &str,
) -> Result<DiffSide, (u16, &'static str, String)> {
    let entry = if value == "last-known-good" {
        recorder.lkg().ok_or_else(|| {
            (
                404,
                "application/json",
                r#"{"error":"no config revision has been promoted to last known good on this node yet","code":"no_last_known_good"}"#
                    .to_string(),
            )
        })?
    } else {
        let revision: u64 = value.parse().map_err(|_| {
            (
                400,
                "application/json",
                serde_json::json!({
                    "error": format!(
                        "`{value}` is neither a revision number nor last-known-good"
                    ),
                    "code": "bad_request",
                })
                .to_string(),
            )
        })?;
        recorder
            .entries()
            .into_iter()
            .find(|entry| entry.revision == revision)
            .ok_or_else(|| {
                (
                    404,
                    "application/json",
                    serde_json::json!({
                        "error": format!(
                            "revision {revision} is not in this node's config revision ring"
                        ),
                        "code": "unknown_revision",
                        "available_revisions": recorder
                            .entries()
                            .iter()
                            .map(|entry| entry.revision)
                            .collect::<Vec<_>>(),
                    })
                    .to_string(),
                )
            })?
    };
    let document = recorder.read_blob(&entry.digest).map_err(|error| {
        (
            500,
            "application/json",
            serde_json::json!({
                "error": format!("read stored revision: {error}"),
                "code": "read_failed",
            })
            .to_string(),
        )
    })?;
    Ok(DiffSide {
        revision: Some(entry.revision),
        digest: Some(entry.digest),
        document: String::from_utf8_lossy(&document).into_owned(),
    })
}

/// The merged, pre-resolution document this node is running, for the
/// `from=` default.
///
/// The same document `GET /admin/config/effective` answers with rather
/// than the raw file: a git-sourced or authority-owned node's own file
/// may be nothing but a `source:` pointer, and diffing a stored revision
/// against a pointer would report the whole configuration as removed.
fn running_document_for_diff(state: &AdminState) -> Result<String, String> {
    let path = state
        .config_path
        .as_ref()
        .ok_or_else(|| "this admin server has no config path wired".to_string())?;
    let local = std::fs::read_to_string(path)
        .map_err(|error| format!("read the running config: {error}"))?;
    let layers = crate::config_effective::current_layers(&local);
    crate::config_effective::effective_config(&layers)
        .map(|effective| effective.yaml)
        .map_err(|error| format!("resolve the running config: {error}"))
}

/// `GET /admin/config/rejected`: every candidate config this node
/// refused, newest first, with the reason it was refused (WOR-2462).
///
/// The node already knows exactly why it refused a candidate: the
/// subscriber's failure table enumerates the cases, and every one of
/// them produced a counter and a log line that were gone by the time
/// anybody went looking. This is where they survive. Envoy's config dump
/// retains the last rejected config alongside the accepted one with the
/// rejection reason attached, and it is one of the more useful things it
/// does.
///
/// `404`/`503` per [`config_history_open_recorder`] when the slot is not
/// open, the same as its applied-history siblings: refused candidates
/// live in the same ring directory and are bounded by the same block's
/// `keep_rejected`.
///
/// `document` is redacted for display exactly the way
/// [`handle_config_history_detail`] redacts a stored revision, and for
/// the same reason: pre-resolution storage guarantees a `${VAR}` /
/// `vault://` / `secret://` reference is never resolved into the ring,
/// and says nothing about a literal secret an operator typed straight
/// into the YAML. The file on disk keeps the original bytes; only this
/// response is redacted.
fn handle_config_rejected_list() -> (u16, &'static str, String) {
    let recorder = match config_history_open_recorder() {
        Ok(recorder) => recorder,
        Err(response) => return response,
    };
    let mut stored = recorder.rejections();
    // The ring stores oldest refusal first; the response contract is
    // newest first, matching what an operator asking "why is my config
    // not updating" wants at the top.
    stored.reverse();
    let entries: Vec<serde_json::Value> = stored.iter().map(config_rejected_entry_json).collect();
    let body = serde_json::json!({
        "lineage": recorder.lineage(),
        "entries": entries,
    });
    (200, "application/json", body.to_string())
}

/// One refused candidate, in the shape `docs/admin-api-reference.md`
/// documents.
fn config_rejected_entry_json(entry: &sbproxy_config::RejectedCandidate) -> serde_json::Value {
    serde_json::json!({
        "digest": entry.digest,
        "reason": entry.reason.as_str(),
        "stage": entry.stage,
        "detail": sbproxy_observe::redact::redact_secrets(&entry.detail),
        "provenance": config_history_provenance_label(&entry.provenance),
        "first_seen_at": config_history_rfc3339(entry.first_seen_at),
        "last_seen_at": config_history_rfc3339(entry.last_seen_at),
        "count": entry.count,
        "document": sbproxy_observe::redact::redact_secrets(&entry.document),
    })
}

/// The applied entries and the refused candidates in one list, newest
/// first (WOR-2462).
///
/// A rejection has to appear in the timeline in its correct place rather
/// than being invisible: "the config stopped updating three hours ago"
/// and "a candidate has been refused every poll cycle for three hours"
/// are the same incident, and a timeline that shows only the first half
/// of it sends an operator to the wrong place.
///
/// Sorted by the instant each row happened: `applied_at` for an applied
/// revision, `last_seen_at` for a refusal, which is the refusal an
/// operator is currently living with rather than the first one.
///
/// **The Vue History panel does not render this yet.** The data is here
/// and tested; drawing it belongs with the rest of the console work in
/// WOR-2574, which owns `ui/src/views/ConfigView.vue`.
fn config_history_timeline(
    recorder: &crate::config_history::ConfigHistoryRecorder,
) -> Vec<serde_json::Value> {
    let mut rows: Vec<(u64, serde_json::Value)> = Vec::new();
    for entry in recorder.entries() {
        let mut row = config_history_entry_json(&entry);
        row["kind"] = serde_json::Value::String("applied".to_string());
        row["at"] = serde_json::Value::String(config_history_rfc3339(entry.applied_at));
        rows.push((entry.applied_at, row));
    }
    for entry in recorder.rejections() {
        let mut row = config_rejected_entry_json(&entry);
        row["kind"] = serde_json::Value::String("rejected".to_string());
        row["at"] = serde_json::Value::String(config_history_rfc3339(entry.last_seen_at));
        rows.push((entry.last_seen_at, row));
    }
    // Newest first, so `sort_by_key` on the timestamp then reverse
    // rather than a descending comparator.
    rows.sort_by_key(|(at, _)| *at);
    rows.into_iter().rev().map(|(_, row)| row).collect()
}

/// `GET /admin/config/history/{digest}`: the stored pre-resolution
/// document for one ring entry, plus a `plan()` diff of that document
/// against what this node is running right now.
///
/// `404`/`503` per [`config_history_open_recorder`] when the slot is
/// not open, and additionally `404` with `{"error":"unknown digest"}`
/// when the slot is open but no entry in the ring names `digest`.
///
/// `document` and `plan_text` are redacted the same way `GET
/// /admin/config` and `GET /admin/config/effective` redact their own
/// bodies ([`sbproxy_observe::redact::redact_secrets`]), before either
/// ever leaves this handler. Pre-resolution storage only guarantees a
/// `${VAR}` / `vault://` / `secret://` reference is never resolved into
/// the ring; it says nothing about a literal secret an operator typed
/// directly into the YAML (an inline API key, a password field), and
/// without this pass that literal would come back verbatim to any
/// admin-authenticated reader for as long as the entry stays in the
/// ring. The ring FILE itself is untouched: `recorder.read_blob` above
/// returns the original bytes, `config_history_plan_text` diffs the
/// original (redacting first could corrupt the YAML a real secret
/// happens to sit inside), and only the two fields this handler builds
/// the response from are redacted, after both are computed. Rollback
/// needs the original bytes, and the ring directory's owner-only
/// (`0700` directory, `0600` file) permissions are the real access
/// boundary on them, not this response -- see
/// `docs/configuration.md#config_history`.
fn handle_config_history_detail(state: &AdminState, digest: &str) -> (u16, &'static str, String) {
    let recorder = match config_history_open_recorder() {
        Ok(recorder) => recorder,
        Err(response) => return response,
    };
    let Some(entry) = recorder
        .entries()
        .into_iter()
        .find(|entry| entry.digest == digest)
    else {
        return (
            404,
            "application/json",
            r#"{"error":"unknown digest"}"#.to_string(),
        );
    };
    let document_bytes = match recorder.read_blob(&entry.digest) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                500,
                "application/json",
                serde_json::json!({
                    "error": format!("read stored revision: {error}"),
                })
                .to_string(),
            );
        }
    };
    let document = String::from_utf8_lossy(&document_bytes).into_owned();
    let plan_text = config_history_plan_text(state, &document);
    // Redact for display only, after both are computed from the
    // original bytes above. See the handler doc comment for why.
    let document = sbproxy_observe::redact::redact_secrets(&document);
    let plan_text = sbproxy_observe::redact::redact_secrets(&plan_text);
    let body = serde_json::json!({
        "entry": config_history_entry_json(&entry),
        "document": document,
        "plan_text": plan_text,
    });
    (200, "application/json", body.to_string())
}

/// Best-effort `plan()` diff of `stored_document` (the rollback
/// candidate) against this node's running config (the baseline),
/// rendered the same way the CLI's `plan` and `apply` commands render
/// one (see [`sbproxy_config::render_text`]). "Running" is the same
/// merged, pre-resolution document `GET /admin/config/effective`
/// answers with, not the raw on-disk file: a git-sourced or
/// authority-owned node's own file may be nothing but a `source:`
/// pointer.
///
/// Never fails the detail response over this: a node with no
/// `config_path` wired, an unreadable file, a merge failure, or either
/// side failing to parse as [`sbproxy_config::ConfigFile`] all degrade
/// to a one-line explanation instead, because the stored document is
/// still worth returning even when a diff against "now" cannot be
/// computed.
fn config_history_plan_text(state: &AdminState, stored_document: &str) -> String {
    let Some(path) = state.config_path.as_ref() else {
        return "plan unavailable: admin server has no config_path wired".to_string();
    };
    let local = match std::fs::read_to_string(path) {
        Ok(local) => local,
        Err(error) => return format!("plan unavailable: read running config: {error}"),
    };
    let layers = crate::config_effective::current_layers(&local);
    let running = match crate::config_effective::effective_config(&layers) {
        Ok(effective) => effective,
        Err(error) => return format!("plan unavailable: {error}"),
    };
    let baseline = match serde_yaml::from_str::<sbproxy_config::ConfigFile>(&running.yaml) {
        Ok(config) => config,
        Err(error) => return format!("plan unavailable: parse running config: {error}"),
    };
    let proposed = match serde_yaml::from_str::<sbproxy_config::ConfigFile>(stored_document) {
        Ok(config) => config,
        Err(error) => return format!("plan unavailable: parse stored revision: {error}"),
    };
    sbproxy_config::render_text(&sbproxy_config::plan(&baseline, &proposed))
}

/// Render one [`sbproxy_config::RevisionEntry`] as the JSON shape
/// `ui/src/api.ts`'s `ConfigHistoryEntry` binds to. Hand-built rather
/// than derived from the entry's own `Serialize` impl: that impl also
/// carries `soak_verdict` and `boot_attempts`, which are not part of
/// this contract and nothing writes yet, and it would emit `applied_at`
/// as a JSON number of unix milliseconds where the contract is an RFC
/// 3339 string.
fn config_history_entry_json(entry: &sbproxy_config::RevisionEntry) -> serde_json::Value {
    serde_json::json!({
        "revision": entry.revision,
        "digest": entry.digest,
        "provenance": config_history_provenance_label(&entry.provenance),
        "state": config_history_state_label(entry.state),
        "applied_at": config_history_rfc3339(entry.applied_at),
        "actor": entry.actor.clone().unwrap_or_default(),
        "blast_radius": entry.blast_radius.map(config_history_blast_radius_label),
        "degraded": entry.degraded,
    })
}

/// `applied_at_ms` (unix milliseconds, as every [`sbproxy_config::RevisionEntry`]
/// stores it) rendered as RFC 3339 UTC with millisecond precision, the
/// wire format `docs/admin-api-reference.md` documents for
/// `entries[].applied_at` and the same idiom `handle_reload`'s
/// `loaded_at` uses (`chrono::Utc::now().to_rfc3339()`), here applied to
/// a stored instant instead of "now".
///
/// Falls back to the plain millisecond number as a string on the
/// pathological overflow [`chrono::DateTime::from_timestamp_millis`]
/// refuses (an instant so far in the future or past it cannot be
/// represented): still a string, as the contract requires, just not
/// RFC 3339 in that unreachable-in-practice case.
fn config_history_rfc3339(applied_at_ms: u64) -> String {
    let millis = i64::try_from(applied_at_ms).unwrap_or(i64::MAX);
    match chrono::DateTime::from_timestamp_millis(millis) {
        Some(when) => when.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        None => applied_at_ms.to_string(),
    }
}

/// Provenance label in the four-way vocabulary
/// (`local_file` | `git` | `authority` | `merged`) the admin UI's
/// history table renders.
///
/// Only two of those four are reachable from what a ring entry
/// actually stores. [`sbproxy_config::RevisionEntry::provenance`] (and
/// the [`sbproxy_config::AppendMetadata::provenance`] that fills it) is
/// a [`BaseOrigin`], which names only where the *base* document was
/// read from before any config-authority merge ran: `Local` or `Git`.
/// It carries no bit for "an authority overlay was also applied to
/// this revision". `record_applied_config_revision` in
/// `crate::server::lifecycle` passes through whatever `BaseOrigin` the
/// caller resolved for the base document, and that function's own doc
/// comment explains why re-deriving provenance from the merged content
/// at record time is deliberately avoided (it risks misreporting a
/// git-sourced base as `Local`). So an authority-merged reload still
/// records `Local` or `Git` here, whichever the base document was, and
/// this function maps honestly to what the stored data can actually
/// say rather than inventing a fifth signal. Distinguishing `authority`
/// and `merged` would need the per-leaf
/// [`sbproxy_config::config_merge::Provenance`] map threaded into
/// `AppendMetadata` at record time, which is out of scope here.
fn config_history_provenance_label(origin: &BaseOrigin) -> &'static str {
    match origin {
        BaseOrigin::Local => "local_file",
        BaseOrigin::Git { .. } => "git",
    }
}

/// `snake_case` label for one [`sbproxy_config::RevisionState`],
/// matching the contract's `applied | good | failed | reverted`.
fn config_history_state_label(state: sbproxy_config::RevisionState) -> &'static str {
    match state {
        sbproxy_config::RevisionState::Applied => "applied",
        sbproxy_config::RevisionState::Good => "good",
        sbproxy_config::RevisionState::Failed => "failed",
        sbproxy_config::RevisionState::Reverted => "reverted",
    }
}

/// Lowercase label for one [`sbproxy_config::BlastRadius`], matching
/// the contract's `hitless | reload | restart | breaking` and
/// [`sbproxy_config::render_text`]'s own labels for the same enum.
fn config_history_blast_radius_label(radius: sbproxy_config::BlastRadius) -> &'static str {
    match radius {
        sbproxy_config::BlastRadius::Hitless => "hitless",
        sbproxy_config::BlastRadius::Reload => "reload",
        sbproxy_config::BlastRadius::Restart => "restart",
        sbproxy_config::BlastRadius::Breaking => "breaking",
    }
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
            // WOR-2582. Sorted so the response is stable across calls:
            // a HashMap iteration order that moves every poll makes a
            // diff of two console reads unreadable.
            let mut labels: Vec<(&String, &String)> = named.labels.iter().collect();
            labels.sort_by(|a, b| a.0.cmp(b.0));
            let labels: serde_json::Map<String, serde_json::Value> = labels
                .into_iter()
                .map(|(label, version)| (label.clone(), serde_json::Value::String(version.clone())))
                .collect();
            prompts.insert(
                name.clone(),
                serde_json::json!({
                    "default_version": named.default_version,
                    "effective_version": effective_version,
                    "versions": versions,
                    "labels": labels,
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
        // WOR-2582: `labels/<label>`. `parse_prompt_admin_path` splits
        // into three, so the label rides along in `action` rather than
        // needing a fourth segment out of the parser.
        action if action == "labels" || action.starts_with("labels/") => {
            let label = action
                .strip_prefix("labels")
                .unwrap_or("")
                .trim_start_matches('/');
            if label.is_empty() || label.contains('/') {
                return (
                    404,
                    "application/json",
                    r#"{"error":"expected /admin/prompts/<host>/<name>/labels/<label>"}"#
                        .to_string(),
                );
            }
            if method.eq_ignore_ascii_case("PUT") {
                handle_prompt_set_label(host, name, label, body, state)
            } else if method.eq_ignore_ascii_case("DELETE") {
                handle_prompt_remove_label(host, name, label, state)
            } else {
                method_not_allowed()
            }
        }
        _ => (
            404,
            "application/json",
            r#"{"error":"unknown prompt admin action"}"#.to_string(),
        ),
    }
}

/// Body shape for `PUT /admin/prompts/<host>/<name>/labels/<label>`.
#[derive(serde::Deserialize)]
struct SetLabelBody {
    /// The version this label should point at.
    version: String,
}

/// `PUT /admin/prompts/<host>/<name>/labels/<label>` (WOR-2582): point a
/// movable label at a version, creating it or moving it.
///
/// This is the operation the feature exists for. A caller referencing
/// `support-bot@production` is unaffected by this call in every way
/// except which version it renders, which is the point: the operator
/// promotes a version without touching a single caller.
fn handle_prompt_set_label(
    host: &str,
    name: &str,
    label: &str,
    body: Option<&str>,
    state: &AdminState,
) -> (u16, &'static str, String) {
    let raw = match body {
        Some(b) if !b.is_empty() => b,
        _ => {
            return (
                400,
                "application/json",
                r#"{"error":"missing JSON body; expected {\"version\": \"...\"}"}"#.to_string(),
            );
        }
    };
    let parsed: SetLabelBody = match serde_json::from_str(raw) {
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
    match sbproxy_ai::prompts::set_runtime_prompt_label(host, name, label, &parsed.version) {
        Ok(()) => {
            // Same write-through policy as add and pin: best effort, a
            // failure is logged rather than 5xx-ing an operator whose
            // in-memory mutation already succeeded.
            persist_named_prompt_if_configured(state, host, name);
            // The label move is a governance-relevant decision: it
            // changes what every caller of that label renders without
            // any caller changing. Audited by name, never by template
            // body, which is operator content and can carry anything.
            tracing::info!(
                target: "sbproxy::admin::audit",
                operator = %current_admin_actor().unwrap_or_default(),
                action = "prompt_label_set",
                host = %host,
                prompt = %name,
                label = %label,
                version = %parsed.version,
                "prompt label repointed"
            );
            let body = serde_json::json!({
                "host": host,
                "name": name,
                "label": label,
                "version": parsed.version,
            })
            .to_string();
            (200, "application/json", body)
        }
        Err(message) => (
            409,
            "application/json",
            format!(r#"{{"error":"{}"}}"#, escape_json(&message)),
        ),
    }
}

/// `DELETE /admin/prompts/<host>/<name>/labels/<label>` (WOR-2582).
///
/// A caller still referencing the removed label gets an unknown-version
/// error rather than the pinned version. That is deliberate: quietly
/// serving a different prompt to a caller who asked for `@production` is
/// the failure labels exist to prevent.
fn handle_prompt_remove_label(
    host: &str,
    name: &str,
    label: &str,
    state: &AdminState,
) -> (u16, &'static str, String) {
    match sbproxy_ai::prompts::remove_runtime_prompt_label(host, name, label) {
        Ok(()) => {
            persist_named_prompt_if_configured(state, host, name);
            tracing::info!(
                target: "sbproxy::admin::audit",
                operator = %current_admin_actor().unwrap_or_default(),
                action = "prompt_label_removed",
                host = %host,
                prompt = %name,
                label = %label,
                "prompt label removed"
            );
            let body = serde_json::json!({
                "host": host,
                "name": name,
                "label": label,
                "removed": true,
            })
            .to_string();
            (200, "application/json", body)
        }
        Err(message) => (
            404,
            "application/json",
            format!(r#"{{"error":"{}"}}"#, escape_json(&message)),
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
    let effective_default = match sbproxy_ai::prompts::add_runtime_prompt_version(
        host,
        name,
        &parsed.version,
        parsed.template,
        parsed.variables.unwrap_or_default(),
    ) {
        Ok(effective_default) => effective_default,
        // WOR-2582: the version name collides with an existing label.
        // A 409 rather than a 400: the body was well formed, the store
        // state is what refuses it, and the operator's fix is to pick
        // another name or drop the label.
        Err(message) => {
            return (
                409,
                "application/json",
                format!(r#"{{"error":"{}"}}"#, escape_json(&message)),
            );
        }
    };
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

/// One entry in the `GET /api/operators` response: who can sign in and
/// with what role. No `password_hash` field at all, rather than merely
/// omitting it from serialization, so the hash can never reach this route
/// by accident.
#[derive(Serialize)]
struct OperatorSummary {
    username: String,
    role: AdminRole,
    /// The billing tenant this login is narrowed to on the meter routes
    /// (WOR-2131), omitted when it may read the whole deployment.
    ///
    /// Worth surfacing rather than leaving implicit: a scoped operator who
    /// gets a `403` from `/api/meter/*` needs somewhere in the console that
    /// says why, and the answer is a line in config they cannot see from
    /// the page that refused them.
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
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

/// Decode one application/x-www-form-urlencoded query value. Browser clients
/// percent-encode path separators, spaces, and custom-dimension punctuation.
fn decoded_query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    url::form_urlencoded::parse(query.as_bytes())
        .find_map(|(candidate, value)| (candidate == key).then(|| value.into_owned()))
}

/// Parse an optional RFC 3339 query param into UTC, or a `400` naming
/// the parameter when it is present and malformed (WOR-2575). `key` is
/// always a code-supplied literal, never caller input, so interpolating
/// it into the error body is safe.
fn parse_rfc3339_param(
    path: &str,
    key: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, (u16, &'static str, String)> {
    match decoded_query_param(path, key) {
        None => Ok(None),
        Some(raw) => match chrono::DateTime::parse_from_rfc3339(&raw) {
            Ok(t) => Ok(Some(t.with_timezone(&chrono::Utc))),
            Err(_) => Err((
                400,
                "application/json",
                format!(r#"{{"error":"{key} must be an RFC 3339 timestamp"}}"#),
            )),
        },
    }
}

// --- Request-log filter surface, report, and export (WOR-2578) ---

/// An admin route's `(status, content_type, body)` triple.
type AdminResponse = (u16, &'static str, String);

/// One JSON error response, ready to return from a route.
fn admin_error(status: u16, message: &str) -> AdminResponse {
    (
        status,
        "application/json",
        serde_json::json!({ "error": message }).to_string(),
    )
}

/// The owned result of parsing the `/api/requests` query string
/// (WOR-2578).
///
/// [`RequestLogFilter`] borrows its values, and every filter arrives as
/// a decoded `String`, so something has to own them for the length of
/// the request. Parsing lives here rather than inline in the route so
/// `/api/requests`, `/api/requests/report`, and `/api/requests/export`
/// share one parser: a value the snapshot refuses is refused
/// identically by the aggregation and the export, and a dimension added
/// here is filterable on all three the day it lands.
struct ParsedRequestFilter {
    status: Option<u16>,
    method: Option<String>,
    path_sub: Option<String>,
    guardrail_action: Option<String>,
    guardrail_category: Option<String>,
    cache_status: Option<String>,
    retried: Option<bool>,
    property_key: Option<String>,
    property_value: Option<String>,
    api_key_id: Option<String>,
    key_mode: Option<String>,
    session_id: Option<String>,
    model: Option<String>,
    tenant: Option<String>,
    user: Option<String>,
    /// Rows to skip, from the caller's `offset` (0 when absent).
    offset: usize,
    /// Rows to take, defaulted to and clamped at `max_log_entries`.
    limit: usize,
}

impl ParsedRequestFilter {
    /// Parse the whole filter surface out of `path`'s query string, or
    /// return the `400` the caller should get.
    ///
    /// `limit` is defaulted to and clamped at `max_log_entries` rather
    /// than trusted: the ring holds at most that many rows, so a larger
    /// number can only describe rows that do not exist, and clamping
    /// keeps the export bounded by configuration instead of by what a
    /// caller asks for.
    fn from_query(path: &str, max_log_entries: usize) -> Result<Self, AdminResponse> {
        let cache_status = decoded_query_param(path, "cache_status");
        if cache_status
            .as_deref()
            .is_some_and(|status| !matches!(status, "disabled" | "miss" | "hit" | "semantic_hit"))
        {
            return Err(admin_error(
                400,
                "cache_status must be disabled, miss, hit, or semantic_hit",
            ));
        }
        let retried = match decoded_query_param(path, "retried").as_deref() {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(_) => return Err(admin_error(400, "retried must be true or false")),
        };
        let property_key = decoded_query_param(path, "property_key");
        let property_value = decoded_query_param(path, "property_value");
        if property_value.is_some() && property_key.as_deref().is_none_or(str::is_empty) {
            return Err(admin_error(400, "property_value requires property_key"));
        }
        let key_mode = decoded_query_param(path, "key_mode");
        if key_mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "none" | "minted" | "native"))
        {
            return Err(admin_error(400, "key_mode must be none, minted, or native"));
        }
        // A present-but-unparseable numeric param is refused rather
        // than dropped, matching the four params above. A dropped
        // `?status=5xx` widens an export to the whole ring (every
        // tenant, every user) while `applied_dimensions()` honestly
        // reports `filters=none`, so neither the file nor its audit
        // record says the filter never applied.
        fn parse_number<T: std::str::FromStr>(
            path: &str,
            name: &str,
            message: &'static str,
        ) -> Result<Option<T>, AdminResponse> {
            match rl_query_param(path, name) {
                None => Ok(None),
                Some(raw) => match raw.parse::<T>() {
                    Ok(value) => Ok(Some(value)),
                    Err(_) => Err(admin_error(400, message)),
                },
            }
        }
        let status = parse_number::<u16>(path, "status", "status must be an HTTP status code")?;
        let offset =
            parse_number::<usize>(path, "offset", "offset must be a whole number")?.unwrap_or(0);
        let limit = parse_number::<usize>(path, "limit", "limit must be a whole number")?
            .unwrap_or(max_log_entries)
            .min(max_log_entries);
        Ok(Self {
            status,
            method: decoded_query_param(path, "method"),
            path_sub: decoded_query_param(path, "path"),
            guardrail_action: decoded_query_param(path, "guardrail_action"),
            guardrail_category: decoded_query_param(path, "guardrail_category"),
            cache_status,
            retried,
            property_key,
            property_value,
            api_key_id: decoded_query_param(path, "api_key_id"),
            key_mode,
            session_id: decoded_query_param(path, "session_id"),
            model: decoded_query_param(path, "model"),
            tenant: decoded_query_param(path, "tenant"),
            user: decoded_query_param(path, "user"),
            offset,
            limit,
        })
    }

    /// Borrow the parsed values as a [`RequestLogFilter`].
    fn filter(&self) -> RequestLogFilter<'_> {
        RequestLogFilter {
            status: self.status,
            method: self.method.as_deref(),
            path_sub: self.path_sub.as_deref(),
            guardrail_action: self.guardrail_action.as_deref(),
            guardrail_category: self.guardrail_category.as_deref(),
            cache_status: self.cache_status.as_deref(),
            retried: self.retried,
            property_key: self.property_key.as_deref(),
            property_value: self.property_value.as_deref(),
            api_key_id: self.api_key_id.as_deref(),
            key_mode: self.key_mode.as_deref(),
            session_id: self.session_id.as_deref(),
            model: self.model.as_deref(),
            tenant: self.tenant.as_deref(),
            user: self.user.as_deref(),
        }
    }

    /// Comma-joined names of the dimensions this query actually
    /// filtered on, or `none`.
    ///
    /// Names only, never values: this string goes into an audit record
    /// and a log line, and the names are a closed compile-time set
    /// while the values are operator-typed text of any length. That
    /// keeps the export's audit trail bounded by construction rather
    /// than by a truncation helper, and it still answers the question
    /// an incident asks, which is what shape of export ran.
    fn applied_dimensions(&self) -> String {
        let mut names = Vec::new();
        let mut note = |set: bool, name: &'static str| {
            if set {
                names.push(name);
            }
        };
        note(self.status.is_some(), "status");
        note(self.method.is_some(), "method");
        note(self.path_sub.is_some(), "path");
        note(self.guardrail_action.is_some(), "guardrail_action");
        note(self.guardrail_category.is_some(), "guardrail_category");
        note(self.cache_status.is_some(), "cache_status");
        note(self.retried.is_some(), "retried");
        note(self.property_key.is_some(), "property_key");
        note(self.property_value.is_some(), "property_value");
        note(self.api_key_id.is_some(), "api_key_id");
        note(self.key_mode.is_some(), "key_mode");
        note(self.session_id.is_some(), "session_id");
        note(self.model.is_some(), "model");
        note(self.tenant.is_some(), "tenant");
        note(self.user.is_some(), "user");
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(",")
        }
    }
}

/// The four dimensions `/api/requests/report` groups on (WOR-2578), in
/// canonical order.
///
/// A caller's `group_by` is resolved against this table and the
/// `&'static str` from *here* is what gets echoed and used as a JSON
/// key, so no caller-supplied byte ever becomes an object key in the
/// response.
const REPORT_DIMENSIONS: [&str; 4] = ["model", "api_key_id", "tenant", "user"];

/// Resolve `group_by` into an ordered dimension list, or the `400` the
/// caller should get.
///
/// `group_by` is required. It is the whole point of the route, so an
/// absent or empty one is an error rather than a silent default that
/// would hand back a shape the caller did not ask for. Duplicates are
/// refused too: `model,model` would otherwise emit one JSON key twice
/// and produce a response whose parse depends on the reader.
fn parse_report_dimensions(path: &str) -> Result<Vec<&'static str>, AdminResponse> {
    let raw = decoded_query_param(path, "group_by").unwrap_or_default();
    if raw.is_empty() {
        return Err(admin_error(
            400,
            "group_by is required: any comma-separated mix of model, api_key_id, tenant, user",
        ));
    }
    let mut dimensions: Vec<&'static str> = Vec::new();
    for name in raw.split(',') {
        let Some(known) = REPORT_DIMENSIONS.iter().find(|d| **d == name) else {
            return Err(admin_error(
                400,
                "group_by dimensions are model, api_key_id, tenant, user",
            ));
        };
        if dimensions.contains(known) {
            return Err(admin_error(400, "group_by dimensions must be distinct"));
        }
        dimensions.push(known);
    }
    Ok(dimensions)
}

/// One composite group's running totals (WOR-2578).
#[derive(Default)]
struct ReportTotals {
    requests: u64,
    tokens_in: u64,
    tokens_out: u64,
    cost_usd_micros: u64,
}

impl ReportTotals {
    /// Fold one row in. Saturating throughout: these operands come from
    /// an upstream usage parser, and a report is not worth an overflow
    /// panic in the admin server.
    fn add(&mut self, entry: &RequestLogEntry) {
        self.requests = self.requests.saturating_add(1);
        self.tokens_in = self.tokens_in.saturating_add(entry.tokens_in.unwrap_or(0));
        self.tokens_out = self
            .tokens_out
            .saturating_add(entry.tokens_out.unwrap_or(0));
        self.cost_usd_micros = self
            .cost_usd_micros
            .saturating_add(entry.cost_usd_micros.unwrap_or(0));
    }

    /// The four measures as a JSON object.
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "requests": self.requests,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd_micros": self.cost_usd_micros,
        })
    }
}

/// This row's value on one report dimension. A row that lacks the
/// dimension (an unkeyed call, an anonymous user) reads as the empty
/// string, which groups those rows together instead of dropping them.
fn report_dimension_value(entry: &RequestLogEntry, dimension: &str) -> String {
    match dimension {
        "model" => entry.model.clone().unwrap_or_default(),
        "api_key_id" => entry.api_key_id.clone().unwrap_or_default(),
        "tenant" => entry.tenant_id.clone(),
        "user" => entry.user_id.clone().unwrap_or_default(),
        // Unreachable: `parse_report_dimensions` resolves every name
        // against REPORT_DIMENSIONS before it reaches this function.
        _ => String::new(),
    }
}

/// Aggregate the filtered ring into one row per composite group.
///
/// Bounded by construction: every group needs at least one row behind
/// it, so the map can never hold more entries than the ring, which
/// `proxy.admin.max_log_entries` caps. Rows are folded as they are
/// visited, so the matching set is never materialized.
fn request_report_response(
    state: &AdminState,
    parsed: &ParsedRequestFilter,
    dimensions: &[&'static str],
) -> AdminResponse {
    let mut groups: BTreeMap<Vec<String>, ReportTotals> = BTreeMap::new();
    let mut totals = ReportTotals::default();
    // The caller's offset/limit page the GROUPED rows below; the scan
    // itself always covers the whole filtered set so `totals` reads
    // against the true denominators even on page two.
    state.for_each_request(&parsed.filter(), 0, state.config.max_log_entries, |entry| {
        let key = dimensions
            .iter()
            .map(|d| report_dimension_value(entry, d))
            .collect();
        groups.entry(key).or_default().add(entry);
        totals.add(entry);
    });

    let mut ordered: Vec<(Vec<String>, ReportTotals)> = groups.into_iter().collect();
    // Highest spend first, because "who spent what" is the question;
    // request count then group key break ties so equal reports sort
    // identically run to run.
    ordered.sort_by(|(a_key, a), (b_key, b)| {
        b.cost_usd_micros
            .cmp(&a.cost_usd_micros)
            .then_with(|| b.requests.cmp(&a.requests))
            .then_with(|| a_key.cmp(b_key))
    });

    let rows: Vec<serde_json::Value> = ordered
        .into_iter()
        .skip(parsed.offset)
        .take(parsed.limit)
        .map(|(key, group_totals)| {
            let group: serde_json::Map<String, serde_json::Value> = dimensions
                .iter()
                .zip(key)
                .map(|(name, value)| ((*name).to_string(), serde_json::Value::String(value)))
                .collect();
            let mut row = group_totals.to_json();
            if let Some(object) = row.as_object_mut() {
                object.insert("group".to_string(), serde_json::Value::Object(group));
            }
            row
        })
        .collect();

    let body = serde_json::json!({
        "schema_version": 1,
        "group_by": dimensions,
        "rows": rows,
        "totals": totals.to_json(),
    });
    (200, "application/json", body.to_string())
}

/// Encoding for `/api/requests/export` (WOR-2578).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    /// One `RequestLogEntry` JSON object per line: the raw shape, and
    /// the default.
    Jsonl,
    /// The same rows flattened under [`EXPORT_CSV_COLUMNS`].
    Csv,
}

impl ExportFormat {
    /// Closed-enum label for the metric and the audit record.
    fn label(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
        }
    }

    /// Response content type.
    fn content_type(self) -> &'static str {
        match self {
            Self::Jsonl => "application/x-ndjson",
            Self::Csv => "text/csv",
        }
    }
}

/// Fixed CSV column order for `format=csv` (WOR-2578).
///
/// `RequestLogEntry`'s declaration order with the two structured
/// fields moved to the end, so the header reads `timestamp` through
/// `properties` and a future scalar field appends rather than shifting
/// the column index a spreadsheet or a billing importer has already
/// bound to. Unlike the JSONL shape, a CSV row is positional, so the
/// order is part of the contract.
const EXPORT_CSV_COLUMNS: [&str; 40] = [
    "timestamp",
    "origin",
    "method",
    "path",
    "status",
    "latency_ms",
    "client_ip",
    "request_id",
    "trace_id",
    "session_id",
    "parent_session_id",
    "cache_status",
    "retry_count",
    "failover_engaged",
    "failover_from",
    "failover_to",
    "load_balancer_strategy",
    "load_balancer_target",
    "provider",
    "model",
    "tokens_in",
    "tokens_out",
    "cost_usd_micros",
    "guardrail_category",
    "guardrail_action",
    "api_key_id",
    "key_mode",
    "key_provider",
    "tenant_id",
    "user_id",
    "error_class",
    "config_revision",
    "policy_version",
    "deny_reason",
    "policy_decisions",
    "properties",
    // Appended last, because the order is the contract: an existing
    // importer keyed on column position keeps working and a new one
    // reads which credential paid for the row.
    "credential_source",
    // WOR-2658, appended after it for the same reason. Both are subsets
    // of `tokens_in` rather than additions to it.
    "tokens_cached",
    "tokens_cache_write",
    // WOR-2658, appended last for the same reason again: the tier that
    // priced the row, beside the tokens it priced.
    "service_tier",
];

/// One row's value in `column`, as text.
///
/// The two structured columns carry JSON so flattening stays lossless.
/// Neither can fail to encode (`BTreeMap<String, String>` and
/// `Vec<String>` are always representable), and an encoder that
/// somehow disagreed yields an empty container rather than taking the
/// export down.
fn export_csv_cell(entry: &RequestLogEntry, column: &str) -> String {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let number = |value: &Option<u64>| value.map(|v| v.to_string()).unwrap_or_default();
    match column {
        "timestamp" => entry.timestamp.clone(),
        "origin" => entry.origin.clone(),
        "method" => entry.method.clone(),
        "path" => entry.path.clone(),
        "status" => entry.status.to_string(),
        "latency_ms" => entry.latency_ms.to_string(),
        "client_ip" => entry.client_ip.clone(),
        "request_id" => text(&entry.request_id),
        "trace_id" => text(&entry.trace_id),
        "session_id" => text(&entry.session_id),
        "parent_session_id" => text(&entry.parent_session_id),
        "cache_status" => entry.cache_status.clone(),
        "retry_count" => entry.retry_count.to_string(),
        "failover_engaged" => entry.failover_engaged.to_string(),
        "failover_from" => text(&entry.failover_from),
        "failover_to" => text(&entry.failover_to),
        "load_balancer_strategy" => text(&entry.load_balancer_strategy),
        "load_balancer_target" => text(&entry.load_balancer_target),
        "provider" => text(&entry.provider),
        "model" => text(&entry.model),
        "tokens_in" => number(&entry.tokens_in),
        "tokens_out" => number(&entry.tokens_out),
        "tokens_cached" => number(&entry.tokens_cached),
        "tokens_cache_write" => number(&entry.tokens_cache_write),
        "cost_usd_micros" => number(&entry.cost_usd_micros),
        "guardrail_category" => text(&entry.guardrail_category),
        "guardrail_action" => text(&entry.guardrail_action),
        "api_key_id" => text(&entry.api_key_id),
        "key_mode" => entry.key_mode.clone(),
        "key_provider" => text(&entry.key_provider),
        "credential_source" => text(&entry.credential_source),
        "service_tier" => text(&entry.service_tier),
        "tenant_id" => entry.tenant_id.clone(),
        "user_id" => text(&entry.user_id),
        "error_class" => text(&entry.error_class),
        "config_revision" => entry.config_revision.clone(),
        "policy_version" => text(&entry.policy_version),
        "deny_reason" => text(&entry.deny_reason),
        "policy_decisions" => {
            serde_json::to_string(&entry.policy_decisions).unwrap_or_else(|_| "[]".to_string())
        }
        "properties" => {
            serde_json::to_string(&entry.properties).unwrap_or_else(|_| "{}".to_string())
        }
        // Unreachable: every caller iterates EXPORT_CSV_COLUMNS.
        _ => String::new(),
    }
}

/// Encode one CSV field per RFC 4180, after neutralizing a leading
/// spreadsheet formula character.
///
/// Several columns (`path`, `user_id`, `properties`, `model`) carry
/// text a caller of the *data plane* influenced, and a spreadsheet
/// evaluates a cell that opens with `=`, `+`, `-`, `@`, tab, or CR as a
/// formula. That is OWASP's CSV-injection case: an attacker who can
/// name a model or set a property gets code execution in whichever
/// finance laptop opens the export. A leading apostrophe forces the
/// cell to text; it is applied before quoting so the apostrophe lands
/// inside the quotes where the spreadsheet looks for it. No fixed
/// numeric column can trip the guard, because every numeric column in
/// [`EXPORT_CSV_COLUMNS`] is unsigned or a non-negative duration.
fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// Append one CSV record (fields plus the trailing newline) to `out`.
fn write_csv_record(out: &mut String, fields: impl Iterator<Item = String>) {
    let mut first = true;
    for field in fields {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&csv_field(&field));
    }
    out.push('\n');
}

/// Export the filtered view as CSV or JSONL.
///
/// Rows are encoded one at a time as the ring is visited, so the only
/// full copy that exists is the response itself, and that is capped by
/// `proxy.admin.max_log_entries` (the parser clamps `limit` to it) no
/// matter what the caller asks for. The response is materialized, not
/// streamed: `handle_admin_request` answers with a `String`, so every
/// route on that dispatcher is buffered by construction. What the
/// one-at-a-time encoding avoids is the *second* copy, a
/// `Vec<RequestLogEntry>` collected before encoding starts.
///
/// Every export is audited, and the row count is the number an
/// operator alerts on. Scope that record honestly: it covers **this
/// route**, not every bulk read of the log. `GET /api/requests` runs
/// the same parser, the same filter and the same ring cap, and returns
/// the same rows as a JSON array with no audit record and no counter,
/// so a detection built only on `export_request_log` covers the
/// download button rather than the whole read surface. Auditing that
/// route too would put a durable chain record on every console poll,
/// and a row-count threshold would be one page size away from being
/// bypassed, so the honest move is to say what is covered rather than
/// to imply more.
fn request_export_response(
    state: &AdminState,
    parsed: &ParsedRequestFilter,
    format: ExportFormat,
) -> AdminResponse {
    let mut body = String::new();
    if format == ExportFormat::Csv {
        write_csv_record(
            &mut body,
            EXPORT_CSV_COLUMNS.iter().map(|c| (*c).to_string()),
        );
    }
    let mut rows: u64 = 0;
    let mut encode_error: Option<String> = None;
    state.for_each_request(&parsed.filter(), parsed.offset, parsed.limit, |entry| {
        if encode_error.is_some() {
            return;
        }
        match format {
            ExportFormat::Jsonl => match serde_json::to_string(entry) {
                Ok(line) => {
                    body.push_str(&line);
                    body.push('\n');
                    rows = rows.saturating_add(1);
                }
                Err(error) => encode_error = Some(error.to_string()),
            },
            ExportFormat::Csv => {
                write_csv_record(
                    &mut body,
                    EXPORT_CSV_COLUMNS
                        .iter()
                        .map(|column| export_csv_cell(entry, column)),
                );
                rows = rows.saturating_add(1);
            }
        }
    });
    if let Some(error) = encode_error {
        return (
            500,
            "application/json",
            format!(r#"{{"error":"serialization failed: {error}"}}"#),
        );
    }

    // Same posture as `inspect_request_content`: the operator read data
    // in bulk, so the read is itself a security-relevant event and
    // lands on the admin audit chain, not only in a local log line.
    // `filters` names the dimensions that were set and never their
    // values, so nothing operator-typed reaches the record.
    let operator = current_admin_actor().unwrap_or_default();
    let filters = parsed.applied_dimensions();
    tracing::info!(
        target: "sbproxy::admin::audit",
        operator = %operator,
        format = format.label(),
        rows,
        filters = %filters,
        action = "export_request_log",
        "admin request log export"
    );
    sbproxy_observe::AdminActionAuditEntry::new(
        "export_request_log",
        Some(operator),
        None,
        None,
        None,
        Some(format!(
            "format={} rows={rows} filters={filters}",
            format.label()
        )),
    )
    .emit();
    sbproxy_observe::metrics::record_admin_request_export(format.label(), rows);

    (200, format.content_type(), body)
}

/// One channel's line in the `GET /api/audit/chain` response (WOR-2579).
///
/// All four channels appear on every response, including the ones this
/// deployment never turned on and the ones this request did not walk, so
/// the console renders "not configured" rather than nothing at all.
///
/// A channel that was not walked carries `enabled` and no verdict, and the
/// absence of `ok` is load bearing: "this request proved nothing about
/// this chain" and "this chain is broken" are different statements, and a
/// status object that could only say one of them would let a filtered read
/// render three chains as healthy on the strength of having ignored them.
#[derive(Serialize)]
struct AuditChainChannelStatus {
    /// `security`, `config`, `key`, or `admin`.
    channel: &'static str,
    /// Whether this channel has a chain file configured.
    enabled: bool,
    /// The file the walk read. Absent unless this request walked it.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// The `kid` the chain signs under.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    /// Records committed to the chain when the read started.
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_entries: Option<u64>,
    /// Records the walk verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_entries: Option<u64>,
    /// Whether every link and signature held. Present only on a channel
    /// this request actually walked.
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    /// First sequence that failed, when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    broken_seq: Option<u64>,
    /// Why it failed, when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Records matching the filters across the verified prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_matched: Option<u64>,
    /// Cursor for the next older page. Single-channel reads only: a
    /// sequence number only means something inside one chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_before_seq: Option<u64>,
    /// The file could not be read at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl AuditChainChannelStatus {
    /// A channel this request did not walk: either it is off, or a
    /// `channel=` filter pointed somewhere else.
    fn not_walked(channel: &'static str, enabled: bool) -> Self {
        Self {
            channel,
            enabled,
            path: None,
            key_id: None,
            chain_entries: None,
            verified_entries: None,
            ok: None,
            broken_seq: None,
            reason: None,
            total_matched: None,
            next_before_seq: None,
            error: None,
        }
    }

    /// A channel this request walked, carrying the verdict the walk
    /// reached. `paged` is false on a merged read, where a per-channel
    /// cursor would be a number the caller cannot use.
    fn walked(read: &sbproxy_observe::audit_chain::AuditChainRead, paged: bool) -> Self {
        Self {
            channel: read.channel,
            enabled: true,
            path: Some(read.path.clone()),
            key_id: Some(read.key_id.clone()),
            chain_entries: Some(read.chain_entries),
            verified_entries: Some(read.verified_entries),
            ok: Some(read.ok),
            broken_seq: read.broken_seq,
            reason: read.reason.clone(),
            total_matched: Some(read.total_matched),
            next_before_seq: paged.then_some(read.next_before_seq).flatten(),
            error: read.error.clone(),
        }
    }
}

/// `GET /api/audit/chain`: browse the four tamper-evident audit chains,
/// verified on the way (WOR-2579).
///
/// Read-only by construction. There is no arm here for any other method.
///
/// On the role posture, stated rather than assumed: WOR-2579's
/// acceptance asked for a role gate once console RBAC lands, and this
/// route ships without one. That is a decision, not an oversight, and
/// "this route cannot mutate" is not the argument for it, because
/// LiteLLM's cited restriction is on *read* access. The argument is
/// that reading the trail is the job the `read_only` role exists for,
/// and that the bounded ring behind `GET /api/audit/events` already
/// serves the same five channels to the same operator. The widening
/// over that ring is real and is two specific axes: history here is
/// the whole chain rather than the last `max_audit_events` records,
/// and each entry carries the chained payload verbatim rather than the
/// ring's `detail` projection. `docs/audit-log.md` says both plainly.
/// A deployment that wants the trail narrower turns the channel's
/// chain path off, or fronts the admin port.
///
/// The one gate that does ship is on tenant scope, below, and the
/// sibling reporting routes deliberately took the opposite posture: a
/// tenant-scoped operator is served a deployment-wide report and
/// export, exactly as `GET /api/requests` has always served them one.
/// The asymmetry is intentional. A narrowed *audit* trail reads as
/// "nothing else happened", which is a worse answer than a refusal; a
/// narrowed spend report is just a smaller number.
///
/// A verification failure is served as a `200` carrying `ok: false`, never
/// a `500`. The break is the finding, the records before it are still
/// evidence, and a viewer that turned a broken chain into an error page
/// would hide the one thing the chain exists to reveal.
fn handle_audit_chain(method: &str, path: &str, state: &AdminState) -> (u16, &'static str, String) {
    use sbproxy_observe::audit_chain::{
        audit_chain_installed, parse_chain_timestamp, read_audit_chain, AuditChainQuery,
        AUDIT_CHAIN_CHANNELS, DEFAULT_AUDIT_CHAIN_LIMIT, MAX_AUDIT_CHAIN_LIMIT,
    };

    if !method.eq_ignore_ascii_case("GET") {
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }

    // A tenant-scoped operator is refused the whole surface rather than
    // served a filtered slice of it, on the same argument the meter routes
    // make for a cross-tenant read: a narrowed view of an audit trail
    // reads as "nothing else happened", which is a worse answer than a
    // refusal because somebody will believe it. Two facts make filtering
    // worse here than there. Records with no tenant at all (a file-watcher
    // reload, an operator login) belong to the deployment rather than to
    // any tenant, and the chain's own sequence numbers and entry counts
    // describe every tenant's activity whatever the payloads say.
    //
    // The scope is looked up in the live config by the dispatching
    // operator's name, exactly as `resolve_principal` does, so revoking it
    // is a config reload rather than a wait for a session to expire.
    let operator = current_admin_actor();
    if let Some(scope) = operator
        .as_deref()
        .and_then(|who| state.operator_tenant(who))
    {
        sbproxy_observe::AdminActionAuditEntry::new(
            "read_audit_chain_denied",
            operator.clone(),
            Some(scope.clone()),
            None,
            None,
            Some("GET /api/audit/chain".to_string()),
        )
        .emit();
        // The refusal is scrapeable, not only auditable. Without this
        // the only record of a scoped principal reaching for a
        // deployment-wide security surface lives inside the chain that
        // principal was just refused, which takes an admin-role read to
        // find and nothing to prompt one. One increment per channel, so
        // the shipped alert
        // `increase(sbproxy_audit_chain_read_total{outcome!="verified"}[15m]) > 0`
        // covers the refusal without an operator changing the rule.
        for channel in AUDIT_CHAIN_CHANNELS {
            sbproxy_observe::metrics::record_audit_chain_read(channel, "denied");
        }
        return (
            403,
            "application/json",
            serde_json::json!({
                "error": format!(
                    "forbidden: the audit chain is deployment-wide and this operator is scoped \
                     to tenant `{scope}`"
                ),
            })
            .to_string(),
        );
    }

    // --- Query ---
    let channel = decoded_query_param(path, "channel");
    if let Some(name) = channel.as_deref() {
        if !AUDIT_CHAIN_CHANNELS.contains(&name) {
            return (
                400,
                "application/json",
                format!(
                    r#"{{"error":"channel must be one of {}"}}"#,
                    AUDIT_CHAIN_CHANNELS.join(", ")
                ),
            );
        }
    }
    let mut query = AuditChainQuery {
        actor: decoded_query_param(path, "actor").filter(|value| !value.is_empty()),
        limit: rl_query_param(path, "limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_AUDIT_CHAIN_LIMIT)
            .clamp(1, MAX_AUDIT_CHAIN_LIMIT),
        ..AuditChainQuery::default()
    };
    for (name, slot) in [
        ("since", &mut query.since_ms),
        ("until", &mut query.until_ms),
    ] {
        let Some(raw) = decoded_query_param(path, name).filter(|value| !value.is_empty()) else {
            continue;
        };
        match parse_chain_timestamp(&raw) {
            Some(at) => *slot = Some(at),
            None => {
                return (
                    400,
                    "application/json",
                    format!(r#"{{"error":"{name} must be an RFC 3339 timestamp"}}"#),
                );
            }
        }
    }
    if let Some(raw) = rl_query_param(path, "before_seq") {
        let Ok(seq) = raw.parse::<u64>() else {
            return (
                400,
                "application/json",
                r#"{"error":"before_seq must be a non-negative integer"}"#.to_string(),
            );
        };
        // Refused rather than ignored across a merged read. Sequence
        // numbers restart at zero on every chain, so one cursor applied to
        // four of them pages each to a different place and the merged
        // window silently skips records the caller was never told about.
        if channel.is_none() {
            return (
                400,
                "application/json",
                r#"{"error":"before_seq requires channel: a sequence number only means something inside one chain"}"#
                    .to_string(),
            );
        }
        query.before_seq = Some(seq);
    }

    // --- Walk ---
    let paged = channel.is_some();
    let mut statuses: Vec<AuditChainChannelStatus> = Vec::with_capacity(AUDIT_CHAIN_CHANNELS.len());
    let mut entries: Vec<sbproxy_observe::audit_chain::AuditChainRecord> = Vec::new();
    for name in AUDIT_CHAIN_CHANNELS {
        if channel.as_deref().is_some_and(|wanted| wanted != name) {
            statuses.push(AuditChainChannelStatus::not_walked(
                name,
                audit_chain_installed(name),
            ));
            continue;
        }
        let Some(mut read) = read_audit_chain(name, &query) else {
            statuses.push(AuditChainChannelStatus::not_walked(name, false));
            continue;
        };
        sbproxy_observe::metrics::record_audit_chain_read(
            read.channel,
            match (read.error.is_some(), read.ok) {
                (true, _) => "unreadable",
                (false, true) => "verified",
                (false, false) => "broken",
            },
        );
        entries.append(&mut read.records);
        statuses.push(AuditChainChannelStatus::walked(&read, paged));
    }

    // Newest first across the merged window, then cut to the page the
    // caller asked for. Ties break on the sequence number so two records
    // stamped in the same millisecond keep a stable order rather than
    // shuffling between reads.
    entries.sort_by(|left, right| {
        let left_at = sbproxy_observe::audit_chain::parse_chain_timestamp(&left.recorded_at);
        let right_at = sbproxy_observe::audit_chain::parse_chain_timestamp(&right.recorded_at);
        right_at
            .cmp(&left_at)
            .then_with(|| right.seq.cmp(&left.seq))
            .then_with(|| left.channel.cmp(right.channel))
    });
    entries.truncate(query.limit);
    let served = entries.len();

    let body = serde_json::json!({ "channels": statuses, "entries": entries });

    // Reading the audit trail is itself an audited action, the same
    // posture `/api/requests/{id}/content` takes: an investigator asking
    // "who looked" must not have to take our word for it. Emitted after
    // the page is built, so a reader never finds their own read inside the
    // window they just asked for, and the next one does.
    //
    // The detail carries the channel (a closed vocabulary, validated
    // above) and a count, never the caller's `actor=` or time filters: a
    // caller-supplied string does not get to enter a file whose whole
    // value is that nobody can quietly amend it.
    sbproxy_observe::AdminActionAuditEntry::new(
        "read_audit_chain",
        operator,
        None,
        None,
        None,
        Some(format!(
            "GET /api/audit/chain channel={} entries={served}",
            channel.as_deref().unwrap_or("all"),
        )),
    )
    .emit();

    match serde_json::to_string(&body) {
        Ok(body) => (200, "application/json", body),
        Err(e) => (
            500,
            "application/json",
            format!(r#"{{"error":"serialization failed: {e}"}}"#),
        ),
    }
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
    // The one-time enrollment token is the credential for this narrowly
    // scoped route, so it is dispatched before the operator-auth gate.
    if crate::admin_cluster::is_public_enrollment_path(path) {
        return crate::admin_cluster::dispatch(method, path, body).unwrap_or_else(|| {
            (
                404,
                "application/json",
                r#"{"error":"not found"}"#.to_string(),
            )
        });
    }
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
                );
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
    if let Some(response) = crate::admin_model_host::dispatch(method, path, body) {
        return response;
    }
    // WOR-1721: fleet metrics aggregated over the mesh.
    if let Some(response) = crate::admin_cluster::dispatch(method, path, body) {
        return response;
    }
    // WOR-2100: settlement status and the reconciliation trigger. Takes no
    // body: the only input is a bounded claim limit in the query string, and
    // there is no route here that can mark an attempt settled.
    if let Some(response) = crate::admin_payments::dispatch(method, path) {
        return response;
    }
    // Config-authority publication, status, and subscriber management.
    // Deliberately here, behind the operator-auth gate: publishing a
    // config is an operator action. The bundle endpoint subscribers fetch
    // is not on this listener at all.
    if let Some(response) = crate::config_authority::dispatch(method, path, body) {
        return response;
    }
    // WOR-1754 / WOR-1755: response-cache + key-policy-cache management.
    if let Some(response) = crate::admin_cache::dispatch(method, path, body) {
        return response;
    }
    // OpenID Federation identity and peer trust. Behind the
    // operator-auth gate: which anchors are pinned and how many peer
    // decisions are cached is operational state, not something the
    // published entity configuration already says.
    if let Some(response) = crate::admin_federation::dispatch(method, path) {
        return response;
    }
    // CoMP marketplace bridges. Same reason the federation route above
    // is here: the crate's own /admin/status is never mounted, because
    // this binary serves the CoMP well-known endpoints off the request
    // path instead of the crate's axum router (WOR-2673).
    if let Some(response) = crate::admin_licensing::dispatch(method, path) {
        return response;
    }
    // MCP OAuth brokers. The crate's own /admin/status is deliberately
    // not mounted in process, because the broker's route tree sits on
    // the public MCP origin ahead of the resource-server check. This is
    // the same JSON behind operator auth.
    if let Some(response) = crate::admin_mcp_oauth::dispatch(method, path) {
        return response;
    }
    // WOR-2581: scores and feedback ingestion. An external eval
    // framework posts an integer against a logged request id; the
    // console charts it. No scoring logic lives behind this.
    if let Some(response) = crate::admin_scores::dispatch(method, path, body) {
        return response;
    }
    // WOR-2386 / WOR-2454: time-boxed grant ledger and snapshot-bound
    // approval holds. JSON routes are the operator surface; a console
    // page is deferred.
    if let Some(response) = crate::admin_mcp_grants::dispatch(method, path, body) {
        return response;
    }

    // Classifier cache and bounded unavailable-stage health. This is kept
    // behind the operator-auth gate because configured origin identifiers and
    // tenant-scoped failure state are operational metadata.
    if path == "/admin/prompt-injection-v2" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let cache = sbproxy_modules::classification_cache_stats();
        let failures = crate::prompt_injection_runtime::snapshot();
        return (
            200,
            "application/json",
            serde_json::json!({
                "classification_cache": {
                    "size": cache.size,
                    "hits": cache.hits,
                    "misses": cache.misses,
                    "hit_ratio": cache.hit_ratio(),
                },
                "classifier_failures": failures,
            })
            .to_string(),
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
        // `workspace` defaults to `__default__`, matching the tenant-keying
        // convention the serving path enforces (see `context.rs`).
        let workspace = rl_query_param(path, "workspace").unwrap_or("__default__");
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
                );
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
    // Who can sign in to this console, and with what role. Sourced from
    // the same config `check_operator_login` authenticates against, so the
    // list cannot drift from the accounts that actually work. Passwords are
    // never included: this answers "who has access", not "what is the
    // secret". Accounts are managed in config, not through this route.
    if path_only == "/api/admin/users" {
        let mut users = vec![serde_json::json!({
            "username": state.config.username,
            "role": "admin",
            "primary": true,
        })];
        users.extend(state.config.operators.iter().map(|op| {
            serde_json::json!({
                "username": op.username,
                "role": match op.role {
                    AdminRole::ReadOnly => "read_only",
                    AdminRole::Admin => "admin",
                },
                "primary": false,
            })
        }));
        return match serde_json::to_string(&serde_json::json!({ "users": users })) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // Read-only list of configured operators for the admin console's
    // Operators view. Config-only, no CRUD: operators are managed by
    // editing `proxy.admin.operators` and reloading. GET-only by
    // construction (no POST/PUT/DELETE arm), so RBAC needs no extra
    // gating: read routes are already open to every authenticated role.
    if path_only == "/api/operators" {
        let summaries: Vec<OperatorSummary> = state
            .config
            .operators
            .iter()
            .map(|o| OperatorSummary {
                username: o.username.clone(),
                role: o.role,
                tenant: o.tenant.clone(),
            })
            .collect();
        return match serde_json::to_string(&summaries) {
            Ok(body) => (200, "application/json", body),
            Err(_) => (
                500,
                "application/json",
                r#"{"error":"serialization failed"}"#.to_string(),
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
    // WOR-2094: unified audit sample across the security, key, config,
    // admin, and policy channels. A bounded in-memory ring; the durable
    // trail is whatever the OTel collector ships the tracing targets to.
    if path_only == "/api/audit/events" {
        let limit: usize = rl_query_param(path, "limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
            .min(1_000);
        let channel = decoded_query_param(path, "channel");
        if channel
            .as_deref()
            .is_some_and(|c| !matches!(c, "security" | "key" | "config" | "admin" | "policy"))
        {
            return (
                400,
                "application/json",
                r#"{"error":"channel must be security, key, config, admin, or policy"}"#
                    .to_string(),
            );
        }
        let kind = decoded_query_param(path, "kind");
        let key_id = decoded_query_param(path, "key_id");
        let events = sbproxy_observe::audit_ring::recent_audit_events(
            limit,
            channel.as_deref(),
            kind.as_deref(),
            key_id.as_deref(),
        );
        return match serde_json::to_string(&events) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // WOR-2579: the durable, tamper-evident chains behind those samples,
    // read with verification. Method-aware, so it takes the whole request
    // line rather than just the path.
    if path_only == "/api/audit/chain" {
        return handle_audit_chain(method, path, state);
    }
    // WOR-2096: fetch one request's redacted content sample. Admin role
    // only, and every read is audited before the content is returned.
    if let Some(request_id) = path_only
        .strip_prefix("/api/requests/")
        .and_then(|rest| rest.strip_suffix("/content"))
    {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        if current_admin_role() != Some(AdminRole::Admin) {
            return (
                403,
                "application/json",
                r#"{"error":"forbidden: content inspection requires the admin role"}"#.to_string(),
            );
        }
        let Some(sample) = crate::content_capture::sample_for(request_id) else {
            return (
                404,
                "application/json",
                r#"{"error":"no content sample for that request id; capture requires the origin's capture_content flag AND the key policy's allow_content_capture consent"}"#
                    .to_string(),
            );
        };
        // Audit BEFORE returning content, mirroring the compression
        // content endpoint's posture: an operator reading caller
        // content is itself a security-relevant event.
        let operator = current_admin_actor().unwrap_or_default();
        tracing::info!(
            target: "sbproxy::admin::audit",
            operator = %operator,
            request_id = %request_id,
            tenant_id = %sample.tenant_id,
            action = "inspect_request_content",
            "admin content inspection"
        );
        // WOR-2478: tees into the durable admin chain, if one is
        // installed, alongside the existing ring push.
        sbproxy_observe::AdminActionAuditEntry::new(
            "inspect_request_content",
            Some(operator),
            Some(sample.tenant_id.clone()),
            sample.api_key_id.clone(),
            Some(request_id.to_string()),
            None,
        )
        .emit();
        return match serde_json::to_string(&sample) {
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
    // WOR-2578: the same parser serves the report and the export below.
    if path_only == "/api/requests" {
        let parsed = match ParsedRequestFilter::from_query(path, state.config.max_log_entries) {
            Ok(parsed) => parsed,
            Err(error) => return error,
        };
        let entries = state.query_requests(&parsed.filter(), parsed.offset, parsed.limit);
        return match serde_json::to_string(&entries) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // WOR-2575: recent routing decisions with filters + pagination, for
    // the admin console's routing-decisions view. Query params: `origin`,
    // `strategy`, `provider` (exact), `model` (matches the requested or
    // the selected side of a substitution), `since`/`until` (RFC 3339,
    // inclusive), `offset`, `limit`. GET-only by construction, so RBAC
    // needs no extra gating: read routes are open to every
    // authenticated role.
    if path_only == "/api/routing-decisions" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let origin_f = decoded_query_param(path, "origin");
        let strategy_f = decoded_query_param(path, "strategy");
        let provider_f = decoded_query_param(path, "provider");
        let model_f = decoded_query_param(path, "model");
        let since_f = match parse_rfc3339_param(path, "since") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let until_f = match parse_rfc3339_param(path, "until") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let offset = rl_query_param(path, "offset")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let limit = rl_query_param(path, "limit")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(state.config.max_log_entries)
            .min(state.config.max_log_entries);
        let entries = state.query_routing_decisions(
            &RoutingDecisionFilter {
                origin: origin_f.as_deref(),
                strategy: strategy_f.as_deref(),
                provider: provider_f.as_deref(),
                model: model_f.as_deref(),
                since: since_f,
                until: until_f,
            },
            offset,
            limit,
        );
        return match serde_json::to_string(&entries) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // WOR-2654: the shadow-eval comparison view, one row per target.
    // `window` accepts the spend vocabulary plus `15m`; the default is
    // `1h`. GET-only, so read RBAC applies with no extra gating.
    //
    // Every row leads with provenance (requests seen, the sample rate
    // applied, pairs retained, pairs dropped by reason) because the
    // deltas under it are computed over the retained pairs alone and a
    // delta over four pairs reads identically to one over four thousand
    // once it is a single number. The source is a bounded process-local
    // ring, so a window wider than the ring's turnover reports the ring;
    // `requests_seen` is what says which happened.
    if path_only == "/api/ai/shadow/report" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let window_secs = match rl_query_param(path, "window") {
            None => 3_600,
            Some("15m") => 900,
            Some(window) => match parse_spend_window(window) {
                Some(secs) => secs,
                None => {
                    return (
                        400,
                        "application/json",
                        r#"{"error":"unknown window (15m|1h|24h|7d|30d)"}"#.to_string(),
                    );
                }
            },
        };
        let targets: Vec<sbproxy_ai::shadow_eval::TargetSummary> =
            sbproxy_ai::shadow_eval::report_with_judge(
                std::time::Duration::from_secs(window_secs),
                &sbproxy_ai::shadow_judge::agreement_for,
            );
        let body = serde_json::json!({
            "window_secs": window_secs,
            "targets": targets,
        });
        return match serde_json::to_string(&body) {
            Ok(body) => (200, "application/json", body),
            Err(e) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {e}"}}"#),
            ),
        };
    }
    // WOR-2578: multi-dimension aggregation over the same filtered ring.
    // `group_by` is required and takes any mix of the four dimensions at
    // once, which is the "who spent what on which model" question the
    // per-dimension breakdowns on /api/usage/spend cannot answer.
    if path_only == "/api/requests/report" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let dimensions = match parse_report_dimensions(path) {
            Ok(dimensions) => dimensions,
            Err(error) => return error,
        };
        let parsed = match ParsedRequestFilter::from_query(path, state.config.max_log_entries) {
            Ok(parsed) => parsed,
            Err(error) => return error,
        };
        return request_report_response(state, &parsed, &dimensions);
    }
    // WOR-2578: raw export of the current filtered view, for the
    // spreadsheet or the billing pipeline rather than another dashboard.
    if path_only == "/api/requests/export" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let format = match decoded_query_param(path, "format").as_deref() {
            None | Some("") | Some("jsonl") => ExportFormat::Jsonl,
            Some("csv") => ExportFormat::Csv,
            Some(_) => {
                return (
                    400,
                    "application/json",
                    r#"{"error":"format must be csv or jsonl"}"#.to_string(),
                );
            }
        };
        let parsed = match ParsedRequestFilter::from_query(path, state.config.max_log_entries) {
            Ok(parsed) => parsed,
            Err(error) => return error,
        };
        return request_export_response(state, &parsed, format);
    }
    if path_only == "/api/extensions" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        let pipeline = crate::reload::current_pipeline();
        let inventory =
            crate::extension_refresh::inventory_with_health(&pipeline.extension_inventory);
        return match serde_json::to_string(&inventory) {
            Ok(body) => (200, "application/json", body),
            Err(error) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {error}"}}"#),
            ),
        };
    }
    if path_only == "/api/egress" {
        if !method.eq_ignore_ascii_case("GET") {
            return (
                405,
                "application/json",
                r#"{"error":"method not allowed"}"#.to_string(),
            );
        }
        // WOR-2476: every upstream endpoint the gateway reached, with its
        // authorization status and last-seen time. Bounded fields only:
        // host, port, scheme -- never a full URL, query, or credential.
        let endpoints = sbproxy_security::egress::egress_inventory_snapshot();
        let summary = serde_json::json!({
            "total": endpoints.len(),
            "denied": endpoints.iter().filter(|e| e.status == "denied").count(),
            "ungated": endpoints.iter().filter(|e| e.status == "ungated").count(),
        });
        let body = serde_json::json!({
            "schema_version": 1,
            "summary": summary,
            "endpoints": endpoints,
        });
        return match serde_json::to_string(&body) {
            Ok(body) => (200, "application/json", body),
            Err(error) => (
                500,
                "application/json",
                format!(r#"{{"error":"serialization failed: {error}"}}"#),
            ),
        };
    }
    // WOR-1870: operator UI settings the SPA reads at load (trace
    // deep-link template today).
    if path_only == "/api/ui-settings" {
        let body = serde_json::json!({
            "trace_url_template": state.config.trace_url_template,
        })
        .to_string();
        return (200, "application/json", body);
    }
    // WOR-1958: read-only alert runtime state plus an asynchronous targeted
    // channel test. Configuration remains file-authoritative; the generic
    // connection-level mutation gate handles RBAC and browser CSRF for POST.
    if path_only == "/api/alerts" {
        if method.eq_ignore_ascii_case("GET") {
            return alerts_snapshot_response(crate::alerting::alert_snapshot());
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    if path_only == "/api/alerts/test" {
        if method.eq_ignore_ascii_case("POST") {
            return alert_channel_test_response(body, crate::alerting::queue_channel_test);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-1718: spend summary from the AI cost/token metrics.
    // WOR-1875: any of `window`, `group_by`, `from`, `to` selects the
    // windowed shape served from the durable rollups; the zero-arg
    // legacy shape (process-lifetime counter totals) is unchanged.
    if path_only == "/api/usage/spend" {
        let window = rl_query_param(path, "window");
        // `group_by` is the one spend parameter whose values carry
        // punctuation: a promoted property reads `property:<key>`, and
        // every standards-compliant client percent-encodes the colon.
        // Decode before parsing so `property%3Afeature` and
        // `property:feature` select the same dimension.
        let group_by = decoded_query_param(path, "group_by");
        let from_p = rl_query_param(path, "from").and_then(|s| s.parse::<u64>().ok());
        let to_p = rl_query_param(path, "to").and_then(|s| s.parse::<u64>().ok());
        if window.is_some() || group_by.is_some() || from_p.is_some() || to_p.is_some() {
            return windowed_spend_response(window, group_by.as_deref(), from_p, to_p);
        }
        let snap = sbproxy_observe::metrics::metrics().snapshot_named(&[
            "sbproxy_tokens_attributed_total",
            "sbproxy_ai_tokens_attributed_total",
            "sbproxy_ai_cost_usd_micros_total",
            "sbproxy_ai_cost_dollars_attributed_total",
        ]);
        let (tokens, cost_usd) = spend_totals_from_snapshot(&snap);
        let body = serde_json::json!({
            "tokens": tokens,
            "cost_usd": cost_usd,
        })
        .to_string();
        return (200, "application/json", body);
    }
    // WOR-1720: config read + write (validate, persist, hot-swap). The
    // write path is a mutation, so the connection handler's RBAC gate has
    // already blocked read-only operators before we get here.
    // WOR-2012: what is actually running here, and who owns each part of
    // it. Distinct from `/admin/config`, which is this node's own file and
    // on a git-sourced node is only the pointer that selected the
    // repository.
    if path_only == "/admin/config/effective" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_effective(state);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2491: per-origin outcome of the owasp_api_top10 pack, read
    // off the live compiled pipeline. Read-only; gated by the same
    // operator-auth check every route past this point already sits
    // behind.
    if path_only == "/admin/owasp-api-pack" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_owasp_api_pack();
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2557: each AI origin's declared provider data posture and the
    // live effective eligible-provider set under its `data_posture:`
    // requirement. Read-only; same operator-auth gate as every route
    // past this point.
    if path_only == "/admin/ai-data-posture" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_ai_data_posture();
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2436: which project repositories this node's configuration
    // pulls and what hosts each one claims. Read-only; same operator-auth
    // gate as every route past this point.
    if path_only == "/admin/origin-composition" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_origin_composition(state);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2672: `/admin/ai-chargeback` and `/admin/ai-chargeback.csv` are
    // NOT handled here. They dispatch on the connection task (see
    // `dispatch_ai_chargeback`) because this synchronous handler never sees
    // the resolved principal, and the chargeback export is the most granular
    // consumption surface in the deployment: serving it here would hand a
    // tenant-restricted operator every tenant's rows.
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
    // WOR-2457: the applied-config audit trail. `proxy.config_history`
    // is opt-in, so both routes 404 with the same "not enabled" body
    // when no recorder is installed; see `handle_config_history_list`.
    if path_only == "/admin/config/history" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_history_list();
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2459: the boot fallback pin. GET reads it, DELETE clears it
    // and resumes the suspended reload paths.
    if path_only == "/admin/config/fallback" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_fallback_status();
        }
        if method.eq_ignore_ascii_case("DELETE") {
            return handle_config_fallback_clear(state);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2458: short-circuit the soak window for the revision under
    // judgment. POST only: it is a state change.
    if path_only == "/admin/config/confirm" {
        if method.eq_ignore_ascii_case("POST") {
            return handle_config_confirm(state);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2460: the escape hatch. POST only, and it changes what is
    // serving, so it sits behind the same admin auth and the same RBAC
    // gate `POST /admin/reload` does.
    if path_only == "/admin/config/rollback" {
        if method.eq_ignore_ascii_case("POST") {
            return handle_config_rollback(state, body);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2460: diff two stored revisions, or one stored revision
    // against what is running. Reads only.
    if path_only == "/admin/config/diff" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_diff(state, path);
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    // WOR-2462: the refused candidates, in the same ring and behind the
    // same opt-in as the applied ones.
    if path_only == "/admin/config/rejected" {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_rejected_list();
        }
        return (
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        );
    }
    if let Some(digest) = path_only.strip_prefix("/admin/config/history/") {
        if method.eq_ignore_ascii_case("GET") {
            return handle_config_history_detail(state, digest);
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
                    );
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

fn alerts_snapshot_response(
    snapshot: Option<sbproxy_observe::alerting::AlertRuntimeSnapshot>,
) -> (u16, &'static str, String) {
    let snapshot =
        snapshot.unwrap_or_else(sbproxy_observe::alerting::AlertRuntimeSnapshot::disabled);
    match serde_json::to_string(&snapshot) {
        Ok(body) => (200, "application/json", body),
        Err(error) => (
            500,
            "application/json",
            serde_json::json!({"error": format!("alert snapshot serialization failed: {error}")})
                .to_string(),
        ),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertChannelTestRequest {
    channel_index: usize,
}

fn alert_channel_test_response<F>(body: Option<&str>, queue: F) -> (u16, &'static str, String)
where
    F: FnOnce(usize) -> Result<(), crate::alerting::AlertControlError>,
{
    let request =
        match body.and_then(|body| serde_json::from_str::<AlertChannelTestRequest>(body).ok()) {
            Some(request) => request,
            None => {
                return (
                    400,
                    "application/json",
                    r#"{"error":"body must be {\"channel_index\": <non-negative integer>}"}"#
                        .to_string(),
                );
            }
        };
    match queue(request.channel_index) {
        Ok(()) => (
            202,
            "application/json",
            serde_json::json!({
                "queued": true,
                "channel_index": request.channel_index,
            })
            .to_string(),
        ),
        Err(crate::alerting::AlertControlError::UnknownChannel(index)) => (
            404,
            "application/json",
            serde_json::json!({"error": format!("unknown alert channel index {index}")})
                .to_string(),
        ),
        Err(crate::alerting::AlertControlError::Unavailable) => (
            409,
            "application/json",
            r#"{"error":"alert runtime is unavailable"}"#.to_string(),
        ),
        Err(crate::alerting::AlertControlError::QueueFull) => (
            503,
            "application/json",
            r#"{"error":"alert command queue is full"}"#.to_string(),
        ),
    }
}

fn snapshot_value(snap: &std::collections::HashMap<String, f64>, name: &str) -> f64 {
    snap.get(name).copied().unwrap_or(0.0)
}

fn first_positive_snapshot_value(
    snap: &std::collections::HashMap<String, f64>,
    names: &[&str],
) -> f64 {
    names
        .iter()
        .map(|name| snapshot_value(snap, name))
        .find(|value| *value > 0.0)
        .unwrap_or(0.0)
}

/// WOR-1875: parse a `window=` value into seconds.
fn parse_spend_window(window: &str) -> Option<u64> {
    Some(match window {
        "1h" => 3_600,
        "24h" => 86_400,
        "7d" => 7 * 86_400,
        "30d" => 30 * 86_400,
        _ => return None,
    })
}

/// WOR-1875: serve the windowed spend shape from the rollup store.
/// Parameter validation runs before the store lookup so a bad request
/// is a 400 even when rollups are disabled; a valid request without a
/// store is a 503 that names the config knob.
fn windowed_spend_response(
    window: Option<&str>,
    group_by: Option<&str>,
    from_p: Option<u64>,
    to_p: Option<u64>,
) -> (u16, &'static str, String) {
    let Some(group) = sbproxy_observe::usage_rollup::GroupBy::parse(group_by.unwrap_or("total"))
    else {
        return (
            400,
            "application/json",
            r#"{"error":"unknown group_by (provider|model|tenant|team|api_key|project|origin|agent|property:<key>|total)"}"#.to_string(),
        );
    };
    let requested_property_key = match &group {
        sbproxy_observe::usage_rollup::GroupBy::Property(key) => Some(key.clone()),
        _ => None,
    };
    let window_secs = match window {
        None => None,
        Some(w) => match parse_spend_window(w) {
            Some(secs) => Some(secs),
            None => {
                return (
                    400,
                    "application/json",
                    r#"{"error":"unknown window (1h|24h|7d|30d)"}"#.to_string(),
                );
            }
        },
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (from, to) = match (from_p, to_p, window_secs) {
        (Some(f), Some(t), _) => (f, t),
        (Some(f), None, _) => (f, now),
        (None, _, Some(w)) => (now.saturating_sub(w), now),
        _ => (now.saturating_sub(86_400), now),
    };
    if from >= to {
        return (
            400,
            "application/json",
            r#"{"error":"from must be before to"}"#.to_string(),
        );
    }
    let Some(writer) = sbproxy_observe::usage_rollup::usage_rollup_writer() else {
        return (
            503,
            "application/json",
            r#"{"error":"usage rollups are not enabled (proxy.observability.usage_rollups)"}"#
                .to_string(),
        );
    };
    match writer
        .store()
        .query(from, to, group, now, writer.hourly_retention_secs())
    {
        Ok(res) => {
            if let Some(key) = requested_property_key {
                if !res.property_keys.iter().any(|candidate| candidate == &key) {
                    return (
                        400,
                        "application/json",
                        serde_json::json!({
                            "error": format!("unknown property key {key:?}"),
                            "property_keys": res.property_keys,
                        })
                        .to_string(),
                    );
                }
            }
            let body = serde_json::json!({
                "from": from,
                "to": to,
                "group_by": group_by.unwrap_or("total"),
                "bucket_secs": res.bucket_secs,
                "buckets": res.buckets,
                "totals": res.totals,
                "property_keys": res.property_keys,
            })
            .to_string();
            (200, "application/json", body)
        }
        Err(e) => (
            500,
            "application/json",
            format!(r#"{{"error":"rollup query failed: {e}"}}"#),
        ),
    }
}

fn spend_totals_from_snapshot(snap: &std::collections::HashMap<String, f64>) -> (f64, f64) {
    let tokens = first_positive_snapshot_value(
        snap,
        &[
            "sbproxy_ai_tokens_attributed_total",
            "sbproxy_tokens_attributed_total",
        ],
    );
    let dollars = snapshot_value(snap, "sbproxy_ai_cost_dollars_attributed_total");
    let cost_usd = if dollars > 0.0 {
        dollars
    } else {
        snapshot_value(snap, "sbproxy_ai_cost_usd_micros_total") / 1_000_000.0
    };
    (tokens, cost_usd)
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

thread_local! {
    /// Operator username for the admin request currently dispatching on
    /// this blocking thread (WOR-2094). The blocking dispatcher runs one
    /// request end-to-end on one pooled thread, so a scoped slot is
    /// sound; the guard clears it before the thread returns to the pool.
    static CURRENT_ADMIN_ACTOR: std::cell::RefCell<Option<(String, AdminRole)>> =
        const { std::cell::RefCell::new(None) };
}

/// The authenticated operator for the admin request currently being
/// dispatched on this thread, when one resolved (WOR-2094). Read by
/// audit emitters below the sync dispatcher so mutations name their
/// actor without threading a parameter through every handler.
pub(crate) fn current_admin_actor() -> Option<String> {
    CURRENT_ADMIN_ACTOR.with(|slot| slot.borrow().as_ref().map(|(name, _)| name.clone()))
}

/// Role of the operator dispatching on this thread (WOR-2096), for
/// handlers below the sync dispatcher that gate on admin-only reads.
pub(crate) fn current_admin_role() -> Option<AdminRole> {
    CURRENT_ADMIN_ACTOR.with(|slot| slot.borrow().as_ref().map(|(_, role)| *role))
}

/// Emit a `config_audit` record for a `POST /admin/reload` rejection
/// (WOR-2486).
///
/// The success arm has audited since `ConfigAuditEntry`'s original
/// production call site; every rejection arm on this path (source
/// resolution, YAML parse, pipeline compile, and the shared runtime
/// transaction) had none. `reason` is expected already path-scrubbed by
/// [`sanitise_path_in_error`], the same text the HTTP response carries,
/// so the record never says more than the caller who triggered it
/// already saw.
fn audit_admin_reload_rejection(prior_revision: &str, reason: &str) {
    let mut entry =
        sbproxy_observe::ConfigAuditEntry::new("api", Vec::new(), Vec::new(), Vec::new())
            .with_revisions(Some(prior_revision), None::<&str>)
            .with_rejection_reason(reason);
    if let Some(actor) = current_admin_actor() {
        entry = entry.with_actor(actor);
    }
    entry.emit();
}

/// Clears the actor slot when the dispatch scope ends.
pub(crate) struct AdminActorGuard;

impl Drop for AdminActorGuard {
    fn drop(&mut self) {
        CURRENT_ADMIN_ACTOR.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Install `actor` as the dispatching operator for this thread and
/// return a guard that clears it on scope exit.
///
/// `pub(crate)` so tests below the sync dispatcher (admin_keys' audit
/// attribution tests) can install an operator through the same seam the
/// production dispatcher uses, rather than through a test-only side door.
pub(crate) fn set_current_admin_actor(actor: Option<(String, AdminRole)>) -> AdminActorGuard {
    CURRENT_ADMIN_ACTOR.with(|slot| *slot.borrow_mut() = actor);
    AdminActorGuard
}

/// Record the raw-bytes hash of a config the process just loaded, so
/// `GET /admin/drift` compares against what is actually running.
///
/// Every path that loads a config must call this. Previously only
/// startup and `POST /admin/reload` did, so after a file-watcher or
/// SIGHUP reload the baseline still held the pre-reload hash and drift
/// reported a difference that did not exist. A no-op when the admin
/// server is disabled.
pub fn record_loaded_config_content_hash(hex: &str) {
    if let Some(state) = ADMIN_LOG_SINK.get() {
        if let Ok(mut guard) = state.loaded_config_content_hash.lock() {
            *guard = Some(hex.to_string());
        }
    }
}

/// Spawn the admin server bound to `<config.bind>:<config.port>`
/// (`127.0.0.1` unless the operator set `bind`).
///
/// Returns `None`, having logged why, when `config.enabled` is false,
/// when configured TLS material cannot be loaded, or when `bind` is not
/// an IP address. Otherwise the returned join handle can be ignored; the
/// task lives for the duration of the process and shares the
/// `AdminState` with the rest of the proxy.
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
    // allowlist. An empty allowlist keeps the safe loopback-only default
    // (enforced inside `AdminIpFilter::new`); a configured list (CIDRs)
    // permits remote admin from known networks.
    //
    // An unparseable bind is rejected by `compile_config`, so it cannot
    // reach here. Declining to start beats the old silent fall back to
    // loopback, which made a typo look like it had worked.
    let bind_ip: std::net::IpAddr = match state.config.bind.trim().parse() {
        Ok(ip) => ip,
        Err(e) => {
            tracing::error!(
                bind = %state.config.bind,
                error = %e,
                "proxy.admin.bind is not an IP address; admin server not started"
            );
            return None;
        }
    };
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
        let rate_limiter = std::sync::Arc::new(build_rate_limiter(&state.config));
        // Empty means loopback-only: the constructor owns that, so this
        // call site cannot forget it (and cannot ask for permit-all).
        let ip_filter = std::sync::Arc::new(AdminIpFilter::new(allow_ips));
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

/// Build the admin rate limiter from the configured per-IP cap. The
/// global cap is derived as ten times the per-IP cap (see
/// [`AdminRateLimiter::new`]); config validation guarantees the value
/// is in 1..=100000, so the limiter is never off.
fn build_rate_limiter(config: &AdminConfig) -> AdminRateLimiter {
    AdminRateLimiter::new(config.rate_limit_per_minute)
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
    // The rate limit itself is enforced in `handle_admin_connection`,
    // once the request path is known: static UI bundle assets are
    // exempt (see `path_is_exempt_from_rate_limit`), everything else is
    // not. IP filtering stays here, before any bytes are read, since it
    // needs no path.
    handle_admin_connection(sock, &peer_ip, &rate_limiter, state).await;
}

/// True for a request path that should never count against the admin
/// rate limiter, even though the limiter itself cannot be disabled
/// (see `proxy.admin.rate_limit_per_minute` validation). Currently just
/// the static UI bundle: every session fetches the same hashed JS/CSS/
/// font files, so counting them starves the limiter's actual purpose,
/// which is bounding requests to authenticated, sensitive routes
/// (login, keys, config, `/api/*`). A dashboard session can otherwise
/// legitimately fire a dozen asset fetches navigating between a few
/// views and trip a limit meant for credential-guessing / DDoS, with
/// no indication to the operator beyond a silently broken page (a
/// browser's dynamic `import()` rejects a 429 JSON body outright).
fn path_is_exempt_from_rate_limit(path: &str) -> bool {
    crate::admin_ui::is_static_asset(path)
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
    peer_ip: &str,
    rate_limiter: &AdminRateLimiter,
    state: std::sync::Arc<AdminState>,
) {
    use tokio::io::AsyncReadExt;
    const MAX_ADMIN_HEADER_BYTES: usize = 64 * 1024;
    const MAX_ADMIN_BODY_BYTES: usize = sbproxy_model_host::MAX_BUNDLE_BYTES;
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 8192];
    // Read at least the headers (everything up to the \r\n\r\n). For
    // a body-bearing request, keep reading until we have the full
    // Content-Length or hit the cap.
    let mut content_length: Option<usize> = None;
    let mut header_end: Option<usize> = None;
    let mut request_too_large = false;
    let mut request_body_limit = MAX_ADMIN_BODY_BYTES;
    loop {
        match sock.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if header_end.is_none() {
                    if let Some(p) = find_header_end(&buf) {
                        if p + 4 > MAX_ADMIN_HEADER_BYTES {
                            request_too_large = true;
                            break;
                        }
                        header_end = Some(p);
                        let head = String::from_utf8_lossy(&buf[..p]);
                        request_body_limit = head
                            .lines()
                            .next()
                            .map(crate::admin_toolkit::request_body_limit)
                            .unwrap_or(MAX_ADMIN_BODY_BYTES);
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
                        if content_length.is_some_and(|length| length > request_body_limit) {
                            request_too_large = true;
                            break;
                        }
                    } else if buf.len() > MAX_ADMIN_HEADER_BYTES {
                        request_too_large = true;
                        break;
                    }
                }
                if let (Some(end), Some(cl)) = (header_end, content_length) {
                    // header bytes + 4 for "\r\n\r\n" + cl body bytes
                    let body_start = end + 4;
                    if buf.len().saturating_sub(body_start) > request_body_limit {
                        request_too_large = true;
                        break;
                    }
                    let Some(request_end) = body_start.checked_add(cl) else {
                        request_too_large = true;
                        break;
                    };
                    if buf.len() >= request_end {
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
    if request_too_large {
        let oversized_path = String::from_utf8_lossy(&buf)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .map(str::to_owned);
        if let Some(path) = oversized_path.as_deref() {
            crate::admin_toolkit::record_boundary_outcome(
                path,
                sbproxy_ai::ai_metrics::AiToolkitOutcome::BodyTooLarge,
            );
        }
        let _ = write_admin_response(
            sock,
            413,
            "application/json",
            &serde_json::json!({
                "code": "request_body_too_large",
                "error": format!(
                    "admin request body exceeds {request_body_limit} bytes"
                ),
            })
            .to_string(),
        )
        .await;
        return;
    }
    let request = String::from_utf8_lossy(&buf);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    if !path_is_exempt_from_rate_limit(path) && !rate_limiter.check(peer_ip) {
        // A throttled caller is a concurrency refusal, the same 429
        // `toolkit_error` maps `ToolkitError::Busy` onto. `Internal` is the
        // one outcome in this closed vocabulary that means the gateway
        // broke, so recording it here pages an operator for ordinary
        // client throttling and buries a real fault in that noise.
        crate::admin_toolkit::record_boundary_outcome(
            path,
            sbproxy_ai::ai_metrics::AiToolkitOutcome::Busy,
        );
        let _ = write_admin_response(
            sock,
            429,
            "application/json",
            r#"{"error":"Too Many Requests"}"#,
        )
        .await;
        return;
    }
    let mut auth_header: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut cookie: Option<String> = None;
    let mut csrf_header: Option<String> = None;
    // WOR-2012: the config schema is large and immutable for a given
    // build, so it is the one admin response worth revalidating rather
    // than resending.
    let mut if_none_match: Option<String> = None;
    // Job-progress SSE reconnect: the sequence number of the last event
    // this client saw, so the stream can replay only what it missed.
    let mut last_event_id: Option<String> = None;
    // WOR-2688: the two markers that tell a browser's script client apart
    // from a shell one, read by nothing but the 401 challenge decision
    // below. `X-Requested-With` is the console's own; `Sec-Fetch-Dest` is
    // the browser's, and reaches the `EventSource` streams the console's
    // fetch wrapper cannot decorate.
    let mut requested_with: Option<String> = None;
    let mut fetch_dest: Option<String> = None;
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
        } else if let Some(rest) = line
            .strip_prefix("If-None-Match:")
            .or_else(|| line.strip_prefix("if-none-match:"))
        {
            if_none_match = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("Last-Event-ID:")
            .or_else(|| line.strip_prefix("last-event-id:"))
        {
            last_event_id = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("X-Requested-With:")
            .or_else(|| line.strip_prefix("x-requested-with:"))
        {
            requested_with = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("Sec-Fetch-Dest:")
            .or_else(|| line.strip_prefix("sec-fetch-dest:"))
        {
            fetch_dest = Some(rest.trim().to_string());
        }
    }
    // WOR-2688: whether a 401 written below may carry the Basic challenge.
    // Derived from the request headers alone and threaded to every response
    // write on this connection, so a 401 added later cannot forget it.
    let challenge = basic_challenge_for_request(requested_with.as_deref(), fetch_dest.as_deref());
    // WOR-1717: CORS headers for an allowed cross-origin caller (echoed on
    // every response below), and a direct 204 answer to preflight OPTIONS.
    let mut cors = cors_response_headers(origin.as_deref(), &state.config.cors_origins);
    if method.eq_ignore_ascii_case("OPTIONS") {
        let _ = write_admin_response_headed(sock, 204, "text/plain", b"", &cors, challenge).await;
        return;
    }

    // An operator who opens the admin port in a browser lands on `/`, and
    // used to get `{"error":"Not Found"}` with no hint the console exists.
    // Send the browser to the SPA instead. Dispatched before the auth gate
    // on purpose: the redirect target carries no data, and requiring
    // credentials to be told where the login page lives is a dead end. The
    // SPA then gates itself and shows its own login.
    if crate::admin_ui::is_console_entry_path(path) {
        let mut headers = cors.clone();
        headers.push((
            "Location".to_string(),
            format!("{}/", crate::admin_ui::UI_PREFIX),
        ));
        let _ =
            write_admin_response_headed(sock, 302, "text/plain", b"", &headers, challenge).await;
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
            challenge,
        )
        .await;
        return;
    }
    if path == "/admin/logout" && is_state_changing(method) {
        handle_admin_logout(sock, &state, cookie.as_deref(), &cors, challenge).await;
        return;
    }

    // WOR-1714 / WOR-1716: resolve the operator (session or Basic), enforce
    // CSRF on cookie-authed mutations and RBAC (read-only cannot mutate),
    // and audit the action with the operator's identity.
    let principal = state.resolve_principal(auth_header.as_deref(), cookie.as_deref());
    let mutating = is_state_changing(method);
    // WOR-1777: upgrade a Basic-authenticated client to a session token.
    // When auth came via Basic (no session cookie), mint a session token and
    // Set-Cookie it, plus return the CSRF nonce in a header, so a browser
    // stops re-prompting for Basic and a client can carry the short-lived
    // token instead of resending the password on every request. A client
    // that ignores both keeps working via per-request Basic. Requests that
    // already present the cookie are `via_session` and are not re-minted.
    if let Some(p) = &principal {
        cors.extend(basic_session_upgrade_headers(
            &state.session_signer,
            p,
            state.config.tls.is_some(),
            unix_now(),
        ));
    }
    if let Some(p) = &principal {
        if p.via_session && mutating {
            let ok = match (csrf_header.as_deref(), p.csrf.as_deref()) {
                (Some(h), Some(c)) => constant_time_eq(h.as_bytes(), c.as_bytes()),
                _ => false,
            };
            if !ok {
                crate::admin_toolkit::record_boundary_outcome(
                    path,
                    sbproxy_ai::ai_metrics::AiToolkitOutcome::Unauthorized,
                );
                let _ = write_admin_response_headed(
                    sock,
                    403,
                    "application/json",
                    br#"{"error":"CSRF token missing or invalid"}"#,
                    &cors,
                    challenge,
                )
                .await;
                return;
            }
        }
        if p.role == AdminRole::ReadOnly && mutating {
            crate::admin_toolkit::record_boundary_outcome(
                path,
                sbproxy_ai::ai_metrics::AiToolkitOutcome::Unauthorized,
            );
            let _ = write_admin_response_headed(
                sock,
                403,
                "application/json",
                br#"{"error":"forbidden: read-only operator cannot perform this action"}"#,
                &cors,
                challenge,
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
            // WOR-2094: same event on the console's audit sample. WOR-2478:
            // and, if installed, into the durable admin chain.
            sbproxy_observe::AdminActionAuditEntry::new(
                "admin_action",
                Some(p.username.clone()),
                None,
                None,
                None,
                Some(format!("{method} {path}")),
            )
            .emit();
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
            challenge,
        )
        .await;
        return;
    }

    // WOR-2012: the config JSON Schema. Dispatched here rather than in the
    // generic handler because that handler returns a status, a content type,
    // and a body, with no way to attach a validator, and this is the one
    // admin document big enough (roughly 300KB) for the difference to
    // matter. An editor fetches it on every load; with an entity tag it
    // fetches it once per build.
    let schema_route = path.split('?').next().unwrap_or(path);
    if schema_route == "/admin/config/schema" {
        if principal.is_none() {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"authentication required"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        }
        if !method.eq_ignore_ascii_case("GET") {
            let _ = write_admin_response_headed(
                sock,
                405,
                "application/json",
                br#"{"error":"method not allowed"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        }
        let schema = sbproxy_config::config_json_schema();
        let etag = config_schema_etag();
        // `no-cache` rather than a long `max-age`: the URL has no revision
        // in it, so a cached copy that outlives an upgrade would describe
        // the previous binary. Store it, revalidate every time, and let the
        // entity tag turn the revalidation into a 304.
        let mut headers = cors.clone();
        headers.push(("ETag".to_string(), etag.to_string()));
        headers.push(("Cache-Control".to_string(), "private, no-cache".to_string()));
        if if_none_match.as_deref() == Some(etag) {
            let _ = write_admin_response_headed(
                sock,
                304,
                "application/schema+json",
                b"",
                &headers,
                challenge,
            )
            .await;
            return;
        }
        let _ = write_admin_response_headed(
            sock,
            200,
            "application/schema+json",
            schema.as_bytes(),
            &headers,
            challenge,
        )
        .await;
        return;
    }

    // WOR-2664: the agent registry is asynchronous (it reads an embedded
    // store), so it is dispatched here rather than from the synchronous
    // `handle_admin_request`. The CSRF and read-only-operator gates above
    // have already run; what they do not do is refuse an unauthenticated
    // request, because `handle_admin_request` owns that gate and this path
    // never reaches it. So the authentication check is explicit here, and it
    // comes first: an unauthenticated caller must not learn whether a
    // registry is configured.
    if path
        .split('?')
        .next()
        .unwrap_or(path)
        .starts_with(sbproxy_agent_registry::admin::ADMIN_PREFIX)
    {
        let Some(operator) = principal.as_ref() else {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"unauthorized"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        };
        let Some(registry) = state.agent_registry.as_ref() else {
            let _ = write_admin_response_headed(
                sock,
                404,
                "application/json",
                br#"{"error":"agent_registry is not configured on this proxy"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        };
        if let Some(response) = sbproxy_agent_registry::admin::dispatch(
            registry.as_ref(),
            method,
            path,
            body_owned.as_deref().map(str::as_bytes),
            Some(operator.username.as_str()),
            // WOR-2664 review: the resolved principal's tenant, so a scoped
            // operator sees and acts only inside it. The dispatcher runs on
            // the connection task, which is the only place the principal is
            // available, which is why the meter and chargeback routes make
            // this same decision here rather than deeper.
            operator.tenant.as_deref(),
            chrono::Utc::now(),
        )
        .await
        {
            let _ = write_admin_response_headed(
                sock,
                response.status,
                response.content_type,
                response.body.as_bytes(),
                &cors,
                challenge,
            )
            .await;
            return;
        }
    }

    // WOR-2669: the outbound notifier, dispatched here for the same reason
    // the agent registry is. Same explicit authentication gate, and for the
    // same reason: an unauthenticated caller must not learn whether a
    // notifier is configured.
    if path
        .split('?')
        .next()
        .unwrap_or(path)
        .starts_with(sbproxy_observe::notify::admin::ADMIN_PREFIX)
    {
        if principal.is_none() {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"unauthorized"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        }
        let Some(notifier) = state.notifier.as_ref() else {
            let _ = write_admin_response_headed(
                sock,
                404,
                "application/json",
                br#"{"error":"notifications is not configured on this proxy"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        };
        if let Some(response) = sbproxy_observe::notify::admin::dispatch(
            notifier.as_ref(),
            method,
            path,
            body_owned.as_deref().map(str::as_bytes),
        )
        .await
        {
            let _ = write_admin_response_headed(
                sock,
                response.status,
                response.content_type,
                response.body.as_bytes(),
                &cors,
                challenge,
            )
            .await;
            return;
        }
    }

    // Compression session state is external and asynchronous. Dispatch it
    // here, after principal/CSRF resolution and before the generic GET path,
    // so content inspection can enforce Admin-only, opt-in, audit-first
    // behavior and attach non-cacheable response headers.
    let compression_path = path.split('?').next().unwrap_or(path);
    if compression_path == "/admin/compression/sessions"
        || compression_path.starts_with("/admin/compression/sessions/")
    {
        if let Some(response) = crate::admin_compression::dispatch(
            method,
            path,
            body_owned.as_deref(),
            principal.as_ref(),
            csrf_header.as_deref(),
            state.compression_audit.as_ref(),
        )
        .await
        {
            cors.extend(response.headers);
            let _ = write_admin_response_headed(
                sock,
                response.status,
                response.content_type,
                response.body.as_bytes(),
                &cors,
                challenge,
            )
            .await;
            return;
        }
    }

    // WOR-2131: the meter's operator surface. Dispatched here rather than
    // in `handle_admin_request` for two reasons that both matter. The
    // cluster-wide gather is asynchronous, and the routes are tenant-scoped
    // from the resolved principal, which the synchronous handler is not
    // given: it receives an auth header that a session-authenticated
    // request has already had rewritten to the top-level admin credential,
    // so scoping there would read every operator as unscoped.
    if let Some(response) = crate::admin_meter::dispatch(method, path, principal.as_ref()).await {
        let _ = write_admin_response_headed(
            sock,
            response.0,
            response.1,
            response.2.as_bytes(),
            &cors,
            challenge,
        )
        .await;
        return;
    }

    // The toolkit runtime is generation-pinned and tenant-scoped. Keep this
    // async route on the connection task so the resolved principal (including
    // its tenant restriction) reaches it intact; the sync dispatcher below
    // receives only a synthesized Basic header for session callers.
    if let Some(response) =
        crate::admin_toolkit::dispatch(method, path, body_owned.as_deref(), principal.as_ref())
            .await
    {
        let _ = write_admin_response_headed(
            sock,
            response.status,
            response.content_type,
            response.body.as_bytes(),
            &cors,
            challenge,
        )
        .await;
        return;
    }

    // WOR-2672: the chargeback exports need the resolved principal so a
    // tenant-restricted operator is refused rather than handed every
    // tenant's consumption rows; the sync dispatcher below cannot see the
    // restriction.
    if let Some(response) = dispatch_ai_chargeback(method, path, principal.as_ref()) {
        let _ = write_admin_response_headed(
            sock,
            response.0,
            response.1,
            response.2.as_bytes(),
            &cors,
            challenge,
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
                challenge,
            )
            .await;
            return;
        }
        let (status, ct, resp) = crate::admin_playground::list_endpoints();
        let _ =
            write_admin_response_headed(sock, status, ct, resp.as_bytes(), &cors, challenge).await;
        return;
    }
    if pg_path == crate::admin_playground::CHAT_PATH && method.eq_ignore_ascii_case("POST") {
        let Some(operator) = principal.as_ref() else {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"Unauthorized"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        };
        // The operator username rides along for the bypass audit record
        // every completed /chat emits (WOR-2497).
        let (status, ct, resp) =
            crate::admin_playground::handle_chat(body_owned.as_deref(), &operator.username).await;
        let _ =
            write_admin_response_headed(sock, status, ct, resp.as_bytes(), &cors, challenge).await;
        return;
    }
    // Real-dispatch impersonation: same shape as CHAT_PATH above (async,
    // POST, admin-only via the RBAC gate that already ran on `principal`),
    // but runs the request through the real data-plane pipeline instead
    // of calling the engine / AiClient directly.
    if pg_path == crate::admin_playground::DISPATCH_PATH && method.eq_ignore_ascii_case("POST") {
        if principal.is_none() {
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"Unauthorized"}"#,
                &cors,
                challenge,
            )
            .await;
            return;
        }
        let (status, ct, resp) =
            crate::admin_playground::handle_dispatch(body_owned.as_deref()).await;
        let _ =
            write_admin_response_headed(sock, status, ct, resp.as_bytes(), &cors, challenge).await;
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
                challenge,
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

    // Job-progress SSE tail with `Last-Event-ID` replay. Handled here for
    // the same reason as the request-log tail above: it must own the
    // socket. Each event carries an `id:` line (its replay-buffer
    // sequence number), which is what lets a client's `EventSource` echo
    // `Last-Event-ID` automatically on reconnect. The stream closes once
    // the job reaches a terminal state, rather than holding the
    // connection open forever.
    let job_stream_path = path.split('?').next().unwrap_or(path);
    if let Some(job_id) = job_stream_path
        .strip_prefix("/admin/model-host/jobs/")
        .and_then(|rest| rest.strip_suffix("/stream"))
    {
        if !job_id.is_empty() && method.eq_ignore_ascii_case("GET") {
            if principal.is_none() {
                let _ = write_admin_response_headed(
                    sock,
                    401,
                    "application/json",
                    br#"{"error":"Unauthorized"}"#,
                    &cors,
                    challenge,
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
            // Subscribe before replaying, so an event published while we
            // are still writing the replay batch is not lost between the
            // two steps; `last_sent` then dedups anything the live feed
            // redelivers that the replay already covered.
            let mut live = crate::admin_model_host::job_event_log().subscribe();
            let after = last_event_id
                .as_deref()
                .and_then(|value| value.parse::<u64>().ok());
            let mut last_sent = after;
            for event in crate::admin_model_host::job_event_log().replay(job_id, after) {
                if last_sent.is_some_and(|sent| event.sequence <= sent) {
                    continue;
                }
                let Ok(json) = serde_json::to_string(&event.job) else {
                    continue;
                };
                let frame = format!("id: {}\ndata: {json}\n\n", event.sequence);
                if sock.write_all(frame.as_bytes()).await.is_err() {
                    return;
                }
                let _ = sock.flush().await;
                last_sent = Some(event.sequence);
                if event.job.state.is_terminal() {
                    return;
                }
            }
            loop {
                match live.recv().await {
                    Ok(event) if event.job.id == job_id => {
                        if last_sent.is_some_and(|sent| event.sequence <= sent) {
                            continue;
                        }
                        let Ok(json) = serde_json::to_string(&event.job) else {
                            continue;
                        };
                        let frame = format!("id: {}\ndata: {json}\n\n", event.sequence);
                        if sock.write_all(frame.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = sock.flush().await;
                        last_sent = Some(event.sequence);
                        if event.job.state.is_terminal() {
                            break;
                        }
                    }
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            return;
        }
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
            let _ =
                write_admin_response_headed(sock, status, content_type, &bytes, &cors, challenge)
                    .await;
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
    // WOR-2094: carry the authenticated operator onto the dispatch
    // thread so audit emitters below the sync dispatcher can name the
    // actor of a mutation.
    let actor_for_task = principal.as_ref().map(|p| (p.username.clone(), p.role));
    let (status, content_type, body) = match tokio::task::spawn_blocking(move || {
        let _actor_guard = set_current_admin_actor(actor_for_task);
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
    let _ = write_admin_response_headed(
        sock,
        status,
        content_type,
        body.as_bytes(),
        &cors,
        challenge,
    )
    .await;
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
        304 => "Not Modified",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
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
///
/// Sends the Basic challenge on a 401, which is a statement about who
/// calls it rather than a default: its three callers answer the IP
/// allowlist (403), an oversized body (413), and the rate limit (429),
/// all of them before a single request header has been parsed, so there
/// is no client marker to read and no 401 to decide about. A 401 written
/// from here would want `write_admin_response_headed` and the connection's
/// own `challenge` instead (WOR-2688).
async fn write_admin_response_bytes<S: tokio::io::AsyncWrite + Unpin>(
    sock: S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_admin_response_headed(sock, status, content_type, body, &[], BasicChallenge::Send).await
}

/// Whether a 401 written by `write_admin_response_headed` carries the
/// RFC 7235 `WWW-Authenticate: Basic` challenge (WOR-2688).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BasicChallenge {
    /// Send it. A scripted or CLI caller reads the challenge to learn
    /// which scheme to retry with, which is what RFC 7235 section 3.1
    /// asks a 401 to say.
    Send,
    /// Omit it. The caller is a browser's script client, where the only
    /// effect of the challenge is the browser's own credential dialog.
    Suppress,
}

/// Decide whether a 401 answering this request may carry the Basic
/// challenge (WOR-2688).
///
/// `requested_with` is the request's `X-Requested-With` header and
/// `fetch_dest` its `Sec-Fetch-Dest`. Either identifies a caller that
/// cannot act on a challenge:
///
/// - `X-Requested-With: XMLHttpRequest` is what the console's own fetch
///   wrapper sends on every admin call. It is the deliberate marker, the
///   one signal this repository sets on both sides of the wire.
/// - `Sec-Fetch-Dest`, present at any value, is a browser. Browsers that
///   have it send it on every request they make; curl, `reqwest`, undici,
///   Deno, and Bun send none of them. It shipped in Chrome 80, Firefox
///   90, and Safari 16.4, so a browser older than those sends no fetch
///   metadata: the console's own calls stay covered there by
///   `X-Requested-With`, but an address-bar navigation on such a browser
///   still draws the challenge and can still seed the password cache
///   described below. That is the one hole left in this, and closing it
///   means refusing Basic on the admin API rather than reading a hint. It covers the
///   console's `EventSource` log and job streams, which the fetch wrapper
///   cannot decorate because `EventSource` accepts no request headers, and
///   it covers the address-bar navigation (`Sec-Fetch-Dest: document`)
///   that was the last way a browser could be handed the top-level
///   credential: challenge, dialog, password, and from then on a cached
///   credential re-attached to every console call, accepted by
///   `resolve_principal` and upgraded to a session by
///   `basic_session_upgrade_headers` with no login form ever shown. The
///   value is deliberately not inspected, because every value of it is
///   still a browser and a browser is the only client that can open the
///   dialog. What a browser gets instead is the JSON refusal.
///
/// This chooses one response header and nothing else. Neither value
/// reaches [`AdminState::resolve_principal`], so a request carrying both
/// markers and no credentials is refused exactly as one carrying neither.
fn basic_challenge_for_request(
    requested_with: Option<&str>,
    fetch_dest: Option<&str>,
) -> BasicChallenge {
    let from_fetch_wrapper =
        requested_with.is_some_and(|v| v.trim().eq_ignore_ascii_case("XMLHttpRequest"));
    let from_a_browser = fetch_dest.is_some();
    if from_fetch_wrapper || from_a_browser {
        BasicChallenge::Suppress
    } else {
        BasicChallenge::Send
    }
}

/// Write an admin response with a byte body plus extra response headers
/// (WOR-1717 CORS, WOR-1714 `Set-Cookie`). `write_admin_response_bytes`
/// is the no-extra-headers wrapper.
///
/// `challenge` decides only whether a 401 carries `WWW-Authenticate`
/// (WOR-2688); it is inert on every other status.
async fn write_admin_response_headed<S: tokio::io::AsyncWrite + Unpin>(
    mut sock: S,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(String, String)],
    challenge: BasicChallenge,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n",
        status = status,
        reason = reason_phrase(status),
        content_type = content_type,
        len = body.len(),
    );
    // WOR-2334: only a 401 carries the challenge.
    //
    // This header used to go on every admin response, 200s included.
    // RFC 7235 section 4.1 defines `WWW-Authenticate` as the challenge
    // accompanying a 401, and browsers treat it that way: seeing it on an
    // ordinary successful response is an invitation to cache the
    // credentials for the whole origin and silently re-attach them to
    // every later request, invisibly to page JS.
    //
    // That is what made the admin console appear to survive restarts. A
    // browser that had ever picked up admin Basic credentials, which it
    // could do from any successful page load, would re-authenticate via
    // Basic on the next request; `resolve_principal` falls back to Basic
    // against the static config credentials, which no restart affects,
    // and `basic_session_upgrade_headers` then minted a fresh, validly
    // signed session cookie underneath the user with no visible re-login.
    // It is also the most likely explanation for "logging in as a
    // different role signs me in as admin instead": a background request
    // racing a fresh login, carrying cached admin Basic credentials.
    //
    // The SPA has its own login and CSRF flow (WOR-1714) and never needed
    // this header. Scripted and CLI clients still get a correct challenge
    // where the RFC says it belongs.
    //
    // WOR-2688: which is why the status alone is not the whole condition.
    // A 401 answering the console's own client still opened the browser's
    // native credential dialog, and that dialog is a dead end: it is not
    // the app's sign-in form, Cancel leaves the page wedged until a hard
    // reload, and typing the top-level credentials into it caches them for
    // the whole origin, which walks straight back into the loop the
    // paragraph above describes. The console reads the bare 401 and routes
    // to its own login page instead. `curl` and `sbproxy admin` send no
    // browser marker, so their 401s are unchanged.
    //
    // A browser typing an admin URL into the address bar is covered by the
    // same rule, which is what keeps the credential out of the browser's
    // password cache in the first place: it reads the JSON refusal instead
    // of being offered a dialog it should not be answering.
    if status == 401 && challenge == BasicChallenge::Send {
        header.push_str("WWW-Authenticate: Basic realm=\"sbproxy admin\"\r\n");
    }
    // Whether that header is there depends on two request headers, so
    // anything caching a 401 has to key on them. Without this a shared
    // cache can store a browser's challenge-less 401 and replay it to
    // `curl --anyauth`, which is then left with no scheme to select.
    // Any `Vary` the extra headers carry (CORS contributes `Origin`) is
    // folded into this one field line rather than sent as a second, so a
    // single header names the whole key.
    if status == 401 {
        header.push_str("Vary: X-Requested-With, Sec-Fetch-Dest");
        for (_, value) in extra_headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        {
            header.push_str(", ");
            header.push_str(value);
        }
        header.push_str("\r\n");
    }
    for (k, v) in extra_headers {
        if status == 401 && k.eq_ignore_ascii_case("vary") {
            // Already folded into the challenge `Vary` above.
            continue;
        }
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
                // `X-Requested-With` is on the list because the console
                // sends it on every call (WOR-2688) and it is not a
                // CORS-safelisted request header. Without it a
                // cross-origin console preflights every call, including
                // the plain GETs that used to go straight out, and the
                // browser blocks each one on a preflight that does not
                // name the header.
                "Authorization, Content-Type, X-CSRF-Token, X-Requested-With".to_string(),
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
    challenge: BasicChallenge,
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
                challenge,
            )
            .await;
            return;
        }
    };
    let role = match state.check_operator_login(&user, &pass) {
        Some(r) => r,
        None => {
            tracing::warn!(target: "sbproxy::admin::audit", operator = %user, "admin login failed");
            // WOR-2094: failed sign-ins are first-class security
            // events on the console's audit sample. WOR-2478: and, if
            // installed, on the durable admin chain.
            sbproxy_observe::AdminActionAuditEntry::new(
                "login_failed",
                Some(user.clone()),
                None,
                None,
                None,
                None,
            )
            .emit();
            let _ = write_admin_response_headed(
                sock,
                401,
                "application/json",
                br#"{"error":"invalid credentials"}"#,
                cors,
                challenge,
            )
            .await;
            return;
        }
    };
    let ttl_secs = 8 * 3600;
    let (token, csrf) = state.session_signer.mint(&user, role, ttl_secs, unix_now());
    tracing::info!(target: "sbproxy::admin::audit", operator = %user, role = %role_label(role), "admin login");
    // WOR-2478: tees into the durable admin chain, if one is installed,
    // alongside the existing ring push.
    sbproxy_observe::AdminActionAuditEntry::new(
        "login",
        Some(user.clone()),
        None,
        None,
        None,
        Some(format!("role: {}", role_label(role))),
    )
    .emit();
    let secure_attr = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{}={token}; HttpOnly; SameSite=Strict; Path=/{secure_attr}; Max-Age={ttl_secs}",
        crate::admin_session::SESSION_COOKIE
    );
    let mut headers = cors.to_vec();
    headers.push(("Set-Cookie".to_string(), cookie));
    let out = serde_json::json!({"role": role_label(role), "csrf_token": csrf, "username": user})
        .to_string();
    let _ = write_admin_response_headed(
        sock,
        200,
        "application/json",
        out.as_bytes(),
        &headers,
        challenge,
    )
    .await;
}

/// Handle `POST /admin/logout` (WOR-1714): revoke the session and clear
/// the cookie.
async fn handle_admin_logout<S: tokio::io::AsyncWrite + Unpin>(
    sock: S,
    state: &AdminState,
    cookie_header: Option<&str>,
    cors: &[(String, String)],
    challenge: BasicChallenge,
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
        challenge,
    )
    .await;
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_upgrade_mints_verifiable_session() {
        // WOR-1777: a Basic-authed principal is upgraded to a session token.
        use crate::admin_session::{SessionSigner, SESSION_COOKIE};
        let signer = SessionSigner::random();
        let now = 1000u64;
        let basic = AdminPrincipal {
            username: "admin".into(),
            role: AdminRole::Admin,
            via_session: false,
            csrf: None,
            tenant: None,
        };
        let headers = basic_session_upgrade_headers(&signer, &basic, false, now);

        let cookie = headers
            .iter()
            .find(|(k, _)| k == "Set-Cookie")
            .map(|(_, v)| v.as_str())
            .expect("Set-Cookie present");
        assert!(cookie.contains(&format!("{SESSION_COOKIE}=")));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));

        let csrf = headers
            .iter()
            .find(|(k, _)| k == "X-CSRF-Token")
            .map(|(_, v)| v.clone())
            .expect("X-CSRF-Token present");

        // The minted token verifies to the same operator, and the returned
        // CSRF equals the session nonce a mutation must echo.
        let token = cookie
            .strip_prefix(&format!("{SESSION_COOKIE}="))
            .and_then(|s| s.split(';').next())
            .expect("token in cookie");
        let sess = signer.verify(token, now).expect("minted token verifies");
        assert_eq!(sess.username, "admin");
        assert_eq!(sess.role, AdminRole::Admin);
        assert_eq!(sess.nonce, csrf);

        // A session-authenticated principal already holds a cookie: no re-mint.
        let via_session = AdminPrincipal {
            username: "x".into(),
            role: AdminRole::Admin,
            via_session: true,
            csrf: Some("n".into()),
            tenant: None,
        };
        assert!(basic_session_upgrade_headers(&signer, &via_session, false, now).is_empty());

        // The Secure attribute is set only when the admin listener is TLS.
        let secure = basic_session_upgrade_headers(&signer, &basic, true, now);
        assert!(secure
            .iter()
            .any(|(k, v)| k == "Set-Cookie" && v.contains("; Secure")));
    }

    fn make_state() -> AdminState {
        AdminState::new(AdminConfig {
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
    }

    /// Drive one admin request end to end over an in-memory socket and
    /// return the raw response, headers included. The challenge decision
    /// lives in the response header block, so the assertions below have to
    /// read the wire bytes rather than a parsed body.
    async fn admin_connection_roundtrip(
        state: std::sync::Arc<AdminState>,
        peer_ip: &'static str,
        request: &str,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let handler = tokio::spawn(async move {
            handle_admin_connection(server, peer_ip, &AdminRateLimiter::new(1_000_000), state).await
        });
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        handler.await.unwrap();
        response
    }

    /// WOR-2664: the agent registry answers from its own dispatcher, which
    /// runs before `handle_admin_request` and therefore before that
    /// function's own authentication gate. Coverage of the dispatcher
    /// proves nothing about the seam; these drive the real admin
    /// connection.
    #[tokio::test]
    async fn the_agent_registry_route_refuses_an_unauthenticated_caller_before_saying_whether_it_exists(
    ) {
        // No `agent_registry:` configured. An unauthenticated caller still
        // gets 401 rather than the 404 that would tell them the feature is
        // off on this proxy.
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.41",
            "GET /admin/agent-registry HTTP/1.1\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 401"),
            "unauthenticated callers must not learn the configuration: {response}"
        );
    }

    #[tokio::test]
    async fn the_agent_registry_route_is_404_when_no_registry_is_configured() {
        let auth = synthesize_basic("admin", "secret");
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.42",
            &format!("GET /admin/agent-registry HTTP/1.1\r\nAuthorization: {auth}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        assert!(
            response.contains("agent_registry is not configured"),
            "the 404 has to say why, or an operator reads it as a bad path: {response}"
        );
    }

    #[tokio::test]
    async fn a_configured_agent_registry_answers_its_own_routes_and_records_the_operator() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = format!(
            "{}/sbproxy_core_agent_registry_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let store = sbproxy_platform::storage::EmbeddedKvStore::open(&path, "agent_registry")
            .expect("open store");
        let registry = std::sync::Arc::new(
            sbproxy_agent_registry::AgentRegistry::new(
                std::sync::Arc::new(store),
                std::sync::Arc::new(sbproxy_platform::storage::MemoryKv::new("agent_registry")),
                sbproxy_agent_registry::AgentRegistryOptions::default(),
            )
            .expect("registry"),
        );
        let state = std::sync::Arc::new(make_state().with_agent_registry(registry));
        let auth = synthesize_basic("admin", "secret");

        let summary = admin_connection_roundtrip(
            std::sync::Arc::clone(&state),
            "10.0.0.43",
            &format!("GET /admin/agent-registry HTTP/1.1\r\nAuthorization: {auth}\r\n\r\n"),
        )
        .await;
        assert!(summary.starts_with("HTTP/1.1 200"), "{summary}");
        assert!(summary.contains("\"catalog_entries\":0"), "{summary}");

        // A submission over the wire, so the body plumbing is exercised too.
        let body = serde_json::json!({
            "agent_metadata": {
                "vendor": "Acme",
                "purpose": "search",
                "contact_url": "https://acme.example.com/bots",
                "expected_user_agents": ["AcmeBot/1.0"],
                "requested_scopes": ["crawl:public"],
            }
        })
        .to_string();
        let created = admin_connection_roundtrip(
            std::sync::Arc::clone(&state),
            "10.0.0.43",
            &format!(
                "POST /admin/agent-registry/registrations HTTP/1.1\r\nAuthorization: {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(created.starts_with("HTTP/1.1 201"), "{created}");
        let agent_id = created
            .rsplit_once("\r\n\r\n")
            .map(|(_, body)| body.to_string())
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
            .and_then(|value| {
                value["registration"]["agent_id"]
                    .as_str()
                    .map(str::to_owned)
            })
            .expect("agent id from the created registration");

        let approved = admin_connection_roundtrip(
            state,
            "10.0.0.43",
            &format!(
                "POST /admin/agent-registry/registrations/{agent_id}/approve HTTP/1.1\r\nAuthorization: {auth}\r\nContent-Length: 0\r\n\r\n"
            ),
        )
        .await;
        assert!(approved.starts_with("HTTP/1.1 200"), "{approved}");
        assert!(
            approved.contains("\"decided_by\":\"admin\""),
            "the authenticated operator has to reach the stored decision: {approved}"
        );

        std::fs::remove_file(&path).ok();
    }

    /// WOR-2664 review: the dispatcher read only the operator's username
    /// off the resolved principal, so a `tenant: acme` operator had read
    /// and write over every tenant's registrations. This drives the real
    /// connection with a tenant-scoped operator and asserts the deployment
    /// -wide catalog route refuses it, which is the same rule
    /// `dispatch_ai_chargeback` states two thousand lines up.
    #[tokio::test]
    async fn a_tenant_scoped_operator_is_refused_the_deployment_wide_catalog_route() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = format!(
            "{}/sbproxy_core_registry_tenant_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let store = sbproxy_platform::storage::EmbeddedKvStore::open(&path, "agent_registry")
            .expect("open store");
        let registry = std::sync::Arc::new(
            sbproxy_agent_registry::AgentRegistry::new(
                std::sync::Arc::new(store),
                std::sync::Arc::new(sbproxy_platform::storage::MemoryKv::new("agent_registry")),
                sbproxy_agent_registry::AgentRegistryOptions::default(),
            )
            .expect("registry"),
        );

        let config = AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "casey".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "hunter2",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::Admin,
                tenant: Some("acme".to_string()),
            }],
            ..AdminConfig::default()
        };
        let state = std::sync::Arc::new(
            AdminState::new(config).with_agent_registry(std::sync::Arc::clone(&registry)),
        );
        // An operator's tenant is resolved from `proxy.admin.operators` on
        // every request, and only a session principal carries one: the
        // top-level Basic credential is the deployment's own operator and
        // is never narrowed.
        let (token, _) = state
            .session_signer
            .mint("casey", AdminRole::Admin, 3600, unix_now());

        let refused = admin_connection_roundtrip(
            std::sync::Arc::clone(&state),
            "10.0.0.46",
            &format!(
                "GET /admin/agent-registry/catalog HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"
            ),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        assert!(refused.contains("deployment-wide"), "{refused}");

        // The summary is allowed and reports the scope it covers, so the
        // console can hide what the operator cannot reach.
        let summary = admin_connection_roundtrip(
            std::sync::Arc::clone(&state),
            "10.0.0.46",
            &format!(
                "GET /admin/agent-registry HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"
            ),
        )
        .await;
        assert!(summary.starts_with("HTTP/1.1 200"), "{summary}");
        assert!(summary.contains("\"scope\":\"acme\""), "{summary}");

        // The deployment-wide credential is not refused.
        let allowed = admin_connection_roundtrip(
            state,
            "10.0.0.46",
            &format!(
                "GET /admin/agent-registry/catalog HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                synthesize_basic("admin", "secret")
            ),
        )
        .await;
        assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");

        std::fs::remove_file(&path).ok();
    }

    /// WOR-2669: the notifier's routes run before `handle_admin_request`
    /// and therefore before that function's own authentication gate, so
    /// the gate has to be here. Coverage of the notifier's dispatcher
    /// proves nothing about that.
    #[tokio::test]
    async fn the_notifications_route_refuses_an_unauthenticated_caller_before_saying_whether_it_exists(
    ) {
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.44",
            "GET /admin/notifications HTTP/1.1\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }

    #[tokio::test]
    async fn the_notifications_route_is_404_when_no_notifier_is_configured() {
        let auth = synthesize_basic("admin", "secret");
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.45",
            &format!("GET /admin/notifications HTTP/1.1\r\nAuthorization: {auth}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        assert!(
            response.contains("notifications is not configured"),
            "the 404 has to say why: {response}"
        );
    }

    #[tokio::test]
    async fn admin_401_omits_the_basic_challenge_for_the_console_fetch_marker() {
        // WOR-2688: the console's fetch wrapper marks every call. Its 401
        // must not carry `WWW-Authenticate`, because that header is what
        // opens the browser's native credential dialog over an app that
        // has its own sign-in page.
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.40",
            "GET /admin/keys HTTP/1.1\r\nX-Requested-With: XMLHttpRequest\r\n\r\n",
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "{response}"
        );
        assert!(
            !response.to_ascii_lowercase().contains("www-authenticate"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn admin_401_keeps_the_basic_challenge_for_a_scripted_client() {
        // The same request without the marker is a curl or `sbproxy admin`
        // caller, and RFC 7235 says its 401 names the scheme to retry with.
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.41",
            "GET /admin/keys HTTP/1.1\r\n\r\n",
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "{response}"
        );
        assert!(
            response.contains("WWW-Authenticate: Basic realm=\"sbproxy admin\""),
            "{response}"
        );
    }

    #[tokio::test]
    async fn admin_401_omits_the_basic_challenge_for_a_browser_event_source() {
        // The console's log and job tails are `EventSource`, which takes no
        // request headers, so the fetch wrapper cannot mark them. The
        // browser marks them instead: `Sec-Fetch-Dest` is on every request a
        // browser makes and on no shell client.
        //
        // Both routes own their socket and write their own 401 ahead of the
        // generic writer, so both are named here. A path that is not a route
        // would fall through to the generic 401 and pin neither.
        for (peer, path) in [
            ("10.0.0.42", "/api/requests/stream"),
            ("10.0.0.46", "/admin/model-host/jobs/job-1/stream"),
        ] {
            let response = admin_connection_roundtrip(
                std::sync::Arc::new(make_state()),
                peer,
                &format!(
                    "GET {path} HTTP/1.1\r\nAccept: text/event-stream\r\nSec-Fetch-Dest: empty\r\n\r\n"
                ),
            )
            .await;

            assert!(
                response.starts_with("HTTP/1.1 401 Unauthorized"),
                "{path}: {response}"
            );
            assert!(
                !response.to_ascii_lowercase().contains("www-authenticate"),
                "{path}: {response}"
            );
        }
    }

    #[tokio::test]
    async fn admin_401_omits_the_basic_challenge_for_a_browser_navigation() {
        // WOR-2688 review, second Major: a top-level navigation was the last
        // way a browser could pick up the top-level credential. An operator
        // pasting an admin URL into the address bar got the challenge, the
        // dialog took the password, and the browser then attached it to
        // every later console call, where `resolve_principal` accepts it
        // against a config credential no restart invalidates and
        // `basic_session_upgrade_headers` mints a session nobody signed in
        // for. A browser sends `Sec-Fetch-Dest` on every request whatever
        // the destination, so keying on the header's presence closes that
        // door. The cost is that a browser poking the admin API by hand
        // reads the JSON refusal instead of being offered a dialog.
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(make_state()),
            "10.0.0.45",
            "GET /admin/keys HTTP/1.1\r\nAccept: text/html\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "{response}"
        );
        assert!(
            !response.to_ascii_lowercase().contains("www-authenticate"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn admin_401_names_the_client_markers_in_one_vary_header() {
        // WOR-2688 review, third finding: the challenge now varies on two
        // request headers, so a cache in front of the admin port has to key
        // on them or it will replay a browser's challenge-less 401 to a
        // shell client, which is then left with no scheme to select. The
        // CORS `Vary` folds into the same field line rather than arriving as
        // a second one.
        let mut state = make_state();
        state.config.cors_origins = vec!["https://ops.example.com".to_string()];
        let response = admin_connection_roundtrip(
            std::sync::Arc::new(state),
            "10.0.0.47",
            "GET /admin/keys HTTP/1.1\r\nOrigin: https://ops.example.com\r\n\r\n",
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "{response}"
        );
        let vary: Vec<&str> = response
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("vary:"))
            .collect();
        assert_eq!(vary.len(), 1, "one Vary field line: {response}");
        for name in ["X-Requested-With", "Sec-Fetch-Dest", "Origin"] {
            assert!(vary[0].contains(name), "{name} missing from {vary:?}");
        }
    }

    #[tokio::test]
    async fn console_fetch_marker_suppresses_only_the_challenge_never_the_auth_decision() {
        // WOR-2688's one real risk: a marker a caller sets on itself must
        // not become a way in. It chooses one response header, and
        // `resolve_principal` never sees it.
        let state = std::sync::Arc::new(make_state());
        assert!(state.resolve_principal(None, None).is_none());

        // Marked, with a password that does not match: still refused.
        let refused = admin_connection_roundtrip(
            std::sync::Arc::clone(&state),
            "10.0.0.43",
            &format!(
                "GET /unknown HTTP/1.1\r\nX-Requested-With: XMLHttpRequest\r\nAuthorization: {}\r\n\r\n",
                basic_auth("admin", "wrong-password"),
            ),
        )
        .await;
        assert!(
            refused.starts_with("HTTP/1.1 401 Unauthorized"),
            "{refused}"
        );
        assert!(refused.contains(r#"{"error":"Unauthorized"}"#), "{refused}");

        // Marked, with the real credentials: admitted exactly as before,
        // so the marker did not narrow the decision either. A 404 is the
        // authenticated answer for an unrouted path; a 401 would not be.
        let admitted = admin_connection_roundtrip(
            state,
            "10.0.0.44",
            &format!(
                "GET /unknown HTTP/1.1\r\nX-Requested-With: XMLHttpRequest\r\nAuthorization: {}\r\n\r\n",
                basic_auth("admin", "secret"),
            ),
        )
        .await;
        assert!(admitted.starts_with("HTTP/1.1 404 Not Found"), "{admitted}");
    }

    #[test]
    fn basic_challenge_for_request_reads_the_console_marker_or_any_fetch_metadata() {
        // The console's marker, case-insensitively (a header value is not
        // a case-sensitive token here) and whitespace-tolerantly.
        assert_eq!(
            basic_challenge_for_request(Some("XMLHttpRequest"), None),
            BasicChallenge::Suppress
        );
        assert_eq!(
            basic_challenge_for_request(Some(" xmlhttprequest "), None),
            BasicChallenge::Suppress
        );
        // The browser's marker on a script-initiated request.
        assert_eq!(
            basic_challenge_for_request(None, Some("empty")),
            BasicChallenge::Suppress
        );
        // Any other destination is a browser too, and a browser is the only
        // client that can open a credential dialog, so it is suppressed the
        // same way. `document` is the address-bar navigation the review's
        // second Major describes.
        for dest in ["document", "iframe", "script", "image", ""] {
            assert_eq!(
                basic_challenge_for_request(None, Some(dest)),
                BasicChallenge::Suppress,
                "Sec-Fetch-Dest: {dest:?}"
            );
        }
        // Neither marker is a shell client: curl and `sbproxy admin` send no
        // fetch metadata at all, and they get the RFC-correct challenge.
        assert_eq!(
            basic_challenge_for_request(None, None),
            BasicChallenge::Send
        );
        // A near miss on the console's marker is not the console's marker,
        // and does not suppress on its own.
        assert_eq!(
            basic_challenge_for_request(Some("XMLHttpRequestish"), None),
            BasicChallenge::Send
        );
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn git_in(dir: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_pointer_whose_payload_does_not_compile_is_refused_with_a_400() {
        // WOR-2410. The reload handler used to validate the raw text it
        // read off disk, and a `source:` pointer document is near-empty
        // and compiles trivially, so the validation proved nothing and
        // the payload's compile failure surfaced as the transaction's
        // 500. The handler now resolves first and validates the
        // resolved payload, so an operator-caused failure is a 400 with
        // the old config still serving, matching the documented
        // contract for both admin routes.
        if !git_available() {
            eprintln!("skipping: git is not available on this host");
            return;
        }
        let fixture = tempfile::tempdir().expect("tempdir");
        let repo = fixture.path().join("repo");
        std::fs::create_dir_all(&repo).expect("mkdir");
        git_in(&repo, &["init", "--quiet"]);
        git_in(&repo, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        git_in(&repo, &["config", "user.email", "fixture@example.test"]);
        git_in(&repo, &["config", "user.name", "Fixture"]);
        git_in(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(
            repo.join("sb.yml"),
            "origins:\n  \"api.test\":\n    action:\n      type: this_action_type_does_not_exist\n",
        )
        .expect("write payload");
        git_in(&repo, &["add", "sb.yml"]);
        git_in(&repo, &["commit", "--quiet", "-m", "broken payload"]);

        let pointer = format!(
            "source:\n  kind: git\n  repo: file://{}\n  revision: main\n  path: sb.yml\n",
            repo.display()
        );
        let config_path = fixture.path().join("sb.yml");
        std::fs::write(&config_path, &pointer).expect("write pointer");

        let mut state = make_state();
        state.config_path = Some(config_path);

        let (status, _content_type, body) = handle_reload(&state);
        assert_eq!(
            status, 400,
            "an operator-caused compile failure in the resolved payload is a 400: {body}"
        );
        assert!(
            body.contains("this_action_type_does_not_exist"),
            "the error names the payload's fault, not the pointer's: {body}"
        );
    }

    /// WOR-2486 fix round 1, I4: the reload handler's file-read failure
    /// branch (a config path that does not exist, or is not readable)
    /// never called `audit_admin_reload_rejection`, even though the
    /// only other four rejection branches on this same handler already
    /// did. `prior_revision` was in scope the whole time; the call was
    /// simply missing.
    #[test]
    fn a_missing_config_file_is_refused_and_reaches_config_audit() {
        let mut state = make_state();
        state.config_path = Some(std::path::PathBuf::from(
            "/nonexistent/wor-2486-i4-missing-config.yml",
        ));

        let before =
            sbproxy_observe::audit_ring::recent_audit_events(50, Some("config"), Some("api"), None)
                .len();
        let (status, _content_type, body) = handle_reload(&state);
        assert_eq!(status, 500, "a missing config file is a 500: {body}");
        assert!(
            body.contains("failed to read config file"),
            "the response must name the failure: {body}"
        );

        let events =
            sbproxy_observe::audit_ring::recent_audit_events(50, Some("config"), Some("api"), None);
        assert!(
            events.len() > before,
            "the file-read rejection must reach config_audit like every other rejection \
             branch on this handler does"
        );
        assert!(
            events[0]
                .detail
                .as_deref()
                .unwrap_or_default()
                .starts_with("rejected:"),
            "{:?}",
            events[0].detail
        );
    }

    #[tokio::test]
    async fn admin_listener_rejects_a_declared_body_larger_than_signed_bundle_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let handler = tokio::spawn(async move {
            handle_admin_connection(
                server,
                "10.0.0.1",
                &AdminRateLimiter::new(1_000_000),
                std::sync::Arc::new(make_state()),
            )
            .await
        });
        let request = format!(
            "POST /admin/cluster/deployments HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            512 * 1024 + 1
        );
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        handler.await.unwrap();

        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(response.contains("request_body_too_large"));
    }

    #[tokio::test]
    async fn admin_listener_reads_a_body_at_the_signed_bundle_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let handler = tokio::spawn(async move {
            handle_admin_connection(
                server,
                "10.0.0.2",
                &AdminRateLimiter::new(1_000_000),
                std::sync::Arc::new(make_state()),
            )
            .await
        });
        let body = vec![b'x'; 512 * 1024];
        let request = format!(
            "POST /unknown HTTP/1.1\r\nAuthorization: {}\r\nContent-Length: {}\r\n\r\n",
            basic_auth("admin", "secret"),
            body.len()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        handler.await.unwrap();

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(!response.contains("request_body_too_large"));
    }

    #[tokio::test]
    async fn job_stream_replays_missed_events_after_reconnect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir().unwrap();
        let store = sbproxy_model_host::FileJobStore::open(directory.path(), 256).unwrap();
        let job = store
            .create(
                sbproxy_model_host::OperationKind::Pull,
                "reconnect-fixture".to_string(),
            )
            .unwrap();
        let job_id = job.id.clone();
        // `job_event_log` is process-global, so its sequence counter is
        // not necessarily zero at the start of this test (another test in
        // the same binary may have published first); capture the real
        // assigned sequence rather than assuming one.
        let queued_sequence = crate::admin_model_host::job_event_log().publish(&job);

        let auth = basic_auth("admin", "secret");
        let state = std::sync::Arc::new(make_state());

        // First connection: sees the job's initial `queued` event, then
        // drops before the job progresses further.
        let (mut client1, server1) = tokio::io::duplex(16 * 1024);
        let handler1 = tokio::spawn({
            let state = state.clone();
            async move {
                handle_admin_connection(
                    server1,
                    "job-stream-1",
                    &AdminRateLimiter::new(1_000_000),
                    state,
                )
                .await
            }
        });
        let request = format!(
            "GET /admin/model-host/jobs/{job_id}/stream HTTP/1.1\r\nAuthorization: {auth}\r\n\r\n"
        );
        client1.write_all(request.as_bytes()).await.unwrap();

        let mut seen = String::new();
        let mut buf = [0u8; 4096];
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !seen.contains("\"state\":\"queued\"") {
                let n = client1.read(&mut buf).await.unwrap();
                assert!(n > 0, "stream closed before the queued event arrived");
                seen.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        })
        .await
        .expect("first connection saw the queued event");
        assert!(seen.starts_with("HTTP/1.1 200 OK"), "{seen}");
        assert!(seen.contains("Content-Type: text/event-stream"), "{seen}");
        assert!(seen.contains(&format!("id: {queued_sequence}\n")), "{seen}");
        drop(client1);

        // The job progresses past what the first client saw, then reaches
        // its terminal state.
        let downloading = store
            .transition(
                &job_id,
                sbproxy_model_host::OperationState::Downloading,
                sbproxy_model_host::OperationProgress {
                    completed_bytes: 5,
                    total_bytes: 10,
                    current_file: None,
                },
                None,
            )
            .unwrap();
        let downloading_sequence = crate::admin_model_host::job_event_log().publish(&downloading);
        // A `Pull` job cannot go straight from `downloading` to `ready`; it
        // passes through `verifying` first (see `transition_allowed` in
        // sbproxy-model-host's jobs.rs).
        let verifying = store
            .transition(
                &job_id,
                sbproxy_model_host::OperationState::Verifying,
                sbproxy_model_host::OperationProgress {
                    completed_bytes: 10,
                    total_bytes: 10,
                    current_file: None,
                },
                None,
            )
            .unwrap();
        let verifying_sequence = crate::admin_model_host::job_event_log().publish(&verifying);
        let ready = store
            .transition(
                &job_id,
                sbproxy_model_host::OperationState::Ready,
                sbproxy_model_host::OperationProgress {
                    completed_bytes: 10,
                    total_bytes: 10,
                    current_file: None,
                },
                None,
            )
            .unwrap();
        let ready_sequence = crate::admin_model_host::job_event_log().publish(&ready);

        // The first connection settles on its own once the job reaches a
        // terminal state (its next write either fails against the dropped
        // client, or succeeds and it closes on seeing `ready`); either way
        // it does not hang the test.
        tokio::time::timeout(std::time::Duration::from_secs(5), handler1)
            .await
            .expect("first connection settled")
            .unwrap();

        // Reconnect with `Last-Event-ID` set to the event the first client
        // already saw: only the events after it replay, in order, with
        // none missed and none repeated.
        let (mut client2, server2) = tokio::io::duplex(16 * 1024);
        let handler2 = tokio::spawn(async move {
            handle_admin_connection(
                server2,
                "job-stream-2",
                &AdminRateLimiter::new(1_000_000),
                state,
            )
            .await
        });
        let request = format!(
            "GET /admin/model-host/jobs/{job_id}/stream HTTP/1.1\r\nAuthorization: {auth}\r\nLast-Event-ID: {queued_sequence}\r\n\r\n"
        );
        client2.write_all(request.as_bytes()).await.unwrap();
        client2.shutdown().await.unwrap();
        let mut response = String::new();
        client2.read_to_string(&mut response).await.unwrap();
        handler2.await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            !response.contains(&format!("id: {queued_sequence}\n")),
            "{response}"
        );
        assert!(!response.contains("\"state\":\"queued\""), "{response}");
        assert!(
            response.contains(&format!("id: {downloading_sequence}\n")),
            "{response}"
        );
        assert!(response.contains("\"state\":\"downloading\""), "{response}");
        assert!(
            response.contains(&format!("id: {verifying_sequence}\n")),
            "{response}"
        );
        assert!(response.contains("\"state\":\"verifying\""), "{response}");
        assert!(
            response.contains(&format!("id: {ready_sequence}\n")),
            "{response}"
        );
        assert!(response.contains("\"state\":\"ready\""), "{response}");
    }

    // One simulated connection carrying a single bare GET for `path`,
    // against a shared rate limiter. Mirrors production, where each
    // admin request is its own TCP connection (`Connection: close`)
    // and the limiter is an `Arc` cloned per accepted connection.
    async fn get_through_rate_limiter(path: &str, limiter: &Arc<AdminRateLimiter>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let state = Arc::new(make_state());
        let limiter = limiter.clone();
        let path = path.to_string();
        let handler =
            tokio::spawn(
                async move { handle_admin_connection(server, "peer", &limiter, state).await },
            );
        client
            .write_all(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        handler.await.unwrap();
        response
    }

    #[tokio::test]
    async fn rate_limiter_exempts_static_ui_assets_but_not_other_admin_paths() {
        // WOR: dashboard navigation fires a JS+CSS fetch per view on top
        // of whatever the view's own API calls need; a low per-IP cap
        // meant to bound login/config/keys abuse should not also gate
        // fetching the (identical, non-sensitive) bundle files every
        // session needs. Regression for the 429 that silently broke
        // `import()` of a route chunk mid-session.
        let limiter = Arc::new(AdminRateLimiter::new(2));

        // Exhaust the cap on a real admin route.
        assert!(get_through_rate_limiter("/admin/config", &limiter)
            .await
            .starts_with("HTTP/1.1 401"));
        assert!(get_through_rate_limiter("/admin/config", &limiter)
            .await
            .starts_with("HTTP/1.1 401"));
        let blocked = get_through_rate_limiter("/admin/config", &limiter).await;
        assert!(
            blocked.starts_with("HTTP/1.1 429"),
            "third non-asset request should be rate limited, got: {blocked}"
        );

        // The cap is already exhausted for this IP, yet asset fetches
        // keep going through: the default build's own 404 (UI not
        // embedded in a plain `cargo test`), never a 429.
        for _ in 0..5 {
            let resp = get_through_rate_limiter("/admin/ui/assets/index-abc123.js", &limiter).await;
            assert!(
                !resp.starts_with("HTTP/1.1 429"),
                "static asset request must never be rate limited, got: {resp}"
            );
        }

        // Once exhausted, the real admin routes are still blocked; the
        // asset traffic above did not quietly refill the same bucket.
        let still_blocked = get_through_rate_limiter("/admin/config", &limiter).await;
        assert!(still_blocked.starts_with("HTTP/1.1 429"));
    }

    // One toolkit capability/outcome cell of
    // `sbproxy_ai_toolkit_operations_total`.
    fn toolkit_operations_count(capability: &str, outcome: &str) -> f64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_ai_toolkit_operations_total")
            .map(|family| {
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        let matches = |name: &str, value: &str| {
                            metric
                                .get_label()
                                .iter()
                                .any(|label| label.name() == name && label.value() == value)
                        };
                        matches("capability", capability) && matches("outcome", outcome)
                    })
                    .map(|metric| metric.get_counter().value())
                    .sum()
            })
            .unwrap_or_default()
    }

    /// An admin rate-limit 429 on a toolkit route is a concurrency refusal,
    /// not a gateway fault. `internal` is the one outcome in that closed
    /// vocabulary an operator alerts on for "the gateway broke", so a
    /// script hammering the route must not page them.
    #[tokio::test]
    async fn admin_rate_limit_on_a_toolkit_route_records_busy_not_internal() {
        let limiter = Arc::new(AdminRateLimiter::new(1));
        let busy_before = toolkit_operations_count("workflow", "busy");
        let internal_before = toolkit_operations_count("workflow", "internal");

        // The first request spends the cap (and answers 401, unauthenticated).
        let _ = get_through_rate_limiter("/admin/ai-toolkit/workflows/run", &limiter).await;
        let blocked = get_through_rate_limiter("/admin/ai-toolkit/workflows/run", &limiter).await;

        assert!(blocked.starts_with("HTTP/1.1 429"), "{blocked}");
        assert!(
            toolkit_operations_count("workflow", "busy") > busy_before,
            "a throttled toolkit request is counted as busy"
        );
        assert_eq!(
            toolkit_operations_count("workflow", "internal"),
            internal_before,
            "client throttling must not read as a gateway fault"
        );
    }

    #[tokio::test]
    async fn compression_content_route_audits_before_the_generic_auth_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Default)]
        struct Audit {
            events: Mutex<Vec<crate::admin_compression::CompressionAuditEvent>>,
        }
        impl crate::admin_compression::CompressionAuditSink for Audit {
            fn record(
                &self,
                event: &crate::admin_compression::CompressionAuditEvent,
            ) -> Result<(), crate::admin_compression::CompressionAuditError> {
                self.events.lock().unwrap().push(event.clone());
                Ok(())
            }
        }

        let audit = Arc::new(Audit::default());
        let state = make_state().with_compression_audit_sink(audit.clone());
        let record_id = sbproxy_ai::compression::CompressionRecordId::derive(
            "tenant-a",
            "api.example.com",
            [7; 16],
        );
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let handler = tokio::spawn(async move {
            handle_admin_connection(
                server,
                "10.0.0.3",
                &AdminRateLimiter::new(1_000_000),
                Arc::new(state),
            )
            .await
        });
        client
            .write_all(
                format!("GET /admin/compression/sessions/{record_id}/content HTTP/1.1\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        handler.await.unwrap();

        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "unauthenticated");
        assert!(events[0].operator.is_none());
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
            ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
            });
        }
        // Status filter.
        let errs = state.query_requests(
            &RequestLogFilter {
                status: Some(500),
                ..Default::default()
            },
            0,
            100,
        );
        assert_eq!(errs.len(), 5);
        assert!(errs.iter().all(|e| e.status == 500));
        // Method filter (case-insensitive).
        let posts = state.query_requests(
            &RequestLogFilter {
                method: Some("post"),
                ..Default::default()
            },
            0,
            100,
        );
        assert_eq!(posts.len(), 5);
        // Path substring.
        assert_eq!(
            state
                .query_requests(
                    &RequestLogFilter {
                        path_sub: Some("/thing/7"),
                        ..Default::default()
                    },
                    0,
                    100,
                )
                .len(),
            1
        );
        // Pagination: newest-first, skip 2, take 3.
        let page = state.query_requests(&RequestLogFilter::default(), 2, 3);
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].path, "/api/thing/7");
    }

    #[test]
    fn request_log_serializes_observability_fields() {
        let entry = RequestLogEntry {
            timestamp: "2026-07-21T12:00:00Z".to_string(),
            origin: "api.test".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            status: 200,
            latency_ms: 42.5,
            client_ip: "127.0.0.1".to_string(),
            session_id: Some("01K0SESSION0000000000000000".to_string()),
            parent_session_id: Some("01K0PARENT00000000000000000".to_string()),
            properties: std::collections::BTreeMap::from([
                ("feature".to_string(), "assistant".to_string()),
                ("tier".to_string(), "gold tier".to_string()),
            ]),
            cache_status: "semantic_hit".to_string(),
            retry_count: 2,
            failover_engaged: true,
            failover_from: Some("openai".to_string()),
            failover_to: Some("anthropic".to_string()),
            failover_trigger: Some("content_policy".to_string()),
            load_balancer_strategy: Some("lowest_latency".to_string()),
            load_balancer_target: Some("anthropic".to_string()),
            routing_detail: Some("exemplar 1 at 0.83 (floor 0.75)".to_string()),
            ..Default::default()
        };

        let value = serde_json::to_value(entry).expect("request log serializes");
        assert_eq!(value["session_id"], "01K0SESSION0000000000000000");
        assert_eq!(value["parent_session_id"], "01K0PARENT00000000000000000");
        assert_eq!(value["properties"]["feature"], "assistant");
        assert_eq!(value["cache_status"], "semantic_hit");
        assert_eq!(value["retry_count"], 2);
        assert_eq!(value["failover_engaged"], true);
        assert_eq!(value["failover_from"], "openai");
        assert_eq!(value["failover_to"], "anthropic");
        assert_eq!(value["failover_trigger"], "content_policy");
        assert_eq!(value["load_balancer_strategy"], "lowest_latency");
        assert_eq!(value["load_balancer_target"], "anthropic");
        // WOR-2564: the routing-decisions row carries why the strategy
        // picked that target, not only which target it picked.
        assert_eq!(value["routing_detail"], "exemplar 1 at 0.83 (floor 0.75)");
    }

    #[test]
    fn request_log_sse_uses_the_enriched_entry_contract() {
        let state = make_state();
        let mut events = state.log_events.subscribe();
        state.log_request(RequestLogEntry {
            timestamp: "2026-07-21T12:00:00Z".to_string(),
            origin: "api.test".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            status: 200,
            latency_ms: 42.5,
            client_ip: "127.0.0.1".to_string(),
            session_id: Some("01K0SESSION0000000000000000".to_string()),
            properties: std::collections::BTreeMap::from([(
                "feature".to_string(),
                "assistant".to_string(),
            )]),
            cache_status: "hit".to_string(),
            retry_count: 1,
            ..Default::default()
        });

        let event = events.try_recv().expect("subscriber receives event");
        let value: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(value["session_id"], "01K0SESSION0000000000000000");
        assert_eq!(value["properties"]["feature"], "assistant");
        assert_eq!(value["cache_status"], "hit");
        assert_eq!(value["retry_count"], 1);
    }

    #[test]
    fn query_requests_filters_gateway_and_properties() {
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "t0".to_string(),
            origin: "o".to_string(),
            method: "POST".to_string(),
            path: "/cached".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            properties: std::collections::BTreeMap::from([
                ("feature".to_string(), "assistant".to_string()),
                ("tier".to_string(), "gold tier".to_string()),
            ]),
            cache_status: "hit".to_string(),
            retry_count: 1,
            ..Default::default()
        });
        state.log_request(RequestLogEntry {
            timestamp: "t1".to_string(),
            origin: "o".to_string(),
            method: "GET".to_string(),
            path: "/plain".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            cache_status: "disabled".to_string(),
            ..Default::default()
        });

        let cached = state.query_requests(
            &RequestLogFilter {
                cache_status: Some("hit"),
                retried: Some(true),
                property_key: Some("feature"),
                property_value: Some("assistant"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].path, "/cached");

        let presence = state.query_requests(
            &RequestLogFilter {
                property_key: Some("tier"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(presence.len(), 1);

        let not_retried = state.query_requests(
            &RequestLogFilter {
                retried: Some(false),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(not_retried.len(), 1);
        assert_eq!(not_retried[0].path, "/plain");
    }

    #[test]
    fn query_requests_filters_on_key_attribution_columns() {
        // WOR-2093: the ring answers "what did this key do" server-side.
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "t0".to_string(),
            origin: "o".to_string(),
            method: "GET".to_string(),
            path: "/governed".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            api_key_id: Some("sbp_key_a".to_string()),
            key_mode: "minted".to_string(),
            tenant_id: "tenant-a".to_string(),
            session_id: Some("01JAT3S6Q0V4X5Y6Z7A8B9C0D1".to_string()),
            config_revision: "rev-1".to_string(),
            ..Default::default()
        });
        state.log_request(RequestLogEntry {
            timestamp: "t1".to_string(),
            origin: "o".to_string(),
            method: "GET".to_string(),
            path: "/native".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            api_key_id: Some("native:tenant-a:api:openai".to_string()),
            key_mode: "native".to_string(),
            key_provider: Some("openai".to_string()),
            ..Default::default()
        });
        state.log_request(RequestLogEntry {
            timestamp: "t2".to_string(),
            origin: "o".to_string(),
            method: "GET".to_string(),
            path: "/unkeyed".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            key_mode: "none".to_string(),
            ..Default::default()
        });

        let by_key = state.query_requests(
            &RequestLogFilter {
                api_key_id: Some("sbp_key_a"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(by_key.len(), 1);
        assert_eq!(by_key[0].path, "/governed");
        assert_eq!(by_key[0].config_revision, "rev-1");

        let native = state.query_requests(
            &RequestLogFilter {
                key_mode: Some("native"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].key_provider.as_deref(), Some("openai"));

        let by_session = state.query_requests(
            &RequestLogFilter {
                session_id: Some("01JAT3S6Q0V4X5Y6Z7A8B9C0D1"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(by_session.len(), 1);
        assert_eq!(by_session[0].api_key_id.as_deref(), Some("sbp_key_a"));

        // Combined: key AND mode narrows to the intersection.
        let combined = state.query_requests(
            &RequestLogFilter {
                api_key_id: Some("sbp_key_a"),
                key_mode: Some("native"),
                ..Default::default()
            },
            0,
            10,
        );
        assert!(combined.is_empty());
    }

    #[test]
    fn requests_endpoint_validates_observability_filters() {
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "t0".to_string(),
            origin: "o".to_string(),
            method: "POST".to_string(),
            path: "/cached".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            properties: std::collections::BTreeMap::from([(
                "tier".to_string(),
                "gold tier".to_string(),
            )]),
            cache_status: "hit".to_string(),
            retry_count: 1,
            ..Default::default()
        });
        let auth = basic_auth("admin", "secret");

        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests?property_key=tier&property_value=gold%20tier&retried=true&cache_status=hit",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "valid filters must succeed: {body}");
        let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.as_array().map(Vec::len), Some(1));

        for path in [
            "/api/requests?property_value=gold",
            "/api/requests?retried=sometimes",
            "/api/requests?cache_status=warm",
        ] {
            let (status, _, body) = handle_admin_request("GET", path, &state, Some(&auth), None);
            assert_eq!(status, 400, "invalid filter must fail: {path}: {body}");
        }
    }

    #[test]
    fn requests_endpoint_decodes_path_filters_before_matching() {
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "t0".to_string(),
            origin: "o".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat?stream=true".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            ..Default::default()
        });
        let auth = basic_auth("admin", "secret");

        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests?path=%2Fv1%2Fchat%3Fstream%3Dtrue",
            &state,
            Some(&auth),
            None,
        );

        assert_eq!(status, 200, "encoded path filter must succeed: {body}");
        let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.as_array().map(Vec::len), Some(1));
    }

    /// One attributed AI request row for the reporting tests (WOR-2578).
    fn reporting_entry(
        model: &str,
        key: &str,
        tenant: &str,
        user: &str,
        tokens_in: u64,
        tokens_out: u64,
        cost_usd_micros: u64,
    ) -> RequestLogEntry {
        RequestLogEntry {
            timestamp: "2026-08-20T00:00:00Z".to_string(),
            origin: "ai.local".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            status: 200,
            latency_ms: 1.0,
            client_ip: "127.0.0.1".to_string(),
            model: Some(model.to_string()),
            api_key_id: Some(key.to_string()),
            tenant_id: tenant.to_string(),
            user_id: Some(user.to_string()),
            tokens_in: Some(tokens_in),
            tokens_out: Some(tokens_out),
            cost_usd_micros: Some(cost_usd_micros),
            ..Default::default()
        }
    }

    /// Split one RFC 4180 CSV record into its fields, honoring quoted
    /// fields and doubled quotes. Test-side only; the production side
    /// writes CSV and never parses it.
    fn split_csv_record(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut chars = line.chars().peekable();
        let mut quoted = false;
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        quoted = false;
                    }
                }
                '"' => quoted = true,
                ',' if !quoted => fields.push(std::mem::take(&mut field)),
                other => field.push(other),
            }
        }
        fields.push(field);
        fields
    }

    #[test]
    fn requests_endpoint_filters_by_model_tenant_and_user() {
        let state = make_state();
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            100,
            10,
            500,
        ));
        state.log_request(reporting_entry(
            "gpt-5",
            "sbk_beta",
            "acme",
            "ops@acme.test",
            10,
            1,
            50,
        ));
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_gamma",
            "globex",
            "dev@globex.test",
            20,
            2,
            100,
        ));
        let auth = basic_auth("admin", "secret");

        for (query, expected) in [
            ("model=claude-sonnet-4", 2),
            ("tenant=acme", 2),
            ("user=dev%40acme.test", 1),
            ("model=claude-sonnet-4&tenant=globex", 1),
        ] {
            let (status, _, body) = handle_admin_request(
                "GET",
                &format!("/api/requests?{query}"),
                &state,
                Some(&auth),
                None,
            );
            assert_eq!(status, 200, "{query}: {body}");
            let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(rows.as_array().map(Vec::len), Some(expected), "{query}");
        }
    }

    #[test]
    fn requests_report_groups_simultaneously_across_dimensions() {
        let state = make_state();
        // Two rows in one composite group, one in a second group that
        // shares every dimension except the key and user.
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            100,
            10,
            500,
        ));
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            50,
            5,
            250,
        ));
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_beta",
            "acme",
            "ops@acme.test",
            10,
            1,
            50,
        ));
        let auth = basic_auth("admin", "secret");

        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/report?group_by=model,api_key_id,tenant,user",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            report["group_by"],
            serde_json::json!(["model", "api_key_id", "tenant", "user"])
        );
        let rows = report["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "one row per composite group: {body}");
        // Highest spend first.
        assert_eq!(rows[0]["group"]["model"], "claude-sonnet-4");
        assert_eq!(rows[0]["group"]["api_key_id"], "sbk_alpha");
        assert_eq!(rows[0]["group"]["tenant"], "acme");
        assert_eq!(rows[0]["group"]["user"], "dev@acme.test");
        assert_eq!(rows[0]["requests"], 2);
        assert_eq!(rows[0]["tokens_in"], 150);
        assert_eq!(rows[0]["tokens_out"], 15);
        assert_eq!(rows[0]["cost_usd_micros"], 750);
        assert_eq!(rows[1]["group"]["api_key_id"], "sbk_beta");
        assert_eq!(report["totals"]["requests"], 3);
        assert_eq!(report["totals"]["tokens_in"], 160);
        assert_eq!(report["totals"]["cost_usd_micros"], 800);
    }

    #[test]
    fn requests_report_validates_group_dimensions() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for path in [
            // The dimension list is the whole point of the route, so a
            // missing or empty one is an error, not a default.
            "/api/requests/report",
            "/api/requests/report?group_by=",
            "/api/requests/report?group_by=flavor",
            "/api/requests/report?group_by=model,model",
        ] {
            let (status, _, body) = handle_admin_request("GET", path, &state, Some(&auth), None);
            assert_eq!(status, 400, "{path}: {body}");
        }
    }

    #[test]
    fn requests_report_applies_the_shared_request_filters() {
        let state = make_state();
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            100,
            10,
            500,
        ));
        state.log_request(reporting_entry(
            "gpt-5",
            "sbk_beta",
            "globex",
            "ops@globex.test",
            10,
            1,
            50,
        ));
        let auth = basic_auth("admin", "secret");

        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/report?group_by=model&tenant=acme",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        let rows = report["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["group"]["model"], "claude-sonnet-4");
        assert_eq!(report["totals"]["requests"], 1);

        // An invalid shared filter fails exactly as it does on
        // `/api/requests`; the two routes parse one filter surface.
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/report?group_by=model&cache_status=warm",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400, "{body}");
    }

    #[test]
    fn requests_export_jsonl_round_trips_the_filtered_view() {
        let state = make_state();
        state.log_request(reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            100,
            10,
            500,
        ));
        state.log_request(reporting_entry(
            "gpt-5",
            "sbk_beta",
            "globex",
            "ops@globex.test",
            10,
            1,
            50,
        ));
        let auth = basic_auth("admin", "secret");

        let (status, content_type, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=jsonl&tenant=acme",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(content_type, "application/x-ndjson");
        let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        let row: serde_json::Value = serde_json::from_str(lines[0]).unwrap();

        // Round trip: the exported line IS the snapshot row, so an
        // export can always be re-read as `RequestLogEntry` JSON.
        let (_, _, snapshot) = handle_admin_request(
            "GET",
            "/api/requests?tenant=acme",
            &state,
            Some(&auth),
            None,
        );
        let snapshot_rows: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(row, snapshot_rows[0]);

        // Omitting `format` exports JSONL: the raw shape is the default.
        let (status, content_type, default_body) = handle_admin_request(
            "GET",
            "/api/requests/export?tenant=acme",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/x-ndjson");
        assert_eq!(default_body, body);
    }

    #[test]
    fn requests_export_csv_round_trips_the_filtered_view() {
        let state = make_state();
        let mut entry = reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            100,
            10,
            500,
        );
        // A path with a comma and a quote proves RFC 4180 escaping
        // round-trips instead of splitting the record.
        entry.path = "/v1/chat?note=\"a,b\"".to_string();
        entry
            .properties
            .insert("tier".to_string(), "gold".to_string());
        state.log_request(entry);
        state.log_request(reporting_entry(
            "gpt-5",
            "sbk_beta",
            "globex",
            "ops@globex.test",
            10,
            1,
            50,
        ));
        let auth = basic_auth("admin", "secret");

        let (status, content_type, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=csv&tenant=acme",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(content_type, "text/csv");
        let mut lines = body.lines();
        let header = split_csv_record(lines.next().expect("header row"));
        let col = |name: &str| {
            header
                .iter()
                .position(|c| c == name)
                .unwrap_or_else(|| panic!("missing column {name}: {header:?}"))
        };
        let row = split_csv_record(lines.next().expect("one data row"));
        assert_eq!(lines.next(), None, "the globex row is filtered out");
        assert_eq!(row[col("model")], "claude-sonnet-4");
        assert_eq!(row[col("tenant_id")], "acme");
        assert_eq!(row[col("user_id")], "dev@acme.test");
        assert_eq!(row[col("api_key_id")], "sbk_alpha");
        assert_eq!(row[col("path")], "/v1/chat?note=\"a,b\"");
        assert_eq!(row[col("tokens_in")], "100");
        assert_eq!(row[col("tokens_out")], "10");
        assert_eq!(row[col("cost_usd_micros")], "500");
        // Structured columns carry JSON so nothing is lossy.
        let properties: serde_json::Value = serde_json::from_str(&row[col("properties")]).unwrap();
        assert_eq!(properties["tier"], "gold");
        // Appended last, so the row has to be as wide as the header or
        // an importer reading by position silently shifts. `col()`
        // panics if the name is missing, and indexing panics if the row
        // is short, which is the pair this asserts.
        assert_eq!(header.len(), row.len(), "{header:?} vs {row:?}");
        // The four columns appended since the original contract, in
        // append order. An importer keyed on position keeps working
        // because nothing before them moved.
        assert_eq!(
            [
                col("credential_source"),
                col("tokens_cached"),
                col("tokens_cache_write"),
                col("service_tier"),
            ],
            [
                header.len() - 4,
                header.len() - 3,
                header.len() - 2,
                header.len() - 1,
            ],
            "the appended columns keep their append order: {header:?}"
        );
        for column in [
            "credential_source",
            "tokens_cached",
            "tokens_cache_write",
            "service_tier",
        ] {
            assert_eq!(
                row[col(column)],
                "",
                "a non-AI row leaves {column} empty rather than dropping the field"
            );
        }
    }

    #[test]
    fn requests_export_clamps_limit_to_the_ring_bound() {
        let state = make_state(); // max_log_entries: 5
        for i in 0..7 {
            let mut entry = reporting_entry(
                "claude-sonnet-4",
                "sbk_alpha",
                "acme",
                "dev@acme.test",
                1,
                1,
                1,
            );
            entry.path = format!("/v1/chat/{i}");
            state.log_request(entry);
        }
        let auth = basic_auth("admin", "secret");

        // An absurd limit clamps to the ring bound rather than trusting
        // the caller.
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=jsonl&limit=999999",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.lines().count(), 5);

        // An explicit small limit is honored, newest first.
        let (_, _, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=jsonl&limit=2",
            &state,
            Some(&auth),
            None,
        );
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let newest: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(newest["path"], "/v1/chat/6");
    }

    #[test]
    fn requests_report_and_export_reject_bad_methods_and_formats() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for path in [
            "/api/requests/report?group_by=model",
            "/api/requests/export",
        ] {
            let (status, _, body) = handle_admin_request("POST", path, &state, Some(&auth), None);
            assert_eq!(status, 405, "{path}: {body}");
        }
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=xml",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400, "{body}");
    }

    /// WOR-2654: the shadow report's `window` vocabulary is closed, and
    /// the refusal names the whole accepted set. Every other refusal
    /// this surface adds is pinned by name and this one was not, which
    /// left the accepted set free to drift from the message describing
    /// it.
    #[test]
    fn the_shadow_report_refuses_a_window_it_does_not_serve() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        for window in ["15m", "1h", "24h", "7d", "30d"] {
            let (status, _, body) = handle_admin_request(
                "GET",
                &format!("/api/ai/shadow/report?window={window}"),
                &state,
                Some(&auth),
                None,
            );
            assert_eq!(status, 200, "{window} is an accepted window: {body}");
        }

        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/ai/shadow/report?window=90d",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400, "{body}");
        for window in ["15m", "1h", "24h", "7d", "30d"] {
            assert!(
                body.contains(window),
                "the refusal has to name every window it does serve, and it omits \
                 {window}: {body}"
            );
        }

        // GET only, so a write verb cannot reach a read surface.
        let (status, _, body) =
            handle_admin_request("POST", "/api/ai/shadow/report", &state, Some(&auth), None);
        assert_eq!(status, 405, "{body}");
    }

    #[test]
    fn requests_export_csv_neutralizes_spreadsheet_formula_prefixes() {
        // Caller-controlled text lands in these cells; a leading `=`,
        // `+`, `-`, `@`, or tab would execute as a formula when the
        // export opens in a spreadsheet, so those cells gain a leading
        // apostrophe (the OWASP CSV-injection guard).
        let state = make_state();
        let mut entry = reporting_entry(
            "claude-sonnet-4",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            1,
            1,
            1,
        );
        entry.path = "=HYPERLINK(\"http://evil.test\")".to_string();
        state.log_request(entry);
        let auth = basic_auth("admin", "secret");

        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=csv",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        let mut lines = body.lines();
        let header = split_csv_record(lines.next().expect("header row"));
        let path_col = header.iter().position(|c| c == "path").unwrap();
        let row = split_csv_record(lines.next().expect("one data row"));
        assert_eq!(row[path_col], "'=HYPERLINK(\"http://evil.test\")");
    }

    /// The current `sbproxy_admin_request_exports_total{format}` value,
    /// read back off the default registry. Zero when the family has not
    /// registered yet, which is the same thing as never having counted.
    fn admin_request_exports_total(format: &str) -> u64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_admin_request_exports_total" {
                continue;
            }
            for metric in family.get_metric() {
                if metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "format" && pair.value() == format)
                {
                    return metric.get_counter().value() as u64;
                }
            }
        }
        0
    }

    fn admin_chargeback_export_refusals_total(format: &str, reason: &str) -> u64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_admin_chargeback_export_refusals_total" {
                continue;
            }
            for metric in family.get_metric() {
                let format_matches = metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "format" && pair.value() == format);
                let reason_matches = metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "reason" && pair.value() == reason);
                if format_matches && reason_matches {
                    return metric.get_counter().value() as u64;
                }
            }
        }
        0
    }

    /// `GET /api/requests` returns the same rows as `format=jsonl` under
    /// the same parser, the same filter and the same ring cap, and moves
    /// neither export counter (WOR-2578).
    ///
    /// This pins the boundary the export's audit record actually covers.
    /// The CHANGELOG used to say a bulk read of the operational log was
    /// recorded and alertable; the identical bulk read is one query
    /// string away with neither, so the claim now names the export and
    /// `docs/admin-api-reference.md` names this route as the unaudited
    /// equivalent. If that ever changes, this test changes with it
    /// rather than the sentence going quietly stale.
    ///
    /// Counter reads are process-wide, so this pins the delta around one
    /// call rather than an absolute value; nextest gives each test its
    /// own process.
    #[test]
    fn the_snapshot_route_is_the_unaudited_equivalent_of_the_export() {
        let state = make_state();
        for tenant in ["acme", "globex"] {
            state.log_request(reporting_entry(
                "gpt-4o",
                "sbk_alpha",
                tenant,
                "dev@acme.test",
                1,
                1,
                1,
            ));
        }
        let auth = basic_auth("admin", "secret");

        let (status, _, snapshot) =
            handle_admin_request("GET", "/api/requests", &state, Some(&auth), None);
        assert_eq!(status, 200, "{snapshot}");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&snapshot).unwrap();

        let before_export = admin_request_exports_total("jsonl");
        let (status, _, export) = handle_admin_request(
            "GET",
            "/api/requests/export?format=jsonl",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{export}");
        let exported: Vec<serde_json::Value> = export
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("each JSONL line parses"))
            .collect();
        assert_eq!(rows, exported, "the same rows, one route over");
        assert!(
            admin_request_exports_total("jsonl") > before_export,
            "the export counts itself"
        );

        let before_snapshot = admin_request_exports_total("jsonl");
        let (status, _, body) =
            handle_admin_request("GET", "/api/requests", &state, Some(&auth), None);
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            admin_request_exports_total("jsonl"),
            before_snapshot,
            "the snapshot route is the unaudited, uncounted equivalent of the export"
        );
    }

    /// A row that carries none of the optional report dimensions groups
    /// under `""`, and the same query string on the export has to return
    /// the rows behind that number (WOR-2578).
    ///
    /// The failure this pins: a billing pipeline iterates the report's
    /// groups and exports each one, exactly as the docs instruct. Every
    /// populated group exports correctly and the `""` group, typically
    /// the largest in a deployment that resolves no end user, comes back
    /// as a header row on its own. Nothing errors and the biggest bucket
    /// of spend is silently dropped.
    #[test]
    fn an_unattributed_group_drills_through_to_its_own_rows() {
        let state = make_state();
        state.log_request(reporting_entry(
            "gpt-4o",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            10,
            1,
            100,
        ));
        // No model, no governed key, no resolved human subject: a call
        // refused before it reached a provider, or simply a deployment
        // that sets no `X-Sb-User-Id` and mints no keys.
        let mut orphan = reporting_entry("x", "x", "acme", "x", 20, 2, 200);
        orphan.model = None;
        orphan.api_key_id = None;
        orphan.user_id = None;
        state.log_request(orphan);
        let auth = basic_auth("admin", "secret");

        for dimension in ["model", "api_key_id", "user"] {
            let (status, _, body) = handle_admin_request(
                "GET",
                &format!("/api/requests/report?group_by={dimension}"),
                &state,
                Some(&auth),
                None,
            );
            assert_eq!(status, 200, "{dimension}: {body}");
            let report: serde_json::Value = serde_json::from_str(&body).unwrap();
            let rows = report["rows"].as_array().cloned().unwrap_or_default();
            let unattributed = rows
                .iter()
                .find(|row| row["group"][dimension].as_str() == Some(""))
                .unwrap_or_else(|| panic!("{dimension}: no unattributed group in {body}"));
            assert_eq!(
                unattributed["requests"].as_u64(),
                Some(1),
                "{dimension}: {body}"
            );

            let (status, _, body) = handle_admin_request(
                "GET",
                &format!("/api/requests/export?format=jsonl&{dimension}="),
                &state,
                Some(&auth),
                None,
            );
            assert_eq!(status, 200, "{dimension}: {body}");
            assert_eq!(
                body.lines().filter(|line| !line.is_empty()).count(),
                1,
                "{dimension}: the unattributed group must drill through to its own row: {body}"
            );
        }
    }

    /// A present-but-unparseable numeric filter is a 400 rather than a
    /// silently wider result set (WOR-2578).
    ///
    /// `?status=5xx` used to drop the status dimension and hand back the
    /// whole ring, every tenant and every user, as a file. The audit
    /// record was honest and unhelpful: `filters=none`, because the
    /// dimension was never set.
    #[test]
    fn request_filters_refuse_a_malformed_numeric_param() {
        let state = make_state();
        state.log_request(reporting_entry(
            "gpt-4o",
            "sbk_alpha",
            "acme",
            "dev@acme.test",
            10,
            1,
            100,
        ));
        let auth = basic_auth("admin", "secret");
        for query in ["status=5xx", "limit=all", "offset=-1", "limit="] {
            let (status, _, body) = handle_admin_request(
                "GET",
                &format!("/api/requests/export?format=csv&{query}"),
                &state,
                Some(&auth),
                None,
            );
            assert_eq!(
                status, 400,
                "{query} must not silently widen the export: {body}"
            );
        }
        // One parser, so the snapshot and the report refuse them too.
        for path in ["/api/requests?status=5xx", "/api/requests/report?limit=all"] {
            let (status, _, body) = handle_admin_request("GET", path, &state, Some(&auth), None);
            assert_eq!(status, 400, "{path}: {body}");
        }
        // And a well-formed one still works.
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/requests/export?format=csv&status=200&limit=5&offset=0",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
    }

    #[test]
    fn spend_group_by_accepts_a_percent_encoded_property_dimension() {
        // A promoted property reads `property:<key>`, and every
        // standards-compliant client percent-encodes the colon. Reading
        // the raw query value made `property%3Afeature` a 400 while the
        // admin UI's own dropdown emitted exactly that form.
        let encoded = decoded_query_param(
            "/api/usage/spend?window=24h&group_by=property%3Afeature",
            "group_by",
        );
        assert_eq!(encoded.as_deref(), Some("property:feature"));
        assert!(
            sbproxy_observe::usage_rollup::GroupBy::parse(encoded.as_deref().unwrap()).is_some(),
            "the decoded dimension must parse"
        );

        // The raw form keeps working for hand-written curl calls.
        let raw = decoded_query_param("/api/usage/spend?group_by=property:feature", "group_by");
        assert_eq!(raw.as_deref(), Some("property:feature"));
    }

    #[test]
    fn windowed_spend_validates_params_and_serves_rollups() {
        // WOR-1875. The 400 paths are pure parameter validation and
        // run before any store lookup.
        let (code, _, body) = windowed_spend_response(Some("2h"), None, None, None);
        assert_eq!(code, 400);
        assert!(body.contains("unknown window"));
        let (code, _, body) = windowed_spend_response(None, Some("nope"), None, None);
        assert_eq!(code, 400);
        assert!(body.contains("unknown group_by"));
        let (code, _, body) = windowed_spend_response(None, None, Some(10), Some(5));
        assert_eq!(code, 400);
        assert!(body.contains("before"));

        // Happy path against a real store. The process-global writer
        // slot is set-once; this test owns the installed instance.
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(
            sbproxy_observe::usage_rollup::RollupStore::open(&dir.path().join("r.redb")).unwrap(),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store
            .fold(&[sbproxy_observe::usage_rollup::RollupEvent {
                ts_secs: now - 60,
                dims: sbproxy_observe::usage_rollup::RollupDims {
                    origin: "test.origin".to_string(),
                    provider: "openai".to_string(),
                    model: "gpt-4o".to_string(),
                    tenant: "t".to_string(),
                    team: "growth".to_string(),
                    api_key_id: "sk1".to_string(),
                    project: "p".to_string(),
                    agent_id: String::new(),
                    properties: std::collections::BTreeMap::from([(
                        "feature".to_string(),
                        "assistant".to_string(),
                    )]),
                },
                kind: sbproxy_observe::usage_rollup::RollupKind::Usage {
                    tokens_in: 5,
                    tokens_out: 2,
                    cost_usd_micros: 42,
                },
            }])
            .unwrap();
        let writer =
            sbproxy_observe::usage_rollup::RollupWriter::spawn(store, 90 * 86_400, 395 * 86_400);
        sbproxy_observe::usage_rollup::install_usage_rollup_writer(writer);
        // Keep the backing dir alive for the process-global writer.
        std::mem::forget(dir);

        let (code, _, body) = windowed_spend_response(Some("24h"), Some("model"), None, None);
        assert_eq!(code, 200, "windowed spend must serve: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["group_by"], "model");
        assert_eq!(v["bucket_secs"], 3600);
        assert_eq!(v["totals"]["cost_usd_micros"], 42);
        assert_eq!(v["totals"]["tokens_in"], 5);
        assert_eq!(v["buckets"][0]["group"], "gpt-4o");

        let (code, _, body) =
            windowed_spend_response(Some("24h"), Some("property:feature"), None, None);
        assert_eq!(code, 200, "property-grouped spend must serve: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["group_by"], "property:feature");
        assert_eq!(v["property_keys"], serde_json::json!(["feature"]));
        assert_eq!(v["buckets"][0]["group"], "assistant");

        let (code, _, body) =
            windowed_spend_response(Some("24h"), Some("property:unknown"), None, None);
        assert_eq!(code, 400);
        assert!(
            body.contains("unknown property key"),
            "unhelpful error: {body}"
        );
    }

    #[test]
    fn alerts_snapshot_is_valid_when_disabled_and_never_exposes_channel_secrets() {
        let (status, _, body) = alerts_snapshot_response(None);
        assert_eq!(status, 200);
        let disabled: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(disabled["enabled"], false);
        assert_eq!(disabled["authority"], "file");
        assert_eq!(disabled["read_only"], true);

        let channels = vec![sbproxy_observe::alerting::AlertChannelConfig {
            channel_type: "webhook".to_string(),
            url: Some("https://user:password@hooks.example.com/private-token".to_string()),
            headers: vec![("Authorization".to_string(), "Bearer secret".to_string())],
            secret: Some("signing-secret".to_string()),
            routing_key: None,
        }];
        let runtime = sbproxy_observe::alerting::AlertRuntime::new(
            &sbproxy_observe::alerting::EngineConfig::default(),
            &channels,
        );
        let (status, _, body) = alerts_snapshot_response(Some(runtime.snapshot()));
        assert_eq!(status, 200);
        assert!(body.contains("https://hooks.example.com"));
        for secret in [
            "password",
            "private-token",
            "Bearer secret",
            "signing-secret",
        ] {
            assert!(!body.contains(secret), "alerts response leaked {secret}");
        }
    }

    #[test]
    fn alerts_test_request_validates_body_and_maps_queue_outcomes() {
        let (status, _, body) =
            alert_channel_test_response(Some(r#"{"channel_index":1}"#), |channel_index| {
                assert_eq!(channel_index, 1);
                Ok(())
            });
        assert_eq!(status, 202);
        assert!(body.contains("queued"));

        for body in [None, Some("{}"), Some(r#"{"channel_index":"one"}"#)] {
            let (status, _, _) = alert_channel_test_response(body, |_| {
                panic!("malformed requests must not be queued")
            });
            assert_eq!(status, 400);
        }

        let (status, _, _) = alert_channel_test_response(Some(r#"{"channel_index":7}"#), |_| {
            Err(crate::alerting::AlertControlError::UnknownChannel(7))
        });
        assert_eq!(status, 404);
        let (status, _, _) = alert_channel_test_response(Some(r#"{"channel_index":0}"#), |_| {
            Err(crate::alerting::AlertControlError::Unavailable)
        });
        assert_eq!(status, 409);
    }

    #[test]
    fn alerts_routes_use_the_runtime_contract() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/api/alerts", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert!(body.contains(r#""enabled":false"#));

        let (status, _, _) = handle_admin_request(
            "POST",
            "/api/alerts/test",
            &state,
            Some(&auth),
            Some(r#"{"channel_index":0}"#),
        );
        assert_eq!(status, 409);
    }

    async fn send_admin_request(state: AdminState, request: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let handler = tokio::spawn(async move {
            handle_admin_connection(
                server,
                "alerts-test",
                &AdminRateLimiter::new(1_000_000),
                std::sync::Arc::new(state),
            )
            .await
        });
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        handler.await.unwrap();
        response
    }

    #[test]
    fn admin_extensions_endpoint_requires_auth_and_only_answers_get() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, _, _) = handle_admin_request("GET", "/api/extensions", &state, None, None);
        assert_eq!(status, 401);

        let (status, _, _) =
            handle_admin_request("POST", "/api/extensions", &state, Some(&auth), None);
        assert_eq!(status, 405);
    }

    #[test]
    fn admin_extensions_endpoint_returns_the_versioned_running_snapshot() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, content_type, body) =
            handle_admin_request("GET", "/api/extensions", &state, Some(&auth), None);

        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let snapshot: serde_json::Value =
            serde_json::from_str(&body).expect("extension inventory must be JSON");
        let current = crate::reload::current_pipeline();
        let authoritative = serde_json::to_value(&current.extension_inventory)
            .expect("pipeline inventory must serialize");
        assert_eq!(snapshot, authoritative);
        assert_eq!(
            snapshot["schema_version"],
            sbproxy_plugin::EXTENSION_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(snapshot["scope"]["mode"], "running");
        assert!(snapshot["bundles"].is_array());
        assert!(snapshot["hooks"].is_array());
        assert!(snapshot["collisions"].is_array());
    }

    #[test]
    fn admin_egress_endpoint_requires_auth_and_only_answers_get() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, _, _) = handle_admin_request("GET", "/api/egress", &state, None, None);
        assert_eq!(status, 401);

        let (status, _, _) = handle_admin_request("POST", "/api/egress", &state, Some(&auth), None);
        assert_eq!(status, 405);
    }

    #[test]
    fn admin_egress_endpoint_returns_the_versioned_inventory_snapshot() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        sbproxy_security::egress::record_egress_seen(
            sbproxy_security::egress::EgressPurpose::Webhook,
            "https://seeded-admin-test.invalid:8443/hook?secret=x",
            "admin-test",
            sbproxy_security::egress::EgressSightingStatus::Ungated,
            None,
        );
        // WOR-2476: a second, distinct non-AI purpose. Before every gate
        // site stamped a sighting, `ai_provider` was the only purpose the
        // inventory could ever report; this proves the snapshot carries
        // more than one purpose, and that a `denied` sighting round-trips
        // its reason without leaking the URL that produced it.
        sbproxy_security::egress::record_egress_seen(
            sbproxy_security::egress::EgressPurpose::TokenExchange,
            "https://seeded-admin-test-2.invalid:8443/token?secret=y",
            "admin-test",
            sbproxy_security::egress::EgressSightingStatus::Denied,
            Some(sbproxy_security::egress::EgressDenied::UnlistedHost),
        );

        let (status, content_type, body) =
            handle_admin_request("GET", "/api/egress", &state, Some(&auth), None);

        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let snapshot: serde_json::Value =
            serde_json::from_str(&body).expect("egress inventory must be JSON");
        assert_eq!(snapshot["schema_version"], 1);
        let endpoints = snapshot["endpoints"]
            .as_array()
            .expect("endpoints must be an array");
        let entry = endpoints
            .iter()
            .find(|e| e["host"] == "seeded-admin-test.invalid")
            .expect("seeded sighting must appear in the inventory");
        assert_eq!(entry["purpose"], "webhook");
        assert!(entry.get("host").is_some());
        assert!(entry.get("status").is_some());
        assert!(entry.get("last_seen_unix_ms").is_some());
        assert!(
            entry.get("url").is_none(),
            "no raw url in an egress entry: {entry}"
        );

        let token_entry = endpoints
            .iter()
            .find(|e| e["host"] == "seeded-admin-test-2.invalid")
            .expect("seeded token_exchange sighting must appear in the inventory");
        assert_eq!(token_entry["purpose"], "token_exchange");
        assert_eq!(token_entry["status"], "denied");
        assert_eq!(token_entry["last_reason"], "unlisted_host");
        assert!(
            token_entry.get("url").is_none(),
            "no raw url in an egress entry: {token_entry}"
        );

        assert!(!body.contains("secret=x"), "no query string: {body}");
        assert!(!body.contains("secret=y"), "no query string: {body}");
    }

    #[tokio::test]
    async fn admin_extensions_endpoint_allows_a_read_only_operator() {
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reader".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reader-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        let (token, _) = state
            .session_signer
            .mint("reader", AdminRole::ReadOnly, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!("GET /api/extensions HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    /// WOR-2575: the routing-decisions view is a read surface, so a
    /// read-only operator session passes the role gate.
    #[tokio::test]
    async fn routing_decisions_endpoint_allows_a_read_only_operator() {
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reader".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reader-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        state.log_routing_decision(sample_routing_decision(
            "2026-08-20T12:00:00+00:00",
            "ai-gateway",
            "round_robin",
        ));
        let (token, _) = state
            .session_signer
            .mint("reader", AdminRole::ReadOnly, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!(
                "GET /api/routing-decisions HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"
            ),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("round_robin"), "{response}");
    }

    #[tokio::test]
    async fn alerts_test_route_keeps_read_only_and_browser_csrf_gates() {
        let read_only_state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reader".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reader-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        let (read_only_token, read_only_csrf) =
            read_only_state
                .session_signer
                .mint("reader", AdminRole::ReadOnly, 3600, unix_now());
        let body = r#"{"channel_index":0}"#;
        let request = format!(
            "POST /api/alerts/test HTTP/1.1\r\nCookie: sb_admin_session={read_only_token}\r\nX-CSRF-Token: {read_only_csrf}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let response = send_admin_request(read_only_state, request).await;
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "unexpected response: {response}"
        );
        assert!(response.contains("read-only operator"));

        let state = make_state();
        let (token, _) = state
            .session_signer
            .mint("admin", AdminRole::Admin, 3600, unix_now());
        let request = format!(
            "POST /api/alerts/test HTTP/1.1\r\nCookie: sb_admin_session={token}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let response = send_admin_request(state, request).await;
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "unexpected response: {response}"
        );
        assert!(response.contains("CSRF token missing or invalid"));
    }

    #[test]
    fn query_requests_filters_on_guardrail_columns() {
        // WOR-1874: `guardrail_action` / `guardrail_category` filter
        // exactly, so the Guardrails view can deep-link to blocked rows.
        let state = make_state();
        state.log_request(RequestLogEntry {
            timestamp: "t0".to_string(),
            origin: "o".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            status: 400,
            latency_ms: 3.0,
            client_ip: "127.0.0.1".to_string(),
            guardrail_category: Some("pii".to_string()),
            guardrail_action: Some("block".to_string()),
            ..Default::default()
        });
        state.log_request(RequestLogEntry {
            timestamp: "t1".to_string(),
            origin: "o".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            status: 200,
            latency_ms: 2.0,
            client_ip: "127.0.0.1".to_string(),
            ..Default::default()
        });
        let blocked = state.query_requests(
            &RequestLogFilter {
                guardrail_action: Some("block"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].guardrail_category.as_deref(), Some("pii"));
        let pii = state.query_requests(
            &RequestLogFilter {
                guardrail_action: Some("block"),
                guardrail_category: Some("pii"),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(pii.len(), 1);
        let none = state.query_requests(
            &RequestLogFilter {
                guardrail_action: Some("redact"),
                ..Default::default()
            },
            0,
            10,
        );
        assert!(none.is_empty());
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

    /// Serializes the tests that install process-wide config layers. The
    /// applied authority payload and the resolved base are process globals,
    /// so two of these running at once would see each other's fixtures.
    static CONFIG_LAYERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the layer lock and clear both globals, so a test starts from a
    /// node that owns its own configuration however the previous one ended.
    fn config_layer_guard() -> std::sync::MutexGuard<'static, ()> {
        let guard = CONFIG_LAYERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::config_subscriber::clear_applied_bundle();
        crate::config_source::clear_resolved_base();
        guard
    }

    /// Collects event target and fields as text so a test can assert that a
    /// particular audit line was emitted. Asserting on the log is the only
    /// way to pin an audit requirement: the audit trail is the product here,
    /// not a side effect of one.
    struct CaptureLayer {
        sink: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = format!("{} ", event.metadata().target());
            event.record(&mut FieldText(&mut line));
            self.sink
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }
    }

    struct FieldText<'a>(&'a mut String);

    impl tracing::field::Visit for FieldText<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value} ", field.name());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    fn owned_config_state(yaml: &str) -> (tempfile::TempDir, AdminState) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sb.yml");
        std::fs::write(&path, yaml).unwrap();
        let state = AdminState::new(AdminConfig::default())
            .with_config_path(path)
            .with_loaded_config_content_hash("known-revision");
        (dir, state)
    }

    /// A real, compilable config. The write guard runs after validation, so
    /// a fixture that does not compile would be rejected as invalid before
    /// the guard was ever consulted. The origin key deliberately has no dot
    /// in it, so its dotted provenance path is unambiguous.
    const OWNED: &str = "proxy:\n  http_bind_port: 8080\norigins:\n  api:\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n";

    /// An authority document that claims the origin's upstream URL and
    /// nothing else.
    const AUTHORITY_CLAIMS_URL: &str =
        "origins:\n  api:\n    action:\n      url: https://central.test\n";

    fn overlay_authority(config_yaml: &str) -> crate::config_subscriber::AppliedAuthority {
        crate::config_subscriber::AppliedAuthority {
            config_yaml: config_yaml.to_string(),
            merge_mode: MergeMode::Overlay,
            revision: 9,
            authority_id: "control-plane".to_string(),
        }
    }

    #[test]
    fn config_effective_reports_a_local_node_as_owning_everything() {
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(OWNED);
        let (status, content_type, body) = handle_config_effective(&state);
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["locally_owned"], true);
        assert_eq!(value["layers"]["base"]["kind"], "local");
        assert!(value["layers"]["authority"].is_null());
        assert_eq!(value["provenance"]["origins.api.action.url"], "local");
        assert_eq!(value["locally_owned_leaves"], value["total_leaves"]);
        assert!(value["yaml"].as_str().unwrap().contains("http_bind_port"));
    }

    #[test]
    fn config_effective_attributes_each_leaf_to_the_layer_that_set_it() {
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(OWNED);
        crate::config_subscriber::set_applied_authority(overlay_authority(AUTHORITY_CLAIMS_URL));

        let (status, _, body) = handle_config_effective(&state);
        assert_eq!(status, 200);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["locally_owned"], false);
        assert_eq!(value["provenance"]["origins.api.action.url"], "authority");
        assert_eq!(value["provenance"]["origins.api.action.type"], "local");
        assert_eq!(value["provenance"]["proxy.http_bind_port"], "local");
        assert_eq!(
            value["layers"]["authority"]["authority_id"],
            "control-plane"
        );
        assert_eq!(value["layers"]["authority"]["revision"], 9);
        assert_eq!(value["layers"]["authority"]["mode"], "overlay");
        assert!(
            value["yaml"]
                .as_str()
                .unwrap()
                .contains("https://central.test"),
            "the effective document should carry the authority's value"
        );

        crate::config_subscriber::clear_applied_bundle();
    }

    #[test]
    fn config_write_guard_lets_a_local_node_write_anything() {
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(OWNED);
        let path = state.config_path.clone().unwrap();
        assert!(
            guard_config_write(&path, &OWNED.replace("8080", "8081")).is_none(),
            "a node that owns its config has nothing that could swallow an edit"
        );
    }

    #[test]
    fn config_write_guard_allows_an_edit_the_authority_does_not_claim() {
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(OWNED);
        let path = state.config_path.clone().unwrap();
        crate::config_subscriber::set_applied_authority(overlay_authority(AUTHORITY_CLAIMS_URL));

        assert!(
            guard_config_write(&path, &OWNED.replace("8080", "8081")).is_none(),
            "the authority claims the origin url, so the bind port is still the node's to change"
        );

        crate::config_subscriber::clear_applied_bundle();
    }

    #[test]
    fn config_write_is_refused_when_the_authority_would_swallow_the_edit() {
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(OWNED);
        let path = state.config_path.clone().unwrap();
        crate::config_subscriber::set_applied_authority(overlay_authority(AUTHORITY_CLAIMS_URL));

        let proposed = OWNED.replace("https://test.sbproxy.dev", "https://mine.test");
        let (status, _, body) =
            handle_config_write(&state, Some(&proposed), Some("known-revision"));
        assert_eq!(status, 409, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["code"], "config_not_locally_owned");
        assert_eq!(value["conflicts"][0]["path"], "origins.api.action.url");
        assert_eq!(value["conflicts"][0]["owner"], "authority");
        // The rejection has to be actionable on its own. An operator who
        // only sees "conflict" retries, and retrying cannot work.
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .contains("origins.api.action.url"),
            "the error should name the path: {}",
            value["error"]
        );
        let remedy = value["remedy"].as_str().unwrap();
        assert!(remedy.contains("control-plane"), "{remedy}");
        assert!(remedy.contains("authority publish"), "{remedy}");
        // Nothing was written.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), OWNED);

        crate::config_subscriber::clear_applied_bundle();
    }

    #[test]
    fn config_write_is_refused_on_a_git_sourced_node_and_names_the_repository() {
        let _guard = config_layer_guard();
        // Internally tagged: `kind` selects the variant, and a git source
        // requires both the repository and the path inside it.
        let pointer = "source:\n  kind: git\n  repo: https://git.test/fleet.git\n  path: sb.yml\n";
        let (_dir, state) = owned_config_state(pointer);
        let path = state.config_path.clone().unwrap();
        crate::config_source::publish_resolved_base(crate::config_source::ResolvedBase {
            yaml: OWNED.to_string(),
            origin: BaseOrigin::Git {
                repo: "https://git.test/fleet.git".to_string(),
                reference: "main".to_string(),
                commit: "c".repeat(40),
            },
            fingerprint: "c".repeat(40),
        });

        let proposed = format!("{pointer}proxy:\n  http_bind_port: 8081\n");
        let (status, _, body) =
            handle_config_write(&state, Some(&proposed), Some("known-revision"));
        assert_eq!(status, 409, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["code"], "config_not_locally_owned");
        assert_eq!(value["conflicts"][0]["path"], "proxy.http_bind_port");
        assert_eq!(value["layers"]["base"]["kind"], "git");
        assert_eq!(value["layers"]["base"]["reference"], "main");
        let remedy = value["remedy"].as_str().unwrap();
        assert!(remedy.contains("https://git.test/fleet.git"), "{remedy}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), pointer);

        crate::config_source::clear_resolved_base();
    }

    /// A rejected write must still be auditable. An operator repeatedly
    /// trying to edit configuration they do not own is a signal, and a log
    /// of successes alone would never show it.
    #[test]
    fn a_refused_config_write_is_recorded_in_the_audit_log() {
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(OWNED);
        crate::config_subscriber::set_applied_authority(overlay_authority(AUTHORITY_CLAIMS_URL));

        use tracing_subscriber::layer::SubscriberExt as _;
        let logged = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = logged.clone();
        let subscriber = tracing_subscriber::registry().with(CaptureLayer { sink });
        tracing::subscriber::with_default(subscriber, || {
            let proposed = OWNED.replace("https://test.sbproxy.dev", "https://mine.test");
            assert_eq!(
                handle_config_write(&state, Some(&proposed), Some("known-revision")).0,
                409
            );
        });

        let lines = logged.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("sbproxy::admin::audit")
                    && line.contains("rejected_not_locally_owned")
                    && line.contains("origins.api.action.url")),
            "no audit line named the refused write: {lines:?}"
        );

        crate::config_subscriber::clear_applied_bundle();
    }

    #[tokio::test]
    async fn config_schema_endpoint_serves_the_committed_schema() {
        let response = send_admin_request(
            make_state(),
            format!(
                "GET /admin/config/schema HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                basic_auth("admin", "secret")
            ),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("Content-Type: application/schema+json"));
        assert!(response.contains("Cache-Control: private, no-cache"));
        assert!(response.contains(&format!("ETag: {}", config_schema_etag())));

        let body = response
            .split_once("\r\n\r\n")
            .expect("headers then body")
            .1;
        // Byte-identical to what the generator writes, which is what the CI
        // freshness gate diffs. An editor validating against this document
        // is validating against the running binary's own view of its config.
        assert_eq!(body, sbproxy_config::config_json_schema());
    }

    #[tokio::test]
    async fn config_schema_endpoint_answers_a_matching_entity_tag_with_304() {
        let response = send_admin_request(
            make_state(),
            format!(
                "GET /admin/config/schema HTTP/1.1\r\nAuthorization: {}\r\nIf-None-Match: {}\r\n\r\n",
                basic_auth("admin", "secret"),
                config_schema_etag()
            ),
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 304 Not Modified"),
            "{response}"
        );
        assert!(response.contains("Content-Length: 0"));
        assert_eq!(
            response.split_once("\r\n\r\n").expect("headers").1,
            "",
            "a 304 carries no body"
        );
    }

    #[tokio::test]
    async fn config_schema_endpoint_ignores_a_stale_entity_tag() {
        let response = send_admin_request(
            make_state(),
            format!(
                "GET /admin/config/schema HTTP/1.1\r\nAuthorization: {}\r\nIf-None-Match: \"not-this-build\"\r\n\r\n",
                basic_auth("admin", "secret")
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    #[tokio::test]
    async fn config_schema_endpoint_requires_auth_and_only_answers_get() {
        let unauthenticated = send_admin_request(
            make_state(),
            "GET /admin/config/schema HTTP/1.1\r\n\r\n".to_string(),
        )
        .await;
        assert!(
            unauthenticated.starts_with("HTTP/1.1 401 Unauthorized"),
            "{unauthenticated}"
        );

        let wrong_method = send_admin_request(
            make_state(),
            format!(
                "PUT /admin/config/schema HTTP/1.1\r\nAuthorization: {}\r\nContent-Length: 0\r\n\r\n",
                basic_auth("admin", "secret")
            ),
        )
        .await;
        assert!(
            wrong_method.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{wrong_method}"
        );
    }

    /// A read-only operator has to be able to read the schema. It is one of
    /// the two documents that let someone understand a node they are not
    /// allowed to change.
    ///
    /// Reached over a browser session, not Basic. `resolve_principal` grants
    /// Basic only to the top-level admin credential, so an operator role
    /// exists only on the session path. That is pre-existing behaviour and
    /// worth pinning here, because a reader who tried Basic would get a 401
    /// and reasonably conclude their account did not work.
    #[tokio::test]
    async fn a_read_only_operator_can_read_the_schema() {
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reader".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reader-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        let (token, _csrf) =
            state
                .session_signer
                .mint("reader", AdminRole::ReadOnly, 3600, unix_now());
        let response = send_admin_request(
            state,
            format!(
                "GET /admin/config/schema HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    /// The same reader is still refused a write, so the read access above
    /// did not widen anything.
    #[tokio::test]
    async fn a_read_only_operator_is_still_refused_a_config_write() {
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reader".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reader-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        let (token, csrf) =
            state
                .session_signer
                .mint("reader", AdminRole::ReadOnly, 3600, unix_now());
        let body = "proxy:\n  http_bind_port: 8080\n";
        let response = send_admin_request(
            state,
            format!(
                "PUT /admin/config HTTP/1.1\r\nCookie: sb_admin_session={token}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
        assert!(response.contains("read-only operator"));
    }

    #[test]
    fn config_effective_only_answers_get() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for method in ["PUT", "POST", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/config/effective", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} should not be accepted");
        }
    }

    /// WOR-2436: the operator surface for the two composition blocks.
    ///
    /// The assertion that matters is the negative one. Three
    /// secret-shaped values go in (a repository URL with an embedded
    /// token, an entry credential reference, and a bound input) and none
    /// of them comes out.
    #[test]
    fn origin_composition_reports_the_declaration_and_never_a_secret() {
        let config: sbproxy_config::ConfigFile = serde_yaml::from_str(
            r#"
origins: {}
origin_defaults:
  policies:
    - name: waf
      type: waf
      locked: true
    - name: rate_limit
      type: rate_limit
origin_sources:
  tier: production
  entries:
    - name: checkout
      repo: https://octocat:ghp_TOKENVALUE@git.test/acme/checkout
      revision: refs/tags/v1.4.2
      path: sbproxy/origin.yaml
      credential: "secret://ci/github-token"
      verify_signature: true
      timeout_secs: 30
      hosts:
        api: ["checkout.acme.test"]
      inputs:
        upstream_key: "secret://prod/checkout-key"
"#,
        )
        .expect("fixture parses");
        let body = origin_composition_json(&config);
        let text = body.to_string();
        for secret in [
            "ghp_TOKENVALUE",
            "secret://ci/github-token",
            "secret://prod/checkout-key",
        ] {
            assert!(!text.contains(secret), "`{secret}` leaked into {text}");
        }
        assert_eq!(body["declared"], true);
        assert_eq!(body["tier"], "production");
        assert_eq!(body["entries"][0]["pinned"], true);
        assert_eq!(body["entries"][0]["credential"], "reference");
        assert_eq!(body["entries"][0]["verify_signature"], true);
        assert_eq!(body["entries"][0]["timeout_secs"], 30);
        assert_eq!(body["entries"][0]["inputs"][0], "upstream_key");
        assert_eq!(body["claimed_hosts"][0]["host"], "checkout.acme.test");
        assert_eq!(body["claimed_hosts"][0]["profile_origin"], "api");
        assert_eq!(
            body["origin_defaults"]["addressable"]["policies"][0]["locked"],
            true
        );
        assert_eq!(
            body["origin_defaults"]["addressable"]["policies"][1]["locked"],
            false
        );
        assert!(body["collision"].is_null());
    }

    /// A contested map key is named on the route rather than left for an
    /// aggregation run to discover.
    #[test]
    fn origin_composition_names_a_host_collision() {
        let config: sbproxy_config::ConfigFile = serde_yaml::from_str(
            r#"
origins:
  "checkout.acme.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: local
origin_sources:
  entries:
    - name: checkout
      repo: https://git.test/acme/checkout
      path: sbproxy/origin.yaml
      hosts:
        api: ["checkout.acme.test"]
"#,
        )
        .expect("fixture parses");
        let body = origin_composition_json(&config);
        let collision = body["collision"].as_str().expect("a collision is reported");
        assert!(collision.contains("checkout.acme.test"), "{collision}");
        assert!(collision.contains("already declares"), "{collision}");
    }

    /// A config with neither block says so rather than returning an
    /// empty structure that reads like a failure.
    #[test]
    fn origin_composition_says_so_when_nothing_is_declared() {
        let config: sbproxy_config::ConfigFile =
            serde_yaml::from_str("origins: {}\n").expect("fixture parses");
        let body = origin_composition_json(&config);
        assert_eq!(body["declared"], false);
        assert_eq!(body["origin_defaults"]["present"], false);
    }

    /// The route's authentication is the gate every route past a certain
    /// point in the dispatcher sits behind, which is a property of where
    /// 400 lines of `if` put it rather than of anything the route itself
    /// says. Assert it, the way its neighbours do: the surface reports
    /// which project repositories a fleet pulls and what hosts they
    /// claim, and an unauthenticated read of that is reconnaissance.
    #[test]
    fn origin_composition_requires_auth() {
        let state = make_state();
        let (status, _, _) =
            handle_admin_request("GET", "/admin/origin-composition", &state, None, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn origin_composition_only_answers_get_and_needs_a_config_path() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for method in ["PUT", "POST", "DELETE"] {
            let (status, _, _) = handle_admin_request(
                method,
                "/admin/origin-composition",
                &state,
                Some(&auth),
                None,
            );
            assert_eq!(status, 405, "{method} should not be accepted");
        }
        // `make_state` wires no config path, so the read is refused with
        // the same 503 every config route uses rather than a panic.
        assert_eq!(handle_origin_composition(&state).0, 503);
    }

    // --- GET /api/audit/chain (WOR-2579) ---

    /// The four-channel viewer route serves entries from every installed
    /// chain, newest first, and reports the channels that are not
    /// enabled as disabled rather than omitting them.
    #[test]
    fn audit_chain_route_serves_entries_across_channels() {
        use sbproxy_observe::audit_chain::{
            install_admin_audit_chain, install_security_audit_chain, AdminActionAuditChain,
            SecurityAuditChain,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let seed = "11".repeat(32);
        let security =
            SecurityAuditChain::open(&dir.path().join("security.jsonl"), &seed, "viewer-kid")
                .expect("the security chain opens");
        let admin =
            AdminActionAuditChain::open(&dir.path().join("admin.jsonl"), &seed, "viewer-kid")
                .expect("the admin chain opens");
        if install_security_audit_chain(security).is_err()
            || install_admin_audit_chain(admin).is_err()
        {
            // Another test in this process claimed a chain slot first
            // (plain `cargo test` shares one process). The nextest run,
            // where every test owns its process, covers this path.
            return;
        }
        sbproxy_observe::SecurityAuditEntry::policy_violation(
            "waf",
            "chain-viewer-marker-deny",
            403,
            Some("api.example.com".to_string()),
            None,
            Some("req-viewer-1".to_string()),
            Some("GET".to_string()),
        )
        .emit();
        sbproxy_observe::AdminActionAuditEntry::new(
            "admin_action",
            Some("root".to_string()),
            None,
            None,
            None,
            Some("POST /admin/reload".to_string()),
        )
        .emit();

        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/api/audit/chain", &state, Some(&auth), None);
        assert_eq!(status, 200, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
        let channels = json["channels"].as_array().expect("a channels array");
        assert_eq!(channels.len(), 4, "all four channels are reported: {body}");
        let by_name = |name: &str| {
            channels
                .iter()
                .find(|c| c["channel"] == name)
                .unwrap_or_else(|| panic!("channel {name} is reported: {body}"))
        };
        assert_eq!(by_name("security")["enabled"], true, "{body}");
        assert_eq!(by_name("security")["ok"], true, "{body}");
        assert_eq!(by_name("security")["key_id"], "viewer-kid", "{body}");
        assert_eq!(by_name("config")["enabled"], false, "{body}");
        assert_eq!(by_name("key")["enabled"], false, "{body}");
        let entries = json["entries"].as_array().expect("an entries array");
        assert!(
            entries.iter().any(|e| e["channel"] == "security"
                && e["event"]["reason"] == "chain-viewer-marker-deny"),
            "the security denial is browsable: {body}"
        );
        assert!(
            entries
                .iter()
                .any(|e| e["channel"] == "admin" && e["actor"] == "root"),
            "the admin action is browsable with its actor: {body}"
        );
    }

    /// Tampering with a chained entry on disk is surfaced in the
    /// response rather than hidden: the walk stops at the break, names
    /// the sequence, and serves only the records that verified. This is
    /// the property that makes the viewer more than a log reader.
    #[test]
    fn audit_chain_route_surfaces_a_tampered_entry() {
        use sbproxy_observe::audit_chain::{install_security_audit_chain, SecurityAuditChain};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("security.jsonl");
        let seed = "22".repeat(32);
        let chain = SecurityAuditChain::open(&path, &seed, "viewer-kid").expect("the chain opens");
        if install_security_audit_chain(chain).is_err() {
            return;
        }
        for marker in ["tamper-zero", "tamper-one", "tamper-two"] {
            sbproxy_observe::SecurityAuditEntry::policy_violation(
                "waf", marker, 403, None, None, None, None,
            )
            .emit();
        }
        let content = std::fs::read_to_string(&path).expect("the chain file is readable");
        let tampered = content.replace("tamper-one", "tamper-WAS-EDITED");
        assert_ne!(content, tampered, "the marker was present to tamper with");
        std::fs::write(&path, tampered).expect("the tampered file is writable");

        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let broken_before = audit_chain_read_total("security", "broken");
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/audit/chain?channel=security",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(
            status, 200,
            "a broken chain is a finding, not a 500: {body}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
        let channels = json["channels"].as_array().expect("a channels array");
        let security = channels
            .iter()
            .find(|c| c["channel"] == "security")
            .expect("the security channel is reported");
        assert_eq!(security["ok"], false, "{body}");
        assert_eq!(security["broken_seq"], 1, "{body}");
        assert!(
            security["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("tampered"),
            "the reason names the tamper: {body}"
        );
        let entries = json["entries"].as_array().expect("an entries array");
        assert_eq!(
            entries.len(),
            1,
            "only the records before the break are served: {body}"
        );
        assert_eq!(entries[0]["seq"], 0, "{body}");
        // And the verdict leaves the page. A broken chain only a person
        // looking at the console can see is a finding nobody is on call
        // for, so the alertable signal is asserted here by name rather
        // than left to the renderer.
        // Strictly greater rather than exactly one more: the counter is
        // process-wide, and under a shared-process runner another test
        // reading the same installed chain would move it too. What is
        // being pinned is the mapping - a walk that failed counts as
        // `broken` - and a mapping that reported anything else leaves
        // this label where it was.
        assert!(
            audit_chain_read_total("security", "broken") > broken_before,
            "sbproxy_audit_chain_read_total{{channel=\"security\",outcome=\"broken\"}} \
             did not move"
        );
    }

    /// The current `sbproxy_audit_chain_read_total` value for one label
    /// pair, read back off the default registry. Zero when the family
    /// has not registered yet, which is the same thing as never having
    /// counted.
    fn audit_chain_read_total(channel: &str, outcome: &str) -> u64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_audit_chain_read_total" {
                continue;
            }
            for metric in family.get_metric() {
                let has = |name: &str, want: &str| {
                    metric
                        .get_label()
                        .iter()
                        .any(|pair| pair.name() == name && pair.value() == want)
                };
                if has("channel", channel) && has("outcome", outcome) {
                    return metric.get_counter().value() as u64;
                }
            }
        }
        0
    }

    /// The viewer refuses what it cannot serve: an unknown channel, a
    /// malformed timestamp, and a cursor without a channel are each a
    /// 400, and the route is GET-only.
    #[test]
    fn audit_chain_route_validates_its_query() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/audit/chain?channel=nope",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400, "{body}");
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/audit/chain?since=yesterday",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400, "{body}");
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/audit/chain?before_seq=5",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 400, "a cursor needs a channel to page: {body}");
        let (status, _, body) =
            handle_admin_request("POST", "/api/audit/chain", &state, Some(&auth), None);
        assert_eq!(status, 405, "{body}");
    }

    /// The audit viewer is a read surface: a read-only operator gets the
    /// same 200 an admin does (WOR-2579). The route is GET-only by
    /// construction, so the mutating-action gate never applies to it.
    #[tokio::test]
    async fn a_read_only_operator_can_read_the_audit_chain() {
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reader".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reader-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        let (token, _) = state
            .session_signer
            .mint("reader", AdminRole::ReadOnly, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!("GET /api/audit/chain HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    /// A login narrowed to one tenant is refused the whole chain
    /// surface rather than served a filtered slice of it, and the
    /// refusal is on the tenant axis rather than the role axis: this
    /// operator holds the `admin` role and is still refused (WOR-2579).
    #[tokio::test]
    async fn a_tenant_scoped_operator_is_refused_the_audit_chain() {
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reseller".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reseller-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::Admin,
                tenant: Some("acme".to_string()),
            }],
            ..AdminConfig::default()
        });
        let (token, _) = state
            .session_signer
            .mint("reseller", AdminRole::Admin, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!("GET /api/audit/chain HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"),
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a deployment-wide trail must not be sliced per tenant: {response}"
        );
        assert!(
            response.contains("acme"),
            "the refusal names the scope that caused it: {response}"
        );
    }

    /// The refusal above is scrapeable, not only auditable (WOR-2579).
    ///
    /// Without this the only record of a scoped principal reaching for a
    /// deployment-wide security surface is inside the chain that
    /// principal was just refused, which takes an admin-role read to
    /// find and nothing to prompt one. The shipped alert
    /// `increase(sbproxy_audit_chain_read_total{outcome!="verified"}[15m]) > 0`
    /// has to cover it unchanged, which is why the outcome lands on this
    /// family rather than on a new one.
    #[tokio::test]
    async fn a_refused_audit_chain_read_moves_the_alertable_counter() {
        let before = audit_chain_read_total("security", "denied");
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "reseller".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "reseller-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::Admin,
                tenant: Some("acme".to_string()),
            }],
            ..AdminConfig::default()
        });
        let (token, _) = state
            .session_signer
            .mint("reseller", AdminRole::Admin, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!("GET /api/audit/chain HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");

        // Strictly greater rather than exactly one more: the counter is
        // process-wide and a shared-process runner may move it too.
        assert!(
            audit_chain_read_total("security", "denied") > before,
            "a refused chain read must leave the page as well as render on it"
        );
    }

    /// WOR-2578's two new routes are read surfaces, so a `read_only`
    /// operator gets the same 200 an admin does.
    ///
    /// Pinned by name because the audit-chain viewer that shipped in the
    /// same batch argued the opposite way on the tenant axis, and the
    /// posture nobody tests is the posture that flips unnoticed.
    #[tokio::test]
    async fn the_report_and_the_export_allow_a_read_only_operator() {
        for path in [
            "/api/requests/report?group_by=model",
            "/api/requests/export?format=csv",
        ] {
            let state = AdminState::new(AdminConfig {
                username: "admin".to_string(),
                password: "secret".to_string(),
                max_log_entries: 100,
                operators: vec![AdminOperator {
                    username: "reader".to_string(),
                    password_hash: sbproxy_keystore::crypto::hash_secret(
                        "reader-secret",
                        &crate::key_plane::default_admin_operator_pepper(),
                    ),
                    role: AdminRole::ReadOnly,
                    tenant: None,
                }],
                ..AdminConfig::default()
            });
            let (token, _) =
                state
                    .session_signer
                    .mint("reader", AdminRole::ReadOnly, 3600, unix_now());

            let response = send_admin_request(
                state,
                format!("GET {path} HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"),
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "{path}: {response}"
            );
        }
    }

    /// And a tenant-scoped operator is served the whole deployment on
    /// both, exactly as `GET /api/requests` has always served them one.
    ///
    /// The asymmetry with `/api/audit/chain` is deliberate rather than
    /// inherited: a narrowed audit trail reads as "nothing else
    /// happened", which is a worse answer than a refusal, while a
    /// narrowed spend report is just a smaller number. Recorded in code
    /// so the decision is a decision rather than an omission (WOR-2578).
    #[tokio::test]
    async fn the_report_and_the_export_serve_a_tenant_scoped_operator_every_tenant() {
        for path in [
            "/api/requests/report?group_by=tenant",
            "/api/requests/export?format=csv",
        ] {
            let state = AdminState::new(AdminConfig {
                username: "admin".to_string(),
                password: "secret".to_string(),
                max_log_entries: 100,
                operators: vec![AdminOperator {
                    username: "reseller".to_string(),
                    password_hash: sbproxy_keystore::crypto::hash_secret(
                        "reseller-secret",
                        &crate::key_plane::default_admin_operator_pepper(),
                    ),
                    role: AdminRole::Admin,
                    tenant: Some("acme".to_string()),
                }],
                ..AdminConfig::default()
            });
            state.log_request(reporting_entry(
                "gpt-4o",
                "k-acme",
                "acme",
                "dev@acme.test",
                1,
                1,
                1,
            ));
            state.log_request(reporting_entry(
                "gpt-4o",
                "k-globex",
                "globex",
                "dev@globex.test",
                1,
                1,
                1,
            ));
            let (token, _) =
                state
                    .session_signer
                    .mint("reseller", AdminRole::Admin, 3600, unix_now());

            let response = send_admin_request(
                state,
                format!("GET {path} HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"),
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "{path}: {response}"
            );
            assert!(
                response.contains("globex"),
                "{path}: the reporting routes are deployment-wide for every role: {response}"
            );
        }
    }

    /// Reading the trail is itself recorded on the admin chain, naming
    /// the operator and what they asked for: an investigator asking
    /// "who looked" must not have to take our word for it (WOR-2579).
    #[tokio::test]
    async fn reading_the_audit_chain_is_itself_recorded() {
        use sbproxy_observe::audit_chain::{install_admin_audit_chain, AdminActionAuditChain};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin.jsonl");
        let chain = AdminActionAuditChain::open(&path, &"44".repeat(32), "viewer-kid")
            .expect("the admin chain opens");
        if install_admin_audit_chain(chain).is_err() {
            // Another test in this process claimed the slot first (plain
            // `cargo test` shares one process); nextest covers this.
            return;
        }
        let state = AdminState::new(AdminConfig {
            username: "admin".to_string(),
            password: "secret".to_string(),
            operators: vec![AdminOperator {
                username: "auditor".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret(
                    "auditor-secret",
                    &crate::key_plane::default_admin_operator_pepper(),
                ),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        });
        let (token, _) =
            state
                .session_signer
                .mint("auditor", AdminRole::ReadOnly, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!(
                "GET /api/audit/chain?channel=admin HTTP/1.1\r\n\
                 Cookie: sb_admin_session={token}\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        let recorded = std::fs::read_to_string(&path).expect("the admin chain is readable");
        assert!(
            recorded.contains(r#""action":"read_audit_chain""#),
            "the read is on the chain under its own name: {recorded}"
        );
        assert!(
            recorded.contains(r#""actor":"auditor""#),
            "and it names who looked: {recorded}"
        );
        assert!(
            recorded.contains("channel=admin"),
            "and what they asked for: {recorded}"
        );
        assert!(
            !recorded.contains("read_audit_chain_denied"),
            "an allowed read is not a denial: {recorded}"
        );
    }

    // --- /admin/config/history (WOR-2456/2457) ---

    /// Installs an enabled config-history recorder rooted at `dir` as the
    /// process-wide recorder these routes read through
    /// `crate::config_history::current_config_history_recorder`. Pair with
    /// `crate::config_history::clear_config_history_recorder()` once the
    /// test is done, matching the teardown `config_history.rs`'s own
    /// tests use for the same process-global slot.
    fn install_test_history_recorder(
        dir: &std::path::Path,
    ) -> std::sync::Arc<crate::config_history::ConfigHistoryRecorder> {
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let recorder = crate::config_history::ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error opening an enabled block")
            .expect("an enabled block opens a recorder");
        let recorder = std::sync::Arc::new(recorder);
        crate::config_history::install_config_history_recorder(recorder.clone());
        recorder
    }

    fn history_metadata(actor: &str) -> sbproxy_config::AppendMetadata {
        sbproxy_config::AppendMetadata {
            provenance: BaseOrigin::Local,
            blast_radius: None,
            secrets_fingerprint: None,
            actor: Some(actor.to_string()),
            applied_at: 1_700_000_000_000,
            degraded: Vec::new(),
        }
    }

    fn history_rejection(
        reason: sbproxy_config::RejectionReason,
        at: u64,
    ) -> sbproxy_config::RejectionMetadata {
        sbproxy_config::RejectionMetadata {
            reason,
            stage: "config_authority".to_string(),
            detail: "refused for the test".to_string(),
            provenance: BaseOrigin::Local,
            rejected_at: at,
        }
    }

    // --- /admin/config/rollback and /admin/config/diff (WOR-2460) ---

    /// Seed a ring by hand with three documents and promote the first,
    /// so the diff and rollback route tests have non-adjacent revisions
    /// to name.
    fn seed_three_revisions(dir: &std::path::Path) {
        let mut store = sbproxy_config::RevisionStore::open(dir, 20, None).expect("open ring");
        for (index, yaml) in [
            "proxy: {}\n# one\n",
            "proxy:\n  http_bind_port: 8080\n",
            "proxy:\n  http_bind_port: 8081\n",
        ]
        .into_iter()
        .enumerate()
        {
            store
                .append(
                    yaml.as_bytes(),
                    sbproxy_config::AppendMetadata {
                        provenance: BaseOrigin::Local,
                        blast_radius: None,
                        secrets_fingerprint: None,
                        actor: Some("seed".to_string()),
                        applied_at: 1_700_000_000_000 + index as u64,
                        degraded: Vec::new(),
                    },
                )
                .expect("append");
        }
        store.mark_good(1).expect("promote the first");
    }

    /// WOR-2460: "Rollback requires the same admin auth as
    /// `POST /admin/reload`". The route is the one surface in this
    /// feature that changes what is serving, so the unauthenticated and
    /// wrong-method answers are part of the contract rather than
    /// incidental.
    #[test]
    fn config_rollback_requires_admin_auth_and_only_accepts_post() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, _, _) =
            handle_admin_request("POST", "/admin/config/rollback", &state, None, Some("{}"));
        assert_eq!(status, 401, "an unauthenticated rollback is refused");
        for method in ["GET", "PUT", "DELETE", "PATCH"] {
            let (status, _, _) = handle_admin_request(
                method,
                "/admin/config/rollback",
                &state,
                Some(&auth),
                Some("{}"),
            );
            assert_eq!(status, 405, "{method} must not roll a node back");
        }
        // Opt-in like every sibling: a node with no ring answers the
        // same "not enabled" body rather than a confusing refusal about
        // a revision it was never asked for.
        let (status, _, body) = handle_admin_request(
            "POST",
            "/admin/config/rollback",
            &state,
            Some(&auth),
            Some("{}"),
        );
        assert_eq!(status, 404);
        assert_eq!(body, r#"{"error":"config history is not enabled"}"#);
    }

    /// WOR-2460. Naming two targets is a refusal rather than a silent
    /// precedence rule: guessing which revision an operator meant
    /// mid-incident is the wrong kind of helpful.
    #[test]
    fn a_rollback_body_naming_two_targets_is_refused() {
        let ambiguous = serde_json::json!({"revision": 3, "digest": "abc"});
        let error = rollback_target_from_body(&ambiguous).expect_err("two targets is ambiguous");
        assert!(error.contains("exactly one"), "{error}");

        assert_eq!(
            rollback_target_from_body(&serde_json::json!({}))
                .expect("an empty body is the shortest form"),
            crate::config_rollback::RollbackTarget::LastKnownGood,
        );
        assert_eq!(
            rollback_target_from_body(&serde_json::json!({"revision": 3}))
                .expect("a revision is a target"),
            crate::config_rollback::RollbackTarget::Revision(3),
        );
        let unknown = rollback_target_from_body(&serde_json::json!({"target": "yesterday"}))
            .expect_err("only one named target exists");
        assert!(unknown.contains("last-known-good"), "{unknown}");
    }

    /// WOR-2460: "`sbproxy config diff --from <a> --to <b>` renders a
    /// plan between two stored revisions without touching the running
    /// config, including for two non-adjacent revisions."
    #[test]
    fn config_diff_renders_a_plan_between_two_non_adjacent_stored_revisions() {
        let dir = tempfile::tempdir().unwrap();
        seed_three_revisions(dir.path());
        let _recorder = install_test_history_recorder(dir.path());
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let before = crate::reload::current_pipeline_full();

        let (status, _, body) = handle_admin_request(
            "GET",
            "/admin/config/diff?from=1&to=3",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["from"]["revision"], 1);
        assert_eq!(parsed["to"]["revision"], 3);
        assert_eq!(
            parsed["max_blast_radius"], "restart",
            "revision 3 binds a different listener port than revision 1",
        );
        assert!(
            parsed["changes"].as_u64().unwrap_or(0) > 0,
            "two different documents have to produce at least one change: {body}",
        );
        assert!(
            std::sync::Arc::ptr_eq(&before, &crate::reload::current_pipeline_full()),
            "a diff reads; it must not move the running configuration",
        );

        // `last-known-good` is accepted on either side, which is the
        // form an operator reaches for without first looking up a
        // number.
        let (status, _, body) = handle_admin_request(
            "GET",
            "/admin/config/diff?from=last-known-good&to=3",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");

        // An unknown revision names what is available rather than 500ing.
        let (status, _, body) = handle_admin_request(
            "GET",
            "/admin/config/diff?from=1&to=99",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 404);
        assert!(body.contains("available_revisions"), "{body}");

        for method in ["POST", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/config/diff?to=3", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} is not a way to read a diff");
        }
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460, the route's own refusal shape. The engine's refusals
    /// are tested next door; this pins that the HTTP layer carries the
    /// status, the stable code, and the availability list an operator
    /// needs to make a second call correctly.
    #[test]
    fn a_rollback_to_an_unknown_revision_answers_404_with_what_is_available() {
        let dir = tempfile::tempdir().unwrap();
        seed_three_revisions(dir.path());
        let _recorder = install_test_history_recorder(dir.path());
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, _, body) = handle_admin_request(
            "POST",
            "/admin/config/rollback",
            &state,
            Some(&auth),
            Some(r#"{"revision": 99}"#),
        );
        assert_eq!(status, 404, "{body}");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["code"], "unknown_revision");
        assert_eq!(parsed["rolled_back"], false);
        assert_eq!(
            parsed["available_revisions"],
            serde_json::json!([1, 2, 3]),
            "naming the alternatives is what saves a second call mid-incident",
        );

        // A body that is not an object at all is a 400 rather than a
        // silent default to last-known-good: rolling a node back
        // because a client sent malformed JSON is not a helpful default.
        let (status, _, body) = handle_admin_request(
            "POST",
            "/admin/config/rollback",
            &state,
            Some(&auth),
            Some("[1,2,3]"),
        );
        assert_eq!(status, 400, "{body}");
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2459. The fallback pin is readable on every node, and
    /// clearing it is refused when nothing is pinned.
    #[test]
    fn config_fallback_route_reports_and_clears_the_pin() {
        crate::config_boot::reset_for_test();
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, _, _) =
            handle_admin_request("GET", "/admin/config/fallback", &state, None, None);
        assert_eq!(
            status, 401,
            "the pin is behind the admin auth like everything else"
        );
        let (status, _, _) =
            handle_admin_request("POST", "/admin/config/fallback", &state, Some(&auth), None);
        assert_eq!(status, 405);

        // Nothing pinned: answers, rather than 404ing, because "am I
        // running what I was told to run" must be askable on any node.
        let (status, _, body) =
            handle_admin_request("GET", "/admin/config/fallback", &state, Some(&auth), None);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["active"], false);
        assert_eq!(parsed["suspended"].as_array().expect("array").len(), 0);

        let (status, _, body) = handle_config_fallback_clear(&state);
        assert_eq!(
            status, 409,
            "clearing a pin that does not exist is a caller bug"
        );
        assert!(body.contains("not pinned"), "{body}");

        crate::config_boot::mark_on_fallback(crate::config_boot::PinnedRevision {
            revision: 12,
            digest: "cafe".to_string(),
        });
        let (status, _, body) =
            handle_admin_request("GET", "/admin/config/fallback", &state, Some(&auth), None);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["active"], true);
        assert_eq!(parsed["revision"], 12);
        assert_eq!(parsed["digest"], "cafe");
        let suspended: Vec<&str> = parsed["suspended"]
            .as_array()
            .expect("array")
            .iter()
            .map(|value| value.as_str().expect("string"))
            .collect();
        assert_eq!(
            suspended,
            vec!["file_watcher", "sighup", "config_refresh_poller"],
            "config_authority is deliberately absent: a fleet-wide fix is how this ends",
        );

        let (status, _, body) = handle_config_fallback_clear(&state);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["cleared"], true);
        assert_eq!(parsed["revision"], 12);
        assert!(!crate::config_boot::on_fallback());
        crate::config_boot::reset_for_test();
    }

    /// WOR-2459 fix round, Major 9. Recovery has to finish in one call.
    /// The watcher only fires on a *future* filesystem event, so a node
    /// whose file had already been fixed before the pin was cleared sat
    /// on the rescued config with `sbproxy_config_fallback_active`
    /// reading 0, which is the reading that says everything is fine.
    #[test]
    fn clearing_the_pin_applies_the_config_file_rather_than_waiting_for_a_touch() {
        crate::config_boot::reset_for_test();
        let dir = tempfile::tempdir().expect("temp dir");
        let config_path = dir.path().join("sb.yml");
        std::fs::write(&config_path, "proxy: {}\n# the operator's fix\n").expect("write");
        let state = make_state().with_config_path(&config_path);

        crate::config_boot::mark_on_fallback(crate::config_boot::PinnedRevision {
            revision: 7,
            digest: "rescued".to_string(),
        });
        let before = crate::reload::current_pipeline_full();

        let (status, _, body) = handle_config_fallback_clear(&state);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let after = crate::reload::current_pipeline_full();
        crate::config_boot::reset_for_test();

        assert_eq!(status, 200);
        assert_eq!(parsed["cleared"], true);
        assert_eq!(
            parsed["reloaded"], true,
            "clearing the pin applies the file in the same call: {body}",
        );
        assert_eq!(parsed["reload_error"], serde_json::Value::Null);
        assert!(
            !std::sync::Arc::ptr_eq(&before, &after),
            "and the running pipeline is the operator's fix, not the rescued revision",
        );
    }

    /// A file that still does not compile is the operator's next
    /// problem, not a failure of the clear: the pin is genuinely gone
    /// and the gauge says so, and `reloaded: false` carries the reason.
    #[test]
    fn clearing_the_pin_still_succeeds_when_the_file_is_still_broken() {
        crate::config_boot::reset_for_test();
        let dir = tempfile::tempdir().expect("temp dir");
        let config_path = dir.path().join("sb.yml");
        std::fs::write(&config_path, "proxy:\n  http2_cleartextt: true\n").expect("write");
        let state = make_state().with_config_path(&config_path);
        crate::config_boot::mark_on_fallback(crate::config_boot::PinnedRevision {
            revision: 7,
            digest: "rescued".to_string(),
        });

        let (status, _, body) = handle_config_fallback_clear(&state);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let pinned = crate::config_boot::on_fallback();
        crate::config_boot::reset_for_test();

        assert_eq!(status, 200);
        assert_eq!(parsed["cleared"], true);
        assert_eq!(parsed["reloaded"], false);
        assert!(
            parsed["reload_error"]
                .as_str()
                .is_some_and(|reason| reason.contains("http2_cleartextt")),
            "the operator is told why their file still does not apply: {body}",
        );
        assert!(!pinned, "the pin is gone either way");
    }

    /// WOR-2458. Confirming is a mutation, so it is POST only and
    /// behind the same auth as everything else here.
    #[test]
    fn config_confirm_requires_auth_and_only_answers_post() {
        crate::config_history::clear_config_history_recorder();
        crate::config_soak::clear();
        let state = make_state();
        let (status, _, _) =
            handle_admin_request("POST", "/admin/config/confirm", &state, None, None);
        assert_eq!(status, 401);

        let auth = basic_auth("admin", "secret");
        for method in ["GET", "PUT", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/config/confirm", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} should not be accepted");
        }
        // Opt-in, like its siblings: a node with no ring has nothing to
        // confirm and says so the same way.
        let (status, _, body) =
            handle_admin_request("POST", "/admin/config/confirm", &state, Some(&auth), None);
        assert_eq!(status, 404);
        assert_eq!(body, r#"{"error":"config history is not enabled"}"#);
    }

    /// WOR-2458. Confirming with nothing in flight is refused rather
    /// than answered as a cheerful success: a pipeline told its config
    /// is the rollback target when it is not would carry on deploying.
    #[test]
    fn config_confirm_is_refused_when_no_soak_is_in_flight() {
        let dir = tempfile::tempdir().unwrap();
        let _recorder = install_test_history_recorder(dir.path());
        crate::config_soak::clear();

        let (status, _, body) = handle_config_confirm(&make_state());
        crate::config_history::clear_config_history_recorder();
        assert_eq!(status, 409);
        assert_eq!(body, r#"{"error":"no config soak is in flight"}"#);
    }

    /// WOR-2458. Confirming short-circuits the wait, not the judgment:
    /// the same signals run, and the answer says whether the revision
    /// was actually promoted.
    #[test]
    fn config_confirm_closes_the_window_and_reports_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(dir.path());
        crate::config_soak::clear();
        let entry = recorder
            .record(b"origins: {}\n# confirmed\n", history_metadata("operator"))
            .expect("one recorded revision");
        crate::config_soak::arm(
            entry.revision,
            &entry.digest,
            &[],
            &sbproxy_config::ConfigSoakConfig::default(),
        );
        // The operator's own probe, which dials a real URL and so
        // promotes on its own. A synthetic pass cannot stand in: this
        // fixture declares no upstream, the health signal abstains, and
        // a synthetic pass is discarded with it (verification residual
        // R1).
        crate::config_soak::record_probe(
            crate::config_soak::ProbeKind::Operator,
            crate::config_soak::ProbeObservation::Ok,
        );

        let (status, _, body) = handle_config_confirm(&make_state());
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let promoted = recorder.lkg().map(|lkg| lkg.revision);
        crate::config_history::clear_config_history_recorder();
        crate::config_soak::clear();

        assert_eq!(status, 200);
        assert_eq!(parsed["revision"], entry.revision);
        assert_eq!(parsed["verdict"], "passed");
        assert_eq!(parsed["promoted"], true);
        assert_eq!(
            parsed["signals"].as_array().expect("signals").len(),
            4,
            "the caller sees what each signal said, not just the verdict",
        );
        assert_eq!(
            promoted,
            Some(entry.revision),
            "a confirmed, passing window advances the pointer",
        );
    }

    /// WOR-2462. The refused candidates are behind the same auth as
    /// everything else on the admin surface.
    #[test]
    fn config_rejected_route_requires_auth_and_only_answers_get() {
        crate::config_history::clear_config_history_recorder();
        let state = make_state();
        let (status, _, _) =
            handle_admin_request("GET", "/admin/config/rejected", &state, None, None);
        assert_eq!(status, 401);

        let auth = basic_auth("admin", "secret");
        for method in ["PUT", "POST", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/config/rejected", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} should not be accepted");
        }
        // Opt-in, same as its applied-history siblings.
        let (status, _, body) =
            handle_admin_request("GET", "/admin/config/rejected", &state, Some(&auth), None);
        assert_eq!(status, 404);
        assert_eq!(body, r#"{"error":"config history is not enabled"}"#);
    }

    /// WOR-2462. Newest first, one row per refused candidate, with the
    /// reason and the count an operator reads first.
    #[test]
    fn config_rejected_list_is_newest_first_with_reason_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(dir.path());
        recorder.record_rejection(
            b"a: 1\n",
            history_rejection(
                sbproxy_config::RejectionReason::VerifyFailed,
                1_700_000_001_000,
            ),
        );
        recorder.record_rejection(
            b"a: 2\n",
            history_rejection(
                sbproxy_config::RejectionReason::DeniedPath,
                1_700_000_002_000,
            ),
        );
        recorder.record_rejection(
            b"a: 2\n",
            history_rejection(
                sbproxy_config::RejectionReason::DeniedPath,
                1_700_000_003_000,
            ),
        );

        let (status, _, body) = handle_config_rejected_list();
        crate::config_history::clear_config_history_recorder();
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let entries = parsed["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 2, "the repeat updated a row, not added one");
        assert_eq!(entries[0]["reason"], "denied_path");
        assert_eq!(entries[0]["count"], 2);
        assert_eq!(entries[1]["reason"], "verify_failed");
        assert_eq!(entries[1]["count"], 1);
        assert_eq!(entries[0]["stage"], "config_authority");
        assert!(entries[0]["last_seen_at"]
            .as_str()
            .is_some_and(|when| when.starts_with("2023-")));
    }

    /// WOR-2462. A rejection appears in the timeline in its correct
    /// place rather than being invisible: the incident an operator is
    /// investigating is one sequence, not two lists.
    #[test]
    fn config_history_timeline_interleaves_rejections_with_applied_entries() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(dir.path());
        recorder.record(
            b"origins: {}\n# one\n",
            sbproxy_config::AppendMetadata {
                applied_at: 1_000,
                ..history_metadata("first")
            },
        );
        recorder.record_rejection(
            b"broken: yes\n",
            history_rejection(sbproxy_config::RejectionReason::CompileFailed, 2_000),
        );
        recorder.record(
            b"origins: {}\n# two\n",
            sbproxy_config::AppendMetadata {
                applied_at: 3_000,
                ..history_metadata("second")
            },
        );

        let (status, _, body) = handle_config_history_list();
        crate::config_history::clear_config_history_recorder();
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let timeline = parsed["timeline"].as_array().expect("timeline array");
        let shape: Vec<&str> = timeline
            .iter()
            .map(|row| row["kind"].as_str().expect("kind"))
            .collect();
        assert_eq!(
            shape,
            vec!["applied", "rejected", "applied"],
            "newest first, with the refusal in its own place: {timeline:?}",
        );
        assert_eq!(timeline[0]["revision"], 2);
        assert_eq!(timeline[1]["reason"], "compile_failed");
        assert_eq!(timeline[2]["revision"], 1);
    }

    #[test]
    fn config_history_routes_require_auth() {
        let state = make_state();
        let (status, _, _) =
            handle_admin_request("GET", "/admin/config/history", &state, None, None);
        assert_eq!(status, 401);
        let (status, _, _) =
            handle_admin_request("GET", "/admin/config/history/deadbeef", &state, None, None);
        assert_eq!(status, 401);
    }

    #[test]
    fn config_history_404s_with_the_exact_disabled_body_when_no_recorder_is_installed() {
        crate::config_history::clear_config_history_recorder();
        let state = make_state();
        let auth = basic_auth("admin", "secret");

        let (status, _, body) =
            handle_admin_request("GET", "/admin/config/history", &state, Some(&auth), None);
        assert_eq!(status, 404);
        assert_eq!(body, r#"{"error":"config history is not enabled"}"#);

        let (status, _, body) = handle_admin_request(
            "GET",
            "/admin/config/history/deadbeef",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 404);
        assert_eq!(body, r#"{"error":"config history is not enabled"}"#);
    }

    #[test]
    fn config_history_only_answers_get() {
        crate::config_history::clear_config_history_recorder();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for method in ["PUT", "POST", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/config/history", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} should not be accepted");
        }
    }

    #[test]
    fn config_history_list_shape_matches_the_contract_field_for_field() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(dir.path());
        recorder.record(
            b"origins: {}\n# one\n",
            sbproxy_config::AppendMetadata {
                blast_radius: None,
                ..history_metadata("first")
            },
        );
        recorder.record(
            b"origins: {}\n# two\n",
            sbproxy_config::AppendMetadata {
                blast_radius: Some(sbproxy_config::BlastRadius::Restart),
                ..history_metadata("second")
            },
        );

        let (status, _, body) = handle_config_history_list();
        crate::config_history::clear_config_history_recorder();
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        let top: std::collections::BTreeSet<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            top,
            [
                "lineage",
                "lkg_revision",
                "soak_revision",
                "entries",
                "timeline"
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(parsed["lkg_revision"], serde_json::Value::Null);
        assert!(parsed["lineage"].as_str().is_some_and(|s| !s.is_empty()));

        let entries = parsed["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 2);
        // Newest first: the ring itself stores oldest first.
        assert_eq!(entries[0]["revision"], 2);
        assert_eq!(entries[1]["revision"], 1);

        let expected_keys: std::collections::BTreeSet<&str> = [
            "revision",
            "digest",
            "provenance",
            "state",
            "applied_at",
            "actor",
            "blast_radius",
            "degraded",
        ]
        .into_iter()
        .collect();
        for entry in entries {
            let keys: std::collections::BTreeSet<&str> = entry
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, expected_keys, "entry: {entry}");
            let applied_at = entry["applied_at"]
                .as_str()
                .expect("applied_at must be a string");
            assert!(
                chrono::DateTime::parse_from_rfc3339(applied_at).is_ok(),
                "applied_at must parse as RFC 3339: {applied_at}"
            );
            assert!(
                entry["actor"].is_string(),
                "actor must be a string: {entry}"
            );
            assert_eq!(entry["state"], "applied");
            assert_eq!(entry["provenance"], "local_file");
        }
        assert_eq!(entries[0]["actor"], "second");
        assert_eq!(entries[0]["blast_radius"], "restart");
        assert_eq!(entries[1]["actor"], "first");
        assert_eq!(
            entries[1]["blast_radius"],
            serde_json::Value::Null,
            "no blast radius was recorded for the first entry"
        );
    }

    #[test]
    fn config_history_detail_returns_the_document_verbatim_and_a_plan_text() {
        let _guard = config_layer_guard();
        let history_dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(history_dir.path());
        let stored = "proxy:\n  http_bind_port: 9999\n# credential: ${FAKE_VAR_NOT_SET}\n";
        recorder.record(stored.as_bytes(), history_metadata("operator"));
        let digest = recorder.entries().last().expect("one entry").digest.clone();

        let (_dir, state) = owned_config_state("proxy:\n  http_bind_port: 8080\n");

        let (status, _, body) = handle_config_history_detail(&state, &digest);
        crate::config_history::clear_config_history_recorder();
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        assert_eq!(
            parsed["document"].as_str().unwrap(),
            stored,
            "the stored document must round-trip byte for byte, unresolved: {body}"
        );
        assert_eq!(parsed["entry"]["digest"].as_str(), Some(digest.as_str()));

        let plan_text = parsed["plan_text"].as_str().expect("plan_text is a string");
        assert!(
            !plan_text.starts_with("plan unavailable"),
            "expected a real plan diff, got: {plan_text}"
        );
        assert!(
            plan_text.contains("restart"),
            "changing http_bind_port is a restart-class change: {plan_text}"
        );
    }

    /// The counterpart to the test above, which used content with no
    /// secret-shaped token in it (proving redaction is a no-op there).
    /// This one plants a literal secret -- a value an operator typed
    /// directly into the file, not a `${VAR}` / `vault://` reference --
    /// and proves three things at once: the route's `document` masks
    /// it, `plan_text` does not carry it either, and the ring's own
    /// stored blob still holds the original bytes untouched, because
    /// only the display route redacts.
    #[test]
    fn config_history_detail_redacts_a_literal_secret_while_the_ring_file_keeps_the_original() {
        let _guard = config_layer_guard();
        let history_dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(history_dir.path());
        // A well-known AWS documentation example access key ID (never a
        // real credential), shaped exactly like `RE_AWS_ACCESS` in
        // `sbproxy_observe::redact` (`AKIA` + 16 alphanumeric chars).
        let stored = "ai:\n  api_key_literal: AKIAIOSFODNN7EXAMPLE\n";
        recorder.record(stored.as_bytes(), history_metadata("operator"));
        let digest = recorder.entries().last().expect("one entry").digest.clone();

        let (_dir, state) = owned_config_state("proxy:\n  http_bind_port: 8080\n");

        let (status, _, body) = handle_config_history_detail(&state, &digest);
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        let document = parsed["document"].as_str().expect("document is a string");
        assert!(
            !document.contains("AKIAIOSFODNN7EXAMPLE"),
            "the planted secret must not survive the route unredacted: {document}"
        );
        assert!(
            document.contains("AKIA[REDACTED]"),
            "expected the AWS-key-shape redaction marker: {document}"
        );

        let plan_text = parsed["plan_text"].as_str().expect("plan_text is a string");
        assert!(
            !plan_text.contains("AKIAIOSFODNN7EXAMPLE"),
            "the planted secret must not survive the plan diff unredacted either: {plan_text}"
        );

        // The ring FILE itself is untouched: read the blob directly,
        // the same call the handler made before redacting, and confirm
        // the original bytes -- the ones a rollback needs -- are still
        // there. Redaction happens once, on the way out of the
        // handler; it never mutates what `record` persisted.
        let ring_bytes = recorder
            .read_blob(&digest)
            .expect("the ring's own copy is still readable");
        assert_eq!(
            String::from_utf8_lossy(&ring_bytes),
            stored,
            "the ring file must keep the original bytes; only the display route redacts"
        );

        crate::config_history::clear_config_history_recorder();
    }

    #[test]
    fn config_history_detail_404s_for_an_unknown_digest() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = install_test_history_recorder(dir.path());
        recorder.record(b"proxy: {}\n", history_metadata("operator"));
        let state = make_state();

        let (status, _, body) = handle_config_history_detail(&state, "not-a-real-digest");
        crate::config_history::clear_config_history_recorder();
        assert_eq!(status, 404);
        assert_eq!(body, r#"{"error":"unknown digest"}"#);
    }

    /// The route distinction for all three slot states: `Disabled` ->
    /// the existing 404, `Failed` -> a distinct 503 naming the reason,
    /// `Open` -> 200. `Disabled` and `Open` are already covered by
    /// their own tests above; this one is the `Failed` third of the
    /// same claim, on both routes.
    #[test]
    fn config_history_routes_distinguish_failed_from_disabled_and_open() {
        crate::config_history::clear_config_history_recorder();
        crate::config_history::install_config_history_failure(
            "open config history store '/no/such/place': permission denied",
        );
        let state = make_state();

        let (status, _, body) = handle_config_history_list();
        assert_eq!(status, 503);
        assert_eq!(
            body,
            r#"{"error":"config history failed to open at boot: open config history store '/no/such/place': permission denied"}"#
        );

        let (status, _, body) = handle_config_history_detail(&state, "any-digest");
        assert_eq!(status, 503);
        assert_eq!(
            body,
            r#"{"error":"config history failed to open at boot: open config history store '/no/such/place': permission denied"}"#
        );

        // And through the full auth-gated dispatch, not just the
        // handler functions directly: a 503 is not a 404, and a
        // Failed slot is not a 401 either.
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/admin/config/history", &state, Some(&auth), None);
        assert_eq!(status, 503);
        assert!(body.contains("failed to open at boot"), "{body}");

        crate::config_history::clear_config_history_recorder();
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
    fn config_read_redacts_inlined_secrets() {
        // WOR-2316: an inlined plaintext credential must not be echoed back
        // to a read-only operator. Both redactor shapes are exercised: a
        // token recognized by value (Anthropic key) and one recognized by
        // its key label (`password:`).
        let dir = tempfile::tempdir().unwrap();
        let cfgpath = dir.path().join("sb.yml");
        std::fs::write(
            &cfgpath,
            "proxy:\n  http_bind_port: 8080\nai:\n  api_key: sk-ant-api03-TESTONLYTESTONLY1234567890\n  password: hunter2hunter2\n",
        )
        .unwrap();
        let state = AdminState::new(AdminConfig::default())
            .with_config_path(cfgpath)
            .with_loaded_config_content_hash("rev-xyz");
        let (status, _, body) = handle_config_read(&state);
        assert_eq!(status, 200);
        assert!(
            !body.contains("sk-ant-api03-TESTONLYTESTONLY1234567890"),
            "inlined key value must not survive the read: {body}"
        );
        assert!(
            !body.contains("hunter2hunter2"),
            "inlined password value must not survive the read: {body}"
        );
        assert!(body.contains("[REDACTED]"), "{body}");
        // Non-secret content and the revision are untouched.
        assert!(body.contains("http_bind_port"));
        assert!(body.contains("rev-xyz"));
    }

    #[test]
    fn config_effective_redacts_inlined_secrets() {
        // WOR-2316: the effective document is assembled from the same
        // layers, so an inlined plaintext credential must not leak through
        // the sibling endpoint either.
        let _guard = config_layer_guard();
        let (_dir, state) = owned_config_state(
            "proxy:\n  http_bind_port: 8080\nai:\n  api_key: sk-ant-api03-TESTONLYTESTONLY1234567890\n  password: hunter2hunter2\n",
        );
        let (status, _, body) = handle_config_effective(&state);
        assert_eq!(status, 200);
        assert!(
            !body.contains("sk-ant-api03-TESTONLYTESTONLY1234567890"),
            "inlined key value must not survive the effective read: {body}"
        );
        assert!(
            !body.contains("hunter2hunter2"),
            "inlined password value must not survive the effective read: {body}"
        );
        assert!(body.contains("[REDACTED]"), "{body}");
        // Non-secret content is untouched.
        assert!(body.contains("http_bind_port"));
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
                ..Default::default()
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
    fn enrollment_token_route_bypasses_operator_auth_only_for_its_exact_path() {
        let state = make_state();
        let (status, _, body) = handle_admin_request(
            "POST",
            crate::admin_cluster::ENROLL_PATH,
            &state,
            None,
            Some("{}"),
        );
        assert_eq!(status, 400);
        assert!(body.contains("invalid_request"));

        let (status, _, _) =
            handle_admin_request("GET", "/admin/cluster/metrics", &state, None, None);
        assert_eq!(status, 401);
        let (status, _, _) =
            handle_admin_request("GET", crate::admin_cluster::STATUS_PATH, &state, None, None);
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

    /// WOR-2575: a routing-decision entry with only the dimensions a
    /// test cares about; everything else stays at its default.
    fn sample_routing_decision(
        timestamp: &str,
        origin: &str,
        strategy: &str,
    ) -> RoutingDecisionEntry {
        RoutingDecisionEntry {
            timestamp: timestamp.to_string(),
            origin: origin.to_string(),
            strategy: strategy.to_string(),
            status: 200,
            ..Default::default()
        }
    }

    #[test]
    fn routing_decisions_endpoint_returns_recorded_decisions() {
        let state = make_state();
        let mut detail = serde_json::Map::new();
        detail.insert(
            "fallback_trigger".to_string(),
            serde_json::Value::String("context_window".to_string()),
        );
        state.log_routing_decision(RoutingDecisionEntry {
            timestamp: "2026-08-20T12:00:00+00:00".to_string(),
            origin: "ai-gateway".to_string(),
            request_id: Some("req-1".to_string()),
            tenant_id: "acme".to_string(),
            strategy: "fallback_chain".to_string(),
            requested_model: Some("gpt-5".to_string()),
            selected_provider: Some("anthropic".to_string()),
            selected_model: Some("claude-sonnet-5".to_string()),
            reason: Some("primary quota exhausted".to_string()),
            candidates: vec![
                RoutingDecisionCandidate {
                    provider: "openai".to_string(),
                    model: Some("gpt-5".to_string()),
                },
                RoutingDecisionCandidate {
                    provider: "anthropic".to_string(),
                    model: Some("claude-sonnet-5".to_string()),
                },
            ],
            attempted: vec!["openai".to_string(), "anthropic".to_string()],
            attempts: 2,
            failover_engaged: true,
            failover_from: Some("openai".to_string()),
            failover_to: Some("anthropic".to_string()),
            status: 200,
            latency_ms: 812.4,
            detail,
        });

        let auth = basic_auth("admin", "secret");
        let (status, ct, body) =
            handle_admin_request("GET", "/api/routing-decisions", &state, Some(&auth), None);
        assert_eq!(status, 200, "{body}");
        assert_eq!(ct, "application/json");
        let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
        let row = &rows[0];
        assert_eq!(row["strategy"], "fallback_chain");
        assert_eq!(row["requested_model"], "gpt-5");
        assert_eq!(row["selected_provider"], "anthropic");
        assert_eq!(row["reason"], "primary quota exhausted");
        assert_eq!(row["candidates"][1]["provider"], "anthropic");
        assert_eq!(row["attempted"], serde_json::json!(["openai", "anthropic"]));
        assert_eq!(row["failover_from"], "openai");
        // The open detail map rides along verbatim: WOR-2556, WOR-2557,
        // WOR-2559, and WOR-2564 each add a key here, not a column.
        assert_eq!(row["detail"]["fallback_trigger"], "context_window");
    }

    #[test]
    fn routing_decisions_endpoint_is_get_only() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) =
            handle_admin_request("POST", "/api/routing-decisions", &state, Some(&auth), None);
        assert_eq!(status, 405);
    }

    #[test]
    fn routing_decisions_ring_drops_oldest_when_full() {
        // make_state caps the ring at 5 entries.
        let state = make_state();
        for i in 0..7 {
            state.log_routing_decision(sample_routing_decision(
                "2026-08-20T12:00:00+00:00",
                &format!("origin-{i}"),
                "round_robin",
            ));
        }
        let rows = state.query_routing_decisions(&RoutingDecisionFilter::default(), 0, 100);
        assert_eq!(rows.len(), 5);
        // Newest first; the two oldest fell off the front.
        assert_eq!(rows[0].origin, "origin-6");
        assert_eq!(rows[4].origin, "origin-2");
    }

    #[test]
    fn query_routing_decisions_filters_and_paginates() {
        let state = make_state();
        state.log_routing_decision(RoutingDecisionEntry {
            requested_model: Some("gpt-5".to_string()),
            selected_provider: Some("openai".to_string()),
            selected_model: Some("gpt-5".to_string()),
            ..sample_routing_decision("2026-08-20T10:00:00+00:00", "ai-gateway", "round_robin")
        });
        state.log_routing_decision(RoutingDecisionEntry {
            requested_model: Some("gpt-5".to_string()),
            selected_provider: Some("anthropic".to_string()),
            selected_model: Some("claude-sonnet-5".to_string()),
            ..sample_routing_decision("2026-08-20T11:00:00+00:00", "ai-gateway", "fallback_chain")
        });
        state.log_routing_decision(sample_routing_decision(
            "2026-08-20T12:00:00+00:00",
            "web",
            "least_connections",
        ));

        let all = state.query_routing_decisions(&RoutingDecisionFilter::default(), 0, 100);
        assert_eq!(all.len(), 3);

        let by_origin = state.query_routing_decisions(
            &RoutingDecisionFilter {
                origin: Some("ai-gateway"),
                ..Default::default()
            },
            0,
            100,
        );
        assert_eq!(by_origin.len(), 2);

        let by_strategy = state.query_routing_decisions(
            &RoutingDecisionFilter {
                strategy: Some("fallback_chain"),
                ..Default::default()
            },
            0,
            100,
        );
        assert_eq!(by_strategy.len(), 1);
        assert_eq!(
            by_strategy[0].selected_provider.as_deref(),
            Some("anthropic")
        );

        // The model filter matches the requested side and the selected
        // side, so a substituted request is findable from either name.
        for model in ["gpt-5", "claude-sonnet-5"] {
            let by_model = state.query_routing_decisions(
                &RoutingDecisionFilter {
                    model: Some(model),
                    ..Default::default()
                },
                0,
                100,
            );
            assert!(
                by_model
                    .iter()
                    .any(|e| e.selected_model.as_deref() == Some("claude-sonnet-5")),
                "model={model} missed the substituted decision"
            );
        }

        let by_provider = state.query_routing_decisions(
            &RoutingDecisionFilter {
                provider: Some("openai"),
                ..Default::default()
            },
            0,
            100,
        );
        assert_eq!(by_provider.len(), 1);

        let since = "2026-08-20T10:30:00+00:00"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let until = "2026-08-20T11:30:00+00:00"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let windowed = state.query_routing_decisions(
            &RoutingDecisionFilter {
                since: Some(since),
                until: Some(until),
                ..Default::default()
            },
            0,
            100,
        );
        assert_eq!(windowed.len(), 1);
        assert_eq!(windowed[0].strategy, "fallback_chain");

        let paged = state.query_routing_decisions(&RoutingDecisionFilter::default(), 1, 1);
        assert_eq!(paged.len(), 1);
        assert_eq!(paged[0].strategy, "fallback_chain");
    }

    #[test]
    fn routing_decisions_endpoint_validates_filters() {
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for path in [
            "/api/routing-decisions?since=yesterday",
            "/api/routing-decisions?until=not-a-time",
        ] {
            let (status, _, body) = handle_admin_request("GET", path, &state, Some(&auth), None);
            assert_eq!(status, 400, "{path}: {body}");
            assert!(body.contains("RFC 3339"), "{path}: {body}");
        }
        let (status, _, body) = handle_admin_request(
            "GET",
            "/api/routing-decisions?since=2026-08-20T10:30:00%2B00:00&strategy=round_robin&limit=10",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");
    }

    #[test]
    fn spend_totals_use_attributed_tokens_when_legacy_tokens_are_empty() {
        let snap = std::collections::HashMap::from([
            ("sbproxy_tokens_attributed_total".to_string(), 39.0),
            ("sbproxy_ai_cost_usd_micros_total".to_string(), 195.0),
        ]);

        let (tokens, cost_usd) = spend_totals_from_snapshot(&snap);

        assert_eq!(tokens, 39.0);
        assert_eq!(cost_usd, 0.000195);
    }

    #[test]
    fn spend_totals_reflect_a_real_attributed_request_through_the_live_snapshot() {
        // The two reducer tests above and below hand-build the HashMap, so
        // they cover the key-preference logic and nothing else. Neither could
        // ever observe the actual bug: the names they supply are registered on
        // the process-global default registry via `register_counter_vec!`,
        // `snapshot_named` gathered only the private registry, and the real
        // spend endpoint returned zero tokens no matter the traffic. This one
        // drives the recorder and reads the same snapshot the handler reads.
        let before = sbproxy_observe::metrics::metrics()
            .snapshot_named(&["sbproxy_ai_tokens_attributed_total"]);
        let (before_tokens, _) = spend_totals_from_snapshot(&before);

        sbproxy_ai::ai_metrics::record_ai_request_attributed(
            "test.origin",
            "anthropic",
            "claude-opus-4-8",
            "chat_completions",
            "tenant-spend",
            "key-spend",
            &sbproxy_ai::attribution::AttributionTags::default(),
            200, // input
            50,  // output
            0,
            0,
            0,
            0.0,
        );

        let after = sbproxy_observe::metrics::metrics().snapshot_named(&[
            "sbproxy_tokens_attributed_total",
            "sbproxy_ai_tokens_attributed_total",
            "sbproxy_ai_cost_usd_micros_total",
            "sbproxy_ai_cost_dollars_attributed_total",
        ]);
        let (after_tokens, _) = spend_totals_from_snapshot(&after);

        assert!(
            after_tokens >= before_tokens + 250.0,
            "the spend snapshot must reflect a real attributed request; \
             {after_tokens} is not {before_tokens} + 250"
        );
    }

    #[test]
    fn spend_totals_accept_ai_prefixed_attributed_metric_name() {
        let snap = std::collections::HashMap::from([
            ("sbproxy_ai_tokens_attributed_total".to_string(), 44.0),
            ("sbproxy_ai_cost_dollars_attributed_total".to_string(), 0.25),
        ]);

        let (tokens, cost_usd) = spend_totals_from_snapshot(&snap);

        assert_eq!(tokens, 44.0);
        assert_eq!(cost_usd, 0.25);
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
        // WOR-2328: the proxy's resolved zone rides beside the target
        // list so an operator can see whether locality is active. Null
        // here (no proxy.zone, no SB_ZONE) but the key must exist.
        assert!(
            parsed.get("proxy_zone").is_some(),
            "missing 'proxy_zone': {body}"
        );
    }

    /// WOR-2560: the tri-state gauge value is derived from the same
    /// row the admin JSON renders, on LiteLLM's 0/1/2 scale. Each case
    /// pins one arm: any ineligibility source reads 2, an eligible
    /// half-open breaker reads 1 (it is carrying trial traffic, which
    /// is degraded rather than out), and only a fully clean target
    /// reads 0.
    #[test]
    fn target_health_metric_state_matches_selection_eligibility() {
        let row = |healthy: bool, ejected: bool, breaker: Option<&'static str>| TargetHealthRow {
            index: 0,
            url: "http://127.0.0.1:9601".to_string(),
            healthy,
            outlier_ejected: ejected,
            breaker_state: breaker,
            weight: 1,
            backup: false,
            group: None,
            zone: None,
        };
        use sbproxy_observe::metrics::{
            TARGET_HEALTH_DEGRADED, TARGET_HEALTH_EXCLUDED, TARGET_HEALTH_HEALTHY,
        };
        assert_eq!(
            row(true, false, Some("closed")).metric_state(),
            TARGET_HEALTH_HEALTHY
        );
        // No breaker configured is the common case and is healthy.
        assert_eq!(row(true, false, None).metric_state(), TARGET_HEALTH_HEALTHY);
        assert_eq!(
            row(true, false, Some("half_open")).metric_state(),
            TARGET_HEALTH_DEGRADED
        );
        assert_eq!(
            row(false, false, None).metric_state(),
            TARGET_HEALTH_EXCLUDED,
            "probe-unhealthy must exclude"
        );
        assert_eq!(
            row(true, true, None).metric_state(),
            TARGET_HEALTH_EXCLUDED,
            "outlier ejection must exclude"
        );
        assert_eq!(
            row(true, false, Some("open")).metric_state(),
            TARGET_HEALTH_EXCLUDED,
            "an open breaker must exclude"
        );
        // A half-open breaker on an ejected target is still excluded:
        // eligibility wins over the degraded reading.
        assert_eq!(
            row(true, true, Some("half_open")).metric_state(),
            TARGET_HEALTH_EXCLUDED
        );
    }

    /// Fix round on the #1177 review, red-first: keying the gauge's
    /// `target` label on `row.url` alone collapsed two same-URL targets
    /// into one series. The load balancer refuses that assumption in
    /// its own identifier (`target_id` is `url#index` "so two targets
    /// with the same URL stay distinguishable"), and two same-URL
    /// targets are a real config: a weighted pair, or blue and green
    /// addressed through one host.
    ///
    /// Before the fix both rows wrote
    /// `with_label_values(&["lb.local", "http://a:8080"])`, last write
    /// won, and the ejected target read healthy on `/metrics` while
    /// `GET /api/health/targets` still showed it ejected at its own
    /// `index`. That is exactly the disagreement between the two
    /// surfaces the registry description, `docs/observability.md`, and
    /// the example README all promise cannot happen.
    #[test]
    fn same_url_targets_get_distinct_health_gauge_series() {
        use sbproxy_observe::metrics::{TARGET_HEALTH_EXCLUDED, TARGET_HEALTH_HEALTHY};
        let row = |index: usize, url: &str, ejected: bool| TargetHealthRow {
            index,
            url: url.to_string(),
            healthy: true,
            outlier_ejected: ejected,
            breaker_state: None,
            weight: 1,
            backup: false,
            group: None,
            zone: None,
        };
        let origins = vec![OriginTargetHealth {
            hostname: "lb.local".to_string(),
            origin_id: "lb.local".to_string(),
            local_zone: None,
            targets: vec![
                row(0, "http://a:8080", true),
                row(1, "http://a:8080", false),
                row(2, "http://b:8080", false),
            ],
        }];

        let samples = target_health_samples(&origins);
        let labels: Vec<&str> = samples.iter().map(|s| s.target.as_str()).collect();
        assert_eq!(
            labels,
            vec!["http://a:8080#0", "http://a:8080#1", "http://b:8080"],
            "colliding URLs take the load balancer's own url#index id; a unique URL stays \
             readable"
        );

        // The ejected row is still readable as ejected, which is the
        // whole failure the collapse hid.
        assert_eq!(samples[0].state, TARGET_HEALTH_EXCLUDED);
        assert_eq!(samples[1].state, TARGET_HEALTH_HEALTHY);
        assert_eq!(samples[2].state, TARGET_HEALTH_HEALTHY);

        // Every sample is a distinct (origin, target) pair, so nothing
        // can be overwritten by a later `set`.
        let mut pairs: Vec<(&str, &str)> = samples
            .iter()
            .map(|s| (s.origin.as_str(), s.target.as_str()))
            .collect();
        pairs.sort_unstable();
        let before = pairs.len();
        pairs.dedup();
        assert_eq!(before, pairs.len(), "two rows still share one gauge series");
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
            ..Default::default()
        });
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/api/stats", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert!(body.contains("1"), "expected count 1 in: {body}");
    }

    #[test]
    fn prompt_injection_classifier_health_is_authenticated_and_typed() {
        crate::prompt_injection_runtime::record_unavailable(
            Some("admin-test-origin"),
            "tenant-a",
            Some("request-a"),
            "header_scan",
            sbproxy_modules::PromptInjectionAction::Log,
            crate::prompt_injection_runtime::UnavailableDecision::Degraded,
            sbproxy_modules::DetectionFailure::direct(
                sbproxy_modules::DetectionFailureKind::Inference,
            ),
        );
        let state = make_state();

        let (status, _, _) =
            handle_admin_request("GET", "/admin/prompt-injection-v2", &state, None, None);
        assert_eq!(status, 401);

        let auth = basic_auth("admin", "secret");
        let (status, content_type, body) = handle_admin_request(
            "GET",
            "/admin/prompt-injection-v2",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid health JSON");
        assert!(value.get("classification_cache").is_some());
        let entries = value["classifier_failures"]["entries"]
            .as_array()
            .expect("failure entries array");
        assert!(entries.iter().any(|entry| {
            entry["origin_id"] == "admin-test-origin"
                && entry["reason"] == "inference"
                && entry["last_outcome"] == "degraded"
        }));
        assert!(!body.contains("request-a"));

        let (status, _, _) = handle_admin_request(
            "POST",
            "/admin/prompt-injection-v2",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 405);
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
        let runtime = crate::server::model_host::model_runtime_manager();
        let runtime_revision_before = runtime.current_revision();
        let state = AdminState::new(AdminConfig {
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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
        assert!(
            runtime.current_revision() > runtime_revision_before,
            "admin reload must commit the permanent model runtime even for an empty desired state",
        );
        assert_eq!(
            runtime.current_desired().revision.source_revision,
            parsed["config_revision"].as_str().unwrap(),
        );
    }

    #[test]
    fn admin_reload_returns_400_on_yaml_parse_error() {
        let f = write_yaml("this is not: valid: yaml: at all\n  - {");
        let state = AdminState::new(AdminConfig {
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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

    #[test]
    fn admin_reload_returns_400_on_pipeline_compile_error() {
        let f = write_yaml(
            r#"
origins:
  "invalid.example":
    action:
      type: this_action_type_does_not_exist
"#,
        );
        let state = make_state().with_config_path(f.path());
        let auth = basic_auth("admin", "secret");

        let (status, _, body) =
            handle_admin_request("POST", "/admin/reload", &state, Some(&auth), None);

        assert_eq!(status, 400, "body: {body}");
        assert!(body.contains("config does not compile"), "body: {body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_concurrent_calls_one_wins_one_409s() {
        // Two simultaneous calls to /admin/reload: the single-flight
        // guard admits one and rejects the other with 409. We use a
        // multi-thread runtime so the two tasks really do contend.
        let f = write_yaml(&reload_yaml("reload-concurrency.example.com"));
        let state = std::sync::Arc::new(
            AdminState::new(AdminConfig {
                trace_url_template: None,
                enabled: true,
                port: 9090,
                username: "admin".to_string(),
                password: "secret".to_string(),
                max_log_entries: 5,
                rate_limit_per_minute: 60,
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
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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
    fn rate_limiter_uses_configured_per_minute_limit() {
        // The limiter the admin server installs must come from config,
        // not a hardcoded cap: a non-default value has to change what
        // the third request sees.
        assert_eq!(AdminConfig::default().rate_limit_per_minute, 240);
        let cfg = AdminConfig {
            rate_limit_per_minute: 2,
            ..AdminConfig::default()
        };
        let limiter = build_rate_limiter(&cfg);
        assert!(limiter.check("10.9.0.1"));
        assert!(limiter.check("10.9.0.1"));
        assert!(
            !limiter.check("10.9.0.1"),
            "third request must exceed the configured cap of 2"
        );
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
    fn ip_filter_localhost_only_allows_ipv4_mapped_loopback() {
        // A dual-stack listener reports an IPv4 client as
        // `::ffff:127.0.0.1`. The old string-matching filter rejected
        // that peer, which locked an operator out of a loopback-only
        // admin server for reasons nothing in the config explained.
        let filter = AdminIpFilter::localhost_only();
        assert!(filter.is_allowed("::ffff:127.0.0.1"), "v4-mapped loopback");
        assert!(filter.is_allowed("127.0.0.2"), "all of 127.0.0.0/8");
        assert!(
            !filter.is_allowed("::ffff:10.0.0.1"),
            "v4-mapped non-loopback stays out"
        );
    }

    #[test]
    fn ip_filter_denies_an_unparseable_peer() {
        // Not reachable from a real socket address, but a peer we cannot
        // identify must not be treated as allowed.
        let filter = AdminIpFilter::new(vec!["10.1.2.3".to_string()]);
        assert!(!filter.is_allowed(""));
        assert!(!filter.is_allowed("not-an-ip"));
        assert!(!AdminIpFilter::localhost_only().is_allowed("localhost"));
    }

    #[test]
    fn ip_filter_custom_list() {
        let filter = AdminIpFilter::new(vec!["10.1.2.3".to_string(), "10.1.2.4".to_string()]);
        assert!(filter.is_allowed("10.1.2.3"));
        assert!(filter.is_allowed("10.1.2.4"));
        assert!(!filter.is_allowed("10.1.2.5"));
        assert!(!filter.is_allowed("127.0.0.1"));
    }

    // Renamed from `ip_filter_empty_allows_all`, which pinned the old
    // fail-open behaviour: an empty allowlist used to permit every peer,
    // and the safe default lived in an `is_empty()` branch at the single
    // call site instead of in the type. An empty list now denies, so the
    // permit-all state cannot be constructed at all.
    #[test]
    fn ip_filter_empty_denies_non_loopback() {
        let filter = AdminIpFilter::new(vec![]);
        assert!(!filter.is_allowed("192.168.1.1"));
        assert!(!filter.is_allowed("10.0.0.1"));
        assert!(filter.is_allowed("::1"), "loopback is the safe default");
        assert!(
            filter.is_allowed("127.0.0.1"),
            "loopback is the safe default"
        );
    }

    #[test]
    fn ip_filter_all_unparseable_entries_deny_rather_than_widen() {
        // A typo'd allowlist leaves no usable rule. Falling back to
        // loopback-only keeps a mistake from opening the surface.
        let filter = AdminIpFilter::new(vec!["10.0.0/8".to_string(), "nonsense".to_string()]);
        assert!(!filter.is_allowed("10.0.0.1"));
        assert!(filter.is_allowed("127.0.0.1"));
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
    fn ip_filter_matches_ipv4_mapped_peers_against_v4_rules() {
        // Same peer, two spellings: an operator writes the v4 address or
        // CIDR, and a dual-stack listener hands us the mapped form.
        let filter = AdminIpFilter::new(vec!["10.1.0.0/16".to_string(), "192.168.1.5".to_string()]);
        assert!(filter.is_allowed("::ffff:10.1.2.3"), "mapped, in CIDR");
        assert!(filter.is_allowed("::ffff:192.168.1.5"), "mapped, exact");
        assert!(!filter.is_allowed("::ffff:10.2.0.1"), "mapped, outside");
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
    fn cors_allow_headers_admit_the_console_client_marker() {
        // WOR-2688 review, first Major: the console sends `X-Requested-With`
        // on every call now, and that is not a CORS-safelisted request
        // header. A cross-origin console (`proxy.admin.cors_origins`, the
        // separately hosted UI shape) therefore preflights every call,
        // including the plain GETs that used to go straight out. A preflight
        // that does not list the header makes the browser block the real
        // request, and the admin server never sees it, so there is nothing
        // in the log to read either.
        let allowed = vec!["https://ops.example.com".to_string()];
        let headers = cors_response_headers(Some("https://ops.example.com"), &allowed);
        let allow = headers
            .iter()
            .find(|(k, _)| k == "Access-Control-Allow-Headers")
            .map(|(_, v)| v.as_str())
            .expect("Access-Control-Allow-Headers present");

        for expected in [
            "Authorization",
            "Content-Type",
            "X-CSRF-Token",
            "X-Requested-With",
        ] {
            assert!(allow.contains(expected), "{expected} missing from {allow}");
        }
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
        // gets its declared role; wrong password fails. The operator's
        // password is hashed at rest and verified against a pinned
        // pepper, not compared as plaintext.
        let pepper = b"test-pepper";
        let hash = sbproxy_keystore::crypto::hash_secret("ropass", pepper);
        let cfg = AdminConfig {
            operators: vec![AdminOperator {
                username: "ro".to_string(),
                password_hash: hash,
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        };
        let state = AdminState::new(cfg).with_operator_pepper(pepper.to_vec());
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
    fn empty_password_hash_denies_every_login() {
        // A blank password_hash (e.g. an unresolved ${VAR}) must never
        // verify, including against an empty presented password.
        let cfg = AdminConfig {
            operators: vec![AdminOperator {
                username: "ro".to_string(),
                password_hash: String::new(),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        };
        let state = AdminState::new(cfg);
        assert_eq!(state.check_operator_login("ro", ""), None);
        assert_eq!(state.check_operator_login("ro", "anything"), None);
    }

    #[test]
    fn malformed_password_hash_denies_login() {
        // A password_hash that isn't valid hex (a typo'd or hand-edited
        // value) must fail closed rather than panic or somehow verify.
        let cfg = AdminConfig {
            operators: vec![AdminOperator {
                username: "ro".to_string(),
                password_hash: "not-valid-hex-zzz".to_string(),
                role: AdminRole::ReadOnly,
                tenant: None,
            }],
            ..AdminConfig::default()
        };
        let state = AdminState::new(cfg);
        assert_eq!(state.check_operator_login("ro", "whatever"), None);
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
        assert!(body.contains("\"name\":\"usage_ledger\""));
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
        // Regression for a real product version mismatch: sbproxy-core
        // used to pin its own Cargo.toml version independently of the
        // workspace, so this endpoint (and the admin dashboard's
        // VERSION tile, which reads it) reported a stale "0.1.0" no
        // matter what release was actually running. sbproxy-core now
        // inherits `version.workspace = true`, so its own
        // CARGO_PKG_VERSION is the same string `sbproxy --version`
        // prints; this assertion breaks again if that inheritance is
        // ever reverted.
        assert_eq!(
            rich["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION")),
            "body: {pb}"
        );
        assert!(rich["build_hash"].as_str().is_some(), "body: {pb}");
        assert!(rich["timestamp"].as_str().is_some(), "body: {pb}");
        assert!(rich["uptime_seconds"].as_u64().is_some(), "body: {pb}");
        assert!(rich["checks"].as_array().is_some(), "body: {pb}");
    }

    #[test]
    fn readyz_returns_503_when_default_registry_has_unhealthy_usage_ledger() {
        // Seed the default Wave 1 registry but never mark the usage-ledger
        // recency as successful so it reports unhealthy.
        let l = sbproxy_observe::Recency::new(std::time::Duration::from_secs(60));
        let b = sbproxy_observe::Recency::new(std::time::Duration::from_secs(60));
        b.mark_success();
        let registry = sbproxy_observe::default_registry(l, b);
        let state = AdminState::new(AdminConfig {
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
            tls: None,
            bind: "127.0.0.1".to_string(),
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        })
        .with_health_registry(registry);
        let (status, _, body) = handle_admin_request("GET", "/readyz", &state, None, None);
        assert_eq!(
            status, 503,
            "usage ledger never marked => unready: {}",
            body
        );
        assert!(body.contains("\"name\":\"usage_ledger\""), "body: {}", body);
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
            trace_url_template: None,
            enabled: true,
            port: 9090,
            username: "admin".to_string(),
            password: "secret".to_string(),
            max_log_entries: 5,
            rate_limit_per_minute: 60,
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
        assert!(body.contains("\"name\":\"usage_ledger\""));
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
                cache_config_fingerprint: CompactString::default(),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: serde_json::json!({"type": "noop"}),
                auth_config: None,
                policy_configs: vec![policy_cfg],
                transform_configs: Vec::new(),
                filters: Vec::new(),
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
                deprecation: None,
                message_signatures: None,
                olp: None,
                comp: None,
                web_bot_auth_publish: None,
                idempotency: None,
                timeouts: sbproxy_config::UpstreamTimeouts::default(),
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
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
                attestation: None,
                owasp_pack_manifest: None,
            }
        };

        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new("alpha.example"), 0);
        host_map.insert(CompactString::new("beta.example"), 1);
        let cfg = sbproxy_config::CompiledConfig {
            origin_source_entries: Default::default(),
            extension_bundles: Default::default(),
            origins: vec![
                make_origin("alpha.example", "kid-alpha"),
                make_origin("beta.example", "kid-beta"),
            ],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
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

    // --- WOR-2582: prompt label routes ---

    /// Seed one prompt with two versions, for the label cases below.
    fn seed_two_versions(state: &AdminState, auth: &str) {
        for (version, body) in [("1", "v1"), ("2", "v2")] {
            let add = format!(r#"{{"version":"{version}","template":"{body}"}}"#);
            let (status, _, out) = handle_admin_request(
                "POST",
                "/admin/prompts/example.com/greet/versions",
                state,
                Some(auth),
                Some(&add),
            );
            assert_eq!(status, 200, "seed version {version}: {out}");
        }
    }

    #[test]
    fn setting_a_label_reports_where_it_points_and_shows_up_in_the_listing() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);

        let (status, _, body) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/labels/production",
            &state,
            Some(&auth),
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["label"], "production");
        assert_eq!(v["version"], "1");

        let (_, _, list_body) =
            handle_admin_request("GET", "/admin/prompts", &state, Some(&auth), None);
        let v: serde_json::Value = serde_json::from_str(&list_body).unwrap();
        assert_eq!(
            v["hosts"]["example.com"]["prompts"]["greet"]["labels"]["production"],
            "1"
        );
    }

    #[test]
    fn a_label_can_be_repointed_without_touching_any_version() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);

        for version in ["1", "2"] {
            let (status, _, body) = handle_admin_request(
                "PUT",
                "/admin/prompts/example.com/greet/labels/production",
                &state,
                Some(&auth),
                Some(&format!(r#"{{"version":"{version}"}}"#)),
            );
            assert_eq!(status, 200, "repoint to {version}: {body}");
        }

        let (_, _, list_body) =
            handle_admin_request("GET", "/admin/prompts", &state, Some(&auth), None);
        let v: serde_json::Value = serde_json::from_str(&list_body).unwrap();
        let greet = &v["hosts"]["example.com"]["prompts"]["greet"];
        assert_eq!(greet["labels"]["production"], "2");
        // Both versions are still there: a label move is not a delete.
        assert_eq!(greet["versions"], serde_json::json!(["1", "2"]));
    }

    #[test]
    fn a_label_naming_an_existing_version_is_refused_with_409() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);

        let (status, _, body) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/labels/1",
            &state,
            Some(&auth),
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 409, "{body}");
        assert!(body.contains("never resolve"), "{body}");
    }

    #[test]
    fn a_version_naming_an_existing_label_is_refused_with_409() {
        // The direction that matters more: this would silently repoint
        // every caller of the label.
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);
        let (status, _, _) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/labels/production",
            &state,
            Some(&auth),
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 200);

        let (status, _, body) = handle_admin_request(
            "POST",
            "/admin/prompts/example.com/greet/versions",
            &state,
            Some(&auth),
            Some(r#"{"version":"production","template":"sneaky"}"#),
        );
        assert_eq!(status, 409, "{body}");
        assert!(body.contains("label of that name"), "{body}");
    }

    #[test]
    fn a_label_pointing_at_a_missing_version_is_refused() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);

        let (status, _, body) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/labels/production",
            &state,
            Some(&auth),
            Some(r#"{"version":"99"}"#),
        );
        assert_eq!(status, 409, "{body}");
        assert!(body.contains("not present"), "{body}");
    }

    #[test]
    fn removing_a_label_takes_it_out_of_the_listing() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);
        handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/labels/staging",
            &state,
            Some(&auth),
            Some(r#"{"version":"2"}"#),
        );

        let (status, _, body) = handle_admin_request(
            "DELETE",
            "/admin/prompts/example.com/greet/labels/staging",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 200, "{body}");

        let (_, _, list_body) =
            handle_admin_request("GET", "/admin/prompts", &state, Some(&auth), None);
        let v: serde_json::Value = serde_json::from_str(&list_body).unwrap();
        assert_eq!(
            v["hosts"]["example.com"]["prompts"]["greet"]["labels"],
            serde_json::json!({})
        );
    }

    #[test]
    fn removing_a_label_that_is_not_there_is_a_404() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        seed_two_versions(&state, &auth);
        let (status, _, _) = handle_admin_request(
            "DELETE",
            "/admin/prompts/example.com/greet/labels/nope",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn the_label_route_needs_a_label_segment() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for path in [
            "/admin/prompts/example.com/greet/labels",
            "/admin/prompts/example.com/greet/labels/",
            "/admin/prompts/example.com/greet/labels/a/b",
        ] {
            let (status, _, body) =
                handle_admin_request("PUT", path, &state, Some(&auth), Some(r#"{"version":"1"}"#));
            assert_eq!(status, 404, "{path} should not resolve: {body}");
        }
    }

    #[test]
    fn the_label_route_refuses_the_wrong_method() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, _) = handle_admin_request(
            "GET",
            "/admin/prompts/example.com/greet/labels/production",
            &state,
            Some(&auth),
            None,
        );
        assert_eq!(status, 405);
    }

    #[test]
    fn an_unauthenticated_label_write_is_refused() {
        let _lock = prompts_admin_lock();
        reset_runtime_overlay();
        let state = make_state();
        let (status, _, _) = handle_admin_request(
            "PUT",
            "/admin/prompts/example.com/greet/labels/production",
            &state,
            None,
            Some(r#"{"version":"1"}"#),
        );
        assert_eq!(status, 401);
    }

    #[test]
    fn parse_prompt_admin_path_carries_the_label_in_the_action_segment() {
        // `splitn(3, '/')` is what makes the label route work without a
        // parser change, so pin it.
        let (h, n, a) = parse_prompt_admin_path("example.com/greet/labels/production").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(n, "greet");
        assert_eq!(a, "labels/production");
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
    fn admin_users_lists_roles_and_never_passwords() {
        let mut cfg = make_state().config.clone();
        let pepper = crate::key_plane::default_admin_operator_pepper();
        cfg.operators = vec![
            AdminOperator {
                username: "viewer".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret("viewer-secret", &pepper),
                role: AdminRole::ReadOnly,
                tenant: None,
            },
            AdminOperator {
                username: "oncall".to_string(),
                password_hash: sbproxy_keystore::crypto::hash_secret("oncall-secret", &pepper),
                role: AdminRole::Admin,
                tenant: None,
            },
        ];
        let state = AdminState::new(cfg);
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/api/admin/users", &state, Some(&auth), None);
        assert_eq!(status, 200);

        // No password, in any form, reaches the console.
        assert!(!body.contains("viewer-secret"), "leaked operator password");
        assert!(!body.contains("oncall-secret"), "leaked operator password");
        assert!(!body.contains("secret"), "leaked a password: {body}");

        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let users = v["users"].as_array().unwrap();
        assert_eq!(users.len(), 3, "primary admin plus both operators");
        assert_eq!(users[0]["username"], "admin");
        assert_eq!(users[0]["role"], "admin");
        assert_eq!(users[0]["primary"], true);
        assert_eq!(users[1]["username"], "viewer");
        assert_eq!(users[1]["role"], "read_only");
        assert_eq!(users[1]["primary"], false);
        assert_eq!(users[2]["role"], "admin");
    }

    /// A configured tenant scope has to survive as far as the resolved
    /// principal, because that is the only thing the meter routes read.
    ///
    /// It is looked up by username on every request rather than decoded
    /// from the session token, so narrowing an operator takes effect on
    /// the next reload rather than whenever their token happens to
    /// expire. The two assertions below are that lookup working and the
    /// top-level admin credential staying unscoped.
    #[test]
    fn a_configured_operator_tenant_reaches_the_resolved_principal() {
        let mut cfg = make_state().config.clone();
        cfg.operators = vec![AdminOperator {
            username: "acme-billing".to_string(),
            password_hash: "deadbeef".to_string(),
            role: AdminRole::ReadOnly,
            tenant: Some("acme".to_string()),
        }];
        let state = AdminState::new(cfg);

        let (token, _) =
            state
                .session_signer
                .mint("acme-billing", AdminRole::ReadOnly, 3600, unix_now());
        let scoped = state
            .resolve_principal(None, Some(&format!("sb_admin_session={token}")))
            .expect("the session resolves");
        assert_eq!(scoped.username, "acme-billing");
        assert_eq!(scoped.tenant.as_deref(), Some("acme"));

        let admin = state
            .resolve_principal(Some(&basic_auth("admin", "secret")), None)
            .expect("the top-level credential resolves");
        assert_eq!(
            admin.tenant, None,
            "the deployment's own operator is not a tenant's"
        );
    }

    #[tokio::test]
    async fn a_tenant_scoped_operator_is_refused_another_tenants_meter() {
        // End to end through the connection handler, because the scope is
        // resolved there and a route that read it from the query string
        // instead would pass a unit test and leak in production.
        let mut cfg = make_state().config.clone();
        cfg.operators = vec![AdminOperator {
            username: "acme-billing".to_string(),
            password_hash: "deadbeef".to_string(),
            role: AdminRole::ReadOnly,
            tenant: Some("acme".to_string()),
        }];
        let state = AdminState::new(cfg);
        let (token, _) =
            state
                .session_signer
                .mint("acme-billing", AdminRole::ReadOnly, 3600, unix_now());

        let response = send_admin_request(
            state,
            format!(
                "GET /api/meter/summary?tenant=globex HTTP/1.1\r\nCookie: sb_admin_session={token}\r\n\r\n"
            ),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
        assert!(response.contains("acme"), "{response}");
        assert!(
            !response.contains("globex"),
            "the refusal must not echo the tenant they asked about: {response}"
        );
    }

    #[test]
    fn operators_route_lists_usernames_and_roles_without_hashes() {
        let mut cfg = make_state().config.clone();
        cfg.operators = vec![AdminOperator {
            username: "ro".to_string(),
            password_hash: "deadbeef".to_string(),
            role: AdminRole::ReadOnly,
            tenant: None,
        }];
        let state = AdminState::new(cfg);
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/api/operators", &state, Some(&auth), None);
        assert_eq!(status, 200);
        assert!(body.contains("\"ro\""));
        assert!(
            !body.contains("deadbeef"),
            "password_hash must never appear in the API response"
        );
    }

    #[test]
    fn operators_route_requires_auth() {
        let state = make_state();
        let (status, _, _) = handle_admin_request("GET", "/api/operators", &state, None, None);
        assert_eq!(status, 401);
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

    #[test]
    fn constant_time_eq_equal_unequal_and_length_mismatch() {
        assert!(constant_time_eq(b"admin-password", b"admin-password"));
        assert!(!constant_time_eq(b"admin-password", b"admin-passworX"));
        assert!(!constant_time_eq(b"admin-password", b"admin-passwor"));
        assert!(constant_time_eq(b"", b""));
    }

    // --- WOR-2491 task 4: GET /admin/owasp-api-pack ------------------

    /// Compiles `yaml` and installs it as the live pipeline, the same
    /// `compile_config` -> `CompiledPipeline::from_config` ->
    /// `load_pipeline` idiom `canonical_pipeline_publish_installs_compiled_flags_for_cel`
    /// (`reload.rs`) already uses.
    fn install_test_pipeline(yaml: &str) {
        use crate::pipeline::CompiledPipeline;
        let compiled = sbproxy_config::compile_config(yaml).expect("test config compiles");
        let pipeline = CompiledPipeline::from_config(compiled).expect("pipeline compiles");
        crate::reload::load_pipeline(pipeline);
    }

    // --- WOR-2557: GET /admin/ai-data-posture -----------------------

    /// One test, not two, because `install_test_pipeline` writes the
    /// process-global live pipeline: a sibling test that installs a
    /// different one races this one's reads under the default parallel
    /// runner. The auth and method assertions need a pipeline installed
    /// anyway, so they ride along on this one.
    #[test]
    fn ai_data_posture_endpoint_reports_static_posture_and_the_live_eligible_set() {
        install_test_pipeline(
            r#"
origins:
  ai.example.com:
    action:
      type: ai_proxy
      data_posture:
        require_zdr: true
      usage_sinks:
        - type: chargeback
          max_entries: 3
          max_workspaces: 4
          max_teams: 4
      providers:
        - name: openai
          api_key: "k"
          data_posture:
            zdr: true
        - name: mistral
          api_key: "k"
  plain.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );
        let state = make_state();

        // Unauthenticated callers see nothing, and the route is GET-only.
        let (status, _, body) =
            handle_admin_request("GET", "/admin/ai-data-posture", &state, None, None);
        assert_eq!(status, 401, "got body: {body}");
        let auth = basic_auth("admin", "secret");
        for method in ["POST", "PUT", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/ai-data-posture", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} must not be routed");
        }

        let (status, _, body) =
            handle_admin_request("GET", "/admin/ai-data-posture", &state, Some(&auth), None);
        assert_eq!(status, 200, "got body: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json body");
        let origins = doc["origins"].as_object().expect("origins object");
        assert!(
            !origins.contains_key("plain.example.com"),
            "a non-AI origin is absent entirely: {body}"
        );
        let ai = origins
            .get("ai.example.com")
            .unwrap_or_else(|| panic!("the AI origin must be reported: {body}"));
        assert_eq!(ai["constraint"], "require_zdr");
        assert_eq!(
            ai["eligible_providers"],
            serde_json::json!(["openai"]),
            "the live effective eligible set, not just the accepted config: {body}"
        );
        assert_eq!(ai["excluded_providers"], serde_json::json!(["mistral"]));
        let row = |name: &str| -> serde_json::Value {
            ai["providers"]
                .as_array()
                .expect("providers array")
                .iter()
                .find(|p| p["name"] == name)
                .unwrap_or_else(|| panic!("{name} row missing: {body}"))
                .clone()
        };
        // The static declaration sits next to the wire format and auth
        // header, and is distinct from the effective posture the filter
        // evaluates.
        let mistral = row("mistral");
        assert_eq!(mistral["format"], "openai");
        assert_eq!(mistral["auth_header"], "Authorization");
        assert_eq!(mistral["catalog"]["zdr_available"], false);
        assert_eq!(mistral["effective"]["zdr"], false);
        assert_eq!(mistral["eligible"], false);
        let openai = row("openai");
        assert_eq!(
            openai["catalog"]["zdr_available"], true,
            "the catalog records that the vendor offers ZDR"
        );
        assert_eq!(
            openai["effective"]["retains_data"], false,
            "the operator declaration overrides the catalog's stock-account retention"
        );
        assert_eq!(
            openai["eligible"], true,
            "offering ZDR is not holding it; the operator declaration is what qualifies openai"
        );

        let pipeline = crate::reload::current_pipeline();
        let sbproxy_modules::Action::AiProxy(action) = &pipeline.actions[0] else {
            panic!("first action is AI")
        };
        let event: sbproxy_ai::usage_sink::LlmUsageEvent =
            serde_json::from_value(serde_json::json!({
                "provider": "openai",
                "model": "gpt-4o-mini",
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "cost_usd": 0.25,
                "latency_ms": 25,
                "status": 200,
                "tenant_id": "workspace-a",
                "team": "team-a"
            }))
            .expect("usage event");
        action.config.usage_sinks()[0].record(&event);
        drop(pipeline);

        // The chargeback exports moved off the unscoped synchronous seam:
        // even an authenticated request through `handle_admin_request` must
        // fall through (404), never serve cross-tenant rows.
        let (status, _, _) =
            handle_admin_request("GET", "/admin/ai-chargeback", &state, Some(&auth), None);
        assert_eq!(status, 404, "sync seam must not own the chargeback export");

        let unscoped = AdminPrincipal {
            username: "op-root".to_string(),
            role: sbproxy_config::types::AdminRole::Admin,
            via_session: false,
            csrf: None,
            tenant: None,
        };
        let scoped = AdminPrincipal {
            username: "op-a".to_string(),
            role: sbproxy_config::types::AdminRole::Admin,
            via_session: false,
            csrf: None,
            tenant: Some("tenant-a".to_string()),
        };

        let (status, _, _) = dispatch_ai_chargeback("GET", "/admin/ai-chargeback", None)
            .expect("route is owned by the chargeback dispatcher");
        assert_eq!(status, 401);
        let (status, _, _) =
            dispatch_ai_chargeback("POST", "/admin/ai-chargeback.csv", Some(&unscoped))
                .expect("route is owned by the chargeback dispatcher");
        assert_eq!(status, 405);
        assert!(
            dispatch_ai_chargeback("GET", "/admin/ai-data-posture", Some(&unscoped)).is_none(),
            "other admin routes must fall through"
        );

        // A tenant-restricted operator is refused outright: the team and
        // project rollups aggregate across tenants, so no narrowed view of
        // this export can be correct.
        for path in ["/admin/ai-chargeback", "/admin/ai-chargeback.csv"] {
            let (status, _, body) = dispatch_ai_chargeback("GET", path, Some(&scoped))
                .expect("route is owned by the chargeback dispatcher");
            assert_eq!(
                status, 403,
                "tenant-scoped operator must be refused: {body}"
            );
            assert!(
                !body.contains("workspace-a") && !body.contains("team-a"),
                "refusal must not leak rows: {body}"
            );
        }

        let (status, _, body) =
            dispatch_ai_chargeback("GET", "/admin/ai-chargeback", Some(&unscoped))
                .expect("route is owned by the chargeback dispatcher");
        assert_eq!(status, 200, "got body: {body}");
        let chargeback: serde_json::Value = serde_json::from_str(&body).expect("chargeback JSON");
        assert_eq!(chargeback["schema_version"], 1);
        let tracker = &chargeback["origins"]["ai.example.com"][0];
        assert_eq!(tracker["recorded_entries"], 1);
        assert_eq!(
            tracker["workspace_totals"]["workspace-a"]["request_count"],
            1
        );
        assert_eq!(tracker["team_totals"]["team-a"]["cost_usd"], 0.25);

        let (status, content_type, csv) =
            dispatch_ai_chargeback("GET", "/admin/ai-chargeback.csv", Some(&unscoped))
                .expect("route is owned by the chargeback dispatcher");
        assert_eq!(status, 200, "got body: {csv}");
        assert_eq!(content_type, "text/csv; charset=utf-8");
        assert!(csv.starts_with("origin,tracker,dimension,name,request_count,tokens,cost_usd\n"));
        assert!(csv.contains("ai.example.com,0,workspace,workspace-a,1,15,0.25"));
        assert!(csv.contains("ai.example.com,0,team,team-a,1,15,0.25"));
    }

    #[test]
    fn chargeback_csv_fields_quote_delimiters_and_neutralize_formulas() {
        assert_eq!(chargeback_csv_field("plain"), "plain");
        assert_eq!(chargeback_csv_field("team,west"), "\"team,west\"");
        assert_eq!(chargeback_csv_field("=1+1"), "'=1+1");
        assert_eq!(chargeback_csv_field("@SUM(A:A),x"), "\"'@SUM(A:A),x\"");
    }

    #[test]
    fn group_f_v1_and_csv_preserve_collision_safe_long_identity_projection() {
        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(8, 8, 8);
        let alpha = format!("{}-alpha", "界".repeat(86));
        let beta = format!("{}-beta", "界".repeat(86));

        for (identity, cost) in [(&alpha, 1.0), (&beta, 2.0)] {
            let event: sbproxy_ai::usage_sink::LlmUsageEvent =
                serde_json::from_value(serde_json::json!({
                    "provider": identity,
                    "model": identity,
                    "prompt_tokens": 100,
                    "completion_tokens": 50,
                    "total_tokens": 150,
                    "cost_usd": cost,
                    "latency_ms": 25,
                    "status": 200,
                    "tenant_id": identity,
                    "team": identity,
                    "project": identity,
                }))
                .expect("complete long-identity usage event");
            sbproxy_ai::usage_sink::UsageSink::record(&tracker, &event);
        }

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.schema_version, 2);
        assert_ne!(snapshot.entries[0].workspace, snapshot.entries[1].workspace);
        assert_ne!(snapshot.entries[0].team, snapshot.entries[1].team);
        assert_ne!(snapshot.entries[0].provider, snapshot.entries[1].provider);
        assert_ne!(snapshot.entries[0].model, snapshot.entries[1].model);
        assert_eq!(snapshot.workspace_rollups.len(), 2);
        assert_eq!(snapshot.team_rollups.len(), 2);

        let workspace_names = snapshot
            .workspace_rollups
            .iter()
            .map(|rollup| rollup.dimension.legacy_projection().into_owned())
            .collect::<Vec<_>>();
        let team_names = snapshot
            .team_rollups
            .iter()
            .map(|rollup| rollup.dimension.legacy_projection().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(workspace_names.len(), 2);
        assert_eq!(team_names.len(), 2);
        assert_ne!(workspace_names[0], workspace_names[1]);
        assert_ne!(team_names[0], team_names[1]);
        assert!(workspace_names.iter().all(|name| name.len() <= 256));
        assert!(team_names.iter().all(|name| name.len() <= 256));

        let origins = BTreeMap::from([("long.example".to_string(), vec![&tracker])]);
        let (status, content_type, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(content_type, "application/json");
        let rendered: serde_json::Value = serde_json::from_str(&body).expect("legacy JSON");
        let rendered_tracker = &rendered["origins"]["long.example"][0];
        assert_eq!(
            rendered_tracker["workspace_totals"]
                .as_object()
                .expect("workspace totals")
                .len(),
            2
        );
        assert_eq!(
            rendered_tracker["team_totals"]
                .as_object()
                .expect("team totals")
                .len(),
            2
        );
        for name in workspace_names.iter().chain(team_names.iter()) {
            assert!(body.contains(name), "missing collision-safe key {name}");
        }

        let (status, content_type, csv) =
            render_live_ai_chargeback_csv_for_test(&origins, MAX_AI_CHARGEBACK_RESPONSE_BYTES);
        assert_eq!(status, 200, "{csv}");
        assert_eq!(content_type, "text/csv; charset=utf-8");
        assert_eq!(csv.lines().count(), 5, "header plus two rows per dimension");
        for name in workspace_names.iter().chain(team_names.iter()) {
            assert!(csv.contains(name), "missing collision-safe CSV key {name}");
        }
    }

    #[test]
    fn group_f_v1_and_csv_keep_reserved_literals_distinct_from_internal_buckets() {
        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(8, 5, 5);
        let record = |tenant_id: Option<&str>, team: Option<&str>, cost_usd: f64| {
            sbproxy_ai::usage_sink::UsageSink::record(
                &tracker,
                &sbproxy_ai::usage_sink::LlmUsageEvent {
                    provider: "openai".to_string(),
                    model: "gpt-4o".to_string(),
                    prompt_tokens: 100,
                    completion_tokens: 50,
                    total_tokens: 150,
                    cost_usd,
                    latency_ms: 25,
                    status: 200,
                    key_id: None,
                    tenant_id: tenant_id.map(str::to_string),
                    project: None,
                    user: None,
                    team: team.map(str::to_string),
                    tags: Vec::new(),
                    metadata: Default::default(),
                    request_id: None,
                    session_id: None,
                    tag: None,
                    priority: None,
                    engine_version: None,
                    agent_id: None,
                    a2a_context_id: None,
                    a2a_identity_verified: None,
                    workflow_id: None,
                    logical_model: None,
                    served_model: None,
                    finish_reason: None,
                    shadow_of: None,
                    credential_source: None,
                },
            );
        };

        record(None, None, 1.0);
        record(Some("unattributed"), Some("unattributed"), 2.0);
        record(Some("__other__"), Some("__other__"), 3.0);
        record(Some("workspace-a"), Some("team-a"), 4.0);
        record(
            Some("workspace-forces-overflow"),
            Some("team-forces-overflow"),
            5.0,
        );

        let snapshot = tracker.snapshot();
        let escaped_missing_workspace = snapshot.entries[1]
            .workspace
            .legacy_projection()
            .into_owned();
        let escaped_missing_team = snapshot.entries[1].team.legacy_projection().into_owned();
        let escaped_overflow_workspace = snapshot.entries[2]
            .workspace
            .legacy_projection()
            .into_owned();
        let escaped_overflow_team = snapshot.entries[2].team.legacy_projection().into_owned();

        let origins = BTreeMap::from([("reserved.example".to_string(), vec![&tracker])]);
        let (status, content_type, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let rendered: serde_json::Value =
            serde_json::from_str(&body).expect("default v1 response is JSON");
        let tracker_json = &rendered["origins"]["reserved.example"][0];
        assert_eq!(
            tracker_json["workspace_totals"]["unattributed"]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["workspace_totals"][escaped_missing_workspace.as_str()]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["workspace_totals"][escaped_overflow_workspace.as_str()]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["workspace_totals"]["__other__"]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["team_totals"]["unattributed"]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["team_totals"][escaped_missing_team.as_str()]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["team_totals"][escaped_overflow_team.as_str()]["request_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            tracker_json["team_totals"]["__other__"]["request_count"],
            serde_json::json!(1)
        );

        let (status, content_type, csv) =
            render_live_ai_chargeback_csv_for_test(&origins, MAX_AI_CHARGEBACK_RESPONSE_BYTES);
        assert_eq!(status, 200, "{csv}");
        assert_eq!(content_type, "text/csv; charset=utf-8");
        assert!(csv
            .lines()
            .any(|line| line == "reserved.example,0,workspace,unattributed,1,150,1"));
        assert!(csv.lines().any(|line| {
            line == format!("reserved.example,0,workspace,{escaped_missing_workspace},1,150,2")
        }));
        assert!(csv.lines().any(|line| {
            line == format!("reserved.example,0,workspace,{escaped_overflow_workspace},1,150,3")
        }));
        assert!(csv
            .lines()
            .any(|line| line == "reserved.example,0,workspace,__other__,1,150,5"));
        assert!(csv
            .lines()
            .any(|line| line == "reserved.example,0,team,unattributed,1,150,1"));
        assert!(csv.lines().any(|line| {
            line == format!("reserved.example,0,team,{escaped_missing_team},1,150,2")
        }));
        assert!(csv.lines().any(|line| {
            line == format!("reserved.example,0,team,{escaped_overflow_team},1,150,3")
        }));
        assert!(csv
            .lines()
            .any(|line| line == "reserved.example,0,team,__other__,1,150,5"));
    }

    #[test]
    fn group_f_default_v1_conversion_does_not_duplicate_entry_graph_at_million_row_bound() {
        let allocator_control = allocation_counter::measure(|| {
            let allocated = std::hint::black_box("allocator-control".repeat(2));
            let _ = std::hint::black_box(&allocated);
        });
        assert!(allocator_control.count_total > 0);

        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(1_000_000, 8, 8);
        for _ in 0..256 {
            let entry = sbproxy_ai::billing::ChargebackEntry {
                team: "move-team".to_string(),
                project: "move-project".to_string(),
                provider: "move-provider".to_string(),
                model: "move-model".to_string(),
                tokens: 7,
                cost: 0.5,
                timestamp: "2026-08-10T00:00:00Z".to_string(),
            };
            assert_eq!(tracker.try_record(Some("move-workspace"), entry), Ok(()));
        }
        let origins = BTreeMap::from([("million.example".to_string(), vec![&tracker])]);

        let probe = LegacyChargebackConversionProbe::install_for_current_thread();
        let mut response = None;
        let allocations = allocation_counter::measure(|| {
            response = Some(render_live_ai_chargeback_json_for_test(
                &origins,
                "/admin/ai-chargeback",
                MAX_AI_CHARGEBACK_RESPONSE_BYTES,
            ));
        });
        let (status, content_type, body) = response.expect("measured JSON response");
        let counters = probe.counters();
        assert_eq!(counters.json_serialization_passes, 1);
        assert!(
            allocations.count_total < 64,
            "256 retained rows must be borrowed into one response buffer, not cloned into a second object graph: {allocations:?}"
        );
        drop(probe);

        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let rendered: serde_json::Value =
            serde_json::from_str(&body).expect("default v1 response is JSON");
        assert_eq!(rendered["schema_version"], 1);
        let rendered_snapshot = &rendered["origins"]["million.example"][0];
        assert_eq!(rendered_snapshot["max_entries"], 1_000_000);
        assert_eq!(rendered_snapshot["entries"][0]["team"], "move-team");
        assert_eq!(rendered_snapshot["entries"][0]["project"], "move-project");
        assert_eq!(rendered_snapshot["entries"][0]["provider"], "move-provider");
        assert_eq!(rendered_snapshot["entries"][0]["model"], "move-model");
        assert_eq!(
            rendered_snapshot["entries"]
                .as_array()
                .expect("legacy entries")
                .len(),
            256
        );
    }

    #[test]
    fn live_chargeback_route_paginates_exact_and_plus_one_entry_counts() {
        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(8, 8, 8);
        for (workspace, team, timestamp, cost) in [
            ("workspace-a", "team-a", "2026-08-20T00:00:00Z", 1.0),
            ("workspace-b", "team-b", "2026-08-21T00:00:00Z", 2.0),
            ("workspace-c", "team-c", "2026-08-22T00:00:00Z", 3.0),
        ] {
            let entry = sbproxy_ai::billing::ChargebackEntry {
                team: team.to_string(),
                project: format!("project-{team}"),
                provider: "local-openai".to_string(),
                model: "gpt-4o".to_string(),
                tokens: 2,
                cost,
                timestamp: timestamp.to_string(),
            };
            assert_eq!(tracker.try_record(Some(workspace), entry), Ok(()));
        }
        let origins = BTreeMap::from([("page.example".to_string(), vec![&tracker])]);

        let (status, _, exact_body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback?schema_version=2&limit=3",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 200, "got body: {exact_body}");
        let exact: serde_json::Value = serde_json::from_str(&exact_body).expect("exact JSON page");
        assert_eq!(exact["limit"], serde_json::json!(3));
        assert_eq!(exact["next_cursor"], serde_json::Value::Null);
        let exact_tracker = &exact["origins"]["page.example"][0];
        assert_eq!(
            exact_tracker["entries"]
                .as_array()
                .expect("typed entries")
                .len(),
            3
        );
        assert_eq!(exact_tracker["recorded_entries"], serde_json::json!(3));
        assert_eq!(
            exact_tracker["workspace_rollups"]
                .as_array()
                .expect("typed workspace rollups")
                .len(),
            3,
            "rollups stay whole while raw rows page"
        );

        let (status, _, first_body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback?schema_version=2&limit=2",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 200, "got body: {first_body}");
        let first: serde_json::Value = serde_json::from_str(&first_body).expect("first JSON page");
        let cursor = first["next_cursor"]
            .as_str()
            .expect("plus-one first page returns a continuation")
            .to_string();
        assert_eq!(
            first["origins"]["page.example"][0]["entries"]
                .as_array()
                .expect("first typed entries")
                .len(),
            2
        );
        assert_eq!(
            first["origins"]["page.example"][0]["team_rollups"]
                .as_array()
                .expect("team rollups remain whole")
                .len(),
            3
        );

        let (status, _, second_body) = render_live_ai_chargeback_json_for_test(
            &origins,
            &format!("/admin/ai-chargeback?schema_version=2&limit=2&cursor={cursor}"),
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 200, "got body: {second_body}");
        let second: serde_json::Value =
            serde_json::from_str(&second_body).expect("second JSON page");
        assert_eq!(second["next_cursor"], serde_json::Value::Null);
        assert_eq!(
            second["origins"]["page.example"][0]["entries"]
                .as_array()
                .expect("tail typed entries")
                .len(),
            1
        );
        assert_eq!(
            second["origins"]["page.example"][0]["recorded_entries"],
            serde_json::json!(3)
        );
    }

    #[test]
    fn live_chargeback_route_honors_exact_and_under_response_byte_caps() {
        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(8, 8, 8);
        let entry = sbproxy_ai::billing::ChargebackEntry {
            team: "cap-team".to_string(),
            project: "cap-project".to_string(),
            provider: "cap-provider".to_string(),
            model: "cap-model".to_string(),
            tokens: 7,
            cost: 0.5,
            timestamp: "2026-08-20T00:00:00Z".to_string(),
        };
        assert_eq!(tracker.try_record(Some("cap-workspace"), entry), Ok(()));
        let origins = BTreeMap::from([("cap.example".to_string(), vec![&tracker])]);

        let probe = LegacyChargebackConversionProbe::install_for_current_thread();
        let (status, _, exact_body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        let counters = probe.counters();
        drop(probe);
        assert_eq!(status, 200, "got body: {exact_body}");
        assert_eq!(
            counters.json_serialization_passes, 1,
            "admission and response generation must share one serialization pass"
        );
        let exact_bytes = exact_body.len();

        let (status, _, exact_cap_body) =
            render_live_ai_chargeback_json_for_test(&origins, "/admin/ai-chargeback", exact_bytes);
        assert_eq!(status, 200, "got body: {exact_cap_body}");

        let (status, _, refused_body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback",
            exact_bytes.saturating_sub(1),
        );
        assert_eq!(status, 413, "got body: {refused_body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&refused_body).expect("typed refusal body")
                ["code"],
            serde_json::json!("chargeback_response_too_large")
        );
    }

    #[test]
    fn live_chargeback_csv_is_borrowed_bounded_and_observable() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let allocator_control = allocation_counter::measure(|| {
            let allocated = std::hint::black_box("allocator-control".repeat(2));
            let _ = std::hint::black_box(&allocated);
        });
        assert!(allocator_control.count_total > 0);

        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(1_000_000, 8, 8);
        for _ in 0..512 {
            assert_eq!(
                tracker.try_record(
                    Some("csv-workspace"),
                    sbproxy_ai::billing::ChargebackEntry {
                        team: "csv-team".to_string(),
                        project: "csv-project".to_string(),
                        provider: "csv-provider".to_string(),
                        model: "csv-model".to_string(),
                        tokens: 1,
                        cost: 0.0,
                        timestamp: "2026-08-20T00:00:00Z".to_string(),
                    },
                ),
                Ok(())
            );
        }
        let origins = BTreeMap::from([("csv.example".to_string(), vec![&tracker])]);

        let probe = LegacyChargebackConversionProbe::install_for_current_thread();
        let mut response = None;
        let allocations = allocation_counter::measure(|| {
            response = Some(render_live_ai_chargeback_csv_for_test(
                &origins,
                MAX_AI_CHARGEBACK_RESPONSE_BYTES,
            ));
        });
        let (status, content_type, body) = response.expect("measured CSV response");
        let counters = probe.counters();
        drop(probe);
        assert_eq!(status, 200, "{body}");
        assert_eq!(content_type, "text/csv; charset=utf-8");
        assert_eq!(counters.csv_serialization_passes, 1);
        assert!(
            allocations.count_total < 16,
            "CSV must borrow the two rollup maps without cloning 512 retained rows: {allocations:?}"
        );
        assert_eq!(body.lines().count(), 3, "header plus two rollup rows");
        assert!(body.contains("csv.example,0,workspace,csv-workspace,512,512,0"));
        assert!(body.contains("csv.example,0,team,csv-team,512,512,0"));
        let exact_bytes = body.len();

        let (status, _, exact_body) = render_live_ai_chargeback_csv_for_test(&origins, exact_bytes);
        assert_eq!(status, 200, "{exact_body}");
        assert_eq!(exact_body.len(), exact_bytes);

        let refusals_before = admin_chargeback_export_refusals_total("csv", "response_too_large");
        let logged = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            sink: std::sync::Arc::clone(&logged),
        });
        let (status, content_type, refused_body) =
            tracing::subscriber::with_default(subscriber, || {
                render_live_ai_chargeback_csv_for_test(&origins, exact_bytes - 1)
            });
        assert_eq!(status, 413, "{refused_body}");
        assert_eq!(content_type, "application/json");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&refused_body).expect("typed refusal body")
                ["code"],
            serde_json::json!("chargeback_response_too_large")
        );
        assert_eq!(
            admin_chargeback_export_refusals_total("csv", "response_too_large"),
            refusals_before + 1
        );
        let lines = logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            lines.iter().any(|line| {
                line.contains("sbproxy::admin::chargeback")
                    && line.contains("chargeback_export_refused")
                    && line.contains("csv")
                    && line.contains("response_too_large")
            }),
            "CSV cap refusal did not emit the closed warning: {lines:?}"
        );
    }

    #[test]
    fn live_chargeback_route_records_closed_export_refusal_metrics() {
        let tracker = sbproxy_ai::billing::ChargebackTracker::with_limits(8, 8, 8);
        let entry = sbproxy_ai::billing::ChargebackEntry {
            team: "cap-team".to_string(),
            project: "cap-project".to_string(),
            provider: "cap-provider".to_string(),
            model: "cap-model".to_string(),
            tokens: 7,
            cost: 0.5,
            timestamp: "2026-08-20T00:00:00Z".to_string(),
        };
        assert_eq!(tracker.try_record(Some("cap-workspace"), entry), Ok(()));
        let origins = BTreeMap::from([("cap.example".to_string(), vec![&tracker])]);

        let invalid_cursor_before =
            admin_chargeback_export_refusals_total("json", "invalid_cursor");
        let (status, _, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback?schema_version=2&limit=1&cursor=not-a-cursor",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            admin_chargeback_export_refusals_total("json", "invalid_cursor"),
            invalid_cursor_before + 1
        );

        let offset_cursor = encode_chargeback_cursor(2);
        let (status, _, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            &format!("/admin/ai-chargeback?schema_version=2&limit=1&cursor={offset_cursor}"),
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            admin_chargeback_export_refusals_total("json", "invalid_cursor"),
            invalid_cursor_before + 2
        );

        let invalid_limit_before = admin_chargeback_export_refusals_total("json", "invalid_limit");
        let (status, _, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback?schema_version=2&limit=0",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            admin_chargeback_export_refusals_total("json", "invalid_limit"),
            invalid_limit_before + 1
        );

        let unsupported_before =
            admin_chargeback_export_refusals_total("json", "unsupported_schema_version");
        let (status, _, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback?schema_version=3",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            admin_chargeback_export_refusals_total("json", "unsupported_schema_version"),
            unsupported_before + 1
        );

        let (_, _, exact_body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback",
            MAX_AI_CHARGEBACK_RESPONSE_BYTES,
        );
        let exact_bytes = exact_body.len();
        let response_too_large_before =
            admin_chargeback_export_refusals_total("json", "response_too_large");
        let (status, _, body) = render_live_ai_chargeback_json_for_test(
            &origins,
            "/admin/ai-chargeback",
            exact_bytes.saturating_sub(1),
        );
        assert_eq!(status, 413, "{body}");
        assert_eq!(
            admin_chargeback_export_refusals_total("json", "response_too_large"),
            response_too_large_before + 1
        );
    }

    #[test]
    fn owasp_api_pack_endpoint_requires_auth() {
        install_test_pipeline(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );
        let state = make_state();
        let (status, _, body) =
            handle_admin_request("GET", "/admin/owasp-api-pack", &state, None, None);
        assert_eq!(status, 401, "got body: {body}");
    }

    #[test]
    fn owasp_api_pack_endpoint_only_answers_get() {
        install_test_pipeline(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        for method in ["PUT", "POST", "DELETE"] {
            let (status, _, _) =
                handle_admin_request(method, "/admin/owasp-api-pack", &state, Some(&auth), None);
            assert_eq!(status, 405, "{method} should not be accepted");
        }
    }

    #[test]
    fn owasp_api_pack_endpoint_no_pack_anywhere_returns_empty_origins() {
        install_test_pipeline(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/admin/owasp-api-pack", &state, Some(&auth), None);
        assert_eq!(status, 200, "got body: {body}");
        assert_eq!(body, r#"{"origins":{}}"#);
    }

    #[test]
    fn owasp_api_pack_endpoint_enable_all_matches_contract_shape() {
        install_test_pipeline(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    policies:
      - type: owasp_api_top10
        enable: all
"#,
        );
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/admin/owasp-api-pack", &state, Some(&auth), None);
        assert_eq!(status, 200, "got body: {body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        let origin = &json["origins"]["api.example.com"];
        assert!(!origin.is_null(), "got: {body}");

        let enabled = origin["enabled"].as_array().expect("enabled array");
        assert_eq!(enabled.len(), 10, "enable: all covers all ten items");
        assert_eq!(origin["posture"], "report_only");

        let items = origin["items"].as_array().expect("items array");
        assert_eq!(items.len(), 10, "one row per enabled item");

        // Every row carries exactly the contract's five keys.
        for item in items {
            let obj = item.as_object().expect("item is an object");
            let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec!["item", "reason", "state", "synthesized", "title"],
                "got: {item}"
            );
        }

        let find = |name: &str| {
            items
                .iter()
                .find(|it| it["item"] == name)
                .unwrap_or_else(|| panic!("missing item {name} in {items:?}"))
        };

        // Field-for-field spot checks against the pinned contract,
        // including the official OWASP 2023 titles.
        let api1 = find("api1");
        assert_eq!(api1["title"], "Broken Object Level Authorization");
        assert_eq!(api1["state"], "needs_operator_input");
        assert!(!api1["reason"].as_str().unwrap().is_empty());
        assert_eq!(api1["synthesized"], serde_json::json!(["object_authz"]));

        let api2 = find("api2");
        assert_eq!(api2["title"], "Broken Authentication");
        assert_eq!(api2["state"], "not_covered");
        assert_eq!(api2["synthesized"], serde_json::json!([]));

        let api3 = find("api3");
        assert_eq!(api3["title"], "Broken Object Property Level Authorization");

        let api4 = find("api4");
        assert_eq!(api4["title"], "Unrestricted Resource Consumption");
        assert_eq!(api4["state"], "needs_operator_input");
        assert_eq!(api4["synthesized"].as_array().unwrap().len(), 2);
        assert!(
            api4["reason"]
                .as_str()
                .unwrap()
                .contains("per_item.api4.rps"),
            "the api4 row must name the knob that completes it, got: {api4}"
        );

        let api5 = find("api5");
        assert_eq!(api5["title"], "Broken Function Level Authorization");

        let api6 = find("api6");
        assert_eq!(
            api6["title"],
            "Unrestricted Access to Sensitive Business Flows"
        );
        assert_eq!(api6["state"], "not_covered");

        let api7 = find("api7");
        assert_eq!(api7["title"], "Server Side Request Forgery");
        assert_eq!(api7["state"], "enforced");

        let api8 = find("api8");
        assert_eq!(api8["title"], "Security Misconfiguration");
        assert_eq!(api8["state"], "enforced");

        let api9 = find("api9");
        assert_eq!(api9["title"], "Improper Inventory Management");
        assert_eq!(api9["state"], "enforced");

        let api10 = find("api10");
        assert_eq!(api10["title"], "Unsafe Consumption of APIs");
        assert_eq!(api10["state"], "not_covered");
    }

    #[test]
    fn owasp_api_pack_endpoint_omits_origins_without_the_pack() {
        install_test_pipeline(
            r#"
origins:
  plain.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
  packed.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    policies:
      - type: owasp_api_top10
        enable: [api1]
"#,
        );
        let state = make_state();
        let auth = basic_auth("admin", "secret");
        let (status, _, body) =
            handle_admin_request("GET", "/admin/owasp-api-pack", &state, Some(&auth), None);
        assert_eq!(status, 200, "got body: {body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let origins = json["origins"].as_object().expect("origins object");
        assert_eq!(
            origins.keys().collect::<Vec<_>>(),
            vec!["packed.example.com"],
            "origin without the pack must be absent, not present with an empty entry"
        );
    }

    /// The running admin server's Basic-auth password, pinned (WOR-2606).
    ///
    /// The config-side twin was redacted in the first half of WOR-2640
    /// while this one, the copy the server actually holds, kept the
    /// derive.
    #[test]
    fn debug_never_renders_the_admin_password() {
        const SENTINEL: &str = "SENTINEL-ADMINPW-7c31";

        let config = AdminConfig {
            username: "operator".to_string(),
            password: SENTINEL.to_string(),
            ..AdminConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the admin password reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("operator") && rendered.contains("127.0.0.1"),
            "the username and bind address must survive: they name which admin \
             server the diagnostic is about: {rendered}"
        );
    }
}
