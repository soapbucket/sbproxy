//! MCP tool-level access control.
//!
//! `ToolAccessPolicy` is the principal-aware ACL guarding the MCP
//! `tools/call` dispatcher. It walks an ordered list of
//! `tool_access` rules and, for each rule whose principal selectors
//! match the inbound [`Principal`], decides whether the named tool is
//! permitted. A `tool_quotas` table sits beside the ACL and enforces
//! per-tool sliding-window quotas keyed on
//! `(tenant_id, principal_id, tool_name)`.
//!
//! ## WOR-1066: default-deny
//!
//! The legacy policy was open-by-default: an unknown caller or an
//! empty allowlist meant "allow every tool". This is a security trap;
//! a typo in the YAML silently disables the gate. WOR-1066 flips the
//! default. `default_allow` is `false` unless the operator opts in,
//! an empty `allowed: []` list means "deny all", and a request that
//! matches no rule is denied.
//!
//! ## WOR-1065: principal-aware selectors
//!
//! Selectors mirror the credentials-block selector shape at
//! `sbproxy_config::types::PrincipalSelector`. An operator writes the
//! same fields (`team`, `project`, `role`, `tenant_id`, glob over
//! `virtual_key`) in both places.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sbproxy_plugin::Principal;
use serde::{Deserialize, Serialize};

// --- Principal selector ---

/// Principal selector matching an inbound [`Principal`] to an ACL row.
///
/// Mirrors the credentials-block selector at
/// `sbproxy_config::types::PrincipalSelector` so an operator writes
/// the same shape in both places. An entry with every field unset
/// matches every principal.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct McpPrincipalSelector {
    /// Glob matching `Principal.virtual_key.name`. `vk_*` matches
    /// every virtual key with that prefix. Absent matches every key.
    #[serde(default)]
    pub virtual_key: Option<String>,
    /// Glob matching `Principal.sub`. Used when the inbound is not a
    /// virtual key (a bearer / api_key / basic auth caller).
    #[serde(default)]
    pub sub: Option<String>,
    /// Exact match on `Principal.attrs.team`.
    #[serde(default)]
    pub team: Option<String>,
    /// Exact match on `Principal.attrs.project`.
    #[serde(default)]
    pub project: Option<String>,
    /// Exact match on `Principal.attrs.user`.
    #[serde(default)]
    pub user: Option<String>,
    /// Match any of the principal's `attrs.roles`.
    #[serde(default)]
    pub role: Option<String>,
    /// Exact match on `Principal.tenant_id`.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl McpPrincipalSelector {
    /// True when this selector matches the given principal. An empty
    /// selector (every field unset) matches every principal. The
    /// virtual-key match is a simple glob on a trailing `*` only; we
    /// do not pull in a full glob crate for what is a one-line check.
    pub fn matches(&self, principal: &Principal) -> bool {
        if let Some(vk_pattern) = &self.virtual_key {
            let name = principal
                .virtual_key
                .as_ref()
                .map(|v| v.name.as_str())
                .unwrap_or("");
            if !glob_match(vk_pattern, name) {
                return false;
            }
        }
        if let Some(sub_pattern) = &self.sub {
            if !glob_match(sub_pattern, &principal.sub) {
                return false;
            }
        }
        if let Some(t) = &self.team {
            if principal.attrs.team.as_deref() != Some(t.as_str()) {
                return false;
            }
        }
        if let Some(p) = &self.project {
            if principal.attrs.project.as_deref() != Some(p.as_str()) {
                return false;
            }
        }
        if let Some(u) = &self.user {
            if principal.attrs.user.as_deref() != Some(u.as_str()) {
                return false;
            }
        }
        if let Some(r) = &self.role {
            if !principal.attrs.roles.iter().any(|role| role == r) {
                return false;
            }
        }
        if let Some(t) = &self.tenant_id {
            if principal.tenant_id.as_str() != t {
                return false;
            }
        }
        true
    }
}

/// Trailing-`*` glob: `vk_*` matches `vk_foo`; exact-match otherwise.
/// Mirrors the credential-resolver glob behaviour so an operator who
/// learned the pattern on the credentials block sees the same one
/// here.
fn glob_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

// --- ACL rules + policy ---

/// One row in the access-control list.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolAccessRule {
    /// Principal selectors. An empty list matches every principal
    /// (useful for a final catch-all rule that pins a default).
    #[serde(default)]
    pub principals: Vec<McpPrincipalSelector>,
    /// Tool names the matched principal can call. `*` matches every
    /// tool known to the MCP server. An empty list (`allowed: []`)
    /// is "deny all" per WOR-1066, NOT "allow all".
    #[serde(default)]
    pub allowed: Vec<String>,
}

/// Policy controlling which MCP tools each principal may invoke.
///
/// The policy walks `tool_access` in declaration order. The first
/// rule whose `principals` selector list matches the principal makes
/// the decision. A request that matches no rule falls through to
/// `default_allow` (see WOR-1066 in the module docs).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolAccessPolicy {
    /// WOR-1066: default-deny. When `false` (the default), an
    /// unknown caller is denied every tool. Operators who want the
    /// legacy open-by-default behaviour set this to `true`.
    #[serde(default)]
    pub default_allow: bool,
    /// Ordered list of access rules. First-match-wins.
    #[serde(default)]
    pub tool_access: Vec<ToolAccessRule>,
    /// Per-tool sliding-window quotas. Keyed on
    /// `(tenant_id, virtual_key_or_sub, tool_name)`.
    #[serde(default)]
    pub tool_quotas: Vec<ToolQuotaRule>,
}

/// Decision returned by [`ToolAccessPolicy::check`]. Kept as a typed
/// enum (not a bool) so call sites at `action_dispatch` cannot
/// accidentally invert the polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAccessDecision {
    /// The principal may invoke the named tool.
    Allow,
    /// The principal is denied. The caller should return a JSON-RPC
    /// error and the upstream must not be contacted.
    Deny,
}

impl ToolAccessPolicy {
    /// Create a new empty `ToolAccessPolicy`.
    ///
    /// The default value of `default_allow` is `false`, so the
    /// resulting policy denies every tool until rules are added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether the given principal may invoke the given tool.
    /// Walks `tool_access` in declaration order. The first rule
    /// whose `principals` selector list matches the principal makes
    /// the decision. No matching rule falls back to `default_allow`
    /// (WOR-1066).
    pub fn check(&self, principal: &Principal, tool: &str) -> ToolAccessDecision {
        for rule in &self.tool_access {
            // Empty principals list means "match every principal".
            // Operators use this to pin a final catch-all row.
            let matches_principal =
                rule.principals.is_empty() || rule.principals.iter().any(|s| s.matches(principal));
            if !matches_principal {
                continue;
            }
            if rule.allowed.iter().any(|t| t == "*" || t == tool) {
                return ToolAccessDecision::Allow;
            }
            // The first matching principal selector with an
            // `allowed` list that does not include the tool is a
            // deny. An empty `allowed: []` list is "deny all" per
            // WOR-1066.
            return ToolAccessDecision::Deny;
        }
        if self.default_allow {
            ToolAccessDecision::Allow
        } else {
            ToolAccessDecision::Deny
        }
    }

    /// Filter the given list of tool names down to the ones the
    /// principal can call. Used by the `tools/list` RBAC filter to
    /// keep denied tools off the catalogue advertised to the agent
    /// (the legacy schema leaked names through `tools/list` even
    /// when the gate would deny the matching `tools/call`).
    pub fn filter_tools<'a>(&self, principal: &Principal, tools: &'a [String]) -> Vec<&'a String> {
        tools
            .iter()
            .filter(|t| matches!(self.check(principal, t), ToolAccessDecision::Allow))
            .collect()
    }
}

// --- Sliding-window per-tool quota ---

/// Per-tool sliding-window quota rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolQuotaRule {
    /// Tool name the quota applies to. Matched verbatim against the
    /// `tools/call` `name` parameter.
    pub tool_name: String,
    /// Principal selectors. An empty list matches every principal.
    /// The same shape as on the ACL rules above.
    #[serde(default)]
    pub principals: Vec<McpPrincipalSelector>,
    /// Window + max-invocations pair.
    pub rate: ToolQuotaRate,
}

/// Sliding-window rate: at most `max` invocations per `per`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolQuotaRate {
    /// Window duration. Accepts `30s`, `15m`, `24h`, `7d`. Parsed
    /// with the small in-crate parser below; we do not pull in
    /// `humantime` for what is a five-line lookup.
    pub per: String,
    /// Maximum invocations per window.
    pub max: u64,
}

/// Composite key for the per-tool quota counter. Tenant-scoped so
/// tenant A's counters do not bleed into tenant B's even if both
/// happen to mint the same principal_id locally.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QuotaKey {
    /// Tenant identifier carried on `Principal::tenant_id`.
    pub tenant_id: String,
    /// Identifier for the principal. Prefers the virtual key name
    /// when present, otherwise the principal's `sub`. An empty
    /// string is the synthetic key used by anonymous traffic.
    pub principal_id: String,
    /// Tool name. Matched verbatim against the `tools/call` `name`
    /// parameter.
    pub tool_name: String,
}

/// Error returned when a quota check rejects a `tools/call`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("tool quota exceeded for {tool_name}")]
pub struct QuotaExceeded {
    /// Tool the caller tried to invoke.
    pub tool_name: String,
}

/// Abstract clock for the sliding-window counter. Default is
/// `Instant::now`; tests substitute a deterministic timeline.
pub trait QuotaClock: Send + Sync + 'static {
    /// Return the current instant.
    fn now(&self) -> Instant;
}

/// Default clock backed by `std::time::Instant`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl QuotaClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Process-wide sliding-window counter store.
///
/// One `VecDeque<Instant>` per `QuotaKey` records the timestamps of
/// every successful invocation. The window check drops expired
/// entries off the front of the deque before deciding. Lookup and
/// insert are both O(window_max) and the deque tops out at `rate.max`
/// entries, so the memory footprint is bounded by the policy.
pub struct ToolQuotaStore<C: QuotaClock = SystemClock> {
    counters: Mutex<HashMap<QuotaKey, std::collections::VecDeque<Instant>>>,
    clock: C,
}

impl ToolQuotaStore<SystemClock> {
    /// Construct an empty store backed by `SystemClock`.
    pub fn new() -> Self {
        Self::with_clock(SystemClock)
    }
}

impl Default for ToolQuotaStore<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: QuotaClock> ToolQuotaStore<C> {
    /// Construct an empty store backed by a caller-supplied clock.
    pub fn with_clock(clock: C) -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Check whether the principal is within quota for `tool` under
    /// `policy`. On allow, records the invocation against the
    /// sliding window. On deny, returns `QuotaExceeded` without
    /// recording.
    pub fn check_quota(
        &self,
        policy: &ToolAccessPolicy,
        principal: &Principal,
        tool: &str,
    ) -> Result<(), QuotaExceeded> {
        // Resolve the first matching quota rule. If none match, the
        // tool has no quota and the call passes.
        let rule = match policy.tool_quotas.iter().find(|q| {
            q.tool_name == tool
                && (q.principals.is_empty() || q.principals.iter().any(|s| s.matches(principal)))
        }) {
            Some(r) => r,
            None => return Ok(()),
        };

        let window = match parse_quota_window(&rule.rate.per) {
            Ok(d) => d,
            Err(_) => {
                // A malformed `per:` string was caught at config
                // load by `parse_quota_window`; reaching here means
                // someone bypassed compile. Fail open on the
                // counter (the ACL gate above still applies) so a
                // bad string never bricks the gateway.
                return Ok(());
            }
        };
        let now = self.clock.now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let key = QuotaKey {
            tenant_id: principal.tenant_id.as_str().to_string(),
            principal_id: principal_id_for(principal),
            tool_name: tool.to_string(),
        };

        let mut counters = self.counters.lock().expect("quota counter mutex poisoned");
        let deque = counters.entry(key).or_default();
        // Drop expired entries off the front. The deque is ordered
        // by insertion time, so a single front-pop loop is enough.
        while let Some(front) = deque.front() {
            if *front < cutoff {
                deque.pop_front();
            } else {
                break;
            }
        }
        if deque.len() as u64 >= rule.rate.max {
            return Err(QuotaExceeded {
                tool_name: tool.to_string(),
            });
        }
        deque.push_back(now);
        Ok(())
    }
}

/// Resolve the per-principal id used as the second part of a
/// [`QuotaKey`]. Prefers the matched virtual key name when present so
/// AI gateway traffic stays attributed to the key the operator
/// minted; falls back to `Principal::sub` for non-virtual-key
/// callers. Empty string is the synthetic key used by anonymous
/// traffic (the credentials epic introduces a typed
/// `Principal::anonymous` for that lane).
fn principal_id_for(principal: &Principal) -> String {
    if let Some(vk) = &principal.virtual_key {
        if !vk.name.is_empty() {
            return vk.name.clone();
        }
    }
    principal.sub.clone()
}

/// Parse a quota-window string. Accepts `30s`, `15m`, `24h`, `7d`.
/// Returns an error on empty input, an unsupported suffix, or a
/// non-numeric prefix.
pub fn parse_quota_window(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let split_at = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num_part, unit) = (&s[..split_at], &s[split_at..]);
    let value: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid duration number '{}': {}", num_part, e))?;
    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "s" | "" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value * 60)),
        "h" => Ok(Duration::from_secs(value * 60 * 60)),
        "d" => Ok(Duration::from_secs(value * 60 * 60 * 24)),
        other => Err(format!(
            "unsupported duration unit '{}' (use ms, s, m, h, d)",
            other
        )),
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_plugin::{PrincipalAttrs, PrincipalSource, TenantId, VirtualKeyRef};
    use std::sync::{Arc, Mutex as StdMutex};

    /// Build a principal with the requested attribution surface
    /// populated. Keeps the per-test setup small.
    fn principal(
        tenant: &str,
        sub: &str,
        team: Option<&str>,
        role: Option<&str>,
        vk_name: Option<&str>,
    ) -> Principal {
        Principal {
            tenant_id: TenantId::from(tenant),
            sub: sub.to_string(),
            source: PrincipalSource::Bearer,
            virtual_key: vk_name.map(|n| VirtualKeyRef {
                name: n.to_string(),
                allowed_providers: vec![],
            }),
            attrs: PrincipalAttrs {
                team: team.map(str::to_string),
                roles: role.map(|r| vec![r.to_string()]).unwrap_or_default(),
                ..PrincipalAttrs::default()
            },
        }
    }

    /// Default-deny: an empty policy with `default_allow = false`
    /// rejects every tool call.
    #[test]
    fn default_deny_unknown_caller_denied() {
        let policy = ToolAccessPolicy::new();
        let p = principal("acme", "user-1", None, None, None);
        assert_eq!(policy.check(&p, "any.tool"), ToolAccessDecision::Deny);
        assert_eq!(policy.check(&p, "search"), ToolAccessDecision::Deny);
    }

    /// A rule with `allowed: []` denies every tool, NOT "allow all".
    /// This is the explicit WOR-1066 inversion.
    #[test]
    fn default_deny_empty_allowed_means_deny_all() {
        let policy = ToolAccessPolicy {
            default_allow: false,
            tool_access: vec![ToolAccessRule {
                principals: vec![McpPrincipalSelector {
                    team: Some("frontend".to_string()),
                    ..Default::default()
                }],
                allowed: vec![],
            }],
            tool_quotas: vec![],
        };
        let p = principal("acme", "user-1", Some("frontend"), None, None);
        assert_eq!(policy.check(&p, "search"), ToolAccessDecision::Deny);
        assert_eq!(policy.check(&p, "anything"), ToolAccessDecision::Deny);
    }

    /// `default_allow: true` is the legacy open-by-default behaviour.
    /// A principal that matches no rule falls through to allow.
    #[test]
    fn default_allow_true_falls_through_to_allow() {
        let policy = ToolAccessPolicy {
            default_allow: true,
            tool_access: vec![],
            tool_quotas: vec![],
        };
        let p = principal("acme", "user-1", None, None, None);
        assert_eq!(policy.check(&p, "search"), ToolAccessDecision::Allow);
    }

    /// A selector with `team: frontend` matches a principal whose
    /// `attrs.team` is `frontend`, denies otherwise.
    #[test]
    fn principal_selector_matches_team_attr() {
        let policy = ToolAccessPolicy {
            default_allow: false,
            tool_access: vec![ToolAccessRule {
                principals: vec![McpPrincipalSelector {
                    team: Some("frontend".to_string()),
                    ..Default::default()
                }],
                allowed: vec!["search".to_string()],
            }],
            tool_quotas: vec![],
        };
        let allowed = principal("acme", "u", Some("frontend"), None, None);
        let denied = principal("acme", "u", Some("backend"), None, None);
        assert_eq!(policy.check(&allowed, "search"), ToolAccessDecision::Allow);
        assert_eq!(policy.check(&denied, "search"), ToolAccessDecision::Deny);
    }

    /// `vk_*` matches every virtual key with that prefix.
    #[test]
    fn principal_selector_matches_virtual_key_glob() {
        let policy = ToolAccessPolicy {
            default_allow: false,
            tool_access: vec![ToolAccessRule {
                principals: vec![McpPrincipalSelector {
                    virtual_key: Some("vk_frontend_*".to_string()),
                    ..Default::default()
                }],
                allowed: vec!["*".to_string()],
            }],
            tool_quotas: vec![],
        };
        let p1 = principal("acme", "", None, None, Some("vk_frontend_alpha"));
        let p2 = principal("acme", "", None, None, Some("vk_frontend_beta"));
        let p3 = principal("acme", "", None, None, Some("vk_backend_alpha"));
        assert_eq!(policy.check(&p1, "any.tool"), ToolAccessDecision::Allow);
        assert_eq!(policy.check(&p2, "any.tool"), ToolAccessDecision::Allow);
        assert_eq!(policy.check(&p3, "any.tool"), ToolAccessDecision::Deny);
    }

    /// An `admin` role gets a wildcard allow; everyone else falls
    /// through to default-deny.
    #[test]
    fn role_selector_grants_wildcard_to_admin() {
        let policy = ToolAccessPolicy {
            default_allow: false,
            tool_access: vec![ToolAccessRule {
                principals: vec![McpPrincipalSelector {
                    role: Some("admin".to_string()),
                    ..Default::default()
                }],
                allowed: vec!["*".to_string()],
            }],
            tool_quotas: vec![],
        };
        let admin = principal("acme", "u", None, Some("admin"), None);
        let user = principal("acme", "u", None, Some("viewer"), None);
        assert_eq!(
            policy.check(&admin, "delete_user"),
            ToolAccessDecision::Allow
        );
        assert_eq!(policy.check(&user, "delete_user"), ToolAccessDecision::Deny);
    }

    /// `tools/list` filter returns only the subset the principal is
    /// allowed to invoke. Used by the dispatcher to keep denied tool
    /// names out of the catalogue advertised to the agent.
    #[test]
    fn tools_list_filter_returns_only_allowed() {
        let policy = ToolAccessPolicy {
            default_allow: false,
            tool_access: vec![ToolAccessRule {
                principals: vec![McpPrincipalSelector {
                    team: Some("frontend".to_string()),
                    ..Default::default()
                }],
                allowed: vec!["search".to_string(), "list_projects".to_string()],
            }],
            tool_quotas: vec![],
        };
        let p = principal("acme", "u", Some("frontend"), None, None);
        let tools = vec![
            "search".to_string(),
            "list_projects".to_string(),
            "delete_user".to_string(),
        ];
        let filtered = policy.filter_tools(&p, &tools);
        let names: Vec<&str> = filtered.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, vec!["search", "list_projects"]);
    }

    // --- Quota tests ---

    /// A deterministic clock backed by an `Arc<StdMutex<Instant>>` so
    /// the test driver can advance time without depending on
    /// wall-clock sleeps.
    #[derive(Clone)]
    struct FakeClock(Arc<StdMutex<Instant>>);

    impl FakeClock {
        fn new(start: Instant) -> Self {
            Self(Arc::new(StdMutex::new(start)))
        }
        fn advance(&self, delta: Duration) {
            let mut g = self.0.lock().unwrap();
            *g += delta;
        }
    }

    impl QuotaClock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    fn quota_policy() -> ToolAccessPolicy {
        ToolAccessPolicy {
            default_allow: true,
            tool_access: vec![],
            tool_quotas: vec![ToolQuotaRule {
                tool_name: "delete_user".to_string(),
                principals: vec![],
                rate: ToolQuotaRate {
                    per: "1h".to_string(),
                    max: 3,
                },
            }],
        }
    }

    /// Firing the same tool past `max` within the window must
    /// rate-limit; the last call returns `QuotaExceeded`.
    #[test]
    fn tool_quota_blocks_after_max() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock(clock.clone());
        let policy = quota_policy();
        let p = principal("acme", "u", None, None, Some("vk_a"));

        assert!(store.check_quota(&policy, &p, "delete_user").is_ok());
        assert!(store.check_quota(&policy, &p, "delete_user").is_ok());
        assert!(store.check_quota(&policy, &p, "delete_user").is_ok());
        let err = store
            .check_quota(&policy, &p, "delete_user")
            .expect_err("4th call must rate-limit");
        assert_eq!(err.tool_name, "delete_user");
    }

    /// After the window elapses, the counter resets so the next call
    /// passes.
    #[test]
    fn tool_quota_resets_after_window() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock(clock.clone());
        let policy = quota_policy();
        let p = principal("acme", "u", None, None, Some("vk_a"));

        for _ in 0..3 {
            store.check_quota(&policy, &p, "delete_user").unwrap();
        }
        assert!(store.check_quota(&policy, &p, "delete_user").is_err());
        // Window is 1h; advance past it.
        clock.advance(Duration::from_secs(60 * 60 + 1));
        assert!(
            store.check_quota(&policy, &p, "delete_user").is_ok(),
            "window must reset",
        );
    }

    /// Tenant A maxing its quota does not block tenant B's identical
    /// call. The `QuotaKey` carries the tenant id, so the counters
    /// live in disjoint buckets.
    #[test]
    fn tool_quota_tenant_a_isolated_from_tenant_b() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock(clock.clone());
        let policy = quota_policy();
        let pa = principal("tenant-a", "u", None, None, Some("vk_x"));
        let pb = principal("tenant-b", "u", None, None, Some("vk_x"));

        for _ in 0..3 {
            store.check_quota(&policy, &pa, "delete_user").unwrap();
        }
        assert!(store.check_quota(&policy, &pa, "delete_user").is_err());
        // Tenant B is in a different bucket.
        assert!(
            store.check_quota(&policy, &pb, "delete_user").is_ok(),
            "tenant B must not be affected by tenant A's quota",
        );
    }

    /// Tools without a matching quota rule are unbounded.
    #[test]
    fn tool_without_quota_rule_is_unbounded() {
        let store = ToolQuotaStore::new();
        let policy = quota_policy();
        let p = principal("acme", "u", None, None, Some("vk_a"));
        // Fire 100 times against a tool with no quota rule.
        for _ in 0..100 {
            store.check_quota(&policy, &p, "search").unwrap();
        }
    }

    /// `parse_quota_window` accepts the documented suffixes.
    #[test]
    fn parse_quota_window_accepts_documented_suffixes() {
        assert_eq!(parse_quota_window("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_quota_window("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(
            parse_quota_window("24h").unwrap(),
            Duration::from_secs(60 * 60 * 24),
        );
        assert_eq!(
            parse_quota_window("7d").unwrap(),
            Duration::from_secs(60 * 60 * 24 * 7),
        );
        assert!(parse_quota_window("").is_err());
        assert!(parse_quota_window("5y").is_err());
        assert!(parse_quota_window("abc").is_err());
    }

    /// Full ACL YAML round-trips through serde without an explicit
    /// `default_allow:`; the default is `false` per WOR-1066.
    #[test]
    fn tool_access_policy_yaml_round_trips() {
        let yaml = r#"
default_allow: false
tool_access:
  - principals:
      - virtual_key: vk_frontend_*
        team: frontend
        tenant_id: acme
    allowed: [search_docs, list_projects]
  - principals:
      - role: admin
    allowed: ["*"]
tool_quotas:
  - tool_name: delete_user
    principals:
      - team: frontend
    rate:
      per: 24h
      max: 5
"#;
        let policy: ToolAccessPolicy = serde_yaml::from_str(yaml).expect("parse");
        assert!(!policy.default_allow);
        assert_eq!(policy.tool_access.len(), 2);
        assert_eq!(policy.tool_quotas.len(), 1);
        assert_eq!(policy.tool_quotas[0].tool_name, "delete_user");
        assert_eq!(policy.tool_quotas[0].rate.max, 5);
        assert_eq!(policy.tool_quotas[0].rate.per, "24h");
    }

    /// Omitting `default_allow:` parses as `false`. Locks the
    /// default-deny invariant against an accidental `default = true`
    /// regression on the struct.
    #[test]
    fn default_allow_default_is_false() {
        let yaml = "tool_access: []\n";
        let policy: ToolAccessPolicy = serde_yaml::from_str(yaml).expect("parse");
        assert!(!policy.default_allow);
    }
}
