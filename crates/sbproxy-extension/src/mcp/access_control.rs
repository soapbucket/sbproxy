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
            if !sbproxy_util::prefix_glob_match(vk_pattern, name) {
                return false;
            }
        }
        if let Some(sub_pattern) = &self.sub {
            if !sbproxy_util::prefix_glob_match(sub_pattern, &principal.sub) {
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

    /// Check that every `tool_quotas[].rate.per` in this policy parses.
    ///
    /// Nothing else validates the string. `ToolAccessPolicy` is plain
    /// serde with no `deny_unknown_fields` hook and no validate step,
    /// so before this existed an operator could write
    /// `per: "1hour"` and have `compile_config` and `sbproxy validate`
    /// both accept it. The window is then read for the first time on
    /// the request path, where the only choices left are bad ones.
    /// Call this wherever a policy is compiled.
    ///
    /// What it does not cover: the `mcp` action's `rbac_policies` are
    /// the only compile site that calls it today. The copy of this
    /// type at `agent_alignment.rbac_policy` is built by an infallible
    /// constructor and is left unchecked, which is sound only because
    /// that lane evaluates [`Self::check`] and never
    /// [`ToolQuotaStore::check_quota`], so its `tool_quotas` are inert
    /// either way. Wire this in there too if that lane ever grows
    /// quota enforcement.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending rule and the accepted
    /// suffixes, suitable for surfacing straight to the operator.
    pub fn validate_quota_windows(&self) -> Result<(), String> {
        for rule in &self.tool_quotas {
            parse_quota_window(&rule.rate.per).map_err(|error| {
                format!(
                    "tool_quotas rule for tool '{}' has an unparseable rate.per '{}' \
                     ({error}); accepted suffixes are ms, s, m, h, d \
                     (for example 30s, 15m, 24h, 7d)",
                    rule.tool_name, rule.rate.per
                )
            })?;
        }
        Ok(())
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

/// Ceiling on the number of distinct `QuotaKey`s this process holds
/// a sliding window for, across every tenant, tool, and principal.
///
/// `QuotaKey::principal_id` is caller-presented (a virtual key name or
/// a JWT `sub`), so the key count is driven by traffic rather than by
/// the policy: one quota rule with no `principals` selector matches
/// everyone, and every distinct `sub` that ever calls the tool once
/// would otherwise leave a permanent entry. The same reasoning and the
/// same order of magnitude as `peer_profile::MAX_TRACKED_PEERS`.
///
/// A window whose entries have all aged out is reclaimed by the sweep
/// long before this matters. The ceiling is the backstop for the case
/// the sweep cannot help with: more distinct principals genuinely
/// active inside their own windows than this process will track.
///
/// Acts as a backstop behind [`MAX_TRACKED_QUOTA_KEYS_PER_TENANT`]: a
/// single tenant cannot reach this ceiling on its own, so this bounds
/// the number of *distinct tenants* holding live windows at once, ten
/// at full sub-cap. That is a deployment-sizing fact, not a
/// per-tenant isolation guarantee; the sub-cap is what isolates one
/// tenant's flood from every other tenant's traffic.
const MAX_TRACKED_QUOTA_KEYS: usize = 100_000;

/// Ceiling on the number of distinct `QuotaKey`s one tenant may hold a
/// sliding window for in this process.
///
/// Without it the global ceiling alone is a cross-tenant denial of
/// service: `principal_id` is caller-presented, so one tenant able to
/// authenticate under many distinct `sub` values fills the whole map,
/// and from that moment every *other* tenant's next unseen principal
/// is refused `tools/call` fail-closed. The same gap, with the same
/// remedy, that `sessions::MAX_TRACKED_SESSIONS_PER_TENANT` and
/// `peer_profile::MAX_TRACKED_PEERS_PER_TENANT` already close for
/// their own registries. A tenant at its sub-cap is refused a new
/// window while every other tenant, and every one of this tenant's
/// own live windows, is unaffected.
const MAX_TRACKED_QUOTA_KEYS_PER_TENANT: usize = 10_000;

/// Shortest interval between two full sweeps of the counter map.
///
/// The sweep is O(keys) and only ever runs when the map is at a
/// ceiling, so without this a saturated store would walk every key on
/// every request. One second bounds that to a single walk per second
/// while still reclaiming aged-out windows fast enough that a ceiling
/// is reached only under genuine live cardinality.
const QUOTA_SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// One principal's sliding window for one tool.
struct QuotaCounter {
    /// The matched rule's window. Held per key so the sweep can decide
    /// whether an entry has aged out without re-resolving the policy
    /// that created it; different rules carry different windows and a
    /// sweep using the wrong one would evict live state.
    window: Duration,
    /// Invocation timestamps, oldest first.
    hits: std::collections::VecDeque<Instant>,
}

/// Process-wide sliding-window counter store.
///
/// One sliding window per [`QuotaKey`] records the timestamps of
/// every successful invocation. The window check drops expired
/// entries off the front of the deque before deciding. Lookup and
/// insert are both O(window_max).
///
/// # What is bounded, and by what
///
/// Each individual deque is bounded by the policy: it tops out at
/// `rate.max` entries because the check refuses the call at that
/// length rather than pushing. The *number of deques* is not bounded
/// by the policy, because the key carries a caller-presented principal
/// id. Three mechanisms bound it instead: a sweep drops keys whose
/// window has fully aged out, [`MAX_TRACKED_QUOTA_KEYS_PER_TENANT`]
/// caps what any one tenant may hold, and `MAX_TRACKED_QUOTA_KEYS`
/// (100_000) caps the whole map. A new key past either ceiling is
/// refused the call rather than waved through, on the same grounds as
/// `peer_profile`'s saturation handling: a limiter that cannot count
/// is not a limiter.
pub struct ToolQuotaStore<C: QuotaClock = SystemClock> {
    state: Mutex<QuotaState>,
    /// Ceiling on `state.counters.len()`. Always
    /// `MAX_TRACKED_QUOTA_KEYS` in production; a field rather than a
    /// direct read of the constant so a test can drive the saturation
    /// branch without allocating six figures of keys.
    max_tracked_keys: usize,
    /// Ceiling on one tenant's share of `state.counters`. Always
    /// `MAX_TRACKED_QUOTA_KEYS_PER_TENANT` in production, a field for
    /// the same test reason as `max_tracked_keys`.
    max_tracked_keys_per_tenant: usize,
    clock: C,
}

/// Everything the quota check mutates, under one lock so the sweep
/// timestamp and the per-tenant counts cannot drift from the map they
/// describe.
#[derive(Default)]
struct QuotaState {
    counters: HashMap<QuotaKey, QuotaCounter>,
    /// Live key count per `tenant_id`, so the per-tenant sub-cap is an
    /// O(1) read rather than a scan of six figures of keys on every
    /// first call by a principal. Maintained at exactly the two places
    /// `counters` changes size: incremented on insert below, rebuilt
    /// wholesale by [`Self::sweep`], which is the only remover.
    per_tenant: HashMap<String, usize>,
    /// Last time the whole map was walked, so the sweep is amortized
    /// rather than per-request. `None` until the first sweep.
    last_sweep: Option<Instant>,
}

impl QuotaState {
    /// Drop every key whose window has fully aged out and rebuild the
    /// per-tenant counts from what survived.
    ///
    /// Rebuilding rather than decrementing is deliberate: the counts
    /// are a cache of `counters`, and a cache that is recomputed from
    /// its source at the only point entries leave cannot drift from
    /// it. The walk is O(keys) either way, so the rebuild is free.
    fn sweep(&mut self, now: Instant) {
        self.counters.retain(|_, counter| {
            counter
                .hits
                .back()
                .is_some_and(|last| now.duration_since(*last) < counter.window)
        });
        self.per_tenant.clear();
        for key in self.counters.keys() {
            *self.per_tenant.entry(key.tenant_id.clone()).or_insert(0) += 1;
        }
        self.last_sweep = Some(now);
    }

    /// Live windows this tenant holds.
    fn tenant_live(&self, tenant_id: &str) -> usize {
        self.per_tenant.get(tenant_id).copied().unwrap_or(0)
    }
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
            state: Mutex::new(QuotaState::default()),
            max_tracked_keys: MAX_TRACKED_QUOTA_KEYS,
            max_tracked_keys_per_tenant: MAX_TRACKED_QUOTA_KEYS_PER_TENANT,
            clock,
        }
    }

    /// Construct a store with lowered key ceilings.
    ///
    /// Test-only, and only the *ceilings* move: the saturation branch
    /// under test is the production one in [`Self::check_quota`],
    /// reached the same way. The defaults are five and six figures,
    /// which no unit test should be allocating its way to.
    #[cfg(test)]
    fn with_clock_and_max(clock: C, max_tracked_keys: usize) -> Self {
        Self {
            max_tracked_keys,
            // A sub-cap above the global cap can never bind, which
            // keeps the existing ceiling tests exercising the global
            // branch. Tests that want the sub-cap set it explicitly
            // with `with_clock_and_tenant_max`.
            max_tracked_keys_per_tenant: max_tracked_keys.saturating_add(1),
            ..Self::with_clock(clock)
        }
    }

    /// Construct a store with a lowered per-tenant sub-cap and a
    /// global ceiling high enough that only the sub-cap can bind.
    #[cfg(test)]
    fn with_clock_and_tenant_max(clock: C, max_tracked_keys_per_tenant: usize) -> Self {
        Self {
            max_tracked_keys_per_tenant,
            ..Self::with_clock(clock)
        }
    }

    /// Number of distinct principals this process currently holds a
    /// window for. Test-only: nothing on the request path reads it.
    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .counters
            .len()
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
            Err(error) => {
                // Unreachable through a compiled config: the `mcp`
                // action refuses `tool_quotas[].rate.per` it cannot
                // parse (`validate_quota_windows`). It stays here as a
                // backstop for any caller that builds a
                // `ToolAccessPolicy` without going through that
                // validation, and it fails *closed*: a quota the
                // operator wrote and this process cannot read is a
                // limit that exists, so refusing the call is the only
                // answer that does not silently make the tool
                // unlimited. This branch used to `return Ok(())`,
                // uncounted and unlogged.
                warn_unparseable_window(tool, &rule.rate.per, &error);
                return Err(QuotaExceeded {
                    tool_name: tool.to_string(),
                });
            }
        };
        let now = self.clock.now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let key = QuotaKey {
            tenant_id: principal.tenant_id.as_str().to_string(),
            principal_id: principal_id_for(principal),
            tool_name: tool.to_string(),
        };

        // A poisoned quota mutex must not take the whole gateway down
        // with it: the critical section below is map arithmetic with
        // no panic site, so a poisoned lock means some other thread
        // died elsewhere and the counts are still readable.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_new_key = !state.counters.contains_key(&key);
        if is_new_key {
            let at_tenant_cap =
                state.tenant_live(&key.tenant_id) >= self.max_tracked_keys_per_tenant;
            let at_global_cap = state.counters.len() >= self.max_tracked_keys;
            if at_tenant_cap || at_global_cap {
                // At a ceiling and this principal has no window yet.
                // Reclaim whatever has aged out before deciding, at
                // most once per `QUOTA_SWEEP_MIN_INTERVAL` so a
                // saturated store does not walk every key on every
                // request.
                let due = state
                    .last_sweep
                    .is_none_or(|last| now.duration_since(last) >= QUOTA_SWEEP_MIN_INTERVAL);
                if due {
                    state.sweep(now);
                }
                // Fail closed on whichever ceiling still binds. A
                // limiter that cannot count is not a limiter, and
                // admitting the call would hand an attacker minting
                // distinct principal ids an unmetered lane through
                // every quota at once.
                //
                // The sub-cap is reported first, the same order
                // `SessionStore::create_capped` uses and for the same
                // reason: a caller whose own tenant is full needs to
                // hear that, not that some unrelated tenant filled the
                // process. The global ceiling behind it bounds how
                // many distinct tenants hold windows at once.
                if state.tenant_live(&key.tenant_id) >= self.max_tracked_keys_per_tenant {
                    warn_quota_registry_saturated(
                        tool,
                        "tenant",
                        self.max_tracked_keys_per_tenant,
                    );
                    sbproxy_observe::metrics::record_mcp_tool_quota_registry_saturated();
                    return Err(QuotaExceeded {
                        tool_name: tool.to_string(),
                    });
                }
                if state.counters.len() >= self.max_tracked_keys {
                    warn_quota_registry_saturated(tool, "global", self.max_tracked_keys);
                    sbproxy_observe::metrics::record_mcp_tool_quota_registry_saturated();
                    return Err(QuotaExceeded {
                        tool_name: tool.to_string(),
                    });
                }
            }
            // Admitted a new key: charge it to its tenant. This is the
            // only place `counters` grows, so it is the only place the
            // per-tenant count has to move outside `sweep`.
            *state
                .per_tenant
                .entry(key.tenant_id.clone())
                .or_insert(0) += 1;
        }
        let counter = state.counters.entry(key).or_insert_with(|| QuotaCounter {
            window,
            hits: std::collections::VecDeque::new(),
        });
        // The rule that matched can change under a reload; keep the
        // window the sweep prunes against in step with it.
        counter.window = window;
        // Drop expired entries off the front. The deque is ordered
        // by insertion time, so a single front-pop loop is enough.
        while let Some(front) = counter.hits.front() {
            if *front < cutoff {
                counter.hits.pop_front();
            } else {
                break;
            }
        }
        if counter.hits.len() as u64 >= rule.rate.max {
            return Err(QuotaExceeded {
                tool_name: tool.to_string(),
            });
        }
        counter.hits.push_back(now);
        Ok(())
    }
}

/// Log an unparseable `rate.per` once per process.
///
/// Once, not per call: the branch denies every `tools/call` for the
/// tool, so a per-call line would turn one bad config string into a
/// log flood on the request path. The single line carries the tool and
/// the accepted suffixes, which is what an operator needs to fix it.
fn warn_unparseable_window(tool: &str, per: &str, error: &str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::warn!(
            tool = %tool,
            per = %per,
            error = %error,
            "mcp tool quota window is unparseable; denying tools/call for this tool. \
             Accepted suffixes are ms, s, m, h, d (for example 30s, 15m, 24h, 7d)"
        );
    });
}

/// Log quota-registry saturation once per process per `scope`, for the
/// same flood reason as [`warn_unparseable_window`].
///
/// One `Once` per scope rather than one for both: a store that hits
/// its per-tenant sub-cap first would otherwise silence the global
/// ceiling forever, and those are different operator actions (raise
/// the tenant's traffic expectations, versus size the process for the
/// number of tenants it now serves). The counter beside this line,
/// `sbproxy_mcp_tool_quota_registry_saturated_total`, is what shows
/// how much traffic the refusal covers; the log line only names it
/// once.
fn warn_quota_registry_saturated(tool: &str, scope: &'static str, cap: usize) {
    static TENANT: std::sync::Once = std::sync::Once::new();
    static GLOBAL: std::sync::Once = std::sync::Once::new();
    let once = if scope == "tenant" { &TENANT } else { &GLOBAL };
    once.call_once(|| {
        tracing::warn!(
            tool = %tool,
            scope = %scope,
            cap = cap,
            "mcp tool quota registry is saturated; denying tools/call for principals \
             with no live window until aged-out windows are reclaimed"
        );
    });
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
    sbproxy_util::parse_duration(s)
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

    /// A `rate.per` string nothing can parse must deny the call, not
    /// wave it through.
    ///
    /// The seam is `check_quota`'s window-parse branch. It used to
    /// `return Ok(())` on a parse failure, justified by a comment
    /// claiming load-time validation that did not exist anywhere in
    /// the workspace, so `per: "1hour"` compiled clean and then made
    /// the tool unlimited at runtime with no log line and no counter.
    #[test]
    fn unparseable_quota_window_denies_rather_than_waving_through() {
        let store = ToolQuotaStore::new();
        let mut policy = quota_policy();
        policy.tool_quotas[0].rate.per = "1hour".to_string();
        let p = principal("acme", "u", None, None, Some("vk_a"));

        let err = store
            .check_quota(&policy, &p, "delete_user")
            .expect_err("an unreadable quota window must fail closed");
        assert_eq!(err.tool_name, "delete_user");
    }

    /// The same string is refused before it ever reaches the request
    /// path, which is where the operator can still act on it.
    #[test]
    fn validate_quota_windows_names_the_rule_and_the_suffixes() {
        let mut policy = quota_policy();
        policy.validate_quota_windows().expect("1h parses");

        policy.tool_quotas[0].rate.per = "1hour".to_string();
        let error = policy
            .validate_quota_windows()
            .expect_err("1hour must be refused");
        assert!(error.contains("delete_user"), "{error}");
        assert!(error.contains("1hour"), "{error}");
        assert!(error.contains("30s"), "{error}");
    }

    /// The counter map stops growing once it is at the ceiling and
    /// nothing has aged out.
    ///
    /// The seam is `check_quota`'s insert. Before the ceiling existed
    /// the map had no `remove`, `retain`, or capacity check anywhere,
    /// so a quota with no `principals` selector left one permanent
    /// entry per distinct caller-presented `sub` for the life of the
    /// process. Every principal here is inside its window, so the
    /// sweep can reclaim nothing and only the ceiling can hold.
    #[test]
    fn quota_key_map_stops_growing_at_the_ceiling() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock_and_max(clock.clone(), 8);
        let policy = quota_policy();

        for index in 0..64 {
            let sub = format!("attacker-{index}");
            let p = principal("acme", &sub, None, None, None);
            let _ = store.check_quota(&policy, &p, "delete_user");
        }

        assert_eq!(
            store.tracked_keys(),
            8,
            "the counter map must stop at the ceiling instead of growing per caller",
        );
    }

    /// Saturation denies the newcomer rather than admitting it
    /// unmetered, and a principal already inside the ceiling keeps
    /// working.
    #[test]
    fn saturated_quota_registry_denies_the_untracked_principal() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock_and_max(clock.clone(), 2);
        let policy = quota_policy();
        let first = principal("acme", "first", None, None, None);
        let second = principal("acme", "second", None, None, None);
        let third = principal("acme", "third", None, None, None);

        store.check_quota(&policy, &first, "delete_user").unwrap();
        store.check_quota(&policy, &second, "delete_user").unwrap();
        assert!(
            store.check_quota(&policy, &third, "delete_user").is_err(),
            "a principal the store cannot track must not get an unmetered lane",
        );
        assert!(
            store.check_quota(&policy, &first, "delete_user").is_ok(),
            "an already-tracked principal keeps its window",
        );
    }

    /// One tenant flooding distinct principals must not refuse
    /// `tools/call` for anybody else.
    ///
    /// The global ceiling alone made the fail-closed refusal a
    /// cross-tenant denial of service: `principal_id` is
    /// caller-presented, so a tenant that can authenticate under many
    /// distinct `sub` values fills the whole map and every other
    /// tenant's next unseen principal is refused. The per-tenant
    /// sub-cap is what confines the flood to its own tenant, the same
    /// remedy `SessionStore` and `peer_profile` already carry.
    #[test]
    fn one_tenants_flood_cannot_saturate_another_tenants_quota_windows() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock_and_tenant_max(clock.clone(), 4);
        let policy = quota_policy();

        for index in 0..64 {
            let sub = format!("flood-{index}");
            let noisy = principal("noisy", &sub, None, None, None);
            let _ = store.check_quota(&policy, &noisy, "delete_user");
        }
        assert_eq!(
            store.tracked_keys(),
            4,
            "the flooding tenant must stop at its own sub-cap",
        );

        let quiet = principal("quiet", "analyst", None, None, None);
        assert!(
            store.check_quota(&policy, &quiet, "delete_user").is_ok(),
            "another tenant's first principal must still be tracked and admitted",
        );
        assert_eq!(store.tracked_keys(), 5);
    }

    /// Once a window ages out, its key is reclaimed and the ceiling
    /// admits a new principal again. Without the sweep the store would
    /// stay wedged at the ceiling for the life of the process.
    #[test]
    fn aged_out_windows_are_reclaimed_and_free_the_ceiling() {
        let clock = FakeClock::new(Instant::now());
        let store = ToolQuotaStore::with_clock_and_max(clock.clone(), 2);
        let policy = quota_policy();
        let first = principal("acme", "first", None, None, None);
        let second = principal("acme", "second", None, None, None);
        let third = principal("acme", "third", None, None, None);

        store.check_quota(&policy, &first, "delete_user").unwrap();
        store.check_quota(&policy, &second, "delete_user").unwrap();
        assert!(store.check_quota(&policy, &third, "delete_user").is_err());

        // Policy window is 1h; both live windows age out past it.
        clock.advance(Duration::from_secs(60 * 60 + 1));
        assert!(
            store.check_quota(&policy, &third, "delete_user").is_ok(),
            "the sweep must reclaim aged-out windows so the ceiling is not permanent",
        );
        assert_eq!(store.tracked_keys(), 1);
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
