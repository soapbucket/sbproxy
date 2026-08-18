//! Object- and function-level authorization policy (`object_authz`).
//!
//! Detects the two top OWASP API risks at the gateway:
//!
//! - **BOLA** (Broken Object Level Authorization, API1:2023): a caller
//!   accesses an object id outside its authorized scope. The gateway
//!   cannot know who owns an arbitrary backend object, so it enforces a
//!   declarative ownership rule: a named segment of the request path
//!   (for example `{owner}` in `/tenants/{owner}/orders/{order_id}`)
//!   must equal the caller's verified owner identity. A mismatch is a
//!   cross-tenant access and is blocked.
//! - **BFLA** (Broken Function Level Authorization, API5:2023): a caller
//!   invokes a privileged operation without the required role. A
//!   function rule binds a path (and optionally a method set) to a
//!   required role; a caller lacking that role is blocked.
//!
//! On top of those it detects **object-id enumeration**: one principal
//! touching many distinct object ids inside a short window (sequential
//! id scanning), which is the signature of a BOLA fuzzing sweep.
//!
//! Enumeration has two independent sources, and they never mix on one
//! origin:
//!
//! - **Rule-scoped.** When [`ObjectAuthzConfig::object_rules`] is
//!   non-empty, only a matched rule's `object_param` capture ever
//!   counts. A request that matches no configured rule is invisible to
//!   enumeration, exactly as if the check were absent for that path;
//!   the rules define the scope, full stop.
//! - **Ruleless heuristic.** Only when `object_rules` is empty
//!   entirely does the detector fall back to guessing: a request whose
//!   trailing path segment is id-shaped (a purely numeric segment or a
//!   canonical UUID) has its whole normalized path counted as one
//!   object. This fallback requires an identified caller
//!   (`principal.owner.is_some()`); anonymous traffic is never
//!   attributable to one principal, so it is never counted, no matter
//!   how many distinct ids it touches. And because the id shape and
//!   the path-to-object mapping are both guesses rather than a
//!   declared contract, a heuristic trip is reported for audit only:
//!   it never blocks, regardless of `test_mode`.
//!
//! The caller identity (owner + roles) is resolved by the enforcer from
//! the verified auth subject (`ctx.auth_result`) or from trusted request
//! headers, and handed to [`ObjectAuthzPolicy::decide`]. Reading the
//! owner from a request header is only safe when a trusted upstream auth
//! layer sets it; the default and recommended source is the verified
//! subject.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Deserialize;

/// Hard cap on the number of principals tracked for enumeration so a
/// flood of distinct principals (`principal.owner` is caller-controlled
/// input) cannot grow the map without bound. An existing principal
/// always keeps updating its own state, cap or no cap: past this many
/// live principals, only a *new* principal is refused a tracking slot
/// (see `ObjectAuthzPolicy::record_and_check_enumeration`), logged and
/// best-effort-skipped rather than counted, the same honest shape
/// `sbproxy_extension::mcp::peer_profile`'s bounded peer registry uses
/// (that module also increments a dedicated Prometheus counter on
/// saturation; this one does not yet, see
/// `report_enumeration_tracker_saturated`'s own doc comment for why).
/// Either way this replaces the old behavior of wiping every
/// principal's state, including principals with nothing to do with the
/// flood, the instant the map got full.
const MAX_TRACKED_PRINCIPALS: usize = 50_000;

/// Where the enforcer reads the caller's owner identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OwnerSource {
    /// The verified auth subject (`ctx.auth_result`). Secure default.
    #[default]
    Sub,
    /// A request header. Only trustworthy when a trusted upstream auth
    /// layer sets it (the client must not be able to spoof it).
    Header,
}

/// How to resolve the caller's identity from the request.
#[derive(Debug, Clone, Deserialize)]
pub struct PrincipalConfig {
    /// Where the owner identity comes from.
    #[serde(default)]
    pub owner_from: OwnerSource,
    /// Header carrying the owner when `owner_from = header`.
    #[serde(default = "default_owner_header")]
    pub owner_header: String,
    /// Header carrying the caller's roles (comma-separated). Read only
    /// when `trust_role_header` is true; a trusted upstream auth layer
    /// must set it and the client must not be able to spoof it.
    #[serde(default = "default_role_header")]
    pub role_header: String,
    /// Whether to trust `role_header` from the inbound request. Defaults
    /// to `false`: roles are not read from a client-settable header
    /// unless an operator explicitly opts in, because a direct client
    /// could otherwise send `x-roles: admin` and satisfy any BFLA role
    /// rule. Set to `true` only when a trusted upstream (an auth proxy,
    /// a service mesh) populates the header and strips any client value.
    #[serde(default)]
    pub trust_role_header: bool,
}

impl Default for PrincipalConfig {
    fn default() -> Self {
        Self {
            owner_from: OwnerSource::default(),
            owner_header: default_owner_header(),
            role_header: default_role_header(),
            trust_role_header: false,
        }
    }
}

fn default_owner_header() -> String {
    "x-owner-id".to_string()
}

fn default_role_header() -> String {
    "x-roles".to_string()
}

/// A BOLA ownership rule: a path whose captured owner segment must equal
/// the caller's owner.
#[derive(Debug, Clone, Deserialize)]
pub struct ObjectRule {
    /// Path template with `{name}` captures, `*` (one segment) and a
    /// trailing `**` (rest). Example: `/tenants/{owner}/orders/{id}`.
    pub path: String,
    /// Which captured segment names the owner. Must appear in `path`.
    pub owner_param: String,
    /// Optional captured segment naming the object id, counted for
    /// enumeration detection. Omit to skip enumeration for this rule.
    #[serde(default)]
    pub object_param: Option<String>,
}

/// A BFLA rule: a privileged path/method that requires a role.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRule {
    /// Path template (same syntax as [`ObjectRule::path`]).
    pub path: String,
    /// HTTP methods this rule covers. Empty matches any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Role the caller must hold to invoke this operation.
    pub require_role: String,
}

/// Enumeration-anomaly configuration.
///
/// Works with or without [`ObjectAuthzConfig::object_rules`], but the
/// two never combine: with rules configured, only a matched rule's
/// `object_param` capture counts (an unmatched path counts nothing).
/// With no rules configured at all, `enabled: true` on its own catches
/// a sweep via a path-shape heuristic instead -- see the module docs
/// for the identity and blocking caveats that apply only to that
/// fallback.
#[derive(Debug, Clone, Deserialize)]
pub struct EnumerationConfig {
    /// Master switch. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Distinct object ids per principal within `window_secs` that trip
    /// the anomaly.
    #[serde(default = "default_max_distinct")]
    pub max_distinct: usize,
    /// Window length in seconds. Counting resets at fixed `window_secs`
    /// boundaries per principal (a tumbling window, not a continuously
    /// sliding one): the per-principal counter state is bounded by
    /// `max_distinct`, not by how much traffic arrived, so this trades a
    /// small amount of boundary precision for work-per-request that
    /// never grows with traffic volume.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

impl Default for EnumerationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_distinct: default_max_distinct(),
            window_secs: default_window_secs(),
        }
    }
}

fn default_max_distinct() -> usize {
    20
}

fn default_window_secs() -> u64 {
    60
}

/// The enumeration fallback signal used in the zero-`object_rules`
/// case: `Some(the whole normalized path)` when the request's *actual
/// trailing* path segment looks like an object id, either a purely
/// numeric run (`42`, `100042`) or a canonical 36-character UUID
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, any hex case); `None`
/// otherwise.
///
/// Two properties that are load-bearing, not incidental:
///
/// - **The object key is the full path, not the matched segment.**
///   `/orders/1/items/1` and `/orders/2/items/1` share a trailing `1`
///   but are different objects; counting the segment value alone would
///   collapse a real sweep across `orders` into "one distinct id" and
///   make it invisible. Counting the full path keeps them distinct.
/// - **Only the trailing segment is checked**, not "any segment
///   scanning from the end." `/tenants/42/orders` does not count: its
///   last segment is `orders`, a collection listing, not an object
///   fetch, even though `42` earlier in the path is id-shaped. This
///   also means a directory-style path (`/reports/2026/08/` -- trailing
///   empty segment) never counts.
///
/// This is a heuristic, not a schema, and it has a known, accepted
/// false-positive class: `/tiles/12/2345/6789` or `/reports/2026/08/17`
/// end in an id-shaped segment and mint one heuristic "object" per
/// request even under normal browsing or map-tile traffic, since the
/// heuristic cannot tell "the id varies because it is a sweep" from
/// "the id varies because that is the resource." A declared
/// `object_rules` entry does not have this problem, because it names
/// the object segment explicitly rather than guessing from shape; the
/// heuristic exists only for the case where no such rule exists at all.
/// Callers must treat a heuristic hit as audit-only for this reason --
/// see `Violation::detect_only`.
fn heuristic_object_key(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let last = trimmed.rsplit('/').next().unwrap_or("");
    if !is_id_shaped(last) {
        return None;
    }
    Some(trimmed.to_string())
}

fn is_id_shaped(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    segment.bytes().all(|b| b.is_ascii_digit()) || is_uuid_like(segment)
}

fn is_uuid_like(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => *b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}

/// Raw deserialized config for the `object_authz` policy.
#[derive(Debug, Clone, Deserialize)]
pub struct ObjectAuthzConfig {
    /// When true, violations are reported (audit + metric) but the
    /// request is allowed through. Mirrors the WAF `test_mode` switch.
    #[serde(default)]
    pub test_mode: bool,
    /// Identity resolution.
    #[serde(default)]
    pub principal: PrincipalConfig,
    /// BOLA ownership rules.
    #[serde(default)]
    pub object_rules: Vec<ObjectRule>,
    /// BFLA function rules.
    #[serde(default)]
    pub function_rules: Vec<FunctionRule>,
    /// Enumeration anomaly detection.
    #[serde(default)]
    pub enumeration: EnumerationConfig,
}

/// The class of authorization violation, used for the OWASP risk tag,
/// the audit `event_type`, and the metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// Cross-scope object access (API1:2023).
    Bola,
    /// Missing function-level role (API5:2023).
    Bfla,
    /// Object-id enumeration sweep (API1:2023).
    Enumeration,
}

impl ViolationKind {
    /// OWASP API Security Top 10 (2023) risk tag.
    pub fn owasp_tag(self) -> &'static str {
        match self {
            ViolationKind::Bola | ViolationKind::Enumeration => "API1:2023",
            ViolationKind::Bfla => "API5:2023",
        }
    }

    /// Closed audit `event_type` string so SIEM rules can route by kind.
    pub fn event_type(self) -> &'static str {
        match self {
            ViolationKind::Bola => "object_authz_bola",
            ViolationKind::Bfla => "object_authz_bfla",
            ViolationKind::Enumeration => "object_authz_enumeration",
        }
    }

    /// Short metric label.
    pub fn label(self) -> &'static str {
        match self {
            ViolationKind::Bola => "bola",
            ViolationKind::Bfla => "bfla",
            ViolationKind::Enumeration => "enumeration",
        }
    }
}

/// A detected violation: the kind plus a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Which authorization check failed.
    pub kind: ViolationKind,
    /// Detailed reason for the audit log (not returned to the client).
    pub message: String,
    /// True only for an enumeration violation produced by the ruleless
    /// path-shape heuristic (see the module docs). The enforcer must
    /// never block on a `detect_only` violation, regardless of
    /// `test_mode`: it is still reported to the audit log and the
    /// violation metric, but the request always proceeds, because a
    /// heuristic id match is not a declared rule and is not trustworthy
    /// enough to refuse traffic on. BOLA, BFLA, and rule-scoped
    /// enumeration violations are never `detect_only`.
    pub detect_only: bool,
}

/// The caller identity the enforcer resolves and hands to [`decide`].
///
/// [`decide`]: ObjectAuthzPolicy::decide
#[derive(Debug, Clone, Default)]
pub struct Principal {
    /// Verified owner identity, if any.
    pub owner: Option<String>,
    /// Roles the caller holds (from the trusted role header).
    pub roles: Vec<String>,
}

/// Compiled `object_authz` policy.
pub struct ObjectAuthzPolicy {
    test_mode: bool,
    principal: PrincipalConfig,
    object_rules: Vec<CompiledObjectRule>,
    function_rules: Vec<CompiledFunctionRule>,
    enumeration: EnumerationConfig,
    /// Per-principal enumeration counter state, keyed by the owner
    /// identity. Never holds a `""` (anonymous) key: `decide` only
    /// calls into enumeration tracking for an identified caller.
    /// Bounded to `MAX_TRACKED_PRINCIPALS` live principals; see
    /// `record_and_check_enumeration` for what happens past that cap.
    tracker: Mutex<HashMap<String, EnumerationWindow>>,
    /// Set once this process has logged the enumeration-tracker
    /// saturation warning, so a sustained flood of distinct principals
    /// logs it once rather than once per refused request.
    enumeration_saturation_warned: std::sync::atomic::AtomicBool,
}

/// One principal's bounded enumeration-counter state.
///
/// Deliberately not a precise sliding-window log of every access: the
/// old implementation stored a `(time, object_id)` entry per request and
/// rebuilt a fresh `HashSet` from the whole in-window history on every
/// single call to recompute the distinct count, which is `O(requests
/// seen so far in the window)` of work, under one global lock, on
/// exactly the traffic the check exists to police -- a burst of N
/// requests from one principal did `O(N^2)` total work. It also had no
/// bound on memory *per principal*: a principal re-fetching the same id
/// a million times in one window grew the deque to a million entries
/// even though the distinct count never left 1.
///
/// This version bounds both. `ids` never holds more than `max_distinct`
/// entries (there is never a reason to remember more: once that many
/// distinct ids are seen, the sweep has already tripped, and `tripped`
/// latches the fact instead), and the window is tumbling rather than
/// continuously sliding: it resets to empty when more than
/// `window_secs` have elapsed since `window_start`, rather than expiring
/// each id individually. Insert and check are O(1) amortized (bounded
/// `HashSet` operations, never a full-history scan), and the map entry
/// this locks to update is a fixed, config-bounded size regardless of
/// how much traffic that principal generated -- the trade is a small
/// amount of window-boundary precision for work-per-request that cannot
/// grow with traffic volume, which is the "detection is best-effort"
/// trade this whole tracker already makes.
struct EnumerationWindow {
    /// When the current window began.
    window_start: Instant,
    /// Distinct object ids seen in the current window so far, capped at
    /// `max_distinct` entries.
    ids: HashSet<String>,
    /// Once `ids` would exceed `max_distinct`, this latches `true` and
    /// `ids` is cleared (its membership no longer matters: every
    /// request is tripped for the rest of the window regardless of
    /// which id it names), mirroring the old sliding-window behavior of
    /// "every subsequent request from that principal is blocked for the
    /// rest of the window, even for ids it already fetched
    /// successfully."
    tripped: bool,
}

impl EnumerationWindow {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            ids: HashSet::new(),
            tripped: false,
        }
    }
}

struct CompiledObjectRule {
    template: PathPattern,
    owner_param: String,
    object_param: Option<String>,
}

struct CompiledFunctionRule {
    template: PathPattern,
    methods: Vec<String>,
    require_role: String,
}

impl std::fmt::Debug for ObjectAuthzPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectAuthzPolicy")
            .field("test_mode", &self.test_mode)
            .field("principal", &self.principal)
            .field("object_rules", &self.object_rules.len())
            .field("function_rules", &self.function_rules.len())
            .field("enumeration", &self.enumeration)
            .finish()
    }
}

impl ObjectAuthzPolicy {
    /// Build the policy from JSON config, compiling each rule's path
    /// template and validating that every `owner_param` / `object_param`
    /// actually appears as a capture in its template.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: ObjectAuthzConfig = serde_json::from_value(value)?;

        let mut object_rules = Vec::with_capacity(config.object_rules.len());
        for rule in config.object_rules {
            let template = PathPattern::parse(&rule.path)?;
            if !template.captures().any(|c| c == rule.owner_param) {
                anyhow::bail!(
                    "object_authz: owner_param '{}' is not a capture in path '{}'",
                    rule.owner_param,
                    rule.path
                );
            }
            if let Some(obj) = &rule.object_param {
                if !template.captures().any(|c| c == obj) {
                    anyhow::bail!(
                        "object_authz: object_param '{}' is not a capture in path '{}'",
                        obj,
                        rule.path
                    );
                }
            }
            object_rules.push(CompiledObjectRule {
                template,
                owner_param: rule.owner_param,
                object_param: rule.object_param,
            });
        }

        let mut function_rules = Vec::with_capacity(config.function_rules.len());
        for rule in config.function_rules {
            let template = PathPattern::parse(&rule.path)?;
            function_rules.push(CompiledFunctionRule {
                template,
                methods: rule
                    .methods
                    .iter()
                    .map(|m| m.to_ascii_uppercase())
                    .collect(),
                require_role: rule.require_role,
            });
        }

        Ok(Self {
            test_mode: config.test_mode,
            principal: config.principal,
            object_rules,
            function_rules,
            enumeration: config.enumeration,
            tracker: Mutex::new(HashMap::new()),
            enumeration_saturation_warned: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Whether violations are reported but not blocked.
    pub fn test_mode(&self) -> bool {
        self.test_mode
    }

    /// The identity-resolution config (read by the enforcer to extract
    /// the principal from the request).
    pub fn principal_config(&self) -> &PrincipalConfig {
        &self.principal
    }

    /// Evaluate the request against every rule. Returns the first
    /// violation found, or `None` to allow. BOLA is checked before
    /// enumeration before BFLA so the most object-specific denial wins.
    pub fn decide(&self, principal: &Principal, method: &str, path: &str) -> Option<Violation> {
        let path = path.split('?').next().unwrap_or(path);

        // BOLA: a matched ownership rule's owner segment must equal the
        // caller's owner. While matching, record object ids for the
        // enumeration sweep so a passing in-scope access still counts.
        let mut enumeration_hit: Option<String> = None;
        for rule in &self.object_rules {
            let Some(bindings) = rule.template.match_path(path) else {
                continue;
            };
            let Some(path_owner) = bindings.get(&rule.owner_param) else {
                continue;
            };
            match &principal.owner {
                None => {
                    return Some(Violation {
                        kind: ViolationKind::Bola,
                        message: format!(
                            "object scope '{}' requires an identified caller but none was resolved",
                            path_owner
                        ),
                        detect_only: false,
                    });
                }
                Some(owner) if owner != path_owner => {
                    return Some(Violation {
                        kind: ViolationKind::Bola,
                        message: format!(
                            "caller '{}' accessed object scope owned by '{}'",
                            owner, path_owner
                        ),
                        detect_only: false,
                    });
                }
                Some(_) => {}
            }
            if let Some(obj_param) = &rule.object_param {
                if let Some(obj_id) = bindings.get(obj_param) {
                    enumeration_hit = Some(obj_id.clone());
                }
            }
        }

        // Enumeration: per-principal distinct object-id velocity.
        //
        // Rule-scoped: a rule-captured id (above) is the only signal
        // used when `object_rules` is non-empty. A request that matched
        // no rule counts nothing here, even though a rule exists for a
        // *different* path -- the configured rules define the scope,
        // and widening that scope with a guess would count traffic the
        // operator never opted into for this origin.
        //
        // Ruleless heuristic: only when `object_rules` is empty at all
        // does a request get a second chance, via `heuristic_object_key`.
        // That fallback additionally requires an identified caller:
        // without one, distinct anonymous clients would collapse into
        // the same "" bucket, where N innocent callers making one
        // request each look identical to one attacker making N (and can
        // just as easily mask a real attacker sharing the bucket's
        // noise). Identity is the prerequisite, not a nice-to-have.
        if self.enumeration.enabled {
            let rule_derived = enumeration_hit.is_some();
            let obj_id = enumeration_hit.or_else(|| {
                if self.object_rules.is_empty() && principal.owner.is_some() {
                    heuristic_object_key(path)
                } else {
                    None
                }
            });
            if let Some(obj_id) = obj_id {
                let key = principal.owner.clone().unwrap_or_default();
                if self.record_and_check_enumeration(&key, &obj_id) {
                    let detect_only = !rule_derived;
                    let suffix = if detect_only {
                        " (ruleless path-shape heuristic; reported for audit only, not blocked)"
                    } else {
                        ""
                    };
                    return Some(Violation {
                        kind: ViolationKind::Enumeration,
                        message: format!(
                            "caller '{}' touched more than {} distinct object ids within {}s{}",
                            key,
                            self.enumeration.max_distinct,
                            self.enumeration.window_secs,
                            suffix
                        ),
                        detect_only,
                    });
                }
            }
        }

        // BFLA: a matched privileged rule requires its role.
        let method_uc = method.to_ascii_uppercase();
        for rule in &self.function_rules {
            if !rule.methods.is_empty() && !rule.methods.iter().any(|m| m == &method_uc) {
                continue;
            }
            if rule.template.match_path(path).is_none() {
                continue;
            }
            if !principal.roles.iter().any(|r| r == &rule.require_role) {
                return Some(Violation {
                    kind: ViolationKind::Bfla,
                    message: format!(
                        "operation requires role '{}' which the caller does not hold",
                        rule.require_role
                    ),
                    detect_only: false,
                });
            }
        }

        None
    }

    /// Record an object-id access for `key` and return true when it
    /// pushes the distinct count within the current window past
    /// `max_distinct`.
    ///
    /// O(1) amortized: no full-history scan runs on any call, and the
    /// lock is held only long enough to touch one `EnumerationWindow`
    /// whose own state is bounded to `max_distinct` entries, so the
    /// work done under the lock cannot grow with how much traffic `key`
    /// has generated. See `EnumerationWindow`'s own doc comment for the
    /// tumbling-window trade this makes to get there.
    ///
    /// Tracking itself is capacity-bounded at `MAX_TRACKED_PRINCIPALS`
    /// live principals: an already-tracked `key` always gets to update
    /// its own state, cap or no cap, but a *new* principal past the cap
    /// gets no slot at all. That principal's request is then simply not
    /// counted (`false`, best-effort: absence of a slot is never treated
    /// as a trip), the same shape `sbproxy_extension::mcp::peer_profile`'s
    /// `ObservationVerdict::Saturated` uses: a saturated pair gets no
    /// baseline rather than a fabricated one from a shared bucket.
    /// Every other principal's own tracked state is completely
    /// unaffected -- unlike the old behavior of wiping the whole map,
    /// this cannot turn one flood of new principals into a
    /// detection-gap for principals that had nothing to do with it.
    fn record_and_check_enumeration(&self, key: &str, object_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.enumeration.window_secs.max(1));
        let mut tracker = self.tracker.lock();

        if !tracker.contains_key(key) && tracker.len() >= MAX_TRACKED_PRINCIPALS {
            drop(tracker);
            self.report_enumeration_tracker_saturated();
            return false;
        }

        let entry = tracker
            .entry(key.to_string())
            .or_insert_with(|| EnumerationWindow::new(now));

        if now.duration_since(entry.window_start) > window {
            entry.window_start = now;
            entry.ids.clear();
            entry.tripped = false;
        }

        if entry.tripped {
            return true;
        }

        if entry.ids.contains(object_id) {
            // A repeat of an already-counted id never trips the sweep
            // on its own, and never needs to touch the set again.
            return false;
        }

        entry.ids.insert(object_id.to_string());
        if entry.ids.len() > self.enumeration.max_distinct {
            entry.tripped = true;
            // Membership no longer matters while tripped; free it now
            // instead of carrying `max_distinct` strings for the rest
            // of the window for no further purpose.
            entry.ids.clear();
            entry.ids.shrink_to_fit();
            return true;
        }
        false
    }

    /// Log the enumeration tracker's capacity being reached, once per
    /// policy instance rather than once per refused request so a
    /// sustained flood does not spam the log. Every occurrence still
    /// reaches an operator: unlike a per-key latch, this is a single
    /// `AtomicBool` on the policy itself, deliberately coarser than
    /// `sbproxy_extension::mcp::peer_profile`'s per-tenant latch,
    /// because there is no tenant dimension here to key it on -- a
    /// second, later saturation episode after the first log line is
    /// silent, which is the same trade that module's own doc comment
    /// makes for its per-tenant version.
    ///
    /// A dedicated `stable` Prometheus counter alongside this log line
    /// (mirroring `record_mcp_peer_registry_saturated`) is the natural
    /// next step, but adding one correctly means also updating the
    /// generated `docs/metrics-stability.md` catalog and satisfying
    /// `sbproxy-capability`'s writer-resolution drift guard, neither of
    /// which this change can verify without `cargo run`/`cargo test`
    /// outside this fix's cargo carve-out -- left as explicit follow-up
    /// rather than shipped unverified.
    fn report_enumeration_tracker_saturated(&self) {
        use std::sync::atomic::Ordering;
        if self
            .enumeration_saturation_warned
            .swap(true, Ordering::Relaxed)
        {
            return;
        }
        tracing::warn!(
            target: "sbproxy::policy::object_authz",
            cap = MAX_TRACKED_PRINCIPALS,
            "object_authz enumeration tracker is full; new principals get no enumeration baseline until it drains"
        );
    }
}

/// A minimal path-template matcher: literal segments, `{name}` single
/// segment captures, `*` single segment wildcard, and a trailing `**`
/// that matches the remaining segments.
struct PathPattern {
    segments: Vec<Segment>,
    /// True when the last segment is `**` (matches the rest).
    trailing_rest: bool,
}

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Capture(String),
    Wildcard,
}

impl PathPattern {
    fn parse(template: &str) -> anyhow::Result<Self> {
        let trimmed = template.trim_start_matches('/');
        let raw: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };
        let mut segments = Vec::with_capacity(raw.len());
        let mut trailing_rest = false;
        for (i, seg) in raw.iter().enumerate() {
            if *seg == "**" {
                if i != raw.len() - 1 {
                    anyhow::bail!(
                        "object_authz: '**' must be the last path segment in '{template}'"
                    );
                }
                trailing_rest = true;
            } else if *seg == "*" {
                segments.push(Segment::Wildcard);
            } else if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                if name.is_empty() {
                    anyhow::bail!("object_authz: empty capture name in path '{template}'");
                }
                segments.push(Segment::Capture(name.to_string()));
            } else {
                segments.push(Segment::Literal((*seg).to_string()));
            }
        }
        Ok(Self {
            segments,
            trailing_rest,
        })
    }

    /// The capture names declared in the template.
    fn captures(&self) -> impl Iterator<Item = &str> {
        self.segments.iter().filter_map(|s| match s {
            Segment::Capture(name) => Some(name.as_str()),
            _ => None,
        })
    }

    /// Match `path` against the template, returning the captured
    /// bindings on success.
    fn match_path(&self, path: &str) -> Option<HashMap<String, String>> {
        let trimmed = path.trim_start_matches('/');
        let parts: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };

        if self.trailing_rest {
            if parts.len() < self.segments.len() {
                return None;
            }
        } else if parts.len() != self.segments.len() {
            return None;
        }

        let mut bindings = HashMap::new();
        for (seg, part) in self.segments.iter().zip(parts.iter()) {
            match seg {
                Segment::Literal(lit) => {
                    if lit != part {
                        return None;
                    }
                }
                Segment::Wildcard => {}
                Segment::Capture(name) => {
                    bindings.insert(name.clone(), (*part).to_string());
                }
            }
        }
        Some(bindings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: serde_json::Value) -> ObjectAuthzPolicy {
        ObjectAuthzPolicy::from_config(json).unwrap()
    }

    fn principal(owner: Option<&str>, roles: &[&str]) -> Principal {
        Principal {
            owner: owner.map(String::from),
            roles: roles.iter().map(|r| r.to_string()).collect(),
        }
    }

    #[test]
    fn role_header_is_not_trusted_by_default() {
        // WOR-1139: a config that omits trust_role_header must default to
        // NOT trusting the client-settable role header, so a direct
        // client cannot send `x-roles: admin` and satisfy a BFLA rule.
        let cfg = PrincipalConfig::default();
        assert!(
            !cfg.trust_role_header,
            "role header must not be trusted by default"
        );
        let from_empty: PrincipalConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!from_empty.trust_role_header);
        // Explicit opt-in still works.
        let opted: PrincipalConfig =
            serde_json::from_value(serde_json::json!({ "trust_role_header": true })).unwrap();
        assert!(opted.trust_role_header);
    }

    #[test]
    fn bola_blocks_cross_tenant_allows_owner() {
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ]
        }));
        // In-scope: caller owns the tenant segment.
        assert_eq!(
            p.decide(
                &principal(Some("tenant-a"), &[]),
                "GET",
                "/tenants/tenant-a/orders/1"
            ),
            None
        );
        // Cross-tenant: blocked.
        let v = p
            .decide(
                &principal(Some("tenant-a"), &[]),
                "GET",
                "/tenants/tenant-b/orders/1",
            )
            .expect("violation");
        assert_eq!(v.kind, ViolationKind::Bola);
    }

    #[test]
    fn bola_requires_identity_when_rule_matches() {
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/data", "owner_param": "owner" }
            ]
        }));
        let v = p
            .decide(&principal(None, &[]), "GET", "/tenants/tenant-a/data")
            .expect("violation");
        assert_eq!(v.kind, ViolationKind::Bola);
        // A path the rule does not cover is unaffected.
        assert_eq!(p.decide(&principal(None, &[]), "GET", "/public/data"), None);
    }

    #[test]
    fn bfla_requires_role_for_privileged_path() {
        let p = policy(serde_json::json!({
            "function_rules": [
                { "path": "/admin/**", "methods": ["POST", "DELETE"], "require_role": "admin" }
            ]
        }));
        // Has the role: allowed.
        assert_eq!(
            p.decide(&principal(Some("u1"), &["admin"]), "POST", "/admin/users/1"),
            None
        );
        // Missing the role: blocked.
        let v = p
            .decide(
                &principal(Some("u1"), &["viewer"]),
                "DELETE",
                "/admin/users/1",
            )
            .expect("violation");
        assert_eq!(v.kind, ViolationKind::Bfla);
        // Method outside the rule's set: not privileged.
        assert_eq!(
            p.decide(&principal(Some("u1"), &["viewer"]), "GET", "/admin/users/1"),
            None
        );
    }

    #[test]
    fn enumeration_trips_after_threshold() {
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 3, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        // First three distinct ids are fine.
        for id in 1..=3 {
            assert_eq!(
                p.decide(&caller, "GET", &format!("/tenants/tenant-a/orders/{id}")),
                None,
                "id {id} should pass"
            );
        }
        // The fourth distinct id trips the sweep detector. Rule-derived,
        // so this must be enforceable, never `detect_only`.
        let v = p
            .decide(&caller, "GET", "/tenants/tenant-a/orders/4")
            .expect("violation");
        assert_eq!(v.kind, ViolationKind::Enumeration);
        assert!(
            !v.detect_only,
            "rule-scoped enumeration must stay enforceable"
        );
    }

    #[test]
    fn enumeration_ignores_repeated_same_id() {
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 2, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        for _ in 0..10 {
            assert_eq!(p.decide(&caller, "GET", "/tenants/tenant-a/orders/1"), None);
        }
    }

    #[test]
    fn enumeration_sticky_trip_covers_new_ids_for_rest_of_window() {
        // Once tripped, every subsequent request stays blocked for the
        // rest of the window, even for an id never seen before -- the
        // bounded tracker latches `tripped` rather than re-deriving the
        // distinct count each time.
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        assert_eq!(p.decide(&caller, "GET", "/tenants/tenant-a/orders/1"), None);
        let first_trip = p
            .decide(&caller, "GET", "/tenants/tenant-a/orders/2")
            .expect("violation");
        assert_eq!(first_trip.kind, ViolationKind::Enumeration);
        // A brand-new id, never seen before, still trips while the
        // window's sticky flag is set.
        let still_tripped = p
            .decide(&caller, "GET", "/tenants/tenant-a/orders/999")
            .expect("violation");
        assert_eq!(still_tripped.kind, ViolationKind::Enumeration);
    }

    #[test]
    fn enumeration_trips_without_object_rules_via_id_heuristic() {
        // WOR-2491 regression: with zero `object_rules` configured (the
        // common zero-config case, and the OWASP pack's api1 default)
        // the detector must still observe traffic instead of staying
        // inert. Before the fix, the counter was only ever populated
        // inside the `object_rules` match loop, so this never fired.
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 3, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        for id in 1..=3 {
            assert_eq!(
                p.decide(&caller, "GET", &format!("/orders/{id}")),
                None,
                "id {id} should pass"
            );
        }
        let v = p
            .decide(&caller, "GET", "/orders/4")
            .expect("violation: enumeration must fire without object_rules");
        assert_eq!(v.kind, ViolationKind::Enumeration);
        // A heuristic id is a guess, not a declared rule: it is reported
        // for audit but must never be the reason a request is blocked.
        assert!(v.detect_only, "ruleless heuristic hits must be detect_only");
    }

    #[test]
    fn enumeration_heuristic_matches_uuid_shaped_ids() {
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 2, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        for id in [
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        ] {
            assert_eq!(p.decide(&caller, "GET", &format!("/resources/{id}")), None);
        }
        let v = p
            .decide(
                &caller,
                "GET",
                "/resources/33333333-3333-3333-3333-333333333333",
            )
            .expect("violation");
        assert_eq!(v.kind, ViolationKind::Enumeration);
        assert!(v.detect_only);
    }

    #[test]
    fn enumeration_heuristic_ignores_paths_with_no_id_shaped_segment() {
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        for path in ["/health", "/tenants/acme/orders", "/v1/status"] {
            for _ in 0..5 {
                assert_eq!(p.decide(&caller, "GET", path), None, "path {path}");
            }
        }
    }

    #[test]
    fn enumeration_heuristic_skips_anonymous_callers() {
        // Review finding: without a resolved principal, the heuristic
        // must not count at all -- not "count under a shared blank
        // bucket." An unattributed caller collapsing into one "" key
        // would let N innocent anonymous clients making one request
        // each look like one attacker making N, and would just as
        // easily let a real attacker hide in that shared bucket's
        // noise. Identity is the prerequisite: no owner, no count, ever,
        // no matter how many distinct id-shaped requests arrive.
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        let anonymous = principal(None, &[]);
        for id in 1..=50 {
            assert_eq!(
                p.decide(&anonymous, "GET", &format!("/orders/{id}")),
                None,
                "anonymous id {id} must never trip enumeration"
            );
        }
    }

    #[test]
    fn enumeration_heuristic_does_not_apply_when_object_rules_configured() {
        // Review finding: pre-fix (v1.12) behavior for a configured
        // origin was that counting was scoped entirely to declared
        // rules. The ruleless heuristic must stay scoped to the
        // zero-`object_rules` case: once any object_rules exist, a
        // request matching none of them counts nothing, even though it
        // is id-shaped and the caller is identified.
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        for id in 1..=50 {
            assert_eq!(
                p.decide(&caller, "GET", &format!("/unmatched/{id}")),
                None,
                "unmatched-path id {id} must not feed the heuristic when rules exist"
            );
        }
    }

    #[test]
    fn heuristic_object_key_counts_the_full_path_not_the_trailing_value() {
        // Review finding: counting only the last id-shaped segment's
        // value collapses a real sweep. `/orders/1/items/1` and
        // `/orders/2/items/1` share a trailing `1` but are different
        // objects; the recorded key must be the whole path so they are
        // counted as two distinct objects, not one.
        assert_ne!(
            heuristic_object_key("/orders/1/items/1"),
            heuristic_object_key("/orders/2/items/1"),
        );
        assert_eq!(
            heuristic_object_key("/orders/1/items/1"),
            Some("orders/1/items/1".to_string())
        );
    }

    #[test]
    fn enumeration_heuristic_full_path_key_catches_shared_trailing_segment_sweep() {
        // The behavioral version of the unit test above: a sweep across
        // `/orders/{n}/items/1` must trip even though every request
        // shares the same trailing segment.
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 2, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        for order in 1..=2 {
            assert_eq!(
                p.decide(&caller, "GET", &format!("/orders/{order}/items/1")),
                None
            );
        }
        let v = p
            .decide(&caller, "GET", "/orders/3/items/1")
            .expect("violation: full-path key must count distinct orders");
        assert_eq!(v.kind, ViolationKind::Enumeration);
    }

    #[test]
    fn heuristic_object_key_requires_the_trailing_segment_itself() {
        // Only the request's actual last segment is checked, not "any
        // segment scanning from the end." A collection path under an
        // id-shaped parent (`/tenants/42/orders`) is not an object
        // fetch and must not count.
        assert_eq!(heuristic_object_key("/tenants/42/orders"), None);
        assert_eq!(heuristic_object_key("/tenants/acme/orders"), None);
        assert_eq!(heuristic_object_key("/health"), None);
        // Trailing-slash directory browsing: the last split segment is
        // empty, which is never id-shaped.
        assert_eq!(heuristic_object_key("/reports/2026/08/"), None);
        // Numeric and UUID trailing segments both count, keyed by the
        // full path.
        assert_eq!(
            heuristic_object_key("/tenants/acme/orders/42"),
            Some("tenants/acme/orders/42".to_string())
        );
        assert_eq!(
            heuristic_object_key("/resources/11111111-1111-1111-1111-111111111111"),
            Some("resources/11111111-1111-1111-1111-111111111111".to_string())
        );
        // Not a valid UUID shape (wrong length): no id-shaped segment.
        assert_eq!(heuristic_object_key("/things/not-a-uuid-1234"), None);
    }

    #[test]
    fn from_config_rejects_unknown_owner_param() {
        let err = ObjectAuthzPolicy::from_config(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/data", "owner_param": "tenant" }
            ]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("owner_param"));
    }

    #[test]
    fn path_pattern_trailing_rest_matches_deeper_paths() {
        let pat = PathPattern::parse("/admin/**").unwrap();
        assert!(pat.match_path("/admin/users/1/roles").is_some());
        // `**` is zero-or-more, so the bare collection root matches too.
        // This is the safer BFLA default: `/admin/**` also gates `/admin`.
        assert!(pat.match_path("/admin").is_some());
        assert!(pat.match_path("/public/x").is_none());
    }
}
