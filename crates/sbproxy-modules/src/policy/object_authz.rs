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
//!   canonical UUID) has its whole path (as received, minus leading
//!   slashes; no percent-decoding or slash-collapsing is applied)
//!   counted as one object. This fallback requires an identified
//!   caller (`principal.owner.is_some()`); anonymous traffic is never
//!   attributable to one principal, so it is never counted, no matter
//!   how many distinct ids it touches. And because the id shape and
//!   the path-to-object mapping are both guesses rather than a
//!   declared contract, a heuristic trip is reported for audit only:
//!   it never blocks, regardless of `test_mode`. To keep the audit
//!   feed proportionate, a tripped detect-only principal is audited
//!   once per window: repeat hits inside the same tripped window are
//!   suppressed and counted, and the count rides along on the next
//!   emitted violation.
//!
//! Enumeration state is keyed by `(tenant, owner)`, never by the owner
//! string alone, so two tenants whose principals share an id string
//! never share a budget and one tenant's sweep cannot trip another
//! tenant's caller.
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
/// always keeps updating its own state, cap or no cap. When the map is
/// at capacity and a *new* principal arrives, entries whose tumbling
/// window has already expired are swept first (see
/// `ObjectAuthzPolicy::record_and_check_enumeration`), so the cap counts
/// genuinely live windows; only when every slot is a live window is the
/// new principal refused a slot, counted on
/// `sbproxy_object_authz_enumeration_tracker_saturated_total`, warned
/// about once per window, and best-effort-skipped rather than counted,
/// the same honest shape `sbproxy_extension::mcp::peer_profile`'s
/// bounded peer registry uses (absence of a slot is never treated as a
/// trip). Either way this replaces the old behavior of wiping every
/// principal's state, including principals with nothing to do with the
/// flood, the instant the map got full.
const MAX_TRACKED_PRINCIPALS: usize = 50_000;

/// Tenant label used to scope the enumeration tracker when the
/// enforcer resolves no tenant, matching the `__default__` label
/// single-tenant traffic reports on every other tenant-scoped surface.
const DEFAULT_TENANT: &str = "__default__";

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
/// case: `Some(the whole path, minus leading slashes)` when the
/// request's *actual trailing* path segment looks like an object id,
/// either a purely numeric run (`42`, `100042`) or a canonical
/// 36-character UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, any hex
/// case); `None` otherwise. The path is used as received: no
/// percent-decoding, no `//` collapsing, no case folding, so
/// `/Orders/1` and `/orders/1` count as distinct objects and a
/// percent-encoded trailing id (`%31`) does not register as id-shaped.
/// Both are accepted imprecision in a detect-only heuristic, and both
/// only widen or narrow a signal that already cannot block.
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
    /// Tenant the request resolved to, used to scope the enumeration
    /// tracker so two tenants whose principals share an id string never
    /// share a budget. An empty string is treated as the `__default__`
    /// tenant label, matching the rest of the tenant-scoped surfaces.
    pub tenant: String,
}

/// Compiled `object_authz` policy.
pub struct ObjectAuthzPolicy {
    test_mode: bool,
    principal: PrincipalConfig,
    object_rules: Vec<CompiledObjectRule>,
    function_rules: Vec<CompiledFunctionRule>,
    enumeration: EnumerationConfig,
    /// Per-principal enumeration counter state, keyed by
    /// `(tenant, owner)` so tenants never share a budget. Never holds
    /// an anonymous (empty-owner) key: `decide` builds the key from
    /// the owner identity itself, so an unidentified caller cannot be
    /// keyed in. Bounded to `max_tracked_principals` live entries; see
    /// `record_and_check_enumeration` for the expiry sweep that keeps
    /// "live" true and for what happens past that cap.
    tracker: Mutex<HashMap<(String, String), EnumerationWindow>>,
    /// When the enumeration-tracker saturation warning last fired, so
    /// a sustained flood of distinct principals re-warns once per
    /// window rather than once per refused request (and rather than
    /// once per policy instance, which hid every episode after the
    /// first).
    saturation_last_warned: Mutex<Option<Instant>>,
    /// Capacity of `tracker`. Always `MAX_TRACKED_PRINCIPALS` in
    /// production; a field rather than the const so tests can exercise
    /// the at-capacity sweep without minting 50,000 entries.
    max_tracked_principals: usize,
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
    /// Detect-only repeat hits since the last *emitted* violation. A
    /// tripped detect-only principal is audited once per window, not
    /// once per request (the request is allowed through, so nothing
    /// else throttles the emission); the repeats land here and the
    /// count rides along on the next emitted violation. Deliberately
    /// survives a window rollover: it is "since the last emission",
    /// not "this window". Never incremented for rule-derived hits,
    /// which block and therefore keep their per-request audit record.
    suppressed_repeats: u64,
}

impl EnumerationWindow {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            ids: HashSet::new(),
            tripped: false,
            suppressed_repeats: 0,
        }
    }
}

/// What [`ObjectAuthzPolicy::record_and_check_enumeration`] observed
/// for one request.
enum EnumerationOutcome {
    /// The distinct-id count is under the threshold, or the id repeats
    /// one already counted. Nothing to report.
    UnderThreshold,
    /// This request pushed the distinct count past `max_distinct`: the
    /// first trip of the current window. Carries the detect-only
    /// repeat hits suppressed since the last emitted violation so the
    /// caller can put the count in this emission.
    Tripped { suppressed_since_last_emission: u64 },
    /// The window is already tripped and the hit is rule-derived. The
    /// caller must keep returning a violation: rule-derived hits block,
    /// so the client pays for each one and each refusal is audited.
    StillTripped,
    /// The window is already tripped, the hit is detect-only, and this
    /// repeat was counted into `suppressed_repeats` instead of being
    /// emitted. The caller reports nothing.
    SuppressedRepeat,
    /// No tracking slot: the map is at capacity with only live windows
    /// even after the expiry sweep. The request is not counted;
    /// absence of a slot is never treated as a trip.
    Saturated,
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
            saturation_last_warned: Mutex::new(None),
            max_tracked_principals: MAX_TRACKED_PRINCIPALS,
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
        self.decide_at(principal, method, path, Instant::now())
    }

    /// [`Self::decide`] with an explicit clock, so tests can advance
    /// time across tumbling-window boundaries and capacity sweeps.
    /// Production always enters through `decide`, which passes
    /// `Instant::now()`.
    fn decide_at(
        &self,
        principal: &Principal,
        method: &str,
        path: &str,
        now: Instant,
    ) -> Option<Violation> {
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
            // First matching rule with an `object_param` wins, matching
            // the first-match convention the BOLA and BFLA checks use;
            // a later rule that also matches must not silently replace
            // the id an earlier rule already captured.
            if enumeration_hit.is_none() {
                if let Some(obj_param) = &rule.object_param {
                    if let Some(obj_id) = bindings.get(obj_param) {
                        enumeration_hit = Some(obj_id.clone());
                    }
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
            // An owner-less principal is never keyed into the tracker.
            // Both sources already imply an identified caller (a matched
            // ownership rule refuses an anonymous caller as BOLA above,
            // and the heuristic checks `owner.is_some()`), but this
            // binding makes that structural rather than incidental: the
            // key is built from the owner itself, so a future edit to
            // either source cannot reintroduce a shared `""` bucket
            // where N innocent anonymous callers look like one attacker.
            if let (Some(obj_id), Some(owner)) = (obj_id, principal.owner.as_deref()) {
                let tenant = if principal.tenant.is_empty() {
                    DEFAULT_TENANT
                } else {
                    principal.tenant.as_str()
                };
                let violation = |suppressed: u64| {
                    let mut message = format!(
                        "caller '{}' touched more than {} distinct object ids within {}s",
                        owner, self.enumeration.max_distinct, self.enumeration.window_secs
                    );
                    if !rule_derived {
                        message.push_str(
                            " (ruleless path-shape heuristic; reported for audit only, not blocked)",
                        );
                    }
                    if suppressed > 0 {
                        message.push_str(&format!(
                            "; {suppressed} repeat hit(s) since the last audited violation were suppressed from the audit feed"
                        ));
                    }
                    Violation {
                        kind: ViolationKind::Enumeration,
                        message,
                        detect_only: !rule_derived,
                    }
                };
                match self.record_and_check_enumeration(tenant, owner, &obj_id, rule_derived, now) {
                    EnumerationOutcome::UnderThreshold
                    | EnumerationOutcome::SuppressedRepeat
                    | EnumerationOutcome::Saturated => {}
                    EnumerationOutcome::Tripped {
                        suppressed_since_last_emission,
                    } => {
                        return Some(violation(suppressed_since_last_emission));
                    }
                    EnumerationOutcome::StillTripped => {
                        return Some(violation(0));
                    }
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

    /// Record an object-id access for `(tenant, owner)` and report
    /// where that leaves the principal's window: under threshold,
    /// freshly tripped, still tripped, a suppressed detect-only
    /// repeat, or refused a slot entirely.
    ///
    /// O(1) amortized on every path but one: no full-history scan runs
    /// on any call, and the lock is held only long enough to touch one
    /// `EnumerationWindow` whose own state is bounded to `max_distinct`
    /// entries, so the work done under the lock cannot grow with how
    /// much traffic the principal generated. See `EnumerationWindow`'s
    /// own doc comment for the tumbling-window trade this makes to get
    /// there.
    ///
    /// The exception is the at-capacity boundary. Tracking is bounded
    /// at `max_tracked_principals` entries: an already-tracked
    /// principal always gets to update its own state, cap or no cap,
    /// but when a *new* principal arrives at a full map, entries whose
    /// tumbling window has already expired are swept first (one O(n)
    /// `retain`, paid only on this boundary case), and the new
    /// principal is admitted into a freed slot. The sweep never
    /// touches a window that is still current, so no live principal's
    /// state is ever wiped by another principal's flood, and the map
    /// self-heals within one window the way the pre-cap code did.
    /// Only when every slot holds a genuinely live window is the new
    /// principal refused: its request is then simply not counted
    /// (best-effort; absence of a slot is never treated as a trip),
    /// the same shape `sbproxy_extension::mcp::peer_profile`'s
    /// `ObservationVerdict::Saturated` uses, with each refusal counted
    /// on `sbproxy_object_authz_enumeration_tracker_saturated_total`.
    fn record_and_check_enumeration(
        &self,
        tenant: &str,
        owner: &str,
        object_id: &str,
        rule_derived: bool,
        now: Instant,
    ) -> EnumerationOutcome {
        let window = Duration::from_secs(self.enumeration.window_secs.max(1));
        let key = (tenant.to_string(), owner.to_string());
        let mut tracker = self.tracker.lock();

        if !tracker.contains_key(&key) && tracker.len() >= self.max_tracked_principals {
            // Sweep expired windows before refusing: an entry whose
            // window already rolled over holds no signal (its next
            // touch would reset it anyway), so evicting it cannot lose
            // a live count. Only refuse when the map is still full of
            // current windows afterward.
            tracker.retain(|_, w| now.duration_since(w.window_start) <= window);
            if tracker.len() >= self.max_tracked_principals {
                drop(tracker);
                self.report_enumeration_tracker_saturated(now);
                return EnumerationOutcome::Saturated;
            }
        }

        let entry = tracker
            .entry(key)
            .or_insert_with(|| EnumerationWindow::new(now));

        if now.duration_since(entry.window_start) > window {
            entry.window_start = now;
            entry.ids.clear();
            entry.tripped = false;
            // `suppressed_repeats` deliberately survives the rollover:
            // it counts "since the last emission", not "this window",
            // so the tally lands in the next emitted violation instead
            // of vanishing at the boundary.
        }

        if entry.tripped {
            if rule_derived {
                // Rule-derived hits block, so every request is refused,
                // audited, and paid for by the client. No suppression.
                return EnumerationOutcome::StillTripped;
            }
            // Detect-only hits are allowed through, so per-request
            // emission would hand a tripped client an unthrottled
            // signed-audit amplifier. Count the repeat for the next
            // emission instead.
            entry.suppressed_repeats = entry.suppressed_repeats.saturating_add(1);
            return EnumerationOutcome::SuppressedRepeat;
        }

        if entry.ids.contains(object_id) {
            // A repeat of an already-counted id never trips the sweep
            // on its own, and never needs to touch the set again.
            return EnumerationOutcome::UnderThreshold;
        }

        entry.ids.insert(object_id.to_string());
        if entry.ids.len() > self.enumeration.max_distinct {
            entry.tripped = true;
            // Membership no longer matters while tripped; free it now
            // instead of carrying `max_distinct` strings for the rest
            // of the window for no further purpose.
            entry.ids.clear();
            entry.ids.shrink_to_fit();
            return EnumerationOutcome::Tripped {
                suppressed_since_last_emission: std::mem::take(&mut entry.suppressed_repeats),
            };
        }
        EnumerationOutcome::UnderThreshold
    }

    /// Report one refused tracking slot: count it on
    /// `sbproxy_object_authz_enumeration_tracker_saturated_total`
    /// (every refusal, so an operator can alert on the episode and see
    /// its size) and re-warn at most once per enumeration window
    /// (recurring, so an operator who missed the first line, or whose
    /// log retention rotated it away, still learns the detector is
    /// refusing new principals; bounded, so a sustained flood cannot
    /// spam the log).
    fn report_enumeration_tracker_saturated(&self, now: Instant) {
        sbproxy_observe::metrics::record_object_authz_tracker_saturated();
        if self.should_emit_saturation_warn(now) {
            tracing::warn!(
                target: "sbproxy::policy::object_authz",
                cap = self.max_tracked_principals,
                "object_authz enumeration tracker is full of live windows; new principals get no enumeration baseline until existing windows expire"
            );
        }
    }

    /// Whether the saturation warn is due: true on the first refusal
    /// and again once per enumeration window for as long as refusals
    /// keep happening.
    fn should_emit_saturation_warn(&self, now: Instant) -> bool {
        let window = Duration::from_secs(self.enumeration.window_secs.max(1));
        let mut last = self.saturation_last_warned.lock();
        match *last {
            Some(prev) if now.duration_since(prev) < window => false,
            _ => {
                *last = Some(now);
                true
            }
        }
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
            tenant: String::new(),
        }
    }

    fn tenant_principal(tenant: &str, owner: &str) -> Principal {
        Principal {
            owner: Some(owner.to_string()),
            roles: Vec::new(),
            tenant: tenant.to_string(),
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

    #[test]
    fn tracker_at_capacity_evicts_expired_windows_and_admits_new_principals() {
        // Review Blocker (v1.13 phase 2): the tracker never evicted, so
        // once `max_tracked_principals` distinct principals had ever
        // been seen, enumeration detection was dead for every new
        // principal for the life of the policy instance. At capacity,
        // entries whose tumbling window already expired must be swept
        // so a new principal is tracked again.
        let mut p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        p.max_tracked_principals = 3;
        let t0 = Instant::now();
        // Fill the map to capacity with principals whose windows will
        // have expired by t1.
        for owner in ["a", "b", "c"] {
            assert_eq!(
                p.decide_at(&principal(Some(owner), &[]), "GET", "/orders/1", t0),
                None
            );
        }
        assert_eq!(p.tracker.lock().len(), 3);
        // One window later, a brand-new principal must be admitted (the
        // expired windows are swept) and must be able to trip the sweep.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(
            p.decide_at(&principal(Some("d"), &[]), "GET", "/orders/1", t1),
            None,
            "a new principal must get a tracking slot once stale windows expired"
        );
        let v = p
            .decide_at(&principal(Some("d"), &[]), "GET", "/orders/2", t1)
            .expect("the newly admitted principal's sweep must trip");
        assert_eq!(v.kind, ViolationKind::Enumeration);
    }

    #[test]
    fn tracker_capacity_sweep_never_wipes_live_windows() {
        let mut p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        p.max_tracked_principals = 3;
        let t0 = Instant::now();
        // Two principals whose windows will be expired at t1...
        for owner in ["a", "b"] {
            assert_eq!(
                p.decide_at(&principal(Some(owner), &[]), "GET", "/orders/1", t0),
                None
            );
        }
        // ...and one whose window is still live at t1.
        let t_mid = t0 + Duration::from_secs(30);
        assert_eq!(
            p.decide_at(&principal(Some("c"), &[]), "GET", "/orders/1", t_mid),
            None
        );
        // A new principal arriving at a full map forces the sweep.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(
            p.decide_at(&principal(Some("d"), &[]), "GET", "/orders/1", t1),
            None
        );
        // The live window survived the sweep with its count intact: a
        // second distinct id inside c's window still trips.
        let v = p
            .decide_at(&principal(Some("c"), &[]), "GET", "/orders/2", t1)
            .expect("a live window must survive the capacity sweep");
        assert_eq!(v.kind, ViolationKind::Enumeration);
        // And the admitted principal is genuinely tracked too.
        let v = p
            .decide_at(&principal(Some("d"), &[]), "GET", "/orders/2", t1)
            .expect("the admitted principal must be tracked");
        assert_eq!(v.kind, ViolationKind::Enumeration);
    }

    #[test]
    fn a_new_principal_at_a_live_capacity_is_skipped_not_tripped() {
        let mut p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        p.max_tracked_principals = 2;
        let t0 = Instant::now();
        for owner in ["a", "b"] {
            assert_eq!(
                p.decide_at(&principal(Some(owner), &[]), "GET", "/orders/1", t0),
                None
            );
        }
        // Map full of genuinely live windows: the new principal is
        // refused a slot, never fabricated into a trip, and existing
        // state is untouched.
        for id in 1..=5 {
            assert_eq!(
                p.decide_at(
                    &principal(Some("c"), &[]),
                    "GET",
                    &format!("/orders/{id}"),
                    t0
                ),
                None,
                "an untracked principal is best-effort skipped, never tripped"
            );
        }
        assert_eq!(p.tracker.lock().len(), 2);
        // Existing principals still update their own state at the cap.
        let v = p
            .decide_at(&principal(Some("a"), &[]), "GET", "/orders/2", t0)
            .expect("a tracked principal still trips at capacity");
        assert_eq!(v.kind, ViolationKind::Enumeration);
    }

    #[test]
    fn enumeration_budgets_are_scoped_per_tenant() {
        // Review Major (v1.13 phase 2): the tracker key carried no
        // tenant identity, so tenant A's user "42" and tenant B's user
        // "42" shared one window, and A tripping the budget handed B's
        // unrelated caller a 403 for the rest of the window. Two
        // tenants with the same principal string must never share a
        // budget.
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 2, "window_secs": 60 }
        }));
        let a = tenant_principal("tenant-a", "42");
        let b = tenant_principal("tenant-b", "42");
        for id in 1..=2 {
            assert_eq!(
                p.decide(&a, "GET", &format!("/tenants/42/orders/{id}")),
                None
            );
        }
        let v = p
            .decide(&a, "GET", "/tenants/42/orders/3")
            .expect("tenant A trips its own budget");
        assert!(!v.detect_only);
        // Tenant B's same-named caller has its own untouched budget.
        for id in [10, 11] {
            assert_eq!(
                p.decide(&b, "GET", &format!("/tenants/42/orders/{id}")),
                None,
                "tenant B must not share tenant A's enumeration budget"
            );
        }
    }

    #[test]
    fn tumbling_window_rollover_resets_the_count_and_clears_the_trip() {
        // Review Major (v1.13 phase 2): the rollover branch (reset
        // window_start, clear ids, clear tripped) had zero coverage
        // because the clock was not injectable. A tripped window must
        // re-arm at the boundary, and an untripped window must restart
        // its distinct count.
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 2, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        let path = |id: u32| format!("/tenants/tenant-a/orders/{id}");
        let t0 = Instant::now();
        for id in 1..=2 {
            assert_eq!(p.decide_at(&caller, "GET", &path(id), t0), None);
        }
        let v = p
            .decide_at(&caller, "GET", &path(3), t0)
            .expect("third distinct id trips");
        assert!(!v.detect_only);
        // Still tripped late in the same window, even for a repeat id.
        assert!(p
            .decide_at(&caller, "GET", &path(1), t0 + Duration::from_secs(59))
            .is_some());
        // One window later the trip is cleared and counting restarts.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(
            p.decide_at(&caller, "GET", &path(4), t1),
            None,
            "rollover must clear the tripped latch"
        );
        assert_eq!(
            p.decide_at(&caller, "GET", &path(5), t1),
            None,
            "rollover must reset the distinct count"
        );
        // The fresh window's own budget still enforces.
        assert!(p.decide_at(&caller, "GET", &path(6), t1).is_some());

        // An untripped window also restarts its count at the boundary:
        // two ids in the first window plus two in the second must not
        // read as four.
        let caller2 = principal(Some("tenant-b"), &[]);
        let path2 = |id: u32| format!("/tenants/tenant-b/orders/{id}");
        for id in 1..=2 {
            assert_eq!(p.decide_at(&caller2, "GET", &path2(id), t0), None);
        }
        for id in 3..=4 {
            assert_eq!(
                p.decide_at(&caller2, "GET", &path2(id), t1),
                None,
                "an untripped window's count must not leak across the boundary"
            );
        }
    }

    #[test]
    fn detect_only_trip_is_audited_once_per_window_and_repeats_ride_the_next_emission() {
        // Review Major (v1.13 phase 2): a tripped detect-only principal
        // emitted one signed audit record per request with no
        // backpressure (the request is allowed through, so nothing
        // throttles the client). After the window's first detect-only
        // violation, repeats must be suppressed and counted, with the
        // count landing in the next emitted violation.
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        let caller = principal(Some("tenant-a"), &[]);
        let t0 = Instant::now();
        assert_eq!(p.decide_at(&caller, "GET", "/orders/1", t0), None);
        let first = p
            .decide_at(&caller, "GET", "/orders/2", t0)
            .expect("second distinct id trips the heuristic");
        assert!(first.detect_only);
        assert!(!first.message.contains("suppressed"));
        // Repeat hits inside the tripped window are allowed through
        // anyway; they must not each mint a fresh audit record.
        for id in 3..=5 {
            assert_eq!(
                p.decide_at(&caller, "GET", &format!("/orders/{id}"), t0),
                None,
                "repeat detect-only hits must be suppressed, not re-emitted"
            );
        }
        // The next emitted violation carries the suppressed count.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(p.decide_at(&caller, "GET", "/orders/10", t1), None);
        let second = p
            .decide_at(&caller, "GET", "/orders/11", t1)
            .expect("the next window's sweep trips again");
        assert!(second.detect_only);
        assert!(
            second.message.contains("3 repeat hit(s)"),
            "the suppressed-repeat count must land in the next emission, got: {}",
            second.message
        );
    }

    #[test]
    fn an_owner_less_principal_is_never_keyed_into_the_tracker() {
        // Review Major (v1.13 phase 2): the pre-fix key construction
        // fell back to `""` for a missing owner. Through `decide` that
        // bucket was already unreachable (a matched ownership rule
        // refuses an anonymous caller as BOLA before counting, and the
        // heuristic requires an owner), so this is a structural pin
        // rather than a behavior change: whatever path produces an
        // object id, the key is built from the owner itself, and an
        // anonymous caller leaves no tracker entry on either path.
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/tenants/{owner}/orders/{id}", "owner_param": "owner", "object_param": "id" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        let anonymous = principal(None, &[]);
        for id in 1..=5 {
            let v = p
                .decide(&anonymous, "GET", &format!("/tenants/tenant-a/orders/{id}"))
                .expect("anonymous caller on an owned scope is refused as BOLA");
            assert_eq!(v.kind, ViolationKind::Bola);
        }
        assert!(
            p.tracker.lock().is_empty(),
            "an owner-less principal must never occupy a tracker slot"
        );

        // Same property on the ruleless heuristic path.
        let p2 = policy(serde_json::json!({
            "enumeration": { "enabled": true, "max_distinct": 1, "window_secs": 60 }
        }));
        for id in 1..=5 {
            assert_eq!(p2.decide(&anonymous, "GET", &format!("/orders/{id}")), None);
        }
        assert!(p2.tracker.lock().is_empty());
    }

    #[test]
    fn first_matching_rules_object_param_wins_for_enumeration() {
        // Review finding: with two rules matching one path, the LAST
        // rule's `object_param` silently won, unlike the first-match
        // convention the other checks use. Under last-wins the constant
        // trailing segment below would collapse a real sweep across
        // `{id}` into one "distinct" id and never trip.
        let p = policy(serde_json::json!({
            "object_rules": [
                { "path": "/x/{owner}/{id}/detail", "owner_param": "owner", "object_param": "id" },
                { "path": "/x/{owner}/*/{tail}", "owner_param": "owner", "object_param": "tail" }
            ],
            "enumeration": { "enabled": true, "max_distinct": 2, "window_secs": 60 }
        }));
        let caller = principal(Some("u1"), &[]);
        for id in 1..=2 {
            assert_eq!(
                p.decide(&caller, "GET", &format!("/x/u1/{id}/detail")),
                None
            );
        }
        let v = p
            .decide(&caller, "GET", "/x/u1/3/detail")
            .expect("the first matching rule's object_param is the one counted");
        assert_eq!(v.kind, ViolationKind::Enumeration);
        assert!(!v.detect_only);
    }

    #[test]
    fn saturation_warn_is_rate_limited_but_recurring() {
        // Review Major (v1.13 phase 2): the saturation warn was a
        // one-shot AtomicBool per policy instance, so every episode
        // after the first was silent. It must recur once per window
        // for as long as refusals continue.
        let p = policy(serde_json::json!({
            "enumeration": { "enabled": true, "window_secs": 60 }
        }));
        let t0 = Instant::now();
        assert!(p.should_emit_saturation_warn(t0), "first refusal warns");
        assert!(
            !p.should_emit_saturation_warn(t0 + Duration::from_secs(1)),
            "the same window stays quiet"
        );
        assert!(!p.should_emit_saturation_warn(t0 + Duration::from_secs(59)));
        assert!(
            p.should_emit_saturation_warn(t0 + Duration::from_secs(120)),
            "a later episode re-warns"
        );
    }
}
