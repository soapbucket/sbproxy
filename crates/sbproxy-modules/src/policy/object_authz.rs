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
//! The caller identity (owner + roles) is resolved by the enforcer from
//! the verified auth subject (`ctx.auth_result`) or from trusted request
//! headers, and handed to [`ObjectAuthzPolicy::decide`]. Reading the
//! owner from a request header is only safe when a trusted upstream auth
//! layer sets it; the default and recommended source is the verified
//! subject.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Deserialize;

/// Hard cap on the number of principals tracked for enumeration so a
/// flood of distinct principals cannot grow the map without bound. When
/// exceeded, the tracker is cleared (the window is short, so the loss is
/// a brief detection gap, not a correctness problem).
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
#[derive(Debug, Clone, Deserialize)]
pub struct EnumerationConfig {
    /// Master switch. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Distinct object ids per principal within `window_secs` that trip
    /// the anomaly.
    #[serde(default = "default_max_distinct")]
    pub max_distinct: usize,
    /// Sliding window length in seconds.
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
    /// Per-principal sliding window of (time, object_id) for enumeration
    /// detection. Keyed by the owner identity (or `""` when anonymous).
    tracker: Mutex<HashMap<String, VecDeque<(Instant, String)>>>,
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
                    });
                }
                Some(owner) if owner != path_owner => {
                    return Some(Violation {
                        kind: ViolationKind::Bola,
                        message: format!(
                            "caller '{}' accessed object scope owned by '{}'",
                            owner, path_owner
                        ),
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
        if self.enumeration.enabled {
            if let Some(obj_id) = enumeration_hit {
                let key = principal.owner.clone().unwrap_or_default();
                if self.record_and_check_enumeration(&key, &obj_id) {
                    return Some(Violation {
                        kind: ViolationKind::Enumeration,
                        message: format!(
                            "caller '{}' touched more than {} distinct object ids within {}s",
                            key, self.enumeration.max_distinct, self.enumeration.window_secs
                        ),
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
                });
            }
        }

        None
    }

    /// Record an object-id access for `key` and return true when the
    /// distinct count within the window exceeds the threshold.
    fn record_and_check_enumeration(&self, key: &str, object_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.enumeration.window_secs);
        let mut tracker = self.tracker.lock();

        if tracker.len() > MAX_TRACKED_PRINCIPALS && !tracker.contains_key(key) {
            // Short window, so dropping the map is a brief detection gap,
            // not a correctness issue. Avoids unbounded growth under a
            // flood of distinct principals.
            tracker.clear();
        }

        let entry = tracker.entry(key.to_string()).or_default();
        entry.push_back((now, object_id.to_string()));
        while let Some((t, _)) = entry.front() {
            if now.duration_since(*t) > window {
                entry.pop_front();
            } else {
                break;
            }
        }

        let mut seen = std::collections::HashSet::new();
        for (_, id) in entry.iter() {
            seen.insert(id.as_str());
        }
        seen.len() > self.enumeration.max_distinct
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
        // The fourth distinct id trips the sweep detector.
        let v = p
            .decide(&caller, "GET", "/tenants/tenant-a/orders/4")
            .expect("violation");
        assert_eq!(v.kind, ViolationKind::Enumeration);
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
