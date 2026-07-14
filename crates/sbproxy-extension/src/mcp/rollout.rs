//! Tool rollout plane: multiple live versions of one MCP tool with
//! per-consumer resolution.
//!
//! MCP has no tool version field, so publishing a breaking change
//! normally means breaking every caller at once. This module lets the
//! gateway serve several versions of a tool simultaneously and pick
//! the right one per consumer through a resolution ladder, most
//! specific first:
//!
//! 1. **Call**: a version requirement in the `tools/call` request
//!    `_meta` (`sbproxy.dev/version`).
//! 2. **Session**: requirements declared once in `initialize`
//!    `_meta.tool_requirements`, held on the MCP session.
//! 3. **Pin**: operator config matching the authenticated principal.
//! 4. **Alias**: a version-suffixed catalogue name (`search_v1`).
//! 5. **Default**: the tool's declared default, else the highest
//!    version.
//!
//! Requirements are semver ranges (`^1`, `~1.4`, `>=1, <2`). Each
//! resolved version routes to its own federated server, optionally
//! through request/response adapters once the old upstream is
//! retired. Versions carry a sunset date; past it the gateway warns
//! or blocks per config.
//!
//! The engine is pure: it owns no I/O and no locks. The action
//! compiles a `RolloutPlan` once per config load and consults it per
//! request.

use std::collections::{BTreeMap, HashMap};

use chrono::NaiveDate;
use sbproxy_plugin::Principal;
use semver::{Version, VersionReq};

use super::access_control::McpPrincipalSelector;

/// `_meta` key carrying a per-call version requirement on
/// `tools/call`, and the per-tool version stamped on `tools/list`
/// entries.
pub const META_VERSION_KEY: &str = "sbproxy.dev/version";
/// `_meta` key on `initialize` carrying a `{tool: requirement}` map.
pub const META_REQUIREMENTS_KEY: &str = "sbproxy.dev/tool_requirements";
/// `_meta` key listing every available version of a tool.
pub const META_AVAILABLE_KEY: &str = "sbproxy.dev/available";
/// `_meta` key carrying a version's sunset date, when set.
pub const META_SUNSET_KEY: &str = "sbproxy.dev/sunset";

/// How a version behaves once its sunset date has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SunsetBehavior {
    /// Keep serving, annotate as deprecated, count the calls.
    #[default]
    Warn,
    /// Fail `tools/call` with a typed error naming the sunset.
    Block,
}

/// Adapter references for translating between tool versions. Each is
/// a runtime-prefixed script reference (`js:...`, `cel:...`) executed
/// by the extension runtimes at dispatch time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdapterPair {
    /// Transforms the caller's v-old arguments into the upstream's
    /// v-new arguments before dispatch.
    pub request: Option<String>,
    /// Transforms the upstream's v-new result back into the v-old
    /// shape the caller expects.
    pub response: Option<String>,
}

/// One published version of a tool, as configured.
#[derive(Debug, Clone, Default)]
pub struct VersionSpec {
    /// Semver string (`"1.4.0"`).
    pub version: String,
    /// Federated server that serves this version natively. When
    /// absent, the version dispatches to the tool's default-version
    /// server (through the adapter, if one is set).
    pub server: Option<String>,
    /// Optional request/response adapters for serving this version
    /// off a newer upstream.
    pub adapter: Option<AdapterPair>,
    /// Inline contract (a `tools/list` tool object) advertised for
    /// this version when no live upstream serves it. When absent the
    /// lockfile's embedded contract (or the live schema) is used.
    pub contract: Option<serde_json::Value>,
    /// `YYYY-MM-DD` date after which the version is past sunset.
    pub sunset: Option<String>,
    /// Behavior once past sunset.
    pub after_sunset: SunsetBehavior,
}

/// Rollout configuration for one tool.
#[derive(Debug, Clone, Default)]
pub struct ToolRolloutSpec {
    /// Published versions. At least one is required.
    pub versions: Vec<VersionSpec>,
    /// Version served when nothing more specific matches. Must be
    /// one of `versions`. Absent means the highest version.
    pub default: Option<String>,
    /// Advertise `"{tool}_v{major}"` catalogue aliases so clients
    /// without identity or `_meta` support can still choose.
    pub aliases: bool,
}

/// One identity pin: a principal selector and the version
/// requirements it pins.
#[derive(Debug, Clone, Default)]
pub struct PinSpec {
    /// Which principals this pin applies to.
    pub selector: McpPrincipalSelector,
    /// `{tool: semver requirement}`.
    pub requirements: HashMap<String, String>,
}

/// Full rollout configuration, as parsed from `sb.yml`.
#[derive(Debug, Clone, Default)]
pub struct RolloutSpec {
    /// Per-tool rollout, keyed by the base tool name.
    pub tools: HashMap<String, ToolRolloutSpec>,
    /// Identity pins, first match wins in declaration order.
    pub pins: Vec<PinSpec>,
}

/// A compiled, validated version entry.
#[derive(Debug, Clone)]
pub struct VersionEntry {
    /// Parsed version.
    pub version: Version,
    /// Federated server for this version, when routed.
    pub server: Option<String>,
    /// Adapters, when translated onto a newer upstream.
    pub adapter: Option<AdapterPair>,
    /// Inline advertised contract, when configured.
    pub contract: Option<serde_json::Value>,
    /// Parsed sunset date.
    pub sunset: Option<NaiveDate>,
    /// Behavior past sunset.
    pub after_sunset: SunsetBehavior,
}

/// Which rung of the ladder chose the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `tools/call` `_meta` requirement.
    CallMeta,
    /// Session requirements from `initialize`.
    Session,
    /// Operator pin on the principal.
    Pin,
    /// Version-suffixed catalogue alias.
    Alias,
    /// Tool default (explicit or highest version).
    Default,
}

impl Via {
    /// Stable label for metrics.
    pub fn label(self) -> &'static str {
        match self {
            Via::CallMeta => "meta",
            Via::Session => "session",
            Via::Pin => "pin",
            Via::Alias => "alias",
            Via::Default => "default",
        }
    }
}

/// Deprecation state carried on a resolved version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationNotice {
    /// The configured sunset date.
    pub sunset: NaiveDate,
    /// True when `today` is strictly past the sunset date.
    pub past_sunset: bool,
}

/// A successful resolution.
#[derive(Debug, Clone)]
pub struct Resolved<'p> {
    /// Base tool name (aliases resolve back to it).
    pub base: &'p str,
    /// The chosen version entry.
    pub entry: &'p VersionEntry,
    /// Which ladder rung chose it.
    pub via: Via,
    /// Present when the version has a sunset date.
    pub deprecation: Option<DeprecationNotice>,
}

/// Why resolution failed for a managed tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A requirement string did not parse as a semver range.
    InvalidRequirement {
        /// The offending requirement.
        requirement: String,
        /// Parser detail.
        detail: String,
    },
    /// No published version satisfies the requirement.
    NoMatchingVersion {
        /// The requirement that could not be satisfied.
        requirement: String,
    },
    /// The resolved version is past sunset and configured to block.
    SunsetBlocked {
        /// The blocked version.
        version: Version,
        /// Its sunset date.
        sunset: NaiveDate,
    },
}

/// Inputs to one resolution: the ladder's upper rungs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolutionInput<'a> {
    /// Per-call requirement from `tools/call` `_meta`.
    pub call_req: Option<&'a str>,
    /// Per-session requirements declared at `initialize`.
    pub session_reqs: Option<&'a HashMap<String, String>>,
    /// Authenticated principal, for pins.
    pub principal: Option<&'a Principal>,
    /// Today's date, injected for testability.
    pub today: NaiveDate,
}

/// One tool's entry in a catalogue view: which version this consumer
/// sees under the base name, plus any alias entries.
#[derive(Debug, Clone)]
pub struct ViewDecision<'p> {
    /// Base tool name.
    pub base: &'p str,
    /// Version served under the base name for this consumer.
    pub chosen: &'p VersionEntry,
    /// `(alias name, version)` catalogue entries, when enabled.
    pub aliases: Vec<(String, &'p VersionEntry)>,
    /// `_meta` object to stamp on the base entry: version, available
    /// versions, sunset when set.
    pub meta: serde_json::Value,
}

/// Compiled rollout plan.
#[derive(Debug, Clone, Default)]
pub struct RolloutPlan {
    tools: HashMap<String, CompiledTool>,
    pins: Vec<CompiledPin>,
    aliases: HashMap<String, (String, u64)>,
}

#[derive(Debug, Clone)]
struct CompiledTool {
    versions: BTreeMap<Version, VersionEntry>,
    default: Version,
    aliases: bool,
}

#[derive(Debug, Clone)]
struct CompiledPin {
    selector: McpPrincipalSelector,
    requirements: HashMap<String, (String, VersionReq)>,
}

impl RolloutPlan {
    /// Compile and validate a spec. Rejects unparsable versions,
    /// requirements, dates, defaults not among the versions, empty
    /// version lists, duplicate versions, and alias names that
    /// collide with another managed tool.
    pub fn compile(spec: &RolloutSpec) -> Result<Self, String> {
        let mut tools = HashMap::new();
        for (name, t) in &spec.tools {
            if t.versions.is_empty() {
                return Err(format!("rollout tool '{name}': versions must not be empty"));
            }
            let mut versions = BTreeMap::new();
            for vs in &t.versions {
                let ver: Version = vs.version.parse().map_err(|e| {
                    format!(
                        "rollout tool '{name}': version '{}' is not semver: {e}",
                        vs.version
                    )
                })?;
                let sunset = match &vs.sunset {
                    None => None,
                    Some(s) => Some(NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| {
                        format!(
                            "rollout tool '{name}' {ver}: sunset '{s}' is not \
                                 YYYY-MM-DD: {e}"
                        )
                    })?),
                };
                let entry = VersionEntry {
                    version: ver.clone(),
                    server: vs.server.clone(),
                    adapter: vs.adapter.clone(),
                    contract: vs.contract.clone(),
                    sunset,
                    after_sunset: vs.after_sunset,
                };
                if versions.insert(ver.clone(), entry).is_some() {
                    return Err(format!("rollout tool '{name}': duplicate version {ver}"));
                }
            }
            let default = match &t.default {
                Some(d) => {
                    let dv: Version = d.parse().map_err(|e| {
                        format!("rollout tool '{name}': default '{d}' is not semver: {e}")
                    })?;
                    if !versions.contains_key(&dv) {
                        return Err(format!(
                            "rollout tool '{name}': default {dv} is not among the \
                             published versions"
                        ));
                    }
                    dv
                }
                None => versions
                    .keys()
                    .next_back()
                    .cloned()
                    .expect("versions checked non-empty above"),
            };
            tools.insert(
                name.clone(),
                CompiledTool {
                    versions,
                    default,
                    aliases: t.aliases,
                },
            );
        }

        let mut aliases: HashMap<String, (String, u64)> = HashMap::new();
        for (name, tool) in &tools {
            if !tool.aliases {
                continue;
            }
            let majors: std::collections::BTreeSet<u64> =
                tool.versions.keys().map(|v| v.major).collect();
            for major in majors {
                let alias = format!("{name}_v{major}");
                if tools.contains_key(&alias) {
                    return Err(format!(
                        "rollout tool '{name}': alias '{alias}' collides with a \
                         managed tool of that name"
                    ));
                }
                aliases.insert(alias, (name.clone(), major));
            }
        }

        let mut pins = Vec::with_capacity(spec.pins.len());
        for (idx, p) in spec.pins.iter().enumerate() {
            let mut requirements = HashMap::new();
            for (tool, req) in &p.requirements {
                let parsed = VersionReq::parse(req).map_err(|e| {
                    format!(
                        "rollout pin #{}: requirement '{req}' for '{tool}' is not a \
                         semver range: {e}",
                        idx + 1
                    )
                })?;
                requirements.insert(tool.clone(), (req.clone(), parsed));
            }
            pins.push(CompiledPin {
                selector: p.selector.clone(),
                requirements,
            });
        }

        Ok(Self {
            tools,
            pins,
            aliases,
        })
    }

    /// True when the plan manages no tools (rollout not configured).
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// True when `name` is a managed base tool or alias.
    pub fn manages(&self, name: &str) -> bool {
        self.tools.contains_key(name) || self.aliases.contains_key(name)
    }

    /// Resolve `name` (base or alias) for one consumer. Returns
    /// `None` for tools the plan does not manage; dispatch passes
    /// those through untouched.
    pub fn resolve<'p>(
        &'p self,
        name: &str,
        input: &ResolutionInput<'_>,
    ) -> Option<Result<Resolved<'p>, ResolveError>> {
        let (base, tool, alias_major) = match self.tools.get_key_value(name) {
            Some((k, t)) => (k.as_str(), t, None),
            None => {
                let (b, major) = self.aliases.get(name)?;
                let t = self.tools.get(b).expect("aliases only index managed tools");
                (b.as_str(), t, Some(*major))
            }
        };
        Some(self.resolve_inner(base, tool, alias_major, input))
    }

    /// Build the catalogue view decisions for one consumer: for every
    /// managed tool, which version it sees and which aliases exist.
    /// Deterministic base-name order.
    pub fn view<'p>(&'p self, input: &ResolutionInput<'_>) -> Vec<ViewDecision<'p>> {
        let mut names: Vec<&String> = self.tools.keys().collect();
        names.sort();
        let view_input = ResolutionInput {
            call_req: None,
            ..*input
        };
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let tool = &self.tools[name.as_str()];
            // The catalogue always shows something: a consumer whose
            // resolution fails (unsatisfiable pin, sunset-blocked
            // version) sees the tool's default so it can migrate.
            let chosen = match self.resolve_inner(name, tool, None, &view_input) {
                Ok(r) => r.entry,
                Err(_) => &tool.versions[&tool.default],
            };
            let aliases: Vec<(String, &'p VersionEntry)> = if tool.aliases {
                let majors: std::collections::BTreeSet<u64> =
                    tool.versions.keys().map(|v| v.major).collect();
                majors
                    .into_iter()
                    .map(|major| {
                        let entry = Self::highest_of_major(tool, major)
                            .expect("majors derive from published versions");
                        (format!("{name}_v{major}"), entry)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let mut meta = serde_json::Map::new();
            meta.insert(
                META_VERSION_KEY.to_string(),
                chosen.version.to_string().into(),
            );
            meta.insert(
                META_AVAILABLE_KEY.to_string(),
                tool.versions
                    .keys()
                    .map(|v| serde_json::Value::from(v.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
            );
            if let Some(s) = chosen.sunset {
                meta.insert(
                    META_SUNSET_KEY.to_string(),
                    s.format("%Y-%m-%d").to_string().into(),
                );
            }
            out.push(ViewDecision {
                base: name.as_str(),
                chosen,
                aliases,
                meta: serde_json::Value::Object(meta),
            });
        }
        out
    }

    /// Run the ladder for one managed tool.
    fn resolve_inner<'p>(
        &'p self,
        base: &'p str,
        tool: &'p CompiledTool,
        alias_major: Option<u64>,
        input: &ResolutionInput<'_>,
    ) -> Result<Resolved<'p>, ResolveError> {
        let (entry, via) = if let Some(req) = input.call_req {
            (Self::pick_str(tool, req)?, Via::CallMeta)
        } else if let Some(req) = input.session_reqs.and_then(|m| m.get(base)) {
            (Self::pick_str(tool, req)?, Via::Session)
        } else if let Some((raw, req)) = self.pin_for(input.principal, base) {
            (Self::pick_req(tool, raw, req)?, Via::Pin)
        } else if let Some(major) = alias_major {
            (
                Self::highest_of_major(tool, major)
                    .expect("aliases derive from published versions"),
                Via::Alias,
            )
        } else {
            (&tool.versions[&tool.default], Via::Default)
        };

        let deprecation = entry.sunset.map(|sunset| DeprecationNotice {
            sunset,
            past_sunset: input.today > sunset,
        });
        if let Some(d) = &deprecation {
            if d.past_sunset && entry.after_sunset == SunsetBehavior::Block {
                return Err(ResolveError::SunsetBlocked {
                    version: entry.version.clone(),
                    sunset: d.sunset,
                });
            }
        }
        Ok(Resolved {
            base,
            entry,
            via,
            deprecation,
        })
    }

    /// First pin whose selector matches the principal and that pins
    /// this tool. Declaration order wins.
    fn pin_for(&self, principal: Option<&Principal>, base: &str) -> Option<(&str, &VersionReq)> {
        let principal = principal?;
        self.pins
            .iter()
            .filter(|pin| pin.selector.matches(principal))
            .find_map(|pin| pin.requirements.get(base))
            .map(|(raw, req)| (raw.as_str(), req))
    }

    /// Parse and match a requirement string against the published
    /// versions, highest match wins.
    fn pick_str<'p>(tool: &'p CompiledTool, req: &str) -> Result<&'p VersionEntry, ResolveError> {
        let parsed = VersionReq::parse(req).map_err(|e| ResolveError::InvalidRequirement {
            requirement: req.to_string(),
            detail: e.to_string(),
        })?;
        Self::pick_req(tool, req, &parsed)
    }

    /// Match a pre-parsed requirement, highest match wins.
    fn pick_req<'p>(
        tool: &'p CompiledTool,
        raw: &str,
        req: &VersionReq,
    ) -> Result<&'p VersionEntry, ResolveError> {
        tool.versions
            .iter()
            .rev()
            .find(|(v, _)| req.matches(v))
            .map(|(_, e)| e)
            .ok_or_else(|| ResolveError::NoMatchingVersion {
                requirement: raw.to_string(),
            })
    }

    /// Highest published version with the given major.
    fn highest_of_major(tool: &CompiledTool, major: u64) -> Option<&VersionEntry> {
        tool.versions
            .iter()
            .rev()
            .find(|(v, _)| v.major == major)
            .map(|(_, e)| e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_plugin::{PrincipalAttrs, PrincipalSource, TenantId, VirtualKeyRef};

    fn principal(sub: &str, team: Option<&str>, vk: Option<&str>) -> Principal {
        Principal {
            tenant_id: TenantId::from("acme"),
            sub: sub.to_string(),
            source: PrincipalSource::Bearer,
            virtual_key: vk.map(|n| VirtualKeyRef {
                name: n.to_string(),
                allowed_providers: vec![],
            }),
            attrs: PrincipalAttrs {
                team: team.map(str::to_string),
                ..PrincipalAttrs::default()
            },
        }
    }

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn v(s: &str) -> VersionSpec {
        VersionSpec {
            version: s.to_string(),
            ..VersionSpec::default()
        }
    }

    /// Two versions of `search`: 1.4.0 routed to `legacy-api`,
    /// 2.0.0 on `new-api`, aliases on.
    fn search_spec() -> RolloutSpec {
        let mut tools = HashMap::new();
        tools.insert(
            "search".to_string(),
            ToolRolloutSpec {
                versions: vec![
                    VersionSpec {
                        version: "1.4.0".into(),
                        server: Some("legacy-api".into()),
                        ..VersionSpec::default()
                    },
                    VersionSpec {
                        version: "2.0.0".into(),
                        server: Some("new-api".into()),
                        ..VersionSpec::default()
                    },
                ],
                default: None,
                aliases: true,
            },
        );
        RolloutSpec {
            tools,
            pins: vec![PinSpec {
                selector: McpPrincipalSelector {
                    team: Some("checkout".into()),
                    ..McpPrincipalSelector::default()
                },
                requirements: HashMap::from([("search".to_string(), "^1".to_string())]),
            }],
        }
    }

    fn input<'a>() -> ResolutionInput<'a> {
        ResolutionInput {
            today: day("2026-07-13"),
            ..ResolutionInput::default()
        }
    }

    #[test]
    fn compile_rejects_bad_semver() {
        let mut spec = RolloutSpec::default();
        spec.tools.insert(
            "t".into(),
            ToolRolloutSpec {
                versions: vec![v("not-a-version")],
                ..ToolRolloutSpec::default()
            },
        );
        assert!(RolloutPlan::compile(&spec).is_err());
    }

    #[test]
    fn compile_rejects_default_not_among_versions() {
        let mut spec = RolloutSpec::default();
        spec.tools.insert(
            "t".into(),
            ToolRolloutSpec {
                versions: vec![v("1.0.0")],
                default: Some("2.0.0".into()),
                ..ToolRolloutSpec::default()
            },
        );
        assert!(RolloutPlan::compile(&spec).is_err());
    }

    #[test]
    fn compile_rejects_empty_versions() {
        let mut spec = RolloutSpec::default();
        spec.tools.insert("t".into(), ToolRolloutSpec::default());
        assert!(RolloutPlan::compile(&spec).is_err());
    }

    #[test]
    fn compile_rejects_bad_pin_requirement() {
        let mut spec = search_spec();
        spec.pins[0]
            .requirements
            .insert("search".into(), "not a req".into());
        assert!(RolloutPlan::compile(&spec).is_err());
    }

    #[test]
    fn compile_rejects_alias_collision_with_managed_tool() {
        let mut spec = search_spec();
        // A second managed tool literally named like the alias the
        // first tool will advertise.
        spec.tools.insert(
            "search_v1".into(),
            ToolRolloutSpec {
                versions: vec![v("1.0.0")],
                ..ToolRolloutSpec::default()
            },
        );
        assert!(RolloutPlan::compile(&spec).is_err());
    }

    #[test]
    fn compile_rejects_bad_sunset_date() {
        let mut spec = RolloutSpec::default();
        spec.tools.insert(
            "t".into(),
            ToolRolloutSpec {
                versions: vec![VersionSpec {
                    version: "1.0.0".into(),
                    sunset: Some("soon".into()),
                    ..VersionSpec::default()
                }],
                ..ToolRolloutSpec::default()
            },
        );
        assert!(RolloutPlan::compile(&spec).is_err());
    }

    #[test]
    fn unmanaged_tool_resolves_none() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        assert!(plan.resolve("weather", &input()).is_none());
        assert!(!plan.manages("weather"));
    }

    #[test]
    fn default_is_highest_version_when_unset() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let r = plan.resolve("search", &input()).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(2, 0, 0));
        assert_eq!(r.via, Via::Default);
        assert_eq!(r.base, "search");
        assert_eq!(r.entry.server.as_deref(), Some("new-api"));
    }

    #[test]
    fn explicit_default_wins_over_highest() {
        let mut spec = search_spec();
        spec.tools.get_mut("search").unwrap().default = Some("1.4.0".into());
        let plan = RolloutPlan::compile(&spec).unwrap();
        let r = plan.resolve("search", &input()).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(1, 4, 0));
        assert_eq!(r.via, Via::Default);
    }

    #[test]
    fn pin_selects_highest_matching_version() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let p = principal("dev-1", Some("checkout"), None);
        let mut i = input();
        i.principal = Some(&p);
        let r = plan.resolve("search", &i).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(1, 4, 0));
        assert_eq!(r.via, Via::Pin);
    }

    #[test]
    fn non_matching_principal_ignores_pin() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let p = principal("dev-1", Some("payments"), None);
        let mut i = input();
        i.principal = Some(&p);
        let r = plan.resolve("search", &i).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(2, 0, 0));
        assert_eq!(r.via, Via::Default);
    }

    #[test]
    fn session_requirements_override_pin() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let p = principal("dev-1", Some("checkout"), None);
        let session = HashMap::from([("search".to_string(), "^2".to_string())]);
        let mut i = input();
        i.principal = Some(&p);
        i.session_reqs = Some(&session);
        let r = plan.resolve("search", &i).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(2, 0, 0));
        assert_eq!(r.via, Via::Session);
    }

    #[test]
    fn call_requirement_overrides_session() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let session = HashMap::from([("search".to_string(), "^2".to_string())]);
        let mut i = input();
        i.session_reqs = Some(&session);
        i.call_req = Some("~1.4");
        let r = plan.resolve("search", &i).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(1, 4, 0));
        assert_eq!(r.via, Via::CallMeta);
    }

    #[test]
    fn invalid_call_requirement_is_typed_error() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let mut i = input();
        i.call_req = Some("not a req");
        match plan.resolve("search", &i).unwrap() {
            Err(ResolveError::InvalidRequirement { requirement, .. }) => {
                assert_eq!(requirement, "not a req");
            }
            other => panic!("expected InvalidRequirement, got {other:?}"),
        }
    }

    #[test]
    fn unsatisfiable_requirement_is_typed_error() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let mut i = input();
        i.call_req = Some("^3");
        match plan.resolve("search", &i).unwrap() {
            Err(ResolveError::NoMatchingVersion { requirement }) => {
                assert_eq!(requirement, "^3");
            }
            other => panic!("expected NoMatchingVersion, got {other:?}"),
        }
    }

    #[test]
    fn alias_resolves_major_and_base_stays_default() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        assert!(plan.manages("search_v1"));
        let r = plan.resolve("search_v1", &input()).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(1, 4, 0));
        assert_eq!(r.via, Via::Alias);
        assert_eq!(r.base, "search");
        let base = plan.resolve("search", &input()).unwrap().unwrap();
        assert_eq!(base.entry.version, Version::new(2, 0, 0));
    }

    #[test]
    fn aliases_disabled_do_not_resolve() {
        let mut spec = search_spec();
        spec.tools.get_mut("search").unwrap().aliases = false;
        let plan = RolloutPlan::compile(&spec).unwrap();
        assert!(plan.resolve("search_v1", &input()).is_none());
        assert!(!plan.manages("search_v1"));
    }

    #[test]
    fn call_requirement_on_alias_overrides_alias_major() {
        // The alias picks the major, but an explicit call requirement
        // still wins: the ladder is absolute.
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let mut i = input();
        i.call_req = Some("^2");
        let r = plan.resolve("search_v1", &i).unwrap().unwrap();
        assert_eq!(r.entry.version, Version::new(2, 0, 0));
        assert_eq!(r.via, Via::CallMeta);
    }

    #[test]
    fn past_sunset_block_is_blocked() {
        let mut spec = search_spec();
        spec.tools.get_mut("search").unwrap().versions[0].sunset = Some("2026-01-01".into());
        spec.tools.get_mut("search").unwrap().versions[0].after_sunset = SunsetBehavior::Block;
        let plan = RolloutPlan::compile(&spec).unwrap();
        let mut i = input();
        i.call_req = Some("^1");
        match plan.resolve("search", &i).unwrap() {
            Err(ResolveError::SunsetBlocked { version, sunset }) => {
                assert_eq!(version, Version::new(1, 4, 0));
                assert_eq!(sunset, day("2026-01-01"));
            }
            other => panic!("expected SunsetBlocked, got {other:?}"),
        }
    }

    #[test]
    fn past_sunset_warn_resolves_with_deprecation() {
        let mut spec = search_spec();
        spec.tools.get_mut("search").unwrap().versions[0].sunset = Some("2026-01-01".into());
        let plan = RolloutPlan::compile(&spec).unwrap();
        let mut i = input();
        i.call_req = Some("^1");
        let r = plan.resolve("search", &i).unwrap().unwrap();
        let d = r.deprecation.expect("deprecation notice");
        assert!(d.past_sunset);
        assert_eq!(d.sunset, day("2026-01-01"));
    }

    #[test]
    fn future_sunset_resolves_with_notice_not_past() {
        let mut spec = search_spec();
        spec.tools.get_mut("search").unwrap().versions[0].sunset = Some("2026-12-31".into());
        let plan = RolloutPlan::compile(&spec).unwrap();
        let mut i = input();
        i.call_req = Some("^1");
        let r = plan.resolve("search", &i).unwrap().unwrap();
        let d = r.deprecation.expect("deprecation notice");
        assert!(!d.past_sunset);
    }

    #[test]
    fn view_reflects_consumer_and_advertises_aliases() {
        let plan = RolloutPlan::compile(&search_spec()).unwrap();
        let p = principal("dev-1", Some("checkout"), None);
        let mut i = input();
        i.principal = Some(&p);
        let view = plan.view(&i);
        assert_eq!(view.len(), 1);
        let d = &view[0];
        assert_eq!(d.base, "search");
        assert_eq!(d.chosen.version, Version::new(1, 4, 0));
        let alias_names: Vec<&str> = d.aliases.iter().map(|(n, _)| n.as_str()).collect();
        assert!(alias_names.contains(&"search_v1"));
        assert!(alias_names.contains(&"search_v2"));
        assert_eq!(d.meta[META_VERSION_KEY], "1.4.0");
        let available: Vec<String> = d.meta[META_AVAILABLE_KEY]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(available, vec!["1.4.0".to_string(), "2.0.0".to_string()]);
    }

    #[test]
    fn view_meta_carries_sunset() {
        let mut spec = search_spec();
        spec.tools.get_mut("search").unwrap().versions[0].sunset = Some("2026-12-31".into());
        spec.tools.get_mut("search").unwrap().default = Some("1.4.0".into());
        let plan = RolloutPlan::compile(&spec).unwrap();
        let view = plan.view(&input());
        assert_eq!(view[0].meta[META_SUNSET_KEY], "2026-12-31");
    }

    #[test]
    fn adapter_is_carried_through_resolution() {
        let mut spec = search_spec();
        {
            let t = spec.tools.get_mut("search").unwrap();
            t.versions[0].server = None;
            t.versions[0].adapter = Some(AdapterPair {
                request: Some("js:adapters/v1_req.js".into()),
                response: Some("js:adapters/v1_res.js".into()),
            });
        }
        let plan = RolloutPlan::compile(&spec).unwrap();
        let mut i = input();
        i.call_req = Some("^1");
        let r = plan.resolve("search", &i).unwrap().unwrap();
        let a = r.entry.adapter.as_ref().expect("adapter");
        assert_eq!(a.request.as_deref(), Some("js:adapters/v1_req.js"));
        assert!(r.entry.server.is_none());
    }
}
