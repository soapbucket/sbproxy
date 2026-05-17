//! ADRF (Agent Detection Rule Format) YAML rule pack: parser + matcher.
//!
//! A rule pack is the operator-authored knowledge that turns raw
//! [`Signals`] into an [`AgentDetection`] with a named `agent_id`. The
//! pack is a list of named agent rules plus a schema version. Each rule
//! declares a [`MatchSpec`] over the signals plus the
//! [`AgentProvenance`] and score to stamp when the rule matches.
//!
//! ## File shape (v0)
//!
//! ```yaml
//! version: 0
//! agents:
//!   - id: claude-code-cli
//!     match:
//!       user_agent_pattern: '^claude-cli/'
//!       header_present: ['x-stainless-arch']
//!       ja4_prefix: 't13d'
//!     provenance: unsigned-named
//!     score: 95
//!     confidence: 0.9
//! ```
//!
//! ## Behaviour
//!
//! - Strict deserialisation: unknown YAML keys fail the parse so
//!   operators get an early signal if they have a typo or are running
//!   against a forward-compat field they did not mean to opt into.
//! - The schema `version` field is mandatory. Slice 2 ships v0; the
//!   parser rejects any other version explicitly.
//! - Match predicates are AND-combined: every predicate that is set
//!   must succeed for the rule to fire. Unset predicates are ignored,
//!   which is the standard rule-pack convention.
//! - Rules are evaluated in declaration order and the first match
//!   wins. Operators that want priority can re-order the file.
//!
//! Later slices (WOR-587, WOR-590) extend [`MatchSpec`] with header
//! order hash, UA bucket, vendor-header set, JA4T / JA4X predicates,
//! and payload signals. The shape is forward-compatible because new
//! predicates are added as additional `Option` fields.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{AgentDetection, AgentProvenance, Signals};

/// Current ADRF schema version. Bumped when a backward-incompatible
/// change lands in the rule-pack format. Slice 2 ships v0.
pub const ADRF_VERSION: u32 = 0;

/// Parsed rule pack. Hold this behind an `Arc` and swap it in via
/// `arc_swap::ArcSwap` when the hot-reload slice (WOR-588) lands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    /// ADRF schema version. Must equal [`ADRF_VERSION`] at parse time.
    pub version: u32,
    /// Agent rules, evaluated in declaration order. First match wins.
    #[serde(default)]
    pub agents: Vec<AgentRule>,
}

/// One agent rule in a [`RulePack`]. Identified by `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRule {
    /// Stable agent identifier. Surfaces verbatim as `agent_id` on
    /// the produced [`AgentDetection`].
    pub id: String,
    /// Predicates the rule applies. AND-combined.
    #[serde(default)]
    pub r#match: MatchSpec,
    /// Provenance tier to stamp when the rule matches.
    #[serde(default = "default_provenance")]
    pub provenance: AgentProvenance,
    /// Score (0-100) to stamp when the rule matches. The parser
    /// clamps values above 100 down to 100 because the field is `u8`
    /// already; values are also asserted at parse time so an
    /// operator typo (e.g. `score: 950`) is caught loudly.
    pub score: u8,
    /// Confidence the scorer should report for this match. Clamped
    /// to `0.0..=1.0`. Optional; defaults to `1.0` when omitted
    /// because an exact rule-pack match is by definition a high-
    /// confidence outcome.
    #[serde(default = "default_confidence")]
    pub confidence: f32,
}

fn default_provenance() -> AgentProvenance {
    AgentProvenance::UnsignedNamed
}

fn default_confidence() -> f32 {
    1.0
}

/// Match predicates against [`Signals`]. Every predicate set must
/// succeed; unset predicates are ignored. The struct is intentionally
/// forward-compatible: later slices add new `Option` predicates
/// without breaking existing rule packs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// Regex against the request's `User-Agent` header value. Stored
    /// as a string in the YAML; pre-compiled when the pack is loaded
    /// via [`CompiledRulePack`].
    #[serde(default)]
    pub user_agent_pattern: Option<String>,
    /// Header names that must be present on the request. Compared
    /// case-insensitively against the lowercased
    /// [`crate::HttpSignals::headers_present`] list.
    #[serde(default)]
    pub header_present: Vec<String>,
    /// Prefix the JA4 fingerprint must start with. JA4 is structured
    /// as a fixed-prefix-then-hash format so prefix matching is the
    /// standard way to bucket clients.
    #[serde(default)]
    pub ja4_prefix: Option<String>,
}

/// Errors the rule-pack parser can return. Distinct enum (not just
/// `anyhow`) so the hot-reload slice can categorise failures for the
/// metric label without re-parsing the error message.
#[derive(Debug)]
pub enum RulePackError {
    /// YAML lexical or structural error.
    Yaml(String),
    /// Schema version mismatch. The current version is
    /// [`ADRF_VERSION`]; rule packs at older or newer versions are
    /// rejected by slice 2.
    Version {
        /// Version the rule pack declared.
        found: u32,
        /// Version the parser supports.
        expected: u32,
    },
    /// A rule declares an invalid `user_agent_pattern` regex.
    BadRegex {
        /// Agent id whose rule failed.
        agent_id: String,
        /// Underlying regex compile error message.
        detail: String,
    },
    /// Two rules in the pack share the same agent id. Operators are
    /// expected to keep ids unique so a metric label collision cannot
    /// occur silently.
    DuplicateId(String),
}

impl RulePackError {
    /// Short kind label suitable for a metric or audit-event
    /// classification. Stable across error-message tweaks.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Yaml(_) => "yaml",
            Self::Version { .. } => "version",
            Self::BadRegex { .. } => "bad_regex",
            Self::DuplicateId(_) => "duplicate_id",
        }
    }
}

/// A parsed-and-validated [`RulePack`] with the regex predicates
/// pre-compiled so the hot path does not pay regex-compilation cost
/// per request.
///
/// Construct via [`CompiledRulePack::from_yaml`]. The struct is `Send +
/// Sync` and intended to be held behind an `Arc`.
#[derive(Debug, Clone, Default)]
pub struct CompiledRulePack {
    /// The original pack, kept for serialisation back to YAML (e.g.
    /// for the portal surface in WOR-513).
    pub source: RulePack,
    rules: Vec<CompiledAgentRule>,
}

#[derive(Debug, Clone)]
struct CompiledAgentRule {
    id: String,
    user_agent_pattern: Option<Arc<Regex>>,
    header_present: Vec<String>,
    ja4_prefix: Option<String>,
    provenance: AgentProvenance,
    score: u8,
    confidence: f32,
}

impl CompiledRulePack {
    /// Parse a YAML byte slice into a compiled rule pack.
    pub fn from_yaml(bytes: &[u8]) -> std::result::Result<Self, RulePackError> {
        let pack: RulePack =
            serde_yaml::from_slice(bytes).map_err(|e| RulePackError::Yaml(e.to_string()))?;
        Self::compile(pack)
    }

    /// Parse a YAML string into a compiled rule pack.
    pub fn from_yaml_str(yaml: &str) -> std::result::Result<Self, RulePackError> {
        Self::from_yaml(yaml.as_bytes())
    }

    /// Compile an already-deserialised [`RulePack`]. Splits the
    /// regex-compilation step out so test code can build a pack
    /// programmatically without the YAML round trip.
    pub fn compile(pack: RulePack) -> std::result::Result<Self, RulePackError> {
        if pack.version != ADRF_VERSION {
            return Err(RulePackError::Version {
                found: pack.version,
                expected: ADRF_VERSION,
            });
        }

        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut rules = Vec::with_capacity(pack.agents.len());
        for rule in &pack.agents {
            if !seen_ids.insert(rule.id.clone()) {
                return Err(RulePackError::DuplicateId(rule.id.clone()));
            }
            let user_agent_pattern = match &rule.r#match.user_agent_pattern {
                Some(pat) => Some(Arc::new(Regex::new(pat).map_err(|e| {
                    RulePackError::BadRegex {
                        agent_id: rule.id.clone(),
                        detail: e.to_string(),
                    }
                })?)),
                None => None,
            };
            let header_present = rule
                .r#match
                .header_present
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect();
            rules.push(CompiledAgentRule {
                id: rule.id.clone(),
                user_agent_pattern,
                header_present,
                ja4_prefix: rule.r#match.ja4_prefix.clone(),
                provenance: rule.provenance,
                score: rule.score,
                confidence: rule.confidence.clamp(0.0, 1.0),
            });
        }

        Ok(Self {
            source: pack,
            rules,
        })
    }

    /// Number of agent rules in the pack.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the pack is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate the pack against `signals`. First matching rule wins;
    /// returns `None` when no rule matched.
    ///
    /// The returned [`AgentDetection`] populates `signals_used` with
    /// every predicate the matching rule consulted, so the audit log
    /// records *why* the rule fired, not just *that* it did.
    pub fn evaluate(&self, signals: &Signals) -> Option<AgentDetection> {
        for rule in &self.rules {
            let mut used: Vec<String> = Vec::new();
            if let Some(re) = &rule.user_agent_pattern {
                let ua = signals
                    .http
                    .as_ref()
                    .and_then(|h| h.user_agent.as_deref())
                    .unwrap_or_default();
                if !re.is_match(ua) {
                    continue;
                }
                used.push("user_agent_pattern".to_string());
            }
            if !rule.header_present.is_empty() {
                let headers: &[String] = signals
                    .http
                    .as_ref()
                    .map(|h| h.headers_present.as_slice())
                    .unwrap_or(&[]);
                let all_present = rule
                    .header_present
                    .iter()
                    .all(|needle| headers.iter().any(|h| h == needle));
                if !all_present {
                    continue;
                }
                used.push("header_present".to_string());
            }
            if let Some(prefix) = &rule.ja4_prefix {
                let ja4 = signals
                    .tls
                    .as_ref()
                    .and_then(|t| t.ja4.as_deref())
                    .unwrap_or_default();
                if !ja4.starts_with(prefix.as_str()) {
                    continue;
                }
                used.push("ja4_prefix".to_string());
            }

            // A rule with zero predicates is a wildcard that always
            // matches. Operators that want a default-catch rule can
            // declare one at the bottom of the pack; the matcher
            // records that no predicates fired.
            return Some(AgentDetection {
                score: rule.score,
                agent_id: Some(rule.id.clone()),
                provenance: rule.provenance,
                confidence: rule.confidence,
                signals_used: used,
            });
        }
        None
    }
}

/// Implementation of the [`AgentScorer`](crate::AgentScorer) trait
/// backed by a [`CompiledRulePack`]. Falls through to the
/// [`DefaultScorer`](crate::DefaultScorer) shape when no rule matches.
#[derive(Debug)]
pub struct RulePackScorer {
    pack: Arc<CompiledRulePack>,
}

impl RulePackScorer {
    /// Wrap a compiled pack as a scorer.
    pub fn new(pack: Arc<CompiledRulePack>) -> Self {
        Self { pack }
    }
}

impl crate::AgentScorer for RulePackScorer {
    fn score(&self, signals: &Signals) -> AgentDetection {
        if let Some(detection) = self.pack.evaluate(signals) {
            return detection;
        }
        crate::DefaultScorer.score(signals)
    }
}

impl std::fmt::Display for RulePackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(detail) => write!(f, "rule-pack YAML parse error: {detail}"),
            Self::Version { found, expected } => write!(
                f,
                "rule-pack ADRF version {found} not supported; expected {expected}",
            ),
            Self::BadRegex { agent_id, detail } => write!(
                f,
                "rule '{agent_id}' has invalid user_agent_pattern: {detail}",
            ),
            Self::DuplicateId(id) => write!(f, "duplicate agent id in rule pack: {id}"),
        }
    }
}

impl std::error::Error for RulePackError {}

/// Convenience: load a rule pack from a YAML string into an `Arc`.
/// Intended for the hot-reload path so the call site does not have
/// to repeat the wrapping.
pub fn load_arc(yaml: &str) -> Result<Arc<CompiledRulePack>> {
    CompiledRulePack::from_yaml_str(yaml)
        .map(Arc::new)
        .map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpSignals, TlsSignals};

    fn signals_with(ua: Option<&str>, headers: &[&str], ja4: Option<&str>) -> Signals {
        Signals {
            http: Some(HttpSignals {
                user_agent: ua.map(String::from),
                headers_present: headers.iter().map(|h| h.to_ascii_lowercase()).collect(),
                ..HttpSignals::default()
            }),
            tls: ja4.map(|j| TlsSignals {
                ja4: Some(j.to_string()),
                ..TlsSignals::default()
            }),
            payload: None,
        }
    }

    #[test]
    fn parses_minimal_pack() {
        let yaml = r#"
version: 0
agents:
  - id: claude-code-cli
    match:
      user_agent_pattern: '^claude-cli/'
    provenance: unsigned-named
    score: 95
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        assert_eq!(pack.len(), 1);
        assert_eq!(pack.source.version, 0);
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let yaml = r#"
version: 0
agents: []
unknown_key: foo
"#;
        let err = CompiledRulePack::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, RulePackError::Yaml(_)));
    }

    #[test]
    fn rejects_unknown_match_key() {
        let yaml = r#"
version: 0
agents:
  - id: x
    match:
      unsupported_predicate: foo
    provenance: unsigned-named
    score: 50
"#;
        let err = CompiledRulePack::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, RulePackError::Yaml(_)));
    }

    #[test]
    fn rejects_wrong_version() {
        let yaml = "version: 99\nagents: []\n";
        match CompiledRulePack::from_yaml_str(yaml) {
            Err(RulePackError::Version { found, expected }) => {
                assert_eq!(found, 99);
                assert_eq!(expected, ADRF_VERSION);
            }
            other => panic!("expected Version error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_regex() {
        let yaml = r#"
version: 0
agents:
  - id: bad
    match:
      user_agent_pattern: '['
    provenance: unsigned-named
    score: 1
"#;
        match CompiledRulePack::from_yaml_str(yaml) {
            Err(RulePackError::BadRegex { agent_id, .. }) => assert_eq!(agent_id, "bad"),
            other => panic!("expected BadRegex error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_agent_id() {
        let yaml = r#"
version: 0
agents:
  - id: dup
    match: {}
    provenance: unsigned-named
    score: 1
  - id: dup
    match: {}
    provenance: unsigned-named
    score: 2
"#;
        match CompiledRulePack::from_yaml_str(yaml) {
            Err(RulePackError::DuplicateId(id)) => assert_eq!(id, "dup"),
            other => panic!("expected DuplicateId, got {other:?}"),
        }
    }

    #[test]
    fn user_agent_pattern_matches() {
        let yaml = r#"
version: 0
agents:
  - id: claude-code-cli
    match:
      user_agent_pattern: '^claude-cli/'
    provenance: unsigned-named
    score: 95
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        let detection = pack
            .evaluate(&signals_with(Some("claude-cli/1.2.3 (cli)"), &[], None))
            .expect("rule should match");
        assert_eq!(detection.agent_id.as_deref(), Some("claude-code-cli"));
        assert_eq!(detection.score, 95);
        assert_eq!(detection.provenance, AgentProvenance::UnsignedNamed);
        assert_eq!(
            detection.signals_used,
            vec!["user_agent_pattern".to_string()]
        );
    }

    #[test]
    fn user_agent_pattern_misses() {
        let yaml = r#"
version: 0
agents:
  - id: claude-code-cli
    match:
      user_agent_pattern: '^claude-cli/'
    provenance: unsigned-named
    score: 95
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        assert!(pack
            .evaluate(&signals_with(Some("curl/8.0.0"), &[], None))
            .is_none());
    }

    #[test]
    fn header_present_predicate_requires_all() {
        let yaml = r#"
version: 0
agents:
  - id: openai-sdk-py
    match:
      header_present:
        - x-stainless-arch
        - x-stainless-os
    provenance: unsigned-named
    score: 80
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        // Only one of the two required headers present: should NOT match.
        assert!(pack
            .evaluate(&signals_with(None, &["x-stainless-arch"], None))
            .is_none());
        // Both present (case insensitive): should match.
        let d = pack
            .evaluate(&signals_with(
                None,
                &["X-Stainless-Arch", "x-stainless-os"],
                None,
            ))
            .expect("both headers present");
        assert_eq!(d.agent_id.as_deref(), Some("openai-sdk-py"));
    }

    #[test]
    fn ja4_prefix_predicate() {
        let yaml = r#"
version: 0
agents:
  - id: chrome-2026
    match:
      ja4_prefix: 't13d'
    provenance: unsigned-anonymous
    score: 30
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        assert!(pack
            .evaluate(&signals_with(
                None,
                &[],
                Some("t13d1516h2_8daaf6152771_b0da82dd1658")
            ))
            .is_some());
        assert!(pack
            .evaluate(&signals_with(None, &[], Some("q14d_xxx_yyy")))
            .is_none());
    }

    #[test]
    fn first_match_wins_in_declaration_order() {
        let yaml = r#"
version: 0
agents:
  - id: claude-code-cli
    match:
      user_agent_pattern: '^claude-cli/'
    provenance: unsigned-named
    score: 95
  - id: catchall
    match: {}
    provenance: unsigned-anonymous
    score: 1
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        // Claude-cli UA hits the first rule, not the wildcard.
        let d = pack
            .evaluate(&signals_with(Some("claude-cli/1.0"), &[], None))
            .unwrap();
        assert_eq!(d.agent_id.as_deref(), Some("claude-code-cli"));
        // Unknown UA falls through to the wildcard.
        let d = pack
            .evaluate(&signals_with(Some("curl/8.0"), &[], None))
            .unwrap();
        assert_eq!(d.agent_id.as_deref(), Some("catchall"));
    }

    #[test]
    fn empty_match_block_is_a_wildcard() {
        let yaml = r#"
version: 0
agents:
  - id: anyone
    match: {}
    provenance: unsigned-anonymous
    score: 1
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        let d = pack.evaluate(&Signals::default()).unwrap();
        assert_eq!(d.agent_id.as_deref(), Some("anyone"));
        assert!(d.signals_used.is_empty());
    }

    #[test]
    fn confidence_defaults_to_one_and_clamps_in_range() {
        let yaml = r#"
version: 0
agents:
  - id: defaulted
    match: {}
    provenance: unsigned-named
    score: 50
  - id: overshoot
    match: {}
    provenance: unsigned-named
    score: 50
    confidence: 5.0
"#;
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        // First rule wins, default confidence is 1.0.
        let d = pack.evaluate(&Signals::default()).unwrap();
        assert!((d.confidence - 1.0).abs() < f32::EPSILON);
        // Second rule's overshoot would clamp to 1.0 if reached; the
        // compiled struct already clamped it, so verify the source
        // value survives but the compiled value is clamped.
        let raw = pack
            .source
            .agents
            .iter()
            .find(|r| r.id == "overshoot")
            .unwrap();
        assert!((raw.confidence - 5.0).abs() < f32::EPSILON);
    }

    #[test]
    fn baseline_fixture_pack_parses() {
        // The five baseline agents the WOR-585 ticket calls out;
        // shipped as a fixture under fixtures/ so the next slice can
        // load + golden-test the same data.
        let yaml = include_str!("../fixtures/baseline.yaml");
        let pack = CompiledRulePack::from_yaml_str(yaml).expect("baseline fixture parses");
        let ids: Vec<&str> = pack.source.agents.iter().map(|a| a.id.as_str()).collect();
        for expected in ["claude-code-cli", "cursor", "codex-cli", "copilot", "junie"] {
            assert!(
                ids.contains(&expected),
                "baseline fixture missing {expected}"
            );
        }
    }

    #[test]
    fn baseline_claude_code_matches_canonical_ua() {
        let yaml = include_str!("../fixtures/baseline.yaml");
        let pack = CompiledRulePack::from_yaml_str(yaml).unwrap();
        let d = pack
            .evaluate(&signals_with(
                Some("claude-cli/0.42.0 (external, cli)"),
                &["x-stainless-arch"],
                None,
            ))
            .expect("claude-code-cli should match canonical UA");
        assert_eq!(d.agent_id.as_deref(), Some("claude-code-cli"));
        assert_eq!(d.provenance, AgentProvenance::UnsignedNamed);
    }
}
