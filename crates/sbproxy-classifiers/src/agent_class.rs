//! Agent-class taxonomy (G1.1 / G1.4).
//!
//! Canonical record describing an automated agent (vendor, purpose,
//! UA pattern, reverse-DNS suffixes, expected Web Bot Auth keyids,
//! robots-compliance score). Consumed by:
//!
//! * `sbproxy-modules::policy::agent_class` resolver (G1.4).
//! * `sbproxy-security::agent_verify` reverse-DNS verifier (G1.5).
//! * Per-agent metric labels (G1.6) and the HTTP ledger payload (A1.2).
//!
//! See `docs/adr-agent-class-taxonomy.md` for the schema rationale.
//!
//! # Reserved sentinels
//!
//! Three values are stable across releases and emitted by the resolver
//! when no concrete entry matches:
//!
//! - [`AgentId::HUMAN`]: no automated-agent signal present.
//! - [`AgentId::ANONYMOUS`]: anonymous Web Bot Auth without a known keyid.
//! - [`AgentId::UNKNOWN`]: looks like a bot but no taxonomy entry caught it.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Embedded default catalog. Parsed once at startup; operators may
/// extend or override entries via inline `sb.yml`.
pub const DEFAULT_CATALOG_YAML: &str = include_str!("../data/agent_classes_default.yaml");

/// Operator-stated purpose of an agent. Bounded so it can flow into
/// audit logs without exploding cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPurpose {
    /// Training data collection for an LLM or other model.
    Training,
    /// User-facing search ranking / index population.
    Search,
    /// Real-time fetch on behalf of a user-issued chat / agent prompt.
    Assistant,
    /// Academic or measurement research.
    Research,
    /// Web archival (Internet Archive style).
    Archival,
    /// Catalog could not classify the purpose; falls back to here.
    Unknown,
}

impl AgentPurpose {
    /// Stable string label used in dashboards and the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Training => "training",
            Self::Search => "search",
            Self::Assistant => "assistant",
            Self::Research => "research",
            Self::Archival => "archival",
            Self::Unknown => "unknown",
        }
    }
}

/// One agent in the taxonomy.
///
/// Loaded from YAML at startup and held read-only for the rest of the
/// process lifetime; the resolver compiles `expected_user_agent_pattern`
/// once into a `Regex` to avoid per-request recompilation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentClass {
    /// Stable identifier. Kebab-case `vendor-bot`. Also serves as the
    /// `agent_id` metric label.
    pub id: String,
    /// Display name of the operator (e.g. `OpenAI`, `Anthropic`).
    pub vendor: String,
    /// Operator-stated purpose.
    pub purpose: AgentPurpose,
    /// Operator's published contact / documentation URL. Optional.
    #[serde(default)]
    pub contact_url: Option<String>,
    /// Anchored, case-insensitive regex matched against the request's
    /// `User-Agent` header.
    pub expected_user_agent_pattern: String,
    /// Suffixes accepted by the forward-confirmed reverse-DNS check.
    /// Empty list disables rDNS verification for this entry.
    #[serde(default)]
    pub expected_reverse_dns_suffixes: Vec<String>,
    /// Web Bot Auth `keyid` values the agent is expected to sign with.
    /// Empty list means the agent does not yet sign.
    #[serde(default)]
    pub expected_keyids: Vec<String>,
    /// Operator-declared or community-attested score for robots.txt
    /// compliance, in `[0.0, 1.0]`.
    #[serde(default)]
    pub robots_compliance_score: Option<f32>,
    /// Latest measured crawl-to-refer ratio (Wave 2 hosted feed; Wave
    /// 1 leaves this `null`).
    #[serde(default)]
    pub crawl_to_refer_ratio: Option<f32>,
    /// Alternate UA substrings or historical IDs that resolve to this
    /// entry.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// When `true`, the resolver still matches the entry but operators
    /// should treat it as superseded.
    #[serde(default)]
    pub deprecated: bool,
}

impl AgentClass {
    /// Validate the entry is well-formed.
    ///
    /// Catches obvious mistakes at config-load time: empty / malformed
    /// `id`, unparseable UA regex, score out of range. Each downstream
    /// consumer (resolver, audit log, metrics) can then assume the
    /// invariants hold.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(anyhow!("agent class id is empty"));
        }
        if !is_kebab_id(&self.id) {
            return Err(anyhow!(
                "agent class id {:?} is not kebab-case lowercase",
                self.id
            ));
        }
        if self.vendor.is_empty() {
            return Err(anyhow!("agent class {:?}: vendor is empty", self.id));
        }
        if self.expected_user_agent_pattern.is_empty() {
            return Err(anyhow!(
                "agent class {:?}: expected_user_agent_pattern is empty",
                self.id
            ));
        }
        Regex::new(&self.expected_user_agent_pattern).with_context(|| {
            format!(
                "agent class {:?}: expected_user_agent_pattern is not a valid regex",
                self.id
            )
        })?;
        if let Some(score) = self.robots_compliance_score {
            if !(0.0..=1.0).contains(&score) {
                return Err(anyhow!(
                    "agent class {:?}: robots_compliance_score {:?} not in [0.0, 1.0]",
                    self.id,
                    score
                ));
            }
        }
        Ok(())
    }
}

fn is_kebab_id(s: &str) -> bool {
    if !(2..=63).contains(&s.len()) {
        return false;
    }
    let mut bytes = s.bytes();
    let first = match bytes.next() {
        Some(b) => b,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Stable identifier emitted by the resolver. Either one of the three
/// reserved sentinels (`human`, `anonymous`, `unknown`) or a catalog
/// `id`. Stored as a `Cow`-like string but kept as `String` for the
/// Wave 1 OSS surface; the small allocation per request is amortised
/// against the per-request HTTP work.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct AgentId(pub String);

impl AgentId {
    /// Reserved sentinel for non-automated traffic.
    pub const HUMAN: &'static str = "human";
    /// Reserved sentinel for an anonymous Web Bot Auth signature with
    /// no matching catalog `keyid`.
    pub const ANONYMOUS: &'static str = "anonymous";
    /// Reserved sentinel for an automated request that no taxonomy
    /// entry caught.
    pub const UNKNOWN: &'static str = "unknown";

    /// Construct the `human` sentinel.
    pub fn human() -> Self {
        Self(Self::HUMAN.to_string())
    }

    /// Construct the `anonymous` sentinel.
    pub fn anonymous() -> Self {
        Self(Self::ANONYMOUS.to_string())
    }

    /// Construct the `unknown` sentinel.
    pub fn unknown() -> Self {
        Self(Self::UNKNOWN.to_string())
    }

    /// Borrow the underlying identifier as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when the identifier is one of the three reserved sentinels.
    pub fn is_sentinel(&self) -> bool {
        matches!(
            self.0.as_str(),
            Self::HUMAN | Self::ANONYMOUS | Self::UNKNOWN
        )
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Diagnostic stamp recording which signal in the resolver chain
/// produced the [`AgentId`]. Mirrors the user-id source pattern from
/// `adr-user-id.md`.
///
/// Closed enum per A1.8 Rule 4. Adding a variant requires an ADR
/// amendment entry; the Wave 5 amendment that introduced
/// [`Self::TlsFingerprint`] is recorded in
/// `docs/adr-tls-fingerprint-pipeline.md` (A5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdSource {
    /// Verified Web Bot Auth `keyid` matched a catalog entry.
    BotAuth,
    /// Verified Skyfire KYA token (Wave 5 / G5.1, G5.2). Sits at
    /// resolver step 1.5 between `BotAuth` and `Rdns`. Bot-auth wins
    /// over KYA on conflict per the G5.1 ADR.
    Kya,
    /// Forward-confirmed reverse-DNS suffix matched a catalog entry.
    Rdns,
    /// `User-Agent` regex matched a catalog entry.
    UserAgent,
    /// Anonymous Web Bot Auth signature, no matching `keyid`.
    AnonymousBotAuth,
    /// Verified TLS fingerprint (JA3/JA4) matched a catalog entry.
    /// Wave 5 / G5.3. Added per `adr-tls-fingerprint-pipeline.md`.
    TlsFingerprint,
    /// Resolver fell through (`human` or `unknown`).
    Fallback,
    /// ML classifier verdict overrode the rule-based resolver. Per
    /// `docs/adr-ml-agent-classifier.md` (A5.2), this only fires when
    /// the ML verdict is `Human` with confidence >= 0.9; in every other
    /// case the rule-based resolver verdict is authoritative.
    MlOverride,
}

impl AgentIdSource {
    /// Stable label for dashboards and structured logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BotAuth => "bot_auth",
            Self::Kya => "kya",
            Self::Rdns => "rdns",
            Self::UserAgent => "user_agent",
            Self::AnonymousBotAuth => "anonymous_bot_auth",
            Self::TlsFingerprint => "tls_fingerprint",
            Self::Fallback => "fallback",
            Self::MlOverride => "ml_override",
        }
    }
}

/// Loaded catalog of [`AgentClass`] entries with compiled regexes for
/// the resolver hot path.
pub struct AgentClassCatalog {
    entries: Vec<AgentClassCompiled>,
    by_id: HashMap<String, usize>,
    by_keyid: HashMap<String, usize>,
}

impl std::fmt::Debug for AgentClassCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentClassCatalog")
            .field("entry_count", &self.entries.len())
            .field("ids", &self.by_id.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// One catalog entry plus its compiled UA regex. Kept private; callers
/// touch the public `AgentClass` view.
struct AgentClassCompiled {
    spec: AgentClass,
    ua_regex: Regex,
}

#[derive(Debug, Deserialize)]
struct CatalogFile {
    agent_classes: Vec<AgentClass>,
}

impl AgentClassCatalog {
    /// Build a catalog from a parsed entry list. Each entry is
    /// validated and its UA pattern compiled once.
    pub fn from_entries(entries: Vec<AgentClass>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(entries.len());
        let mut by_id = HashMap::with_capacity(entries.len());
        let mut by_keyid = HashMap::new();
        for (idx, entry) in entries.into_iter().enumerate() {
            entry
                .validate()
                .with_context(|| format!("invalid agent class entry at index {idx}"))?;
            let ua_regex = Regex::new(&entry.expected_user_agent_pattern)
                .expect("validate() above guarantees the UA pattern compiles");
            if by_id.insert(entry.id.clone(), idx).is_some() {
                return Err(anyhow!("duplicate agent class id {:?}", entry.id));
            }
            for keyid in &entry.expected_keyids {
                if by_keyid.insert(keyid.clone(), idx).is_some() {
                    return Err(anyhow!(
                        "duplicate keyid {:?} across agent class entries",
                        keyid
                    ));
                }
            }
            compiled.push(AgentClassCompiled {
                spec: entry,
                ua_regex,
            });
        }
        Ok(Self {
            entries: compiled,
            by_id,
            by_keyid,
        })
    }

    /// Parse YAML content (the embedded default or operator override).
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        let file: CatalogFile = serde_yaml::from_str(input).context("parse agent_classes YAML")?;
        Self::from_entries(file.agent_classes)
    }

    /// Build the embedded default catalog. Panics only if the embedded
    /// YAML is malformed (caught by the unit test below).
    pub fn defaults() -> Self {
        Self::from_yaml_str(DEFAULT_CATALOG_YAML).expect("embedded agent class catalog is valid")
    }

    /// Number of entries in the catalog.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries are present.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entries in the order they were declared.
    pub fn iter(&self) -> impl Iterator<Item = &AgentClass> {
        self.entries.iter().map(|c| &c.spec)
    }

    /// Look up an entry by `id`.
    pub fn get(&self, id: &str) -> Option<&AgentClass> {
        self.by_id.get(id).map(|idx| &self.entries[*idx].spec)
    }

    /// Look up an entry by Web Bot Auth `keyid`.
    pub fn lookup_by_keyid(&self, keyid: &str) -> Option<&AgentClass> {
        self.by_keyid.get(keyid).map(|idx| &self.entries[*idx].spec)
    }

    /// Look up the first entry whose `expected_user_agent_pattern`
    /// matches the supplied `User-Agent` header. Falls back to scanning
    /// `aliases` (case-insensitive substring) on no UA-regex match.
    pub fn lookup_by_user_agent(&self, user_agent: &str) -> Option<&AgentClass> {
        for entry in &self.entries {
            if entry.ua_regex.is_match(user_agent) {
                return Some(&entry.spec);
            }
        }
        let ua_lower = user_agent.to_ascii_lowercase();
        for entry in &self.entries {
            for alias in &entry.spec.aliases {
                if !alias.is_empty() && ua_lower.contains(&alias.to_ascii_lowercase()) {
                    return Some(&entry.spec);
                }
            }
        }
        None
    }

    /// Look up the first entry whose `expected_reverse_dns_suffixes`
    /// list contains a suffix that matches `hostname` (case-insensitive).
    pub fn lookup_by_reverse_dns(&self, hostname: &str) -> Option<&AgentClass> {
        let host_lower = hostname.to_ascii_lowercase();
        for entry in &self.entries {
            for suffix in &entry.spec.expected_reverse_dns_suffixes {
                if suffix.is_empty() {
                    continue;
                }
                let s = suffix.to_ascii_lowercase();
                if host_lower.ends_with(&s) {
                    return Some(&entry.spec);
                }
            }
        }
        None
    }

    /// Collect every reverse-DNS suffix from every entry, lowercased
    /// and deduped. Used by the resolver to avoid running PTR lookups
    /// when the catalog has no rDNS expectations at all.
    pub fn all_rdns_suffixes(&self) -> Vec<String> {
        let mut out = Vec::new();
        for entry in &self.entries {
            for s in &entry.spec.expected_reverse_dns_suffixes {
                let lower = s.to_ascii_lowercase();
                if !lower.is_empty() && !out.contains(&lower) {
                    out.push(lower);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_load_eight_or_more_entries() {
        let cat = AgentClassCatalog::defaults();
        // Wave 1 ADR locks the floor at the eight well-known vendors;
        // we ship ten today (GPTBot + ChatGPT-User both for OpenAI,
        // Googlebot + Google-Extended both for Google).
        assert!(
            cat.len() >= 8,
            "expected at least 8 agent classes in defaults, got {}",
            cat.len()
        );
        assert!(cat.get("openai-gptbot").is_some());
        assert!(cat.get("anthropic-claudebot").is_some());
        assert!(cat.get("google-googlebot").is_some());
    }

    #[test]
    fn lookup_by_user_agent_matches_known_bots() {
        let cat = AgentClassCatalog::defaults();
        let m = cat
            .lookup_by_user_agent(
                "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)",
            )
            .expect("GPTBot should match openai-gptbot");
        assert_eq!(m.id, "openai-gptbot");
        let m = cat
            .lookup_by_user_agent(
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            )
            .expect("Googlebot should match google-googlebot");
        assert_eq!(m.id, "google-googlebot");
    }

    #[test]
    fn lookup_by_user_agent_returns_none_for_browser() {
        let cat = AgentClassCatalog::defaults();
        let m = cat.lookup_by_user_agent(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
        );
        assert!(m.is_none(), "browser UA should not match any AgentClass");
    }

    #[test]
    fn lookup_by_reverse_dns_suffix_matches_googlebot() {
        let cat = AgentClassCatalog::defaults();
        let m = cat
            .lookup_by_reverse_dns("crawl-66-249-66-1.googlebot.com")
            .expect("rDNS suffix for googlebot.com should match");
        assert_eq!(m.id, "google-googlebot");
    }

    #[test]
    fn agent_id_sentinels_round_trip() {
        assert_eq!(AgentId::human().as_str(), "human");
        assert_eq!(AgentId::anonymous().as_str(), "anonymous");
        assert_eq!(AgentId::unknown().as_str(), "unknown");
        assert!(AgentId::human().is_sentinel());
        assert!(!AgentId(String::from("openai-gptbot")).is_sentinel());
    }

    #[test]
    fn rejects_duplicate_id() {
        let entries = vec![
            AgentClass {
                id: "dup-bot".to_string(),
                vendor: "v".to_string(),
                purpose: AgentPurpose::Search,
                contact_url: None,
                expected_user_agent_pattern: "(?i)dup".to_string(),
                expected_reverse_dns_suffixes: vec![],
                expected_keyids: vec![],
                robots_compliance_score: None,
                crawl_to_refer_ratio: None,
                aliases: vec![],
                deprecated: false,
            },
            AgentClass {
                id: "dup-bot".to_string(),
                vendor: "v".to_string(),
                purpose: AgentPurpose::Search,
                contact_url: None,
                expected_user_agent_pattern: "(?i)dup".to_string(),
                expected_reverse_dns_suffixes: vec![],
                expected_keyids: vec![],
                robots_compliance_score: None,
                crawl_to_refer_ratio: None,
                aliases: vec![],
                deprecated: false,
            },
        ];
        let err = AgentClassCatalog::from_entries(entries).unwrap_err();
        assert!(err.to_string().contains("duplicate agent class id"));
    }

    #[test]
    fn rejects_invalid_id_format() {
        let entry = AgentClass {
            id: "BadID".to_string(),
            vendor: "v".to_string(),
            purpose: AgentPurpose::Search,
            contact_url: None,
            expected_user_agent_pattern: "(?i)x".to_string(),
            expected_reverse_dns_suffixes: vec![],
            expected_keyids: vec![],
            robots_compliance_score: None,
            crawl_to_refer_ratio: None,
            aliases: vec![],
            deprecated: false,
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn agent_purpose_serializes_snake_case() {
        let p = AgentPurpose::Training;
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, "\"training\"");
    }

    #[test]
    fn all_rdns_suffixes_dedupes() {
        let cat = AgentClassCatalog::defaults();
        let suffixes = cat.all_rdns_suffixes();
        // Suffixes are deduped + lowercased.
        let lower_sorted: Vec<String> = {
            let mut v = suffixes.clone();
            v.sort();
            v.dedup();
            v
        };
        assert_eq!(suffixes.len(), lower_sorted.len());
        // Spot-check a known suffix.
        assert!(suffixes.iter().any(|s| s == ".googlebot.com"));
    }
}
