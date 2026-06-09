// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Declarative principal-matching policy.
//!
//! Shortcut for the common allow / deny rules that today require a
//! hand-written CEL expression. Operators describe what they want to
//! match in YAML and the policy returns a typed verdict at request
//! time:
//!
//! ```yaml
//! policies:
//!   - type: match_principal
//!     match:
//!       tenant: acme-corp
//!       team: [frontend, support]
//!       attrs.environment: prod
//!       claims.iss: https://idp.example.com
//!     action: allow
//! ```
//!
//! ## Semantics
//!
//! * The selector is a conjunction: every key under `match:` must
//!   match the principal for the policy to fire.
//! * A scalar value matches when the corresponding principal field
//!   equals it. A list value matches when any element equals the
//!   field. The any-of form is convenient for `team: [frontend,
//!   support]`-style allowlists without needing a regex.
//! * The `action:` field picks `allow` or `deny`. The default is
//!   `allow` (the explicit `deny` form lets operators short-circuit
//!   downstream policies).
//! * When multiple `match_principal` policies stack, the policy
//!   evaluator runs each independently and takes the most-restrictive
//!   outcome: any `deny` whose selector matches shorts the request,
//!   regardless of how many `allow` policies also matched.
//!
//! ## Selector grammar
//!
//! | Key | Source | Match shape |
//! |---|---|---|
//! | `tenant` | `Principal.tenant_id` | scalar |
//! | `team` | `Principal.attrs.team` | scalar or any-of list |
//! | `project` | `Principal.attrs.project` | scalar or any-of list |
//! | `user` | `Principal.attrs.user` | scalar |
//! | `tags` | `Principal.attrs.tags` | any-of list intersected with the principal's tags |
//! | `attrs.<name>` | `Principal.attrs.metadata[name]` | scalar or any-of list |
//! | `claims.<name>` | `Principal.attrs.claims[name]` | scalar or any-of list |
//! | `source` | `Principal.source` (slug) | scalar matching a `PrincipalSource` slug |
//!
//! Selector keys with no matching field on the principal evaluate as
//! "no match" rather than "vacuous match" so a typo on the YAML side
//! does not silently allow every request.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Operator-facing configuration block.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MatchPrincipalConfig {
    /// Conjunction of selectors. Empty matches every principal so
    /// operators can write `match: {}` to apply a default action.
    #[serde(default)]
    pub r#match: MatchPrincipalSelector,
    /// What the policy returns when the selector matches. Defaults
    /// to `allow`; `deny` lets a policy gate downstream evaluation.
    #[serde(default)]
    pub action: MatchPrincipalAction,
}

/// One policy verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchPrincipalAction {
    /// Policy fires; the request is allowed.
    #[default]
    Allow,
    /// Policy fires; the request is denied. Stacks restrictively
    /// across multiple policies.
    Deny,
}

/// Selector. Each field is matched against the corresponding
/// principal field at evaluation time; empty fields are skipped.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MatchPrincipalSelector {
    /// Match `Principal.tenant_id`.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Match `Principal.attrs.team`. Accepts scalar or any-of list.
    #[serde(default)]
    pub team: Option<ScalarOrList>,
    /// Match `Principal.attrs.project`. Accepts scalar or any-of list.
    #[serde(default)]
    pub project: Option<ScalarOrList>,
    /// Match `Principal.attrs.user`.
    #[serde(default)]
    pub user: Option<String>,
    /// Match any element of the principal's `attrs.tags` against the
    /// declared set. A single tag in the policy plus a multi-tag
    /// principal matches.
    #[serde(default)]
    pub tags: Option<ScalarOrList>,
    /// Match a `PrincipalSource` slug (`bearer`, `virtual_key`, ...).
    #[serde(default)]
    pub source: Option<String>,
    /// Match `Principal.attrs.metadata[name]`. Keys are written as
    /// `attrs.<name>` in YAML and parsed into this map.
    ///
    /// Implementation note: serde's `flatten` does not work with the
    /// dotted-prefix key naming convention, so operators write
    /// metadata matches under an explicit `attrs:` sub-map. See the
    /// module docs for the YAML grammar.
    #[serde(default, rename = "attrs")]
    pub attrs: BTreeMap<String, ScalarOrList>,
    /// Match `Principal.attrs.claims[name]`. Same shape as `attrs`.
    #[serde(default, rename = "claims")]
    pub claims: BTreeMap<String, ScalarOrList>,
}

/// Scalar or any-of list value used for matching multi-valued fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScalarOrList {
    /// Single value.
    Scalar(String),
    /// Any-of list. The principal field matches when it equals any
    /// element.
    List(Vec<String>),
}

impl ScalarOrList {
    /// Returns the list of candidate values regardless of the
    /// underlying shape.
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            Self::Scalar(s) => vec![s.as_str()],
            Self::List(v) => v.iter().map(String::as_str).collect(),
        }
    }

    /// Whether any candidate equals `value`. An empty list never
    /// matches.
    pub fn matches(&self, value: &str) -> bool {
        self.as_slice().contains(&value)
    }
}

impl MatchPrincipalConfig {
    /// Build from a JSON config value the policy compiler hands in.
    pub fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// Evaluate the policy against a `Principal`. Returns the
    /// configured `action` when every selector matches; returns
    /// `None` when the selector does not match (the policy is
    /// inert).
    pub fn evaluate(&self, principal: &sbproxy_plugin::Principal) -> Option<MatchPrincipalAction> {
        if self.r#match.matches(principal) {
            Some(self.action)
        } else {
            None
        }
    }
}

impl MatchPrincipalSelector {
    /// Whether the selector matches the principal. Every set field
    /// must match for the conjunction to hold.
    pub fn matches(&self, p: &sbproxy_plugin::Principal) -> bool {
        if let Some(t) = &self.tenant {
            if t != p.tenant_id.as_str() {
                return false;
            }
        }
        if let Some(team) = &self.team {
            let principal_team = p.attrs.team.as_deref().unwrap_or("");
            if !team.matches(principal_team) {
                return false;
            }
        }
        if let Some(project) = &self.project {
            let principal_project = p.attrs.project.as_deref().unwrap_or("");
            if !project.matches(principal_project) {
                return false;
            }
        }
        if let Some(u) = &self.user {
            let principal_user = p.attrs.user.as_deref().unwrap_or("");
            if u != principal_user {
                return false;
            }
        }
        if let Some(tags) = &self.tags {
            // Any-of intersection: principal must carry at least one
            // tag the policy declares.
            let principal_tags: Vec<&str> = p.attrs.tags.iter().map(String::as_str).collect();
            if !tags
                .as_slice()
                .iter()
                .any(|candidate| principal_tags.iter().any(|t| t == candidate))
            {
                return false;
            }
        }
        if let Some(source) = &self.source {
            if source != p.source.as_str() {
                return false;
            }
        }
        for (name, expected) in &self.attrs {
            let principal_value = p.attrs.metadata.get(name).map(String::as_str).unwrap_or("");
            if !expected.matches(principal_value) {
                return false;
            }
        }
        for (name, expected) in &self.claims {
            let principal_value = p
                .attrs
                .claims
                .as_ref()
                .and_then(|c| c.get(name))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !expected.matches(principal_value) {
                return false;
            }
        }
        true
    }
}

/// Combine the verdicts from a stack of `match_principal` policies.
/// Any `Deny` whose selector matches takes precedence; otherwise the
/// request is allowed iff at least one policy returned `Allow`.
///
/// Callers that want a "deny by default unless allowed" surface pass
/// `default_allow: false`; the more common "allow unless denied"
/// surface uses `default_allow: true`.
pub fn combine_verdicts(
    verdicts: impl IntoIterator<Item = MatchPrincipalAction>,
    default_allow: bool,
) -> bool {
    let mut any_allow = false;
    for v in verdicts {
        match v {
            MatchPrincipalAction::Deny => return false,
            MatchPrincipalAction::Allow => any_allow = true,
        }
    }
    any_allow || default_allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_plugin::{Principal, PrincipalAttrs, PrincipalSource, TenantId, VirtualKeyRef};

    fn principal_acme_frontend() -> Principal {
        let mut metadata = BTreeMap::new();
        metadata.insert("environment".to_string(), "prod".to_string());
        metadata.insert("cost_center".to_string(), "eng-001".to_string());
        let mut claims = serde_json::Map::new();
        claims.insert(
            "iss".to_string(),
            serde_json::Value::String("https://idp.example.com".to_string()),
        );
        Principal {
            tenant_id: TenantId::from("acme-corp"),
            sub: "vk_frontend_alice".to_string(),
            source: PrincipalSource::VirtualKey,
            virtual_key: Some(VirtualKeyRef {
                name: "vk_frontend_alice".to_string(),
                allowed_providers: vec!["openai".to_string()],
            }),
            attrs: PrincipalAttrs {
                project: Some("frontend".to_string()),
                user: Some("alice".to_string()),
                team: Some("frontend".to_string()),
                tags: vec!["team-frontend".to_string(), "tier-haiku".to_string()],
                metadata,
                roles: vec!["engineer".to_string()],
                claims: Some(claims),
            },
        }
    }

    fn cfg_from_yaml(yaml: &str) -> MatchPrincipalConfig {
        let v: serde_json::Value = serde_yaml::from_str(yaml).unwrap();
        MatchPrincipalConfig::from_value(v).unwrap()
    }

    /// Tenant selector matches the configured value.
    #[test]
    fn tenant_selector_matches() {
        let cfg = cfg_from_yaml("match: { tenant: acme-corp }\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// Tenant selector fails on a different tenant; the policy is
    /// inert (returns None).
    #[test]
    fn tenant_selector_no_match_returns_none() {
        let cfg = cfg_from_yaml("match: { tenant: beta-corp }\naction: deny");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// Team selector accepts an any-of list.
    #[test]
    fn team_selector_accepts_any_of_list() {
        let cfg = cfg_from_yaml("match:\n  team: [frontend, support]\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// Team selector rejects a principal not in the list.
    #[test]
    fn team_selector_rejects_unlisted_team() {
        let cfg = cfg_from_yaml("match:\n  team: [data, ops]\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// `attrs.<name>` matches a metadata entry.
    #[test]
    fn attrs_selector_matches_metadata_entry() {
        let cfg = cfg_from_yaml("match:\n  attrs:\n    environment: prod\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// `attrs.<name>` mismatch on the value evaluates as no-match.
    #[test]
    fn attrs_selector_value_mismatch_no_match() {
        let cfg = cfg_from_yaml("match:\n  attrs:\n    environment: staging\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// `attrs.<name>` reference to a missing metadata key evaluates
    /// as no-match (typos do not silently allow every request).
    #[test]
    fn attrs_selector_missing_key_no_match() {
        let cfg = cfg_from_yaml("match:\n  attrs:\n    typoed_key: anything\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// `claims.<name>` matches a claim entry.
    #[test]
    fn claims_selector_matches() {
        let cfg =
            cfg_from_yaml("match:\n  claims:\n    iss: https://idp.example.com\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// Tags selector matches when any policy tag is on the principal.
    #[test]
    fn tags_selector_any_of_match() {
        let cfg = cfg_from_yaml("match:\n  tags: [team-frontend, team-data]\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// Tags selector rejects when no policy tag is on the principal.
    #[test]
    fn tags_selector_no_intersection_no_match() {
        let cfg = cfg_from_yaml("match:\n  tags: [team-data, team-platform]\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// `source` matches the principal slug.
    #[test]
    fn source_selector_matches_virtual_key_slug() {
        let cfg = cfg_from_yaml("match: { source: virtual_key }\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// `source` mismatch does not match.
    #[test]
    fn source_selector_mismatch_no_match() {
        let cfg = cfg_from_yaml("match: { source: bearer }\naction: allow");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// Empty selector matches every principal (default-action pattern).
    #[test]
    fn empty_selector_matches_everything() {
        let cfg = cfg_from_yaml("match: {}\naction: deny");
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Deny));
    }

    /// Multiple-selector conjunction: every field must match. The
    /// policy below combines tenant + team + a metadata entry; all
    /// three hit on the test principal so the verdict is Allow.
    #[test]
    fn conjunction_all_selectors_must_match() {
        let cfg = cfg_from_yaml(
            r"match:
  tenant: acme-corp
  team: [frontend]
  attrs:
    environment: prod
action: allow",
        );
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), Some(MatchPrincipalAction::Allow));
    }

    /// Conjunction fails when one selector mismatches.
    #[test]
    fn conjunction_short_circuits_on_first_mismatch() {
        let cfg = cfg_from_yaml(
            r"match:
  tenant: acme-corp
  team: [frontend]
  attrs:
    environment: staging
action: allow",
        );
        let p = principal_acme_frontend();
        assert_eq!(cfg.evaluate(&p), None);
    }

    /// `combine_verdicts`: any deny shorts the request regardless
    /// of how many policies also allowed.
    #[test]
    fn combine_verdicts_deny_shorts() {
        let allowed = combine_verdicts(
            [
                MatchPrincipalAction::Allow,
                MatchPrincipalAction::Allow,
                MatchPrincipalAction::Deny,
            ],
            true,
        );
        assert!(!allowed);
    }

    /// `combine_verdicts` with `default_allow=true` allows when no
    /// policy fired.
    #[test]
    fn combine_verdicts_default_allow_passes_empty_list() {
        assert!(combine_verdicts(std::iter::empty(), true));
    }

    /// `combine_verdicts` with `default_allow=false` denies when no
    /// policy fired (deny-by-default pattern).
    #[test]
    fn combine_verdicts_default_deny_blocks_empty_list() {
        assert!(!combine_verdicts(std::iter::empty(), false));
    }
}
