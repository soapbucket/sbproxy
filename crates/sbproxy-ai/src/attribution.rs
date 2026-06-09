// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Business-attribution tags for AI spend records.
//!
//! The Token-to-Value Ledger needs every AI spend record stamped
//! with the *business* context that produced it: which project,
//! which feature, which team, which OKR, which workflow trace.
//! Without that context, "AI spend went up 30 percent this week"
//! is unactionable: no operator can answer "who, on what, for
//! what return". This module ships the small, fixed schema the
//! gateway accepts on each inbound AI request and stamps onto the
//! access log, the OpenTelemetry GenAI span, and (in
//! [`crate::ai_metrics`]) the metric labels.
//!
//! ## Schema
//!
//! Eight optional tags, each accepted via a documented header
//! convention `SB-Attr-<Key>`. Operators can also pin defaults
//! per-route via config (see the wave-2 wiring in
//! `sbproxy-config`); the request header wins when both are
//! present.
//!
//! | Tag         | Header             | Purpose                                                                                              |
//! |-------------|--------------------|------------------------------------------------------------------------------------------------------|
//! | project     | `SB-Attr-Project`  | The objective / product this request advances.                                                       |
//! | feature     | `SB-Attr-Feature`  | The feature inside the project. Enables feature-level burn-rate dashboards.                          |
//! | okr         | `SB-Attr-Okr`      | Key-result id this workflow advances. The ledger's join key for outcome-to-spend reports.            |
//! | team        | `SB-Attr-Team`     | Owning team for chargeback/showback.                                                                 |
//! | customer    | `SB-Attr-Customer` | End customer / account / segment, when the gateway brokers spend per customer.                       |
//! | environment | `SB-Attr-Env`      | `prod` / `staging` / `dev` (free-form; the spend dashboard expects three buckets).                   |
//! | agent_type  | `SB-Attr-Agent`    | `runtime` (production agent) or `development` (CI / IDE / eval harness). Separates "real" spend.    |
//! | risk_tier   | `SB-Attr-Risk`     | Free-form risk tier (`internal-only` / `customer-facing` / `regulated`); used by approval gates.    |
//! | trace_id    | `SB-Attr-Trace-Id` | Caller-supplied workflow correlation id. The ledger's Allocate-layer join key.                       |
//!
//! ## Bounds
//!
//! Per-tag length is capped at [`MAX_TAG_VALUE_LEN`]; the total
//! number of recognised tags is fixed (the [`AttributionTags`]
//! struct is closed). The gateway REJECTS unknown
//! `SB-Attr-*` headers and oversized values rather than silently
//! truncating: a silent truncation produces a corrupted ledger
//! entry the operator cannot detect.
//!
//! ## Redaction
//!
//! Values flow through the workspace's `Redactor` before they
//! land on a span / log / metric label, so a tag that
//! accidentally carries an API key or a PII string is scrubbed
//! BEFORE persistence.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// HTTP header-name prefix the gateway recognises for attribution
/// tags. Per-tag header name is `SB-Attr-<Kebab>` where `<Kebab>`
/// is the schema field's name in canonical casing.
pub const ATTR_HEADER_PREFIX: &str = "sb-attr-";

/// Cap on each tag value's length. Picked to bound the metric
/// label cardinality + the span attribute size without truncating
/// any sensible business identifier (a UUID is 36 chars; a long
/// human-readable OKR slug fits inside 256).
pub const MAX_TAG_VALUE_LEN: usize = 256;

/// Maximum number of distinct values per tag the metrics layer
/// accepts before the cardinality limiter coalesces further values
/// into `_other`. The schema already restricts which tag KEYS are
/// allowed; this cap protects the metrics surface from a per-tag
/// cardinality explosion when an integration mints a fresh value
/// every request (an unbounded `trace_id` is the obvious risk).
pub const MAX_DISTINCT_VALUES_PER_TAG: usize = 1024;

/// Errors raised when an inbound request carries an attribution
/// tag that fails validation. The gateway surfaces these to the
/// caller with a `400 Bad Request` + the variant's message; a
/// silent truncation would corrupt the ledger.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttributionError {
    /// The header `SB-Attr-<key>` had a key the schema does not
    /// recognise. Operators MUST extend the typed schema (and
    /// teach this module + the metrics labels) rather than ship
    /// ad-hoc keys.
    #[error("unknown attribution tag `{0}`")]
    UnknownTag(String),
    /// The value exceeded [`MAX_TAG_VALUE_LEN`]. Silently
    /// truncating would corrupt the ledger join, so the gateway
    /// rejects.
    #[error("attribution tag `{tag}` value is {len} chars; max is {max}")]
    ValueTooLong {
        /// The offending tag name.
        tag: &'static str,
        /// Length the caller submitted (in characters).
        len: usize,
        /// Cap the gateway enforces.
        max: usize,
    },
    /// The value was empty. Empty tag values produce label
    /// collisions in metrics and a corrupted ledger; treat them
    /// as missing tags instead.
    #[error("attribution tag `{0}` value is empty; omit the header instead")]
    EmptyValue(&'static str),
    /// The header byte sequence was not valid UTF-8. Attribution
    /// tags travel through OTel attributes + Prometheus labels +
    /// JSON log records, all of which assume UTF-8.
    #[error("attribution tag `{0}` value is not UTF-8")]
    NotUtf8(String),
}

/// Strongly-typed attribution tag set. Every field is optional:
/// callers stamp the dimensions they care about. The struct is
/// closed (no `#[non_exhaustive]`) so extending the schema is a
/// deliberate workspace-wide change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionTags {
    /// Project / objective this request advances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Feature within the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature: Option<String>,
    /// Key-result id this workflow advances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub okr: Option<String>,
    /// Owning team for chargeback / showback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// End customer / account / segment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
    /// Environment slug (`prod` / `staging` / `dev`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// `runtime` (production agent) vs `development` (CI / IDE /
    /// eval harness).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// Free-form risk tier (`internal-only` / `customer-facing` /
    /// `regulated`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<String>,
    /// Caller-supplied workflow correlation id (the ledger's
    /// Allocate-layer join key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl AttributionTags {
    /// True when every field is `None`. Used by metrics + span
    /// stamping to avoid emitting empty label sets that would
    /// inflate cardinality with no signal.
    pub fn is_empty(&self) -> bool {
        self.project.is_none()
            && self.feature.is_none()
            && self.okr.is_none()
            && self.team.is_none()
            && self.customer.is_none()
            && self.environment.is_none()
            && self.agent_type.is_none()
            && self.risk_tier.is_none()
            && self.trace_id.is_none()
    }

    /// Compose self over a base set: each field of `self` falls
    /// back to the corresponding field of `base` when missing.
    /// Used by the request handler to apply per-route default
    /// tags from config beneath the per-request header overrides.
    pub fn or_default_from(self, base: &AttributionTags) -> Self {
        Self {
            project: self.project.or_else(|| base.project.clone()),
            feature: self.feature.or_else(|| base.feature.clone()),
            okr: self.okr.or_else(|| base.okr.clone()),
            team: self.team.or_else(|| base.team.clone()),
            customer: self.customer.or_else(|| base.customer.clone()),
            environment: self.environment.or_else(|| base.environment.clone()),
            agent_type: self.agent_type.or_else(|| base.agent_type.clone()),
            risk_tier: self.risk_tier.or_else(|| base.risk_tier.clone()),
            trace_id: self.trace_id.or_else(|| base.trace_id.clone()),
        }
    }

    /// Iterate the populated tags in a stable (schema-defined)
    /// order. Useful for stamping OTel span attributes and
    /// access-log JSON fields where field order matters for
    /// deterministic diffs.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("project", self.project.as_deref()),
            ("feature", self.feature.as_deref()),
            ("okr", self.okr.as_deref()),
            ("team", self.team.as_deref()),
            ("customer", self.customer.as_deref()),
            ("environment", self.environment.as_deref()),
            ("agent_type", self.agent_type.as_deref()),
            ("risk_tier", self.risk_tier.as_deref()),
            ("trace_id", self.trace_id.as_deref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|s| (k, s)))
    }
}

/// Map an inbound HTTP header pair to the schema field name it
/// represents. Returns `None` for non-`SB-Attr-` headers and for
/// `SB-Attr-` headers whose key is outside the schema.
fn schema_field_for(header_name: &str) -> Option<&'static str> {
    let lower = header_name.to_ascii_lowercase();
    let suffix = lower.strip_prefix(ATTR_HEADER_PREFIX)?;
    match suffix {
        "project" => Some("project"),
        "feature" => Some("feature"),
        "okr" => Some("okr"),
        "team" => Some("team"),
        "customer" => Some("customer"),
        "env" | "environment" => Some("environment"),
        "agent" | "agent-type" | "agent_type" => Some("agent_type"),
        "risk" | "risk-tier" | "risk_tier" => Some("risk_tier"),
        "trace-id" | "trace_id" | "traceid" => Some("trace_id"),
        _ => None,
    }
}

/// Build an [`AttributionTags`] from an iterator of
/// `(header_name, header_value)` pairs.
///
/// Rejects unknown `SB-Attr-*` headers (with `UnknownTag`), empty
/// values (with `EmptyValue`), and values exceeding
/// [`MAX_TAG_VALUE_LEN`] (with `ValueTooLong`). Non-`SB-Attr-`
/// headers pass through (unrelated to attribution).
///
/// Headers whose name matches the schema's canonical name OR an
/// accepted alias (`SB-Attr-Env` ⇔ `SB-Attr-Environment`) all
/// resolve to the same field. When the same field is supplied
/// twice (under different aliases), the LAST wins; deduplication
/// is undefined in HTTP, so the gateway picks a deterministic
/// rule.
pub fn parse_from_headers<'a, I>(headers: I) -> Result<AttributionTags, AttributionError>
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut tags = AttributionTags::default();
    // Track per-field which header name produced the current
    // value so a duplicate under a different alias overwrites
    // cleanly.
    let mut seen: HashMap<&'static str, ()> = HashMap::new();
    for (name, value_bytes) in headers {
        let lower = name.to_ascii_lowercase();
        if !lower.starts_with(ATTR_HEADER_PREFIX) {
            continue;
        }
        let field = schema_field_for(&lower).ok_or_else(|| {
            AttributionError::UnknownTag(lower[ATTR_HEADER_PREFIX.len()..].to_string())
        })?;
        let value = std::str::from_utf8(value_bytes)
            .map_err(|_| AttributionError::NotUtf8(field.to_string()))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(AttributionError::EmptyValue(field));
        }
        let len = value.chars().count();
        if len > MAX_TAG_VALUE_LEN {
            return Err(AttributionError::ValueTooLong {
                tag: field,
                len,
                max: MAX_TAG_VALUE_LEN,
            });
        }
        seen.insert(field, ());
        store_field(&mut tags, field, value.to_string());
    }
    Ok(tags)
}

fn store_field(tags: &mut AttributionTags, field: &'static str, value: String) {
    match field {
        "project" => tags.project = Some(value),
        "feature" => tags.feature = Some(value),
        "okr" => tags.okr = Some(value),
        "team" => tags.team = Some(value),
        "customer" => tags.customer = Some(value),
        "environment" => tags.environment = Some(value),
        "agent_type" => tags.agent_type = Some(value),
        "risk_tier" => tags.risk_tier = Some(value),
        "trace_id" => tags.trace_id = Some(value),
        _ => {} // unreachable: schema_field_for returns only the names above
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Iterator<Item = (&'a str, &'a [u8])> + 'a {
        pairs.iter().map(|(k, v)| (*k, v.as_bytes()))
    }

    /// Happy path: every schema field stamped via its canonical
    /// header name lands on the struct.
    #[test]
    fn parse_every_canonical_header() {
        let pairs = [
            ("SB-Attr-Project", "growth-q3"),
            ("SB-Attr-Feature", "onboarding-summary"),
            ("SB-Attr-Okr", "wor-kr-2026-q3-001"),
            ("SB-Attr-Team", "platform"),
            ("SB-Attr-Customer", "acme"),
            ("SB-Attr-Env", "prod"),
            ("SB-Attr-Agent", "runtime"),
            ("SB-Attr-Risk", "customer-facing"),
            ("SB-Attr-Trace-Id", "01J6FQ7X"),
        ];
        let tags = parse_from_headers(h(&pairs)).expect("parse");
        assert_eq!(tags.project.as_deref(), Some("growth-q3"));
        assert_eq!(tags.feature.as_deref(), Some("onboarding-summary"));
        assert_eq!(tags.okr.as_deref(), Some("wor-kr-2026-q3-001"));
        assert_eq!(tags.team.as_deref(), Some("platform"));
        assert_eq!(tags.customer.as_deref(), Some("acme"));
        assert_eq!(tags.environment.as_deref(), Some("prod"));
        assert_eq!(tags.agent_type.as_deref(), Some("runtime"));
        assert_eq!(tags.risk_tier.as_deref(), Some("customer-facing"));
        assert_eq!(tags.trace_id.as_deref(), Some("01J6FQ7X"));
        assert!(!tags.is_empty());
    }

    /// Header-name aliases (`Env` vs `Environment`, `Agent` vs
    /// `Agent-Type`) resolve to the same schema field.
    #[test]
    fn aliases_resolve_to_same_field() {
        let tags = parse_from_headers(h(&[
            ("SB-Attr-Environment", "staging"),
            ("SB-Attr-Agent-Type", "development"),
        ]))
        .expect("parse");
        assert_eq!(tags.environment.as_deref(), Some("staging"));
        assert_eq!(tags.agent_type.as_deref(), Some("development"));
    }

    /// Unknown SB-Attr keys are rejected: silently ignoring them
    /// would teach operators to ship typos that never reach the
    /// ledger.
    #[test]
    fn unknown_tag_rejected() {
        let err = parse_from_headers(h(&[("SB-Attr-Nonsense", "value")])).unwrap_err();
        assert!(matches!(err, AttributionError::UnknownTag(name) if name == "nonsense"));
    }

    /// Non-`SB-Attr-` headers are not part of the attribution
    /// surface; the parser ignores them entirely.
    #[test]
    fn non_attr_headers_ignored() {
        let tags = parse_from_headers(h(&[
            ("Content-Type", "application/json"),
            ("X-Forwarded-For", "203.0.113.1"),
            ("SB-Attr-Project", "alpha"),
        ]))
        .expect("parse");
        assert_eq!(tags.project.as_deref(), Some("alpha"));
        // No accidental capture of unrelated headers.
        assert!(tags.team.is_none());
    }

    /// Empty value rejected: an empty tag corrupts the ledger
    /// join more than a missing tag.
    #[test]
    fn empty_value_rejected() {
        let err = parse_from_headers(h(&[("SB-Attr-Team", "")])).unwrap_err();
        assert!(matches!(err, AttributionError::EmptyValue("team")));
    }

    /// Whitespace-only value collapses to empty after trim and is
    /// rejected.
    #[test]
    fn whitespace_only_value_rejected() {
        let err = parse_from_headers(h(&[("SB-Attr-Team", "   \t")])).unwrap_err();
        assert!(matches!(err, AttributionError::EmptyValue("team")));
    }

    /// Oversized value rejected: silent truncation would corrupt
    /// the ledger join AND inflate metric cardinality.
    #[test]
    fn oversized_value_rejected() {
        let big = "a".repeat(MAX_TAG_VALUE_LEN + 1);
        let err = parse_from_headers(h(&[("SB-Attr-Project", &big)])).unwrap_err();
        assert!(matches!(
            err,
            AttributionError::ValueTooLong {
                tag: "project",
                len,
                max,
            } if len == MAX_TAG_VALUE_LEN + 1 && max == MAX_TAG_VALUE_LEN
        ));
    }

    /// Exact-bound value accepted: the length check is `>`, not
    /// `>=`.
    #[test]
    fn at_max_length_value_accepted() {
        let big = "a".repeat(MAX_TAG_VALUE_LEN);
        let tags = parse_from_headers(h(&[("SB-Attr-Project", &big)])).expect("parse");
        assert_eq!(
            tags.project.as_deref().unwrap().chars().count(),
            MAX_TAG_VALUE_LEN
        );
    }

    /// `or_default_from` lets a per-route default fill missing
    /// fields without overriding header-supplied values.
    #[test]
    fn or_default_from_composes() {
        let base = AttributionTags {
            team: Some("platform".to_string()),
            environment: Some("prod".to_string()),
            ..Default::default()
        };
        let header_supplied = AttributionTags {
            project: Some("growth".to_string()),
            environment: Some("staging".to_string()), // overrides base
            ..Default::default()
        };
        let resolved = header_supplied.or_default_from(&base);
        assert_eq!(resolved.project.as_deref(), Some("growth"));
        assert_eq!(resolved.team.as_deref(), Some("platform"));
        assert_eq!(resolved.environment.as_deref(), Some("staging"));
    }

    /// `iter()` walks the populated tags in schema order so a
    /// span attribute / log JSON has a deterministic shape.
    #[test]
    fn iter_yields_schema_order() {
        let tags = AttributionTags {
            customer: Some("acme".to_string()),
            project: Some("growth".to_string()),
            trace_id: Some("01J6FQ7X".to_string()),
            ..Default::default()
        };
        let names: Vec<&'static str> = tags.iter().map(|(k, _)| k).collect();
        // Schema order: project before customer before trace_id.
        assert_eq!(names, vec!["project", "customer", "trace_id"]);
    }

    /// Duplicate header values for the same logical field
    /// (canonical + alias): the LAST one wins.
    #[test]
    fn duplicate_under_alias_last_wins() {
        let tags = parse_from_headers(h(&[
            ("SB-Attr-Env", "staging"),
            ("SB-Attr-Environment", "prod"),
        ]))
        .expect("parse");
        assert_eq!(tags.environment.as_deref(), Some("prod"));
    }

    /// `is_empty` returns true for a default-constructed
    /// `AttributionTags` and false once any field is populated.
    #[test]
    fn is_empty_predicate() {
        let mut tags = AttributionTags::default();
        assert!(tags.is_empty());
        tags.project = Some("growth".to_string());
        assert!(!tags.is_empty());
    }

    /// Non-UTF-8 header value rejected: every downstream surface
    /// (OTel attribute, JSON log, Prometheus label) assumes UTF-8.
    #[test]
    fn non_utf8_value_rejected() {
        let header_pairs: Vec<(&str, &[u8])> = vec![("SB-Attr-Team", &[0xff, 0xfe, 0x00, 0xc0])];
        let err = parse_from_headers(header_pairs).unwrap_err();
        assert!(matches!(err, AttributionError::NotUtf8(name) if name == "team"));
    }
}
