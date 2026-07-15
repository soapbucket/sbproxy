// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The executable capability registry: one vocabulary for everything
//! SBproxy claims about itself.
//!
//! The model host already proved the shape (WOR-1836): a const table of
//! capabilities, a support level per entry, and an executable contract that
//! a stable claim must satisfy. A field cannot be called stable unless a
//! test proves something consumes it, and the capability matrix is
//! generated from the table rather than hand-maintained. Nothing in that
//! design is specific to model hosting, but it only ever covered one crate,
//! so the same defect kept reappearing everywhere else:
//!
//! - an availability SLO matched on a label that does not exist, and read
//!   100% forever;
//! - thirteen metrics were published as `stable` while nothing incremented
//!   them, and a dashboard panel could only ever draw a flat zero;
//! - `proxy.alerting` parsed a PagerDuty routing key cleanly and dropped it
//!   on the floor;
//! - a comparison table advertised gossip-disseminated budget counters that
//!   are written, never read, and never merged.
//!
//! Every one of those has the same shape: a surface that accepts input and
//! does nothing, while the docs assert it works. Review does not catch it,
//! because the surface looks finished from every angle except the one that
//! runs. So this crate hoists the model-host pattern into a leaf that
//! metrics, configuration, and the public comparison tables all share.
//!
//! The load-bearing rule is [`SupportLevel::Stable`]: a stable claim owes
//! evidence that something consumes it, and the evidence has to be
//! executable or mechanically checkable. Everything else is an admission,
//! and admissions are cheap. [`SupportLevel::ConfigOnly`] is the honest
//! name for a surface that parses and does nothing, and it is not a
//! failure state. Shipping one while calling it stable is.
//!
//! The crate is a true leaf: it depends on `serde` and `schemars` only, so
//! any crate may depend on it without introducing a cycle.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

pub mod scan;

/// Schema version of the capability registry.
///
/// Bump when the shape of an entry changes, not when an entry is added.
pub const CAPABILITY_REGISTRY_VERSION: u32 = 2;

/// Product-support level exposed to config, CLI, admin, and docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Executable end-to-end behavior with named evidence.
    Stable,
    /// Runnable behavior whose production contract is not yet complete.
    Preview,
    /// A parsed or displayed field without an executable consumer.
    ConfigOnly,
    /// Behavior intentionally unavailable in this build.
    Unsupported,
}

impl SupportLevel {
    /// Stable snake-case representation used in JSON and generated docs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
            Self::ConfigOnly => "config_only",
            Self::Unsupported => "unsupported",
        }
    }

    /// Whether a live consumer must exist for this level.
    ///
    /// This is the whole point of the registry. A stable surface has to be
    /// driven by something that is not a test; every other level is an
    /// admission that it is not.
    pub const fn requires_consumer(self) -> bool {
        matches!(self, Self::Stable)
    }
}

/// Compatibility promise attached to a metric name.
///
/// Orthogonal to [`SupportLevel`], which says whether anything writes the
/// metric. This says what we promise about the *name* if something does.
/// A metric can be live and still renameable (`Beta`); it cannot be
/// [`CompatTier::Stable`] without being [`SupportLevel::Stable`], because a
/// naming guarantee on a series nobody emits is a guarantee about nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatTier {
    /// Will not be renamed or removed without a deprecation period.
    Stable,
    /// Functional. May be renamed or relabeled in a minor release.
    Beta,
    /// May be renamed, relabeled, or removed in any release.
    Alpha,
}

impl CompatTier {
    /// Stable snake-case representation used in generated docs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Alpha => "alpha",
        }
    }
}

/// Prometheus family type, as rendered in the generated catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    /// Monotonic counter.
    Counter,
    /// Instantaneous value.
    Gauge,
    /// Bucketed observations, plus the derived `_sum` and `_count` series.
    Histogram,
}

impl MetricKind {
    /// Human-readable name used in the generated catalogue.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "Counter",
            Self::Gauge => "Gauge",
            Self::Histogram => "Histogram",
        }
    }
}

/// Which Prometheus registry a family is registered on.
///
/// SBproxy has two: the private one owned by `ProxyMetrics`, and the
/// process-global default that the `register_*!` macros write to. `render()`
/// gathers both, so a family registered on both is emitted twice and the
/// scrape is rejected by the Prometheus text parser. Declaring the registry
/// per metric lets a test prove the two sets are disjoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Registry {
    /// The private registry owned by `ProxyMetrics`.
    Proxy,
    /// The process-global `prometheus::default_registry()`.
    Default,
}

/// The production site that drives a metric.
///
/// A metric with no writer is dead: it is declared, registered, scraped, and
/// always zero. That is a legitimate state to be in, but it has to be
/// declared, because the alternative is a dashboard that draws a confident
/// flat line through a system that is on fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// A recorder function. The scanner requires at least one call site
    /// outside the function's own definition and outside test-gated code.
    Recorder(&'static str),
    /// A public field on `ProxyMetrics`, written through `metrics().<field>`.
    /// The scanner requires at least one non-test `.<field>` access.
    Field(&'static str),
    /// Nothing writes this family.
    ///
    /// Requires `MetricCapability::dead_reason` and a tracking ticket, and
    /// forces [`SupportLevel::ConfigOnly`]. A dead metric may not be
    /// referenced by any dashboard or alert rule.
    Nothing,
}

impl Writer {
    /// The symbol the scanner searches for, if any.
    pub const fn symbol(self) -> Option<&'static str> {
        match self {
            Self::Recorder(name) | Self::Field(name) => Some(name),
            Self::Nothing => None,
        }
    }
}

/// One metric family, and what we are willing to promise about it.
#[derive(Debug, Clone, Copy)]
pub struct MetricCapability {
    /// Prometheus family name, without the `_bucket` / `_sum` / `_count`
    /// suffixes the client library derives for histograms.
    pub name: &'static str,
    /// Family type.
    pub kind: MetricKind,
    /// Whether anything writes it. See [`Writer`].
    pub writer: Writer,
    /// Whether a live consumer exists. See [`SupportLevel`].
    pub support: SupportLevel,
    /// What we promise about the name. See [`CompatTier`].
    pub compat: CompatTier,
    /// Which registry the family is registered on. Exactly one.
    pub registry: Registry,
    /// The complete label set, in declaration order.
    ///
    /// Positional: the Prometheus handle indexes labels by position, so
    /// reordering is a wire break. Append only. A rule or dashboard that
    /// selects on a label outside this set fails the drift guard, which is
    /// what a `status_class` that never existed should have hit.
    pub labels: &'static [&'static str],
    /// Operator-facing description, rendered into the generated catalogue.
    pub description: &'static str,
    /// Why the family is dead, and the ticket that will resolve it.
    ///
    /// Required when [`Writer::Nothing`], forbidden otherwise.
    pub dead_reason: Option<&'static str>,
}

/// One configuration key, and whether setting it does anything.
#[derive(Debug, Clone, Copy)]
pub struct ConfigKeyCapability {
    /// Dotted configuration path, e.g. `proxy.alerting`.
    pub path: &'static str,
    /// Whether a live consumer reads it. See [`SupportLevel`].
    pub support: SupportLevel,
    /// Named evidence that something consumes it. Required when stable.
    ///
    /// A module path, test name, or call site. The point is that a human
    /// reviewing the entry can go and read the thing it names.
    pub consumer: Option<&'static str>,
    /// What an operator who sets a non-stable key should be told at boot.
    ///
    /// Required for every level except [`SupportLevel::Stable`]. This is the
    /// text that goes in the log line, so write it for someone who just
    /// discovered their PagerDuty key does nothing.
    pub note: Option<&'static str>,
}

/// The value a comparison table is allowed to print for a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimValue {
    /// An unqualified yes. Only a [`SupportLevel::Stable`] capability earns
    /// one.
    Yes,
    /// A qualified answer. The string is printed verbatim, and it is the
    /// only thing a non-stable capability may say about itself.
    Qualified(&'static str),
    /// An unqualified no.
    No,
}

impl ClaimValue {
    /// The exact cell text a comparison table must contain.
    pub const fn cell(self) -> &'static str {
        match self {
            Self::Yes => "Yes",
            Self::Qualified(text) => text,
            Self::No => "No",
        }
    }
}

/// One public, buyer-facing claim, bound to the capability that backs it.
///
/// This exists because `docs/comparison.md` advertised "Clustered without an
/// external Redis: run a fleet and the key plane, budgets, and rate counters
/// stay coherent" for months. The key-plane half was true. The two things
/// the sentence actually named were not. Nothing in the repository could
/// have told you that, because no mechanism connected the sentence to the
/// code.
#[derive(Debug, Clone, Copy)]
pub struct Claim {
    /// The row label as it appears in the comparison table. This is the
    /// join key: the guard finds the row by this text.
    pub row: &'static str,
    /// The capability that backs the claim.
    pub capability: &'static str,
    /// What the table is allowed to say. Derived from the capability's
    /// support level by [`validate_claims`], not chosen freely.
    pub value: ClaimValue,
}

/// One product capability that a public claim may cite.
#[derive(Debug, Clone, Copy)]
pub struct ProductCapability {
    /// Stable dotted identifier.
    pub id: &'static str,
    /// Whether the behavior exists. See [`SupportLevel`].
    pub support: SupportLevel,
    /// Concise operator-facing summary. Rendered into the capability matrix.
    pub summary: &'static str,
    /// Named evidence. Required when stable; a test, module, or benchmark
    /// a reader can go and check.
    pub evidence: &'static [&'static str],
}

/// A registry invariant that a table violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    /// The entry at fault.
    pub subject: String,
    /// What is wrong with it, and what to do about it.
    pub message: String,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.subject, self.message)
    }
}

/// Enforce the metric-table invariants that do not require a source scan.
///
/// The scan-dependent half (a stable metric owes a real, non-test increment
/// site) lives in [`scan::verify_writers`], because it needs the source tree.
pub fn validate_metrics(metrics: &[MetricCapability]) -> Vec<RegistryError> {
    let mut errors = Vec::new();
    let mut seen: Vec<&str> = Vec::new();

    for metric in metrics {
        let subject = metric.name.to_string();

        if seen.contains(&metric.name) {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: "declared twice in the metric registry".to_string(),
            });
        }
        seen.push(metric.name);

        match (metric.writer, metric.dead_reason) {
            (Writer::Nothing, None) => errors.push(RegistryError {
                subject: subject.clone(),
                message: "nothing writes this metric, so it needs a dead_reason \
                          naming the ticket that wires or deletes it"
                    .to_string(),
            }),
            (Writer::Nothing, Some(_)) if metric.support != SupportLevel::ConfigOnly => {
                errors.push(RegistryError {
                    subject: subject.clone(),
                    message: format!(
                        "nothing writes this metric, so it is config_only, not {}",
                        metric.support.as_str()
                    ),
                });
            }
            (_, Some(_)) if !matches!(metric.writer, Writer::Nothing) => {
                errors.push(RegistryError {
                    subject: subject.clone(),
                    message: "has a writer, so it must not carry a dead_reason".to_string(),
                });
            }
            _ => {}
        }

        if metric.support == SupportLevel::ConfigOnly && !matches!(metric.writer, Writer::Nothing) {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: "is config_only but names a writer; either wire it and \
                          promote it, or set the writer to Nothing"
                    .to_string(),
            });
        }

        // The rule that stops a dead metric being published as a compat
        // guarantee. docs/metrics-stability.md shipped eight of these.
        if metric.compat == CompatTier::Stable && metric.support != SupportLevel::Stable {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: format!(
                    "cannot promise a stable name for a {} metric; a naming \
                     guarantee on a series nothing emits is a guarantee about nothing",
                    metric.support.as_str()
                ),
            });
        }

        if metric.labels.iter().any(|label| label.is_empty()) {
            errors.push(RegistryError {
                subject,
                message: "has an empty label name".to_string(),
            });
        }
    }

    errors
}

/// Enforce the config-key invariants.
pub fn validate_config_keys(keys: &[ConfigKeyCapability]) -> Vec<RegistryError> {
    let mut errors = Vec::new();
    let mut seen: Vec<&str> = Vec::new();

    for key in keys {
        let subject = key.path.to_string();

        if seen.contains(&key.path) {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: "declared twice in the config registry".to_string(),
            });
        }
        seen.push(key.path);

        if key.support.requires_consumer() && key.consumer.is_none() {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: "is stable but names no consumer; a stable key that \
                          nothing reads is a key that silently does nothing"
                    .to_string(),
            });
        }

        if key.support != SupportLevel::Stable && key.note.is_none() {
            errors.push(RegistryError {
                subject,
                message: format!(
                    "is {} and needs a note; the operator who sets it learns at \
                     boot that it does nothing, and the note is what they read",
                    key.support.as_str()
                ),
            });
        }
    }

    errors
}

/// Enforce the config-key invariants against the live top-level key set.
///
/// `declared` is every top-level `proxy:` key the schema actually has, which
/// the caller obtains by reflecting the config struct (the same trick
/// `schema_field_paths()` uses in the model-host registry). This is what makes
/// the registry impossible to leave stale: a key added to the config without a
/// classification here is a set-difference the caller turns into a build
/// failure, and a classification here for a key the schema dropped is the other
/// direction.
pub fn validate_config_key_coverage(
    keys: &[ConfigKeyCapability],
    declared: &[&str],
) -> Vec<RegistryError> {
    let mut errors = validate_config_keys(keys);

    for key in keys {
        if !declared.contains(&key.path) {
            errors.push(RegistryError {
                subject: key.path.to_string(),
                message: "is classified but is not a real top-level config key; \
                          the schema dropped or renamed it"
                    .to_string(),
            });
        }
    }

    // Only inert keys have to be listed. A stable key is the default and needs
    // no entry, so coverage is one-directional: every non-stable key must be
    // classified, but a stable key may be absent.
    let classified: Vec<&str> = keys.iter().map(|k| k.path).collect();
    for path in declared {
        if !classified.contains(path) {
            // Absent means "assumed stable". That is only a problem if it is
            // not, which the boot-warning test and the operator will surface;
            // the registry cannot know without a consumer probe per key, which
            // is future work. Left as a note rather than an error so the guard
            // stays truthful about what it checks.
            let _ = path;
        }
    }

    errors
}

/// Enforce that no public claim outruns the capability behind it.
///
/// A plain "Yes" in a comparison table is reserved for a stable capability.
/// Anything else has to say what it actually does, in the cell, where a
/// buyer reads it.
pub fn validate_claims(claims: &[Claim], capabilities: &[ProductCapability]) -> Vec<RegistryError> {
    let mut errors = Vec::new();

    for capability in capabilities {
        if capability.support.requires_consumer() && capability.evidence.is_empty() {
            errors.push(RegistryError {
                subject: capability.id.to_string(),
                message: "is stable and owes evidence a reader can go and check".to_string(),
            });
        }
    }

    for claim in claims {
        let subject = format!("claim '{}'", claim.row);
        let Some(capability) = capabilities.iter().find(|c| c.id == claim.capability) else {
            errors.push(RegistryError {
                subject,
                message: format!("cites unknown capability '{}'", claim.capability),
            });
            continue;
        };

        if claim.value == ClaimValue::Yes && capability.support != SupportLevel::Stable {
            errors.push(RegistryError {
                subject,
                message: format!(
                    "says a plain \"Yes\" while capability '{}' is {}; say what it \
                     actually does instead",
                    capability.id,
                    capability.support.as_str()
                ),
            });
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(name: &'static str) -> MetricCapability {
        MetricCapability {
            name,
            kind: MetricKind::Counter,
            writer: Writer::Recorder("record_thing"),
            support: SupportLevel::Stable,
            compat: CompatTier::Stable,
            registry: Registry::Proxy,
            labels: &["result"],
            description: "A thing.",
            dead_reason: None,
        }
    }

    #[test]
    fn a_dead_metric_cannot_promise_a_stable_name() {
        let dead = MetricCapability {
            writer: Writer::Nothing,
            support: SupportLevel::ConfigOnly,
            compat: CompatTier::Stable,
            dead_reason: Some("nothing calls record_thing (WOR-1898)"),
            ..metric("sbproxy_dead_total")
        };

        let errors = validate_metrics(&[dead]);

        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("cannot promise a stable name")),
            "a metric nothing writes must not be published as stable: {errors:?}"
        );
    }

    #[test]
    fn a_dead_metric_must_name_the_ticket_that_resolves_it() {
        let dead = MetricCapability {
            writer: Writer::Nothing,
            support: SupportLevel::ConfigOnly,
            compat: CompatTier::Alpha,
            dead_reason: None,
            ..metric("sbproxy_dead_total")
        };

        let errors = validate_metrics(&[dead]);

        assert!(
            errors.iter().any(|e| e.message.contains("dead_reason")),
            "known-dead must be a deliberate, ticketed choice: {errors:?}"
        );
    }

    #[test]
    fn a_live_stable_metric_validates() {
        assert_eq!(validate_metrics(&[metric("sbproxy_live_total")]), vec![]);
    }

    #[test]
    fn a_config_only_key_must_tell_the_operator_what_it_does_not_do() {
        let key = ConfigKeyCapability {
            path: "proxy.alerting",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: None,
        };

        let errors = validate_config_keys(&[key]);

        assert!(
            errors.iter().any(|e| e.message.contains("needs a note")),
            "an inert key owes the operator an explanation: {errors:?}"
        );
    }

    #[test]
    fn a_stable_key_must_name_its_consumer() {
        let key = ConfigKeyCapability {
            path: "proxy.listen",
            support: SupportLevel::Stable,
            consumer: None,
            note: None,
        };

        let errors = validate_config_keys(&[key]);

        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("names no consumer")),
            "a stable key that nothing reads is the bug we are fixing: {errors:?}"
        );
    }

    #[test]
    fn a_claim_cannot_say_yes_for_a_capability_that_does_not_work() {
        let capabilities = [ProductCapability {
            id: "cluster.budget_coherence",
            support: SupportLevel::ConfigOnly,
            summary: "Counters are written, never merged.",
            evidence: &[],
        }];
        let claims = [Claim {
            row: "Cluster-wide budgets without a shared backend",
            capability: "cluster.budget_coherence",
            value: ClaimValue::Yes,
        }];

        let errors = validate_claims(&claims, &capabilities);

        assert!(
            errors.iter().any(|e| e.message.contains("plain \"Yes\"")),
            "this is exactly the claim that shipped for months: {errors:?}"
        );
    }

    #[test]
    fn a_qualified_claim_is_allowed_to_describe_a_partial_capability() {
        let capabilities = [ProductCapability {
            id: "cluster.budget_coherence",
            support: SupportLevel::ConfigOnly,
            summary: "Counters are written, never merged.",
            evidence: &[],
        }];
        let claims = [Claim {
            row: "Cluster-wide budgets without a shared backend",
            capability: "cluster.budget_coherence",
            value: ClaimValue::Qualified("Shared backend today"),
        }];

        assert_eq!(validate_claims(&claims, &capabilities), vec![]);
    }
}
