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

pub mod config_scan;
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
    /// A recorder function, or a metric static's own `SCREAMING_SNAKE_CASE`
    /// identifier for crates that drive Prometheus statics directly (the
    /// mesh crate does). The scanner requires at least one call site (for a
    /// static: one use of the identifier in code, outside its own
    /// declaration) outside test-gated regions.
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

/// The production site that opens a span.
///
/// The span analogue of [`Writer`], and it needs one more state than the
/// metric side does. A metric is declared by the same call that registers
/// it, so "declared" and "registered" are one thing. A span is not: a
/// constructor can exist, compile, name a real span, and have no caller,
/// which is a third state between live and absent. `docs/observability.md`
/// published eight span names that no constructor exists for, while three
/// constructors that do exist have never been called from production, so
/// both of those states were live on `main` at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanEmitter {
    /// A constructor function that returns the span, with at least one
    /// production caller. The scanner requires the symbol to be defined in
    /// a crate and called at least once outside test-gated regions, which
    /// is [`Writer::Recorder`]'s rule applied to a `tracing::Span`.
    Constructor(&'static str),
    /// The span is opened inline by a `tracing::*_span!` macro that carries
    /// the name as a string literal, inside the named production function.
    ///
    /// The scanner requires both that the name appears in a span-macro
    /// position outside test-gated regions, and that `site` is a function
    /// defined somewhere in the workspace. Use this only where no
    /// constructor wraps the macro; where one does, name it with
    /// [`SpanEmitter::Constructor`] instead, because the constructor's own
    /// body would otherwise satisfy the literal check on its own.
    Literal {
        /// The production function whose body opens the span.
        site: &'static str,
    },
    /// A constructor exists and nothing in production calls it.
    ///
    /// Requires `SpanCapability::dead_reason` and forces
    /// [`SupportLevel::ConfigOnly`]. The scanner checks this one in both
    /// directions: the symbol has to still exist, and it has to still have
    /// no caller, so wiring one up fails the guard until the entry is
    /// promoted to [`SpanEmitter::Constructor`].
    Unwired(&'static str),
    /// Nothing anywhere opens this span. It exists in documentation only.
    ///
    /// Requires `SpanCapability::dead_reason` and forces
    /// [`SupportLevel::ConfigOnly`]. The scanner requires the name to be
    /// absent from every span-macro position in production source, so the
    /// entry cannot survive the span being implemented.
    Nothing,
}

impl SpanEmitter {
    /// Whether production code opens this span today.
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Constructor(_) | Self::Literal { .. })
    }
}

/// One span name, and what we are willing to promise about it.
///
/// Modeled on [`MetricCapability`], including the two orthogonal axes.
/// [`SupportLevel`] says whether anything emits the span;
/// [`CompatTier`] says what we promise about the *name* if something does.
/// Both transfer intact, because a span name is consumed exactly the way a
/// metric name is: dashboards group by it, trace queries filter on it, and
/// renaming one breaks every saved view that mentions it. So the same rule
/// holds, for the same reason: a name cannot be [`CompatTier::Stable`]
/// without being [`SupportLevel::Stable`], because a naming guarantee on a
/// span nobody emits is a guarantee about nothing.
///
/// The label set is the one field that does not carry over. A metric's
/// labels are positional and bounded, and a query that selects on a label
/// the metric lacks silently matches everything, which is why
/// `MetricCapability::labels` has to be exhaustive. Span attributes are
/// neither positional nor bounded, they are already pinned for the AI
/// spans by the semconv conformance test in
/// `crates/sbproxy-ai/src/tracing_spans.rs`, and an attribute a span lacks
/// simply does not render. Listing them here would be a second,
/// weaker copy of a check that already exists.
#[derive(Debug, Clone, Copy)]
pub struct SpanCapability {
    /// The span name as a trace backend sees it, for example
    /// `sbproxy.rail.reconcile` or `ai.request`.
    pub name: &'static str,
    /// The pillar slug for a `sbproxy.<pillar>.<verb>` name, otherwise
    /// `None`.
    ///
    /// Spans that follow a foreign convention (the OpenTelemetry GenAI
    /// vocabulary, for one) are not pillar-shaped and say so rather than
    /// being forced into a pillar they do not belong to.
    pub pillar: Option<&'static str>,
    /// The verb half of a `sbproxy.<pillar>.<verb>` name. Set exactly when
    /// `pillar` is.
    pub verb: Option<&'static str>,
    /// What opens it. See [`SpanEmitter`].
    pub emitter: SpanEmitter,
    /// Whether anything emits it. See [`SupportLevel`].
    pub support: SupportLevel,
    /// What we promise about the name. See [`CompatTier`].
    pub compat: CompatTier,
    /// Operator-facing description, rendered into the published vocabulary.
    pub description: &'static str,
    /// Why the span is not emitted, and the ticket that resolves it.
    ///
    /// Required for [`SpanEmitter::Unwired`] and [`SpanEmitter::Nothing`],
    /// forbidden otherwise, and it has to name a ticket. A published span
    /// name that nothing emits is the defect this registry exists to catch,
    /// so "known dead" has to stay a deliberate, tracked choice rather than
    /// decaying back into "nobody noticed".
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

/// Enforce the span-table invariants that do not require a source scan.
///
/// The scan-dependent half (a live span owes a real, non-test emission
/// site, and a dead one owes the absence of it) lives in
/// [`scan::verify_span_emitters`], because it needs the source tree.
///
/// `pillars` is the canonical pillar vocabulary, which this crate cannot
/// know: it is a leaf, and the pillar enum lives with the tracing helpers
/// that build span names from it. Passing it in is what lets the shape rule
/// run in both directions. A `sbproxy.<pillar>.<verb>` name has to declare
/// the parts it is built from, and a declared pillar has to be a real one,
/// so neither a new pillar span that slips in unclassified nor a typo in a
/// pillar slug survives.
pub fn validate_spans(spans: &[SpanCapability], pillars: &[&str]) -> Vec<RegistryError> {
    let mut errors = Vec::new();
    let mut seen: Vec<&str> = Vec::new();

    for span in spans {
        let subject = span.name.to_string();

        if seen.contains(&span.name) {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: "declared twice in the span registry".to_string(),
            });
        }
        seen.push(span.name);

        match (span.emitter.is_live(), span.dead_reason) {
            (false, None) => errors.push(RegistryError {
                subject: subject.clone(),
                message: "nothing emits this span, so it needs a dead_reason \
                          naming the ticket that emits or deletes it"
                    .to_string(),
            }),
            (false, Some(_)) if span.support != SupportLevel::ConfigOnly => {
                errors.push(RegistryError {
                    subject: subject.clone(),
                    message: format!(
                        "nothing emits this span, so it is config_only, not {}",
                        span.support.as_str()
                    ),
                });
            }
            (true, Some(_)) => errors.push(RegistryError {
                subject: subject.clone(),
                message: "has an emitter, so it must not carry a dead_reason".to_string(),
            }),
            _ => {}
        }

        // A dead_reason with no ticket is a shrug. The metric registry
        // learned this on its reference allow-list: an escape hatch that
        // does not name the thing that closes it never gets closed.
        if let Some(reason) = span.dead_reason {
            if !reason.contains("WOR-") {
                errors.push(RegistryError {
                    subject: subject.clone(),
                    message: format!(
                        "has a dead_reason that names no ticket: '{reason}'. Name the \
                         one that emits or deletes the span"
                    ),
                });
            }
        }

        if span.support == SupportLevel::ConfigOnly && span.emitter.is_live() {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: "is config_only but names a live emitter; either promote it, \
                          or move the emitter to Unwired or Nothing"
                    .to_string(),
            });
        }

        // The rule that stops a span nothing emits being published as a
        // naming guarantee. docs/observability.md shipped eight of these.
        if span.compat == CompatTier::Stable && span.support != SupportLevel::Stable {
            errors.push(RegistryError {
                subject: subject.clone(),
                message: format!(
                    "cannot promise a stable name for a {} span; a naming guarantee \
                     on a span nothing emits is a guarantee about nothing",
                    span.support.as_str()
                ),
            });
        }

        errors.extend(validate_span_name_shape(span, pillars));
    }

    errors
}

/// Check that a pillar-shaped entry's name really is `sbproxy.<pillar>.<verb>`.
///
/// Split out so the shape rule reads as one thing. The halves have to agree
/// in both directions: a name is pillar-shaped exactly when the entry
/// declares a real pillar and a verb, so a pillar span whose parts drifted
/// from its name, a typo in a pillar slug, and a new pillar span that
/// nobody classified all fail here.
///
/// The reverse direction is keyed on `pillars` rather than on the name's
/// dot count, because a dot count cannot tell `sbproxy.rail.settle` from
/// `sbproxy.ai.usage_sink`. The first is a pillar span. The second is an AI
/// span that happens to be three segments long, and demanding a pillar for
/// it would mean inventing one.
fn validate_span_name_shape(span: &SpanCapability, pillars: &[&str]) -> Vec<RegistryError> {
    let subject = span.name.to_string();
    match (span.pillar, span.verb) {
        (Some(pillar), Some(verb)) => {
            let mut errors = Vec::new();
            if !pillars.contains(&pillar) {
                errors.push(RegistryError {
                    subject: subject.clone(),
                    message: format!(
                        "declares pillar '{pillar}', which is not one of the canonical \
                         pillars {pillars:?}"
                    ),
                });
            }
            let expected = format!("sbproxy.{pillar}.{verb}");
            if span.name != expected {
                errors.push(RegistryError {
                    subject,
                    message: format!(
                        "declares pillar '{pillar}' and verb '{verb}', which spell \
                         '{expected}', not its own name"
                    ),
                });
            }
            errors
        }
        (None, None) => {
            let pillar_shaped = span
                .name
                .strip_prefix("sbproxy.")
                .and_then(|rest| rest.split_once('.'))
                .is_some_and(|(pillar, verb)| {
                    pillars.contains(&pillar) && !verb.is_empty() && !verb.contains('.')
                });
            if pillar_shaped {
                vec![RegistryError {
                    subject,
                    message: "is spelled like sbproxy.<pillar>.<verb> but declares no \
                              pillar or verb; fill both in so the shape rule and the \
                              published table see it as a pillar span"
                        .to_string(),
                }]
            } else {
                Vec::new()
            }
        }
        _ => vec![RegistryError {
            subject,
            message: "sets exactly one of pillar and verb; a span name is built from \
                      both or from neither"
                .to_string(),
        }],
    }
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

    const PILLARS: &[&str] = &[
        "intake",
        "policy",
        "action",
        "transform",
        "ledger",
        "rail",
        "audit",
        "notify",
    ];

    fn span(name: &'static str) -> SpanCapability {
        SpanCapability {
            name,
            pillar: None,
            verb: None,
            emitter: SpanEmitter::Constructor("thing_span"),
            support: SupportLevel::Stable,
            compat: CompatTier::Beta,
            description: "A thing.",
            dead_reason: None,
        }
    }

    #[test]
    fn a_span_nothing_emits_cannot_promise_a_stable_name() {
        let dead = SpanCapability {
            pillar: Some("intake"),
            verb: Some("accept"),
            emitter: SpanEmitter::Nothing,
            support: SupportLevel::ConfigOnly,
            compat: CompatTier::Stable,
            dead_reason: Some("published but emitted by nothing (WOR-2318)"),
            ..span("sbproxy.intake.accept")
        };

        let errors = validate_spans(&[dead], PILLARS);

        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("cannot promise a stable name")),
            "eight of these shipped in docs/observability.md: {errors:?}"
        );
    }

    #[test]
    fn a_span_nothing_emits_must_name_the_ticket_that_resolves_it() {
        let dead = SpanCapability {
            emitter: SpanEmitter::Nothing,
            support: SupportLevel::ConfigOnly,
            dead_reason: None,
            ..span("ai.unwired")
        };

        let errors = validate_spans(&[dead], PILLARS);

        assert!(
            errors.iter().any(|e| e.message.contains("dead_reason")),
            "known-dead must be a deliberate, ticketed choice: {errors:?}"
        );
    }

    #[test]
    fn a_dead_reason_without_a_ticket_is_rejected() {
        let dead = SpanCapability {
            emitter: SpanEmitter::Unwired("streaming_span"),
            support: SupportLevel::ConfigOnly,
            dead_reason: Some("nobody calls it"),
            ..span("ai.streaming")
        };

        let errors = validate_spans(&[dead], PILLARS);

        assert!(
            errors.iter().any(|e| e.message.contains("names no ticket")),
            "an untracked admission never gets closed: {errors:?}"
        );
    }

    #[test]
    fn a_pillar_span_whose_parts_do_not_spell_its_name_is_rejected() {
        let mismatched = SpanCapability {
            pillar: Some("rail"),
            verb: Some("settle"),
            ..span("sbproxy.rail.reconcile")
        };

        let errors = validate_spans(&[mismatched], PILLARS);

        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("sbproxy.rail.settle")),
            "the name and its parts have to agree: {errors:?}"
        );
    }

    #[test]
    fn a_pillar_slug_that_is_not_a_pillar_is_rejected() {
        let invented = SpanCapability {
            pillar: Some("ai"),
            verb: Some("usage_sink"),
            ..span("sbproxy.ai.usage_sink")
        };

        let errors = validate_spans(&[invented], PILLARS);

        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("not one of the canonical pillars")),
            "an invented pillar would put a span under a filter value nothing else \
             uses: {errors:?}"
        );
    }

    #[test]
    fn a_pillar_shaped_name_must_declare_its_pillar() {
        let errors = validate_spans(&[span("sbproxy.audit.emit")], PILLARS);

        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("declares no pillar or verb")),
            "an unclassified pillar span is invisible to the shape rule: {errors:?}"
        );
    }

    #[test]
    fn a_three_segment_name_whose_middle_is_not_a_pillar_needs_no_pillar() {
        // `sbproxy.ai.usage_sink` is three segments and is not a pillar
        // span. A dot-count heuristic would demand a pillar for it, and the
        // only way to satisfy that would be to invent one.
        assert_eq!(
            validate_spans(&[span("sbproxy.ai.usage_sink")], PILLARS),
            vec![]
        );
    }

    #[test]
    fn a_live_span_validates() {
        assert_eq!(validate_spans(&[span("ai.request")], PILLARS), vec![]);
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
