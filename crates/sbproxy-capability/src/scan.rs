// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Source and query scanning: the half of the registry that cannot be a
//! const table.
//!
//! The old drift guard substring-matched each dashboard metric against a
//! concatenation of every `.rs` file in the workspace. A metric mentioned in
//! a comment passed. A metric that was declared and never incremented passed,
//! because the declaration *is* the match. That is how a Grafana panel for
//! `sbproxy_ai_guardrail_blocks_total` shipped against a counter with no
//! writer, drawing a flat zero over a guardrail that was never observed.
//!
//! So this module answers three questions the table cannot:
//!
//! 1. Does a production caller drive this metric? ([`verify_writers`])
//! 2. Is every metric a dashboard or alert rule names actually live?
//!    ([`verify_references`])
//! 3. Does every label a query selects on exist on the metric it selects
//!    from? ([`verify_references`], again)
//!
//! Question 3 is the one that had been open longest. `deploy/alerts/` matched
//! `sbproxy_requests_total{status_class!="5xx"}` against a label set that has
//! never contained `status_class`. In PromQL an absent label is the empty
//! string and `"" != "5xx"` is true, so the matcher selected every series,
//! the numerator equalled the denominator, and the availability SLO read a
//! confident 1.0 through any outage you care to imagine.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use syn::parse::Parser;

use crate::{MetricCapability, RegistryError, SpanCapability, SpanEmitter, SupportLevel, Writer};

/// Labels Prometheus itself attaches, which no metric declares.
const IMPLICIT_LABELS: &[&str] = &["job", "instance", "le", "quantile", "__name__"];

/// Metric-name prefixes this registry sanctions.
///
/// `sbproxy_` covers the proxy and its gateway surfaces; `mesh_` covers
/// the clustering substrate (SWIM membership, replication, cross-node
/// transport). Both [`declared_metrics`] and [`references_in`] recognize
/// exactly these prefixes: a declaration or query outside them is
/// invisible to the drift guard.
const SANCTIONED_PREFIXES: &[&str] = &["sbproxy_", "mesh_"];

/// Directories scanned for PromQL: dashboards and alert rules alike.
///
/// The old guard looked at `dashboards/grafana/` only, which is precisely the
/// one directory where nothing was broken.
///
/// `deploy/dashboards/` was excluded for a while, on the grounds that its
/// panels filter on `tenant_id` and no metric they query carries that label, so
/// switching the guard on would fail the build on an open schema question
/// (whether `tenant_id` becomes a real label, which is a wire break). That
/// framing was wrong twice over. The panels did not merely filter on a missing
/// label: they read seven metric names no crate declares, grouped on `route`,
/// `rail`, `policy` and `decision`, which are not labels on anything, and
/// computed error rates from `status_class`, the exact matcher whose absence
/// pinned the availability SLO at 1.0 and is the reason this guard exists. And
/// the `tenant_id` filter was never load bearing: the variable behind it is
/// populated by `label_values(<metric>, tenant_id)`, which returns nothing, so
/// operators got an always-empty dropdown over unfiltered data while the panel
/// title promised one tenant's slice.
///
/// So the directory is in, and the queries were corrected the same way
/// `deploy/alerts/recording-rules.yml` had already corrected its own copy of
/// these defects: `status` is the raw code, the ledger and audit counts come
/// from their histograms' `_count` series, and the grouping keys are the labels
/// the metrics actually carry.
///
/// Nine panels could not be retargeted, because they asked for a dimension no
/// metric in this workspace has. Grafana JSON carries no comments, so the
/// ledger is here:
///
/// - `traces-overview.json` lost its three PromQL panels.
///   `sbproxy_spans_emitted_total` and `sbproxy_traces_started_total` are
///   declared nowhere, and nothing on the OTLP path counts spans or traces at
///   all; `sbproxy_telemetry_dropped_total` counts drops, which is a different
///   question. WOR-2318 owns the non-AI tracing gap, and the panels come back
///   with the counters that feed them. The dashboard keeps its Tempo search and
///   its `pillar` variable, which `span_drift.rs` pins to the `Pillar` enum.
/// - `audit-log.json` lost "Audit chain-position lag"
///   (`sbproxy_audit_chain_position_lag` is declared nowhere, and the only
///   chain metrics in the workspace belong to the meter, a different
///   subsystem) and "Top audit subjects" (`subject_kind` is not a label, and
///   per-subject identity is unbounded, which is what the run-scoped label
///   guard exists to keep off metrics; that panel's own description already
///   said it belongs on a span).
/// - `content-shapes.json` lost the Markdown token histogram
///   (`sbproxy_markdown_token_estimate` is declared nowhere; the estimate is
///   stamped on a response header and never observed) and the Content-Signal
///   breakdown (`content_signal` is not a label on anything).
/// - `boilerplate-stripping.json` lost its Markdown projection latency panel:
///   the transform records stripped bytes but never times itself.
/// - `per-agent.json` lost "Latency p95 by agent class".
///   `sbproxy_request_duration_seconds` carries only `hostname`, and no
///   histogram here has an agent dimension. Left in place with the agent
///   filters silently ignored, it would have shown an operator who had narrowed
///   to one vendor the latency of all of them.
///
/// One control went the other way, gaining a matcher rather than losing a
/// panel. `per-agent.json` shipped an `agent_id` textbox labeled "logs/traces
/// only", above a description asserting that `agent_id` is not a Prometheus
/// label. It is one: `record_request_with_labels` stamps it on
/// `sbproxy_requests_total` next to `agent_class` and `agent_vendor`, and
/// `RUN_SCOPED_LABEL_STEMS` in `sbproxy-observe` names it in its own doc as a
/// live label the cardinality rule deliberately passes (the segment before its
/// `_id` suffix is `agent`, not a run stem). So an operator typed an agent id
/// into a control that filtered nothing and read the whole fleet under four
/// panels titled for the agents they had selected. All four matchers now carry
/// `agent_id=~"$agent_id"`, and the box defaults to `.*` so the unfiltered
/// view is exactly where it was. No guard catches this one: a dashboard that
/// declines to filter on a label that exists is not a query defect, which is
/// why it is written down here.
///
/// Variable queries are read too, not just `expr`. A Grafana `templating`
/// entry whose query is `label_values(<selector>, <label>)` is a live read of
/// the same metric the panels use, and it fails the same three ways, so
/// [`promql_only`] rewrites it into the selector it implies and the shared
/// extractor checks it like any other query. Leaving it out was not a
/// theoretical gap: `deploy/dashboards/licensing-edits.json` sourced its
/// tenant dropdown from `label_values(sbproxy_audit_emit_total, tenant_id)`,
/// and no crate has ever declared `sbproxy_audit_emit_total`. Every panel on
/// that dashboard filters `tenant_id IN ($tenant_id)`, so the one variable
/// nothing could populate was the one every panel depended on. It now reads
/// `SELECT DISTINCT tenant_id FROM admin_audit_events`, the table those panels
/// already query and the only place the tenant dimension exists: `tenant_id`
/// is a column there and is not a label on any audit metric. With the
/// Prometheus variable gone, nothing on that dashboard reads Prometheus, so
/// its datasource picker went too.
///
/// A dropdown is worth the check for a reason the panel case does not cover.
/// A dead `expr` draws an empty panel, which an operator sees. A dead
/// `label_values` leaves an empty *selector*, and what happens next depends on
/// the query it feeds rather than on the dropdown. Feeding SQL, as
/// licensing-edits did, it produces `IN ()` and the panel fails loudly.
/// Feeding a PromQL matcher it does the opposite: `=~"$var"` over an empty
/// variable stops constraining anything, so the operator does not get no data,
/// they get everyone's data under a title naming one of them. That is the
/// `status_class` failure again, arriving through the variable rather than
/// through the matcher, and `dashboards/grafana/sbproxy-ai-value.json` is
/// where it would land: its tenant and api-key dropdowns both come from
/// `label_values` and both feed `=~` matchers on per-tenant panels. They are
/// correct today, and now a rename cannot quietly make them otherwise.
///
/// One blind spot remains, and it is not a place a broken SLO can hide: a
/// dashboard shipped outside these four directories is not scanned at all.
const QUERY_DIRS: &[&str] = &[
    "dashboards/grafana",
    "dashboards/prometheus",
    "deploy/alerts",
    "deploy/dashboards",
];

/// A Rust source file with both its original and production-only views.
pub struct SourceFile {
    /// Path, relative to the repo root.
    pub path: PathBuf,
    /// Original file text, used for syntax-aware analysis.
    pub raw_text: String,
    /// File text with `#[cfg(test)]` items and `#[test]` functions stripped.
    pub text: String,
    /// [`Self::raw_text`] parsed exactly once, when the file was collected.
    ///
    /// Every consumer that needs an AST borrows this rather than calling
    /// `syn::parse_file` again. Before this field existed each production file
    /// was parsed up to five times per guard invocation: once to walk its
    /// `mod` declarations, then again by the parse-error check, the type
    /// index, the field-read resolver, and every symbol lookup. Parsing the
    /// workspace is the dominant cost in the two capability guards, so the
    /// repeats were most of a 23s test.
    ///
    /// The error is rendered to `String` because `syn::Error` is not `Clone`
    /// and its only consumer wants the formatted message.
    pub ast: Result<syn::File, String>,
}

/// Whether an item's attributes make it unreachable in every production build.
pub(crate) fn attributes_exclude_production(attributes: &[syn::Attribute]) -> bool {
    if attributes
        .iter()
        .any(|attribute| path_is_test_attribute(attribute.path()))
    {
        return true;
    }

    let predicates = production_cfg_predicates(attributes);
    predicates.is_some_and(|predicates| {
        !predicates.is_empty() && !cfg_predicates_can_be_production(&predicates)
    })
}

fn path_is_test_attribute(path: &syn::Path) -> bool {
    if path.is_ident("test") {
        return true;
    }
    let mut segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string());
    matches!(
        (
            segments.next().as_deref(),
            segments.next().as_deref(),
            segments.next()
        ),
        (Some("tokio" | "async_std"), Some("test"), None)
    )
}

fn production_cfg_predicates(attributes: &[syn::Attribute]) -> Option<Vec<syn::Meta>> {
    let mut predicates = Vec::new();
    for attribute in attributes {
        let syn::Meta::List(list) = &attribute.meta else {
            if attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr") {
                return None;
            }
            continue;
        };
        if list.path.is_ident("cfg") {
            predicates.push(list.parse_args::<syn::Meta>().ok()?);
        } else if list.path.is_ident("cfg_attr") {
            let items = parse_meta_items(list)?;
            let (condition, attributes) = items.split_first()?;
            collect_cfg_attr_predicates(condition, attributes, &mut predicates)?;
        }
    }
    Some(predicates)
}

fn collect_cfg_attr_predicates(
    condition: &syn::Meta,
    attributes: &[syn::Meta],
    predicates: &mut Vec<syn::Meta>,
) -> Option<()> {
    for attribute in attributes {
        if path_is_test_attribute(attribute.path()) {
            let condition = condition.clone();
            predicates.push(syn::parse_quote!(not(#condition)));
            continue;
        }
        let syn::Meta::List(list) = attribute else {
            continue;
        };
        if list.path.is_ident("cfg") {
            let predicate = list.parse_args::<syn::Meta>().ok()?;
            let condition = condition.clone();
            predicates.push(syn::parse_quote!(any(not(#condition), #predicate)));
        } else if list.path.is_ident("cfg_attr") {
            let items = parse_meta_items(list)?;
            let (nested_condition, attributes) = items.split_first()?;
            let condition = condition.clone();
            let nested_condition = nested_condition.clone();
            let combined: syn::Meta = syn::parse_quote!(all(#condition, #nested_condition));
            collect_cfg_attr_predicates(&combined, attributes, predicates)?;
        }
    }
    Some(())
}

#[derive(Clone, Copy)]
struct CfgPossibility {
    can_be_true: bool,
    can_be_false: bool,
}

impl CfgPossibility {
    const UNKNOWN: Self = Self {
        can_be_true: true,
        can_be_false: true,
    };
}

fn cfg_predicates_can_be_production(predicates: &[syn::Meta]) -> bool {
    if cfg_conjunction_has_direct_contradiction(predicates) {
        return false;
    }
    let mut atoms = BTreeSet::new();
    for predicate in predicates {
        collect_cfg_atoms(predicate, &mut atoms);
    }
    atoms.remove("test");
    let mut polarities = BTreeMap::<String, CfgAtomPolarity>::new();
    for predicate in predicates {
        collect_cfg_atom_polarities(predicate, true, &mut polarities);
    }
    let mut atoms: Vec<_> = atoms.into_iter().collect();
    atoms.sort_by(|left, right| {
        cfg_atom_search_priority(left, &polarities)
            .cmp(&cfg_atom_search_priority(right, &polarities))
            .then_with(|| left.cmp(right))
    });
    cfg_assignment_can_satisfy(predicates, &atoms, 0, &mut BTreeMap::<&str, bool>::new())
}

pub(crate) fn production_cfg_condition_possibility(predicate: &syn::Meta) -> (bool, bool) {
    let can_be_true = cfg_predicates_can_be_production(std::slice::from_ref(predicate));
    let predicate = predicate.clone();
    let negated: syn::Meta = syn::parse_quote!(not(#predicate));
    let can_be_false = cfg_predicates_can_be_production(std::slice::from_ref(&negated));
    (can_be_true, can_be_false)
}

fn cfg_atom_search_priority(atom: &str, polarities: &BTreeMap<String, CfgAtomPolarity>) -> u8 {
    if atom == "unix"
        || atom == "windows"
        || atom
            .split_once('=')
            .is_some_and(|(key, _)| cfg_key_has_single_value(key))
    {
        return 0;
    }
    if polarities
        .get(atom)
        .is_some_and(|polarity| polarity.positive && polarity.negative)
    {
        return 1;
    }
    2
}

fn cfg_assignment_can_satisfy<'a>(
    predicates: &[syn::Meta],
    atoms: &'a [String],
    index: usize,
    values: &mut BTreeMap<&'a str, bool>,
) -> bool {
    if predicates
        .iter()
        .any(|predicate| !evaluate_cfg_predicate(predicate, values).can_be_true)
    {
        return false;
    }
    let Some(atom) = atoms.get(index).map(String::as_str) else {
        return true;
    };
    for value in [false, true] {
        if value && !cfg_true_assignment_is_compatible(atom, values) {
            continue;
        }
        values.insert(atom, value);
        if cfg_assignment_can_satisfy(predicates, atoms, index + 1, values) {
            values.remove(atom);
            return true;
        }
        values.remove(atom);
    }
    false
}

#[derive(Default)]
struct CfgAtomPolarity {
    positive: bool,
    negative: bool,
}

fn collect_cfg_atom_polarities(
    predicate: &syn::Meta,
    positive: bool,
    polarities: &mut BTreeMap<String, CfgAtomPolarity>,
) {
    match predicate {
        syn::Meta::Path(path) => {
            record_cfg_atom_polarity(meta_path_key(path), positive, polarities);
        }
        syn::Meta::NameValue(name_value) => {
            if let Some(atom) = cfg_name_value_key(name_value) {
                record_cfg_atom_polarity(atom, positive, polarities);
            }
        }
        syn::Meta::List(list) if list.path.is_ident("not") => {
            let Some(items) = parse_meta_items(list) else {
                return;
            };
            let [item] = items.as_slice() else {
                return;
            };
            collect_cfg_atom_polarities(item, !positive, polarities);
        }
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            if let Some(items) = parse_meta_items(list) {
                for item in &items {
                    collect_cfg_atom_polarities(item, positive, polarities);
                }
            }
        }
        syn::Meta::List(_) => {}
    }
}

fn record_cfg_atom_polarity(
    atom: String,
    positive: bool,
    polarities: &mut BTreeMap<String, CfgAtomPolarity>,
) {
    let polarity = polarities.entry(atom).or_default();
    if positive {
        polarity.positive = true;
    } else {
        polarity.negative = true;
    }
}

fn cfg_true_assignment_is_compatible(atom: &str, values: &BTreeMap<&str, bool>) -> bool {
    if atom == "unix" && values.get("windows") == Some(&true)
        || atom == "windows" && values.get("unix") == Some(&true)
    {
        return false;
    }
    let Some((key, _)) = atom.split_once('=') else {
        return true;
    };
    !cfg_key_has_single_value(key)
        || values.iter().all(|(assigned, value)| {
            !*value
                || assigned
                    .split_once('=')
                    .is_none_or(|(assigned_key, _)| assigned_key != key || *assigned == atom)
        })
}

#[derive(Default)]
struct RequiredCfgValues {
    positive: BTreeSet<String>,
    negative: BTreeSet<String>,
    single_values: BTreeMap<String, String>,
    impossible: bool,
}

fn cfg_conjunction_has_direct_contradiction(predicates: &[syn::Meta]) -> bool {
    let mut required = RequiredCfgValues::default();
    for predicate in predicates {
        collect_required_cfg_values(predicate, true, &mut required);
    }
    required.impossible
        || required.positive.contains("unix") && required.positive.contains("windows")
}

fn collect_required_cfg_values(
    predicate: &syn::Meta,
    positive: bool,
    required: &mut RequiredCfgValues,
) {
    if required.impossible {
        return;
    }
    match predicate {
        syn::Meta::List(list) if positive && list.path.is_ident("all") => {
            if let Some(items) = parse_meta_items(list) {
                for item in &items {
                    collect_required_cfg_values(item, true, required);
                }
            }
        }
        syn::Meta::List(list) if !positive && list.path.is_ident("any") => {
            if let Some(items) = parse_meta_items(list) {
                for item in &items {
                    collect_required_cfg_values(item, false, required);
                }
            }
        }
        syn::Meta::List(list) if list.path.is_ident("not") => {
            let Some(items) = parse_meta_items(list) else {
                return;
            };
            let [item] = items.as_slice() else {
                return;
            };
            collect_required_cfg_values(item, !positive, required);
        }
        syn::Meta::Path(path) => {
            record_required_cfg_atom(meta_path_key(path), positive, required);
        }
        syn::Meta::NameValue(name_value) => {
            let Some((key, value)) = cfg_name_value_parts(name_value) else {
                return;
            };
            let atom = format!("{key}={value}");
            record_required_cfg_atom(atom, positive, required);
            if positive
                && cfg_key_has_single_value(&key)
                && required
                    .single_values
                    .insert(key, value.clone())
                    .is_some_and(|existing| existing != value)
            {
                required.impossible = true;
            }
        }
        syn::Meta::List(_) => {}
    }
}

fn record_required_cfg_atom(atom: String, positive: bool, required: &mut RequiredCfgValues) {
    let (same, opposite) = if positive {
        (&mut required.positive, &required.negative)
    } else {
        (&mut required.negative, &required.positive)
    };
    if opposite.contains(&atom) {
        required.impossible = true;
    }
    same.insert(atom);
}

fn cfg_key_has_single_value(key: &str) -> bool {
    matches!(
        key,
        "panic"
            | "target_arch"
            | "target_abi"
            | "target_endian"
            | "target_env"
            | "target_os"
            | "target_pointer_width"
            | "target_vendor"
    )
}

fn collect_cfg_atoms(predicate: &syn::Meta, atoms: &mut BTreeSet<String>) {
    match predicate {
        syn::Meta::Path(path) => {
            atoms.insert(meta_path_key(path));
        }
        syn::Meta::NameValue(name_value) => {
            if let Some(key) = cfg_name_value_key(name_value) {
                atoms.insert(key);
            }
        }
        syn::Meta::List(list)
            if list.path.is_ident("all")
                || list.path.is_ident("any")
                || list.path.is_ident("not") =>
        {
            if let Some(items) = parse_meta_items(list) {
                for item in &items {
                    collect_cfg_atoms(item, atoms);
                }
            }
        }
        syn::Meta::List(_) => {}
    }
}

fn evaluate_cfg_predicate(predicate: &syn::Meta, values: &BTreeMap<&str, bool>) -> CfgPossibility {
    match predicate {
        syn::Meta::Path(path) if path.is_ident("test") => CfgPossibility {
            can_be_true: false,
            can_be_false: true,
        },
        syn::Meta::Path(path) => assigned_cfg_atom(&meta_path_key(path), values),
        syn::Meta::NameValue(name_value) => cfg_name_value_key(name_value)
            .map(|key| assigned_cfg_atom(&key, values))
            .unwrap_or(CfgPossibility::UNKNOWN),
        syn::Meta::List(list) if list.path.is_ident("all") => {
            let Some(items) = parse_meta_items(list) else {
                return CfgPossibility::UNKNOWN;
            };
            CfgPossibility {
                can_be_true: items
                    .iter()
                    .all(|item| evaluate_cfg_predicate(item, values).can_be_true),
                can_be_false: items
                    .iter()
                    .any(|item| evaluate_cfg_predicate(item, values).can_be_false),
            }
        }
        syn::Meta::List(list) if list.path.is_ident("any") => {
            let Some(items) = parse_meta_items(list) else {
                return CfgPossibility::UNKNOWN;
            };
            CfgPossibility {
                can_be_true: items
                    .iter()
                    .any(|item| evaluate_cfg_predicate(item, values).can_be_true),
                can_be_false: items
                    .iter()
                    .all(|item| evaluate_cfg_predicate(item, values).can_be_false),
            }
        }
        syn::Meta::List(list) if list.path.is_ident("not") => {
            let Some(items) = parse_meta_items(list) else {
                return CfgPossibility::UNKNOWN;
            };
            let [item] = items.as_slice() else {
                return CfgPossibility::UNKNOWN;
            };
            let possibility = evaluate_cfg_predicate(item, values);
            CfgPossibility {
                can_be_true: possibility.can_be_false,
                can_be_false: possibility.can_be_true,
            }
        }
        syn::Meta::List(_) => CfgPossibility::UNKNOWN,
    }
}

fn assigned_cfg_atom(key: &str, values: &BTreeMap<&str, bool>) -> CfgPossibility {
    values
        .get(key)
        .map_or(CfgPossibility::UNKNOWN, |value| CfgPossibility {
            can_be_true: *value,
            can_be_false: !value,
        })
}

fn meta_path_key(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn cfg_name_value_key(name_value: &syn::MetaNameValue) -> Option<String> {
    let (key, value) = cfg_name_value_parts(name_value)?;
    Some(format!("{key}={value}"))
}

fn cfg_name_value_parts(name_value: &syn::MetaNameValue) -> Option<(String, String)> {
    let value = match &name_value.value {
        syn::Expr::Lit(expression) => match &expression.lit {
            syn::Lit::Bool(value) => value.value.to_string(),
            syn::Lit::Byte(value) => value.value().to_string(),
            syn::Lit::ByteStr(value) => format!("{:?}", value.value()),
            syn::Lit::Char(value) => value.value().escape_default().to_string(),
            syn::Lit::Float(value) => value.base10_digits().to_string(),
            syn::Lit::Int(value) => value.base10_digits().to_string(),
            syn::Lit::Str(value) => format!("{:?}", value.value()),
            syn::Lit::CStr(_) | syn::Lit::Verbatim(_) => return None,
            _ => return None,
        },
        _ => return None,
    };
    Some((meta_path_key(&name_value.path), value))
}

fn parse_meta_items(list: &syn::MetaList) -> Option<Vec<syn::Meta>> {
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .map(|items| items.into_iter().collect())
}

/// One metric reference found in a dashboard or rule file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricReference {
    /// The file it was found in, relative to the repo root.
    pub file: String,
    /// The metric family name, with any histogram suffix stripped.
    pub metric: String,
    /// Every label the query selects or groups on.
    pub labels: BTreeSet<String>,
}

/// A deliberate, ticketed exception to the reference rules.
///
/// The escape hatch exists so that "known dead" is a visible choice rather
/// than an accident, which is the entire difference between this guard and
/// the one it replaces. An entry costs you a line in a reviewed table and a
/// ticket number; leaving the metric dead and unlisted costs you a green CI
/// run over a broken dashboard.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceExemption {
    /// The metric name the query names.
    pub metric: &'static str,
    /// Why the exception is tolerable, and the ticket that removes it.
    pub reason: &'static str,
}

/// Read production `.rs` files under `crates/`, with test-gated code stripped.
///
/// Integration tests, benches, examples, conventional `tests.rs` modules, and
/// `e2e/` are excluded. A test driving a metric or reading a configuration
/// field does not make that behavior live in production.
///
/// The result is collected and parsed once per `root` per thread, then shared,
/// so a caller that reaches several guards never rescans the workspace.
///
/// Keyed by `root` rather than held in a single slot on purpose: the
/// `config_scan` tests call this against a temporary fixture directory, and a
/// one-slot cache would hand them the real workspace tree instead.
///
/// The cache is thread-local because `syn::File` is not `Sync`: `proc_macro2`'s
/// fallback token types hold `Rc`, so a parsed tree cannot be placed in a
/// `static`. That is not the limitation it appears to be. `cargo nextest` runs
/// every test in its own process, so "once per process" and "once per test"
/// are the same thing under the runner this workspace gates on, and the
/// expensive repeat was never across tests. It was five parses of the same file
/// inside a single guard call. See [`SourceFile::ast`].
///
/// Entries are leaked to yield `&'static [SourceFile]`, which avoids cloning a
/// tree of `syn::File` values. These guards only run inside short-lived test
/// binaries, so the memory is reclaimed at process exit.
pub fn rust_sources(root: &Path) -> &'static [SourceFile] {
    thread_local! {
        static CACHE: RefCell<BTreeMap<PathBuf, &'static [SourceFile]>> =
            const { RefCell::new(BTreeMap::new()) };
    }
    CACHE.with(|cache| {
        if let Some(hit) = cache.borrow().get(root).copied() {
            return hit;
        }
        // Collected outside the borrow: `collect_rust_sources` walks the
        // filesystem and must not run with the cache borrowed.
        let leaked: &'static [SourceFile] =
            Box::leak(collect_rust_sources(root).into_boxed_slice());
        cache.borrow_mut().insert(root.to_path_buf(), leaked);
        leaked
    })
}

/// Do the actual filesystem walk. See [`rust_sources`], which caches this.
fn collect_rust_sources(root: &Path) -> Vec<SourceFile> {
    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    let crates = root.join("crates");
    let Ok(crate_entries) = fs::read_dir(&crates) else {
        return out;
    };
    for crate_entry in crate_entries.flatten() {
        let crate_dir = crate_entry.path();
        let src_dir = crate_dir.join("src");
        if !src_dir.is_dir() {
            continue;
        }
        for root_name in ["lib.rs", "main.rs"] {
            let crate_root = src_dir.join(root_name);
            if crate_root.is_file() {
                collect_reachable_source(root, &crate_root, &mut visited, &mut out);
            }
        }
        let bin_dir = src_dir.join("bin");
        let Ok(bin_entries) = fs::read_dir(bin_dir) else {
            continue;
        };
        for bin_entry in bin_entries.flatten() {
            let path = bin_entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                collect_reachable_source(root, &path, &mut visited, &mut out);
            } else {
                let main = path.join("main.rs");
                if main.is_file() {
                    collect_reachable_source(root, &main, &mut visited, &mut out);
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn collect_reachable_source(
    repo_root: &Path,
    path: &Path,
    visited: &mut BTreeSet<PathBuf>,
    out: &mut Vec<SourceFile>,
) {
    let normalized = path.to_path_buf();
    if !visited.insert(normalized) {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    // The single parse. The AST is walked here to discover child `mod` files
    // and then handed to every downstream consumer via `SourceFile::ast`.
    let parsed = syn::parse_file(&text);
    if let Ok(file) = &parsed {
        let module_dir = child_module_directory(path);
        collect_external_modules(repo_root, &file.items, &module_dir, visited, out);
    }
    // Pushed after the recursive walk, because that walk needs `&mut out`.
    // `rust_sources` sorts by path before returning, so the resulting order is
    // unchanged by pushing the parent after its children.
    out.push(SourceFile {
        text: strip_test_regions(&text),
        raw_text: text,
        path: path.strip_prefix(repo_root).unwrap_or(path).to_path_buf(),
        ast: parsed.map_err(|error| error.to_string()),
    });
}

fn collect_external_modules(
    repo_root: &Path,
    items: &[syn::Item],
    module_dir: &Path,
    visited: &mut BTreeSet<PathBuf>,
    out: &mut Vec<SourceFile>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if attributes_exclude_production(&module.attrs) {
            continue;
        }
        if let Some((_, inline_items)) = &module.content {
            collect_external_modules(
                repo_root,
                inline_items,
                &module_dir.join(module.ident.to_string()),
                visited,
                out,
            );
            continue;
        }

        if let Some(target) = module_path_override(module)
            .map(|relative| module_dir.join(relative))
            .or_else(|| {
                let name = module.ident.to_string();
                [
                    module_dir.join(format!("{name}.rs")),
                    module_dir.join(name).join("mod.rs"),
                ]
                .into_iter()
                .find(|candidate| candidate.is_file())
            })
        {
            collect_reachable_source(repo_root, &target, visited, out);
        }
    }
}

fn child_module_directory(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    match path.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
    }
}

fn module_path_override(module: &syn::ItemMod) -> Option<PathBuf> {
    module.attrs.iter().find_map(|attribute| {
        if !attribute.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(name_value) = &attribute.meta else {
            return None;
        };
        let syn::Expr::Lit(expression) = &name_value.value else {
            return None;
        };
        let syn::Lit::Str(path) = &expression.lit else {
            return None;
        };
        Some(PathBuf::from(path.value()))
    })
}

/// Remove `#[cfg(test)]` items and `#[test]` functions from Rust source.
///
/// Blunt but honest: it brace-matches from the attribute to the end of the
/// item it guards, skipping string literals and comments so a `{` inside
/// either does not throw off the count. What remains is code that ships.
pub fn strip_test_regions(src: &str) -> String {
    // Byte-wise, not char-wise: source files contain multi-byte characters
    // (an em dash in a doc comment is enough), and slicing `src[i..i + 1]` on
    // one of them panics. Every offset this walk produces lands on an ASCII
    // delimiter, so copying whole byte sequences preserves them intact.
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if let Some(end) = lexical_region_end(src, i) {
            out.extend_from_slice(&bytes[i..end]);
            i = end;
            continue;
        }
        if let Some(attribute_end) = test_attribute_end(src, i) {
            i = end_of_item(src, attribute_end);
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

/// Given an offset just past an attribute, return the offset just past the
/// item it decorates.
fn end_of_item(src: &str, from: usize) -> usize {
    let bytes = src.as_bytes();
    let mut i = from;

    // Skip to whichever comes first: the item's opening brace, or the
    // semicolon that ends a brace-less item such as a gated `use`.
    while i < bytes.len() && bytes[i] != b'{' && bytes[i] != b';' {
        if let Some(end) = lexical_region_end(src, i) {
            i = end;
            continue;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return bytes.len();
    }
    if bytes[i] == b';' {
        return i + 1;
    }

    let mut depth = 0usize;
    while i < bytes.len() {
        if let Some(end) = lexical_region_end(src, i) {
            i = end;
            continue;
        }
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

fn test_attribute_end(src: &str, start: usize) -> Option<usize> {
    const EXACT: &[&str] = &["#[cfg(test)]", "#[test]"];
    for marker in EXACT {
        if src.as_bytes()[start..].starts_with(marker.as_bytes()) {
            return Some(start + marker.len());
        }
    }

    for prefix in ["#[tokio::test", "#[async_std::test"] {
        if src.as_bytes()[start..].starts_with(prefix.as_bytes()) {
            let after = start + prefix.len();
            if !matches!(src.as_bytes().get(after), Some(b']' | b'(')) {
                continue;
            }
            return attribute_end(src, start);
        }
    }
    None
}

fn attribute_end(src: &str, start: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut i = start + 2;
    let mut parens = 0usize;
    while i < bytes.len() {
        if let Some(end) = lexical_region_end(src, i) {
            i = end;
            continue;
        }
        match bytes[i] {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b']' if parens == 0 => return Some(i + 1),
            _ => {}
        }
        i += 1;
    }
    None
}

fn lexical_region_end(src: &str, start: usize) -> Option<usize> {
    if let Some(end) = skip_raw_string(src, start) {
        return Some(end);
    }

    let bytes = src.as_bytes();
    match bytes.get(start).copied()? {
        b'"' => Some(skip_string(src, start)),
        b'\'' => skip_char_literal(src, start),
        b'/' if bytes.get(start + 1) == Some(&b'/') => {
            let mut i = start + 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            Some(i)
        }
        b'/' if bytes.get(start + 1) == Some(&b'*') => {
            let mut i = start + 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes.get(i..i + 2) == Some(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes.get(i..i + 2) == Some(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Some(i)
        }
        _ => None,
    }
}

fn skip_raw_string(src: &str, start: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut i = start;
    if bytes.get(i) == Some(&b'b') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'r') {
        return None;
    }
    i += 1;
    let hashes_start = i;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    let hashes = i - hashes_start;
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'"'
            && bytes
                .get(i + 1..i + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(bytes.len())
}

fn skip_char_literal(src: &str, start: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut i = start + 1;
    if bytes.get(i) == Some(&b'\\') {
        i += 2;
    } else {
        let ch = src.get(i..)?.chars().next()?;
        i += ch.len_utf8();
    }
    (bytes.get(i) == Some(&b'\'')).then_some(i + 1)
}

/// Skip a double-quoted Rust string literal, honoring backslash escapes.
fn skip_string(src: &str, start: usize) -> usize {
    let bytes = src.as_bytes();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Blank out `//` and `/* */` comments, preserving byte offsets.
///
/// Needed because a metric declaration's own comment block is allowed to say
/// anything, including things that look like code. The label list on
/// `sbproxy_requests_total` is preceded by "never reorder;" and that
/// semicolon is enough to fool a naive scan into reading no labels at all.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(src, i),
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    out[i] = b' ';
                    i += 1;
                }
                out[i] = b' ';
                if i + 1 < out.len() {
                    out[i + 1] = b' ';
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

/// The constructors and macros that declare a Prometheus family.
///
/// An allowlist rather than a "ends in `new(` or `!(`" heuristic, so that
/// `format!("sbproxy_{lane}_...")` is not mistaken for a declaration.
const METRIC_CTORS: &[&str] = &[
    "Opts::new(",
    "HistogramOpts::new(",
    "register_int_counter_vec!(",
    "register_counter_vec!(",
    "register_int_gauge_vec!(",
    "register_gauge_vec!(",
    "register_histogram_vec!(",
    "register_int_counter!(",
    "register_int_gauge!(",
    "register_gauge!(",
    "register_histogram!(",
    "IntCounter::new(",
    "IntGauge::new(",
    "Gauge::new(",
];

/// Every metric family name declared anywhere under `crates/`, for each
/// prefix in `SANCTIONED_PREFIXES`.
///
/// This is the direction that keeps the registry honest as the code grows: a
/// metric added to `metrics.rs` without a registry entry fails the build,
/// exactly as a `serve:` schema field added without a capability entry
/// already does. Without it the table is a snapshot that rots.
pub fn declared_metrics(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();

    for source in rust_sources(root) {
        let text = strip_comments(&source.text);
        let bytes = text.as_bytes();

        for prefix in SANCTIONED_PREFIXES {
            let quoted = format!("\"{prefix}");
            for (at, _) in text.match_indices(&quoted) {
                // The literal must be the first argument of a declaration.
                let mut j = at;
                while j > 0 && bytes[j - 1].is_ascii_whitespace() {
                    j -= 1;
                }
                let head = &text[..j];
                if !METRIC_CTORS.iter().any(|ctor| head.ends_with(ctor)) {
                    continue;
                }

                let start = at + 1;
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                // A dynamically composed name (`sbproxy_{lane}_...`) stops at
                // the brace and is not a literal declaration.
                if bytes.get(end) == Some(&b'"') {
                    out.insert(text[start..end].to_string());
                }
            }
        }
    }

    out
}

/// Prove the registry covers every metric the code declares.
pub fn verify_coverage(metrics: &[MetricCapability], root: &Path) -> Vec<RegistryError> {
    let declared = declared_metrics(root);
    let registered: BTreeSet<&str> = metrics.iter().map(|m| m.name).collect();
    let mut errors = Vec::new();

    for name in &declared {
        if !registered.contains(name.as_str()) {
            errors.push(RegistryError {
                subject: name.clone(),
                message: "is declared in code but missing from the metric registry. \
                          Add an entry saying what writes it and what we promise about \
                          it, the same way a new `serve:` field must be classified."
                    .to_string(),
            });
        }
    }

    errors
}

/// Count occurrences of `needle` that are whole identifiers.
///
/// The boundary to check depends on the needle's shape, which is easy to get
/// wrong in a way that silently reports zero:
///
/// - `record_cache(` starts with an identifier character, so the byte before
///   it must not be one. Otherwise it matches inside `try_record_cache(`.
///   It ends with `(`, so nothing needs checking after.
/// - `.cache_hits` starts with a dot, and the byte before that dot is *always*
///   an identifier (`m.cache_hits`), so checking before it rejects every real
///   access. It ends with an identifier character, so the byte after must not
///   be one. Otherwise it matches inside `.cache_hits_by_tier`.
fn count_tokens(haystack: &str, needle: &str) -> usize {
    fn ident(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    let check_before = needle.as_bytes().first().is_some_and(|b| ident(*b));
    let check_after = needle.as_bytes().last().is_some_and(|b| ident(*b));
    let bytes = haystack.as_bytes();

    let mut count = 0;
    let mut from = 0;
    while let Some(found) = haystack[from..].find(needle) {
        let at = from + found;
        let end = at + needle.len();
        let before_ok = !check_before || at == 0 || !ident(bytes[at - 1]);
        let after_ok = !check_after || end >= bytes.len() || !ident(bytes[end]);
        if before_ok && after_ok {
            count += 1;
        }
        from = end;
    }
    count
}

/// Whether a writer symbol names a Prometheus metric static
/// (`SCREAMING_SNAKE_CASE`) rather than a recorder function.
///
/// The mesh crate drives its metrics through `LazyLock` statics directly
/// (`MESH_PEER_EVICTED.with_label_values(..).inc()`) instead of recorder
/// functions, so its registry entries name the static's identifier and the
/// scanner counts uses of that identifier as call sites.
fn is_metric_static(symbol: &str) -> bool {
    symbol
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Blank out the contents of double-quoted string literals, preserving
/// byte offsets.
///
/// Needed for static-writer counting: the registry entry itself contains
/// `Writer::Recorder("MESH_...")`, and a bare-identifier count that read
/// string literals would report every static live because its own registry
/// row names it.
fn blank_string_literals(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let end = skip_string(src, i);
            for byte in out.iter_mut().take(end.saturating_sub(1)).skip(i + 1) {
                *byte = b' ';
            }
            i = end;
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

/// Local names a `use` statement binds a recorder to via `... as <alias>`.
///
/// A file may rename a recorder on import:
///
/// ```text
/// use sbproxy_observe::metrics::{record_rate_limit, record_rate_limit_suspend as record_suspend};
/// ...
/// record_suspend(workspace);
/// ```
///
/// The call site then reads `record_suspend(`, and a text search for the real
/// symbol `record_rate_limit_suspend(` never sees it, so a metric with a
/// genuine production writer is reported dead. `sbproxy_rate_limit_suspend_total`
/// was exactly this: written on every auto-suspend, invisible to the scanner.
///
/// Following the alias is narrow on purpose. It only fires on an explicit
/// `<symbol> as <ident>` rebinding of the very symbol the registry names, and
/// the returned alias is counted only in the file that declares it, since a
/// `use` alias is scoped to its module. It does not chase glob imports or
/// re-exports.
fn recorder_aliases(text: &str, symbol: &str) -> Vec<String> {
    fn ident(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = text[from..].find(symbol) {
        let at = from + found;
        let mut i = at + symbol.len();
        from = i;

        // The symbol must be a whole token, not a suffix of a longer name.
        let whole = (at == 0 || !ident(bytes[at - 1])) && (i >= bytes.len() || !ident(bytes[i]));
        if !whole {
            continue;
        }

        // Expect `as`, as its own token, then the alias identifier.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if !text[i..].starts_with("as") {
            continue;
        }
        i += 2;
        if i < bytes.len() && ident(bytes[i]) {
            continue;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let alias_start = i;
        while i < bytes.len() && ident(bytes[i]) {
            i += 1;
        }
        if i > alias_start {
            out.push(text[alias_start..i].to_string());
        }
    }
    out
}

/// Prove that every metric the registry calls live is driven by production
/// code, and that every metric it calls dead really is.
///
/// The check runs in both directions on purpose. A stable metric whose
/// recorder lost its last caller is the bug this whole registry exists to
/// catch, and it looks identical to a metric that was never wired: the
/// declaration is still there, the recorder still compiles, the scrape still
/// emits a zero. Only the call site is gone.
///
/// A `Writer::Recorder` may name a recorder function, or (see
/// `is_metric_static`) a metric static's own `SCREAMING_SNAKE_CASE`
/// identifier for crates that drive Prometheus statics directly. For a
/// static, comments and string literals are blanked before counting so a
/// rustdoc cross-reference or the registry row itself cannot pass as a call
/// site; any remaining use of the identifier outside its own declaration
/// implies a live driver, because an import the production build never uses
/// fails the workspace's deny-warnings gate.
pub fn verify_writers(metrics: &[MetricCapability], root: &Path) -> Vec<RegistryError> {
    let sources = rust_sources(root);
    let mut errors = Vec::new();

    // `blank_string_literals(strip_comments(..))` does not depend on the metric,
    // so it is computed once per file rather than once per (metric, file) pair.
    // The loop below is a metric table in the hundreds crossed with ~680 files,
    // so recomputing it inside meant tens of thousands of full-text passes.
    // Built only when some metric actually needs the blanked view.
    let needs_static_view = metrics
        .iter()
        .any(|metric| matches!(metric.writer, Writer::Recorder(name) if is_metric_static(name)));
    let static_views: Vec<String> = if needs_static_view {
        sources
            .iter()
            .map(|source| blank_string_literals(&strip_comments(&source.text)))
            .collect()
    } else {
        Vec::new()
    };

    // One tokenisation pass per file, so the per-metric skip test below is a
    // hash lookup instead of a full-text search. Without it the loop searches
    // every file's whole text once per metric, which is the metric table
    // multiplied by ~680 files of scanning.
    //
    // Built from `source.text`. The blanked static view is derived from that
    // text by removing content, so its identifiers are a subset and this set
    // stays a safe filter for both views: it can only ever over-approximate,
    // which costs a wasted iteration rather than a missed match.
    let identifiers: Vec<BTreeSet<&str>> = sources
        .iter()
        .map(|source| identifier_set(&source.text))
        .collect();

    // Two views of the same files, so the resolver below can be handed
    // whichever one this metric needs without rebuilding either.
    let plain_texts: Vec<&str> = sources.iter().map(|source| source.text.as_str()).collect();
    let static_texts: Vec<&str> = static_views.iter().map(String::as_str).collect();

    for metric in metrics {
        let is_static = matches!(metric.writer, Writer::Recorder(name) if is_metric_static(name));
        let (symbol, call, define) = match metric.writer {
            Writer::Recorder(name) if is_static => {
                (name, name.to_string(), Some(format!("static {name}:")))
            }
            Writer::Recorder(name) => (name, format!("{name}("), Some(format!("fn {name}("))),
            Writer::Field(name) => (name, format!(".{name}"), None),
            Writer::Nothing => continue,
        };
        // A recorder can be called under an import alias; a field cannot,
        // and a static's bare-identifier count already covers any alias's
        // rebinding `use`.
        let follow_aliases = matches!(metric.writer, Writer::Recorder(_)) && !is_static;

        let texts: &[&str] = if is_static {
            &static_texts
        } else {
            &plain_texts
        };
        let (defined, calls) = resolve_symbol(
            texts,
            &identifiers,
            symbol,
            &call,
            define.as_deref(),
            follow_aliases,
        );

        if !defined {
            errors.push(RegistryError {
                subject: metric.name.to_string(),
                message: format!(
                    "names writer '{symbol}', which does not exist in any crate; \
                     the metric or the registry entry is stale"
                ),
            });
            continue;
        }

        if calls == 0 {
            errors.push(RegistryError {
                subject: metric.name.to_string(),
                message: format!(
                    "names writer '{symbol}', which has no call site outside tests. \
                     Nothing increments this metric, so every dashboard and alert \
                     reading it is reading a flat zero. Wire it, delete it, or set \
                     its writer to Nothing with a dead_reason."
                ),
            });
        } else if metric.support == SupportLevel::ConfigOnly {
            errors.push(RegistryError {
                subject: metric.name.to_string(),
                message: format!(
                    "is marked config_only but writer '{symbol}' has {calls} live \
                     call site(s); promote it out of config_only"
                ),
            });
        }
    }

    errors
}

/// Every Rust identifier appearing anywhere in `text`, as borrowed slices.
///
/// Used as a cheap rejection filter: a symbol that is not an identifier in a
/// file cannot be called, defined, or aliased there. Deliberately ignores
/// context, since a superset is safe for that use and a single pass is the
/// point.
///
/// Byte-wise rather than char-wise. Identifier bytes are all ASCII, so a
/// multi-byte character can never open or close a run, and every slice
/// boundary lands on an ASCII byte.
fn identifier_set(text: &str) -> BTreeSet<&str> {
    fn is_identifier_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifier_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_identifier_byte(bytes[index]) {
            index += 1;
        }
        out.insert(&text[start..index]);
    }
    out
}

/// Resolve one symbol against production source: is it defined, and how
/// many times is it called?
///
/// The shared core of [`verify_writers`] and [`verify_span_emitters`], so
/// the two guards cannot disagree about what "has a production caller"
/// means. Both of them ask the same question of a different kind of
/// symbol, and the fiddly parts (the definition is itself a match for the
/// call needle, an import alias hides a real call site, an identifier-set
/// pre-filter keeps this from being a full-text search per symbol) are
/// exactly the parts worth having in one place.
///
/// `texts` and `identifiers` are parallel to each other and to
/// [`rust_sources`], and both are built once by the caller because the
/// caller loops over a table and these do not depend on the table.
fn resolve_symbol(
    texts: &[&str],
    identifiers: &[BTreeSet<&str>],
    symbol: &str,
    call: &str,
    define: Option<&str>,
    follow_aliases: bool,
) -> (bool, usize) {
    let mut calls = 0usize;
    let mut defined = define.is_none();

    for (index, text) in texts.iter().enumerate() {
        // Every needle a caller passes (`symbol(`, `.symbol`, `fn symbol(`,
        // `static symbol:`) contains `symbol` as a whole identifier, and an
        // alias can only be introduced by a `use` that names it. So a file
        // whose identifier set lacks `symbol` cannot contribute a call, a
        // definition, or an alias, and skipping it changes no outcome.
        if !identifiers[index].contains(symbol) {
            continue;
        }
        calls += count_tokens(text, call);
        if follow_aliases {
            for alias in recorder_aliases(text, symbol) {
                calls += count_tokens(text, &format!("{alias}("));
            }
        }
        if let Some(define) = define {
            if text.contains(define) {
                defined = true;
                // The definition is itself a match for the call needle
                // (`fn name(` contains `name(`; `static NAME:` contains the
                // bare `NAME`). Do not let a symbol count as its own caller.
                calls -= count_tokens(text, define);
            }
        }
    }

    (defined, calls)
}

/// Whether `define` appears in any production file that also names `symbol`.
///
/// The definition half of [`resolve_symbol`] on its own, for the cases that
/// want to know a function exists without asking who calls it.
fn defines_symbol(
    texts: &[&str],
    identifiers: &[BTreeSet<&str>],
    symbol: &str,
    define: &str,
) -> bool {
    texts
        .iter()
        .enumerate()
        .any(|(index, text)| identifiers[index].contains(symbol) && text.contains(define))
}

/// The macros that open a `tracing` span.
///
/// An allowlist for the same reason `METRIC_CTORS` is one: a name that
/// merely appears in a string somewhere is not an emission, and the whole
/// point of scanning rather than substring-matching is to tell those two
/// apart.
const SPAN_MACROS: &[&str] = &[
    "info_span!",
    "debug_span!",
    "trace_span!",
    "warn_span!",
    "error_span!",
];

/// Every span name opened by a `tracing::*_span!` macro anywhere under
/// `crates/`, outside test-gated regions.
///
/// The span analogue of [`declared_metrics`], and the direction that keeps
/// the registry honest as the code grows: a span opened without a registry
/// entry fails the build. Names composed at runtime (the pillar helper
/// builds `sbproxy.<pillar>.<verb>` from its arguments) are invisible here
/// by construction, which is why a pillar span is classified by its
/// constructor symbol instead.
pub fn declared_spans(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for source in rust_sources(root) {
        span_names_in(&strip_comments(&source.text), &mut out);
    }
    out
}

/// Collect the literal span names opened in one file's production text.
///
/// Split from [`declared_spans`] so the parse is testable without a
/// workspace on disk. The caller strips comments first, for the reason
/// `declared_metrics` does: a name in a doc comment is documentation, not
/// an emission, and treating the two alike is the substring match this
/// module exists to replace.
fn span_names_in(text: &str, out: &mut BTreeSet<String>) {
    fn ident(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    let bytes = text.as_bytes();

    for macro_name in SPAN_MACROS {
        for (at, _) in text.match_indices(macro_name) {
            // `info_span!` must be a whole token, so `my_info_span!` is
            // somebody else's macro and not one of ours.
            if at > 0 && ident(bytes[at - 1]) {
                continue;
            }
            let mut index = at + macro_name.len();
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if bytes.get(index) != Some(&b'(') {
                continue;
            }
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            // The name is the macro's first argument and it has to be a
            // literal. A non-literal first argument does not compile as a
            // span name, so there is nothing to miss here.
            if bytes.get(index) != Some(&b'"') {
                continue;
            }
            let start = index + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'"' {
                end += 1;
            }
            if end < bytes.len() {
                out.insert(text[start..end].to_string());
            }
        }
    }
}

/// Prove the registry covers every span the code opens.
pub fn verify_span_coverage(spans: &[SpanCapability], root: &Path) -> Vec<RegistryError> {
    let declared = declared_spans(root);
    let registered: BTreeSet<&str> = spans.iter().map(|span| span.name).collect();
    let mut errors = Vec::new();

    for name in &declared {
        if !registered.contains(name.as_str()) {
            errors.push(RegistryError {
                subject: name.clone(),
                message: "is opened in code but missing from the span registry. Add an \
                          entry saying what emits it and what we promise about the name, \
                          the same way a new metric family must be classified."
                    .to_string(),
            });
        }
    }

    errors
}

/// Prove that every span the registry calls live is opened by production
/// code, and that every span it calls dead really is.
///
/// Both directions, for the reason [`verify_writers`] runs both: a span
/// whose constructor lost its last caller looks identical to one that was
/// never wired, and a span the registry still calls dead after somebody
/// wired it is how the table goes stale in the flattering direction. The
/// second half is the one `docs/observability.md` needed and did not have.
/// It published eight `sbproxy.<pillar>.<verb>` names that no code has ever
/// emitted, next to three AI span constructors that exist, compile, and
/// have never been called from anything but their own tests.
pub fn verify_span_emitters(spans: &[SpanCapability], root: &Path) -> Vec<RegistryError> {
    let sources = rust_sources(root);
    let texts: Vec<&str> = sources.iter().map(|source| source.text.as_str()).collect();
    let identifiers: Vec<BTreeSet<&str>> = sources
        .iter()
        .map(|source| identifier_set(&source.text))
        .collect();
    let declared = declared_spans(root);
    let mut errors = Vec::new();

    for span in spans {
        let subject = span.name.to_string();

        match span.emitter {
            SpanEmitter::Constructor(symbol) => {
                let call = format!("{symbol}(");
                let define = format!("fn {symbol}(");
                let (defined, calls) = resolve_symbol(
                    &texts,
                    &identifiers,
                    symbol,
                    &call,
                    Some(define.as_str()),
                    true,
                );

                if !defined {
                    errors.push(RegistryError {
                        subject,
                        message: format!(
                            "names emitter '{symbol}', which is not a function in any \
                             crate; the span or the registry entry is stale"
                        ),
                    });
                    continue;
                }

                if calls == 0 {
                    errors.push(RegistryError {
                        subject,
                        message: format!(
                            "names emitter '{symbol}', which has no call site outside \
                             tests. Nothing opens this span, so a trace query that \
                             filters on the name returns nothing and a panel grouped by \
                             it draws nothing. Wire it, delete it, or move it to \
                             SpanEmitter::Unwired with a dead_reason."
                        ),
                    });
                } else if span.support == SupportLevel::ConfigOnly {
                    errors.push(RegistryError {
                        subject,
                        message: format!(
                            "is marked config_only but emitter '{symbol}' has {calls} \
                             live call site(s); promote it out of config_only"
                        ),
                    });
                }
            }

            SpanEmitter::Literal { site } => {
                if !declared.contains(span.name) {
                    errors.push(RegistryError {
                        subject: subject.clone(),
                        message: "is classified as opened inline, but the name appears \
                                  in no tracing span macro outside tests. The emission \
                                  site moved, or the name changed under it."
                            .to_string(),
                    });
                }

                let define = format!("fn {site}(");
                if !defines_symbol(&texts, &identifiers, site, &define) {
                    errors.push(RegistryError {
                        subject,
                        message: format!(
                            "names emission site '{site}', which is not a function in \
                             any crate; the site was renamed or removed"
                        ),
                    });
                }
            }

            SpanEmitter::Unwired(symbol) => {
                let call = format!("{symbol}(");
                let define = format!("fn {symbol}(");
                let (defined, calls) = resolve_symbol(
                    &texts,
                    &identifiers,
                    symbol,
                    &call,
                    Some(define.as_str()),
                    true,
                );

                if !defined {
                    errors.push(RegistryError {
                        subject,
                        message: format!(
                            "is recorded as an unwired constructor '{symbol}', which no \
                             longer exists. Delete the entry, or point it at the \
                             constructor that replaced it."
                        ),
                    });
                } else if calls > 0 {
                    errors.push(RegistryError {
                        subject,
                        message: format!(
                            "is recorded as unwired, but constructor '{symbol}' now has \
                             {calls} production call site(s). The span is live: move it \
                             to SpanEmitter::Constructor, drop the dead_reason, and give \
                             it a support level that says so."
                        ),
                    });
                }
            }

            SpanEmitter::Nothing => {
                if declared.contains(span.name) {
                    errors.push(RegistryError {
                        subject,
                        message: "is recorded as emitted by nothing, but the name now \
                                  appears in a tracing span macro outside tests. \
                                  Something emits it: classify the emitter and drop the \
                                  dead_reason."
                            .to_string(),
                    });
                }
            }
        }
    }

    errors
}

/// Every metric reference in every dashboard and alert-rule file.
pub fn query_references(root: &Path) -> Vec<MetricReference> {
    let mut out = Vec::new();
    for dir in QUERY_DIRS {
        let Ok(entries) = fs::read_dir(root.join(dir)) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|s| s.to_str()),
                    Some("json") | Some("yml") | Some("yaml")
                )
            })
            .collect();
        paths.sort();
        for path in paths {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let file = format!(
                "{dir}/{}",
                path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
            );
            out.extend(references_in(&promql_only(&text), &file));
        }
    }
    out
}

/// Reduce a rule or dashboard file to the PromQL it actually evaluates.
///
/// Scanning the raw file text is not good enough. A rule group is *named*
/// `sbproxy_slo_substrate_availability`, an annotation's prose quotes metric
/// names, and a comment explaining why a metric was removed necessarily
/// mentions it. All three look exactly like a query to a token scanner, and
/// the guard would then indict the file for the very sentence explaining the
/// fix. So two things are read and nothing else: `expr`, and a Grafana
/// templating variable's `label_values(...)` call.
///
/// `label_values` is matched on the call rather than on the key it sits under.
/// The key is not reliable (`query` and `definition` both carry it, and
/// `query` also carries a datasource name, a custom variable's comma-separated
/// options, and on some datasources raw SQL), while the call is: it is a
/// Grafana Prometheus-datasource function, it never appears in PromQL, and it
/// never appears in prose here. Matching the key instead would mean deciding
/// whether an arbitrary `query` string is PromQL, which is the guess that let
/// prose into the old substring guard.
fn promql_only(text: &str) -> String {
    let mut out = String::new();
    let mut lines = text.lines().peekable();

    while let Some(line) = lines.next() {
        // Grafana templating: `"query": "label_values(<selector>, <label>)"`.
        if let Some(selector) = label_values_as_selector(line) {
            out.push_str(&selector);
            out.push('\n');
            continue;
        }

        // Grafana JSON: `"expr": "sum(rate(...))"`.
        if let Some(at) = line.find("\"expr\"") {
            if let Some(value) = json_string_after(&line[at + 6..]) {
                out.push_str(&value);
                out.push('\n');
            }
            continue;
        }

        // Prometheus YAML: `expr: <inline>`, or `expr: |` + an indented block.
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("expr:") else {
            continue;
        };
        let rest = rest.trim();
        if !rest.is_empty() && rest != "|" && rest != ">" {
            out.push_str(rest);
            out.push('\n');
            continue;
        }
        let indent = line.len() - trimmed.len();
        while let Some(next) = lines.peek() {
            let next_indent = next.len() - next.trim_start().len();
            if next.trim().is_empty() || next_indent > indent {
                out.push_str(lines.next().unwrap_or_default());
                out.push('\n');
            } else {
                break;
            }
        }
    }

    out
}

/// Rewrite a Grafana `label_values(...)` call into the selector it implies.
///
/// `label_values(sbproxy_requests_total{agent_class=~"$agent_class"}, agent_vendor)`
/// becomes `sbproxy_requests_total{agent_class=~"$agent_class",agent_vendor=""}`,
/// which is a plain selector [`references_in`] already knows how to read: the
/// family has to exist and be live, and every label named has to be one it
/// carries. The dropdown's own label joins the selector because populating a
/// dropdown from a label is a claim that the label is there.
///
/// Returns `None` when the line carries no such call, and also for the
/// single-argument form `label_values(<label>)`, which names no family and so
/// gives the guard nothing to check the label against.
///
/// Two details are worth naming. The argument list is split at the *last*
/// comma outside every bracket, because a selector brings its own commas
/// (`{a="x",b="y"}`) and the label is always last. And an unparseable label
/// position, a template variable or an expression rather than a name, still
/// yields the bare selector: the family is checkable even when the label is
/// not, and returning nothing there would hide a dead metric behind an
/// unreadable second argument.
fn label_values_as_selector(line: &str) -> Option<String> {
    const CALL: &str = "label_values(";
    let at = line.find(CALL)?;
    // Grafana stores the query inside a JSON string, so a selector's quotes
    // arrive escaped. Everything downstream reads plain PromQL.
    let rest = line[at + CALL.len()..].replace("\\\"", "\"");

    let mut depth = 1usize;
    let mut close = None;
    for (index, byte) in rest.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let arguments = &rest[..close?];

    let mut depth = 0usize;
    let mut split = None;
    for (index, byte) in arguments.bytes().enumerate() {
        match byte {
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => split = Some(index),
            _ => {}
        }
    }
    let split = split?;
    let selector = arguments[..split].trim();
    let label = arguments[split + 1..].trim();
    if selector.is_empty() {
        return None;
    }
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Some(selector.to_string());
    }

    Some(match selector.strip_suffix('}') {
        Some(head) if head.ends_with('{') => format!("{head}{label}=\"\"}}"),
        Some(head) => format!("{head},{label}=\"\"}}"),
        None => format!("{selector}{{{label}=\"\"}}"),
    })
}

/// Read the first JSON string value after a `"expr":` key, unescaping `\"`.
fn json_string_after(rest: &str) -> Option<String> {
    let open = rest.find('"')?;
    let bytes = rest.as_bytes();
    let mut i = open + 1;
    let mut out = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                if bytes[i + 1] == b'"' {
                    out.push('"');
                }
                i += 2;
            }
            b'"' => return Some(out),
            _ => {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    None
}

/// Extract metric references from one file's text.
///
/// Line-scoped, which is what makes `by (...)` attribution tractable without
/// a PromQL parser: when a line names exactly one metric, its grouping labels
/// belong to that metric. Both real defects this needed to catch (`status_class`
/// as a selector, and `status_class` as a grouping key in the cardinality rule)
/// sit on a single line.
fn references_in(text: &str, file: &str) -> Vec<MetricReference> {
    let mut merged: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for line in text.lines() {
        let mut on_line: Vec<(String, BTreeSet<String>)> = Vec::new();
        let bytes = line.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            // Compare bytes, not chars: dashboard JSON is full of multi-byte
            // characters in titles and descriptions, and `line[i..]` panics the
            // moment `i` lands inside one. A sanctioned prefix mid-identifier
            // (`semcache_mesh_x`) is not a metric name, hence the boundary
            // check on the byte before the match.
            let at_prefix = SANCTIONED_PREFIXES
                .iter()
                .any(|prefix| bytes[i..].starts_with(prefix.as_bytes()));
            let at_boundary =
                i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if !at_prefix || !at_boundary {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let Ok(token) = std::str::from_utf8(&bytes[start..i]) else {
                continue;
            };
            // A Grafana template variable interpolates mid-name
            // (`sbproxy_ai_${surface}_total`), leaving a stub that ends in an
            // underscore. No real family name does, so this is unambiguous.
            if token.ends_with('_') {
                continue;
            }
            let name = canonical_name(token).to_string();

            // A `{...}` immediately after the name is a label selector.
            let mut labels = BTreeSet::new();
            if bytes.get(i) == Some(&b'{') {
                if let Some(close) = line[i..].find('}') {
                    labels.extend(selector_labels(&line[i + 1..i + close]));
                    i += close + 1;
                }
            }
            on_line.push((name, labels));
        }

        // `by (a, b)` / `without (a, b)` group on labels of whatever the
        // expression selects. Attribute only when there is no ambiguity.
        let grouped = grouping_labels(line);
        let distinct: BTreeSet<&String> = on_line.iter().map(|(name, _)| name).collect();
        if distinct.len() == 1 && !grouped.is_empty() {
            for (_, labels) in on_line.iter_mut() {
                labels.extend(grouped.iter().cloned());
            }
        }

        for (name, labels) in on_line {
            merged.entry(name).or_default().extend(labels);
        }
    }

    merged
        .into_iter()
        .map(|(metric, labels)| MetricReference {
            file: file.to_string(),
            metric,
            labels,
        })
        .collect()
}

/// Pull label names out of the inside of a `{...}` selector.
fn selector_labels(inner: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for part in inner.split(',') {
        let name: String = part
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// Pull label names out of every `by (...)` / `without (...)` clause.
fn grouping_labels(line: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for keyword in ["by", "without"] {
        let mut from = 0;
        while let Some(found) = line[from..].find(keyword) {
            let at = from + found;
            from = at + keyword.len();

            // Must be a standalone word.
            let before_ok = at == 0 || !line.as_bytes()[at - 1].is_ascii_alphanumeric();
            if !before_ok {
                continue;
            }
            let rest = line[from..].trim_start();
            if !rest.starts_with('(') {
                continue;
            }
            let open = line.len() - rest.len();
            if let Some(close) = line[open..].find(')') {
                out.extend(selector_labels(&line[open + 1..open + close]));
            }
        }
    }
    out
}

/// Strip the suffixes the Prometheus client derives for histograms.
fn canonical_name(name: &str) -> &str {
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped;
        }
    }
    name
}

/// Prove that every dashboard and alert rule reads a metric that exists, is
/// live, and carries the labels the query selects on.
pub fn verify_references(
    metrics: &[MetricCapability],
    references: &[MetricReference],
    exemptions: &[ReferenceExemption],
) -> Vec<RegistryError> {
    let index: BTreeMap<&str, &MetricCapability> = metrics.iter().map(|m| (m.name, m)).collect();
    let mut errors = Vec::new();

    for reference in references {
        if exemptions.iter().any(|e| e.metric == reference.metric) {
            continue;
        }

        let Some(metric) = index.get(reference.metric.as_str()) else {
            errors.push(RegistryError {
                subject: reference.metric.clone(),
                message: format!(
                    "{} queries a metric that no crate declares. The panel or rule \
                     that reads it can only ever return no data.",
                    reference.file
                ),
            });
            continue;
        };

        if matches!(metric.writer, Writer::Nothing) {
            errors.push(RegistryError {
                subject: reference.metric.clone(),
                message: format!(
                    "{} queries a metric that nothing increments. The panel or rule \
                     that reads it can only ever draw a flat zero.",
                    reference.file
                ),
            });
        }

        for label in &reference.labels {
            if IMPLICIT_LABELS.contains(&label.as_str()) {
                continue;
            }
            if !metric.labels.contains(&label.as_str()) {
                errors.push(RegistryError {
                    subject: reference.metric.clone(),
                    message: format!(
                        "{} selects on label '{label}', which this metric does not \
                         have. Its labels are {:?}. In PromQL an absent label is the \
                         empty string, so a `!=` matcher on it silently selects every \
                         series and an `=` matcher selects none.",
                        reference.file, metric.labels
                    ),
                });
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompatTier, MetricKind, Registry};

    fn metric(
        name: &'static str,
        writer: Writer,
        labels: &'static [&'static str],
    ) -> MetricCapability {
        MetricCapability {
            name,
            kind: MetricKind::Counter,
            writer,
            support: if matches!(writer, Writer::Nothing) {
                SupportLevel::ConfigOnly
            } else {
                SupportLevel::Stable
            },
            compat: CompatTier::Alpha,
            registry: Registry::Proxy,
            labels,
            description: "A thing.",
            dead_reason: if matches!(writer, Writer::Nothing) {
                Some("nothing calls it")
            } else {
                None
            },
        }
    }

    #[test]
    fn test_modules_are_stripped() {
        let src = r#"
pub fn live() { record_thing("a"); }

#[cfg(test)]
mod tests {
    #[test]
    fn t() { record_thing("b"); }
}
"#;
        let stripped = strip_test_regions(src);
        assert_eq!(count_tokens(&stripped, "record_thing("), 1);
    }

    #[test]
    fn a_brace_inside_a_string_does_not_end_the_test_module() {
        let src = r#"
#[cfg(test)]
mod tests {
    fn t() { let s = "}"; }
}
pub fn live() { record_thing("a"); }
"#;
        let stripped = strip_test_regions(src);
        assert!(stripped.contains("pub fn live"));
        assert!(!stripped.contains("mod tests"));
    }

    #[test]
    fn test_markers_inside_strings_and_comments_are_not_attributes() {
        let src = r##"
const FIXTURE: &str = r#"#[cfg(test)] fn fixture() { record_thing("fixture"); }"#;
// #[test] fn comment_only() { record_thing("comment"); }
pub fn live() { record_thing("live"); }
"##;

        let stripped = strip_test_regions(src);

        assert!(
            syn::parse_file(&stripped).is_ok(),
            "stripping must preserve valid Rust: {stripped}"
        );
        assert!(stripped.contains("const FIXTURE"));
        assert!(stripped.contains("record_thing(\"fixture\")"));
        assert!(stripped.contains("record_thing(\"live\")"));
    }

    #[test]
    fn attributed_tokio_test_with_arguments_is_stripped() {
        let src = r#"
#[tokio::test(flavor = "multi_thread")]
async fn only_test() { record_thing("test"); }

pub fn live() { record_thing("live"); }
"#;

        let stripped = strip_test_regions(src);

        assert_eq!(count_tokens(&stripped, "record_thing("), 1);
        assert!(!stripped.contains("only_test"));
    }

    #[test]
    fn impossible_cfg_predicates_are_not_production_attributes() {
        for predicate in [
            "all(unix, windows)",
            "all(feature = \"x\", not(feature = \"x\"))",
        ] {
            let item: syn::ItemFn =
                syn::parse_str(&format!("#[cfg({predicate})] fn impossible() {{}}"))
                    .expect("probe must be valid Rust syntax");

            assert!(
                attributes_exclude_production(&item.attrs),
                "cfg({predicate}) cannot exist in any production build"
            );
        }
    }

    #[test]
    fn single_valued_builtin_cfg_keys_cannot_take_competing_values() {
        let item: syn::ItemFn = syn::parse_str(
            "#[cfg(all(target_os = \"linux\", target_os = \"windows\"))] fn impossible() {}",
        )
        .expect("probe must be valid Rust syntax");

        assert!(
            attributes_exclude_production(&item.attrs),
            "target_os cannot equal linux and windows in one build"
        );
    }

    #[test]
    fn contradictions_remain_impossible_above_the_search_threshold() {
        let item: syn::ItemFn = syn::parse_str(
            "#[cfg(all(feature = \"x\", not(feature = \"x\"), \
             feature = \"a\", feature = \"b\", feature = \"c\", feature = \"d\", \
             feature = \"e\", feature = \"f\", feature = \"g\", feature = \"h\", \
             feature = \"i\", feature = \"j\", feature = \"k\", feature = \"l\", \
             feature = \"m\"))] fn impossible() {}",
        )
        .expect("probe must be valid Rust syntax");

        assert!(
            attributes_exclude_production(&item.attrs),
            "an atom-count guard cannot hide a direct contradiction"
        );
    }

    #[test]
    fn nested_exclusivity_remains_impossible_with_many_atoms() {
        let item: syn::ItemFn = syn::parse_str(
            "#[cfg(all(target_os = \"windows\", not(feature = \"x\"), \
             any(target_os = \"linux\", feature = \"x\"), \
             any(feature = \"a\", feature = \"b\", feature = \"c\", feature = \"d\", \
             feature = \"e\", feature = \"f\", feature = \"g\", feature = \"h\", \
             feature = \"i\", feature = \"j\", feature = \"k\", feature = \"l\", \
             feature = \"m\")))] fn impossible() {}",
        )
        .expect("probe must be valid Rust syntax");

        assert!(
            attributes_exclude_production(&item.attrs),
            "nested target exclusivity cannot fail open above an atom-count threshold"
        );
    }

    #[test]
    fn possible_cfg_predicates_remain_production_attributes() {
        for predicate in [
            "any(unix, windows)",
            "any(test, feature = \"fixtures\")",
            "all(feature = \"x\", unix)",
            "all(custom_cfg(foo), not(custom_cfg(bar)))",
        ] {
            let item: syn::ItemFn =
                syn::parse_str(&format!("#[cfg({predicate})] fn possible() {{}}"))
                    .expect("probe must be valid Rust syntax");

            assert!(
                !attributes_exclude_production(&item.attrs),
                "cfg({predicate}) has at least one production assignment"
            );
        }
    }

    #[test]
    fn a_prefix_does_not_count_as_a_call() {
        // The bug this prevents: `record_cache` is dead, `record_cache_savings`
        // is live, and a substring match would call both live.
        assert_eq!(count_tokens("outer_record_cache(x)", "record_cache("), 0);
        assert_eq!(count_tokens("record_cache_savings(x)", "record_cache("), 0);
        assert_eq!(count_tokens("self.record_cache(x)", "record_cache("), 1);
    }

    #[test]
    fn a_field_access_counts_despite_its_receiver() {
        // A `.field` needle is always preceded by an identifier, so checking
        // the boundary before it rejects every real access and reports the
        // metric dead. A suffix after it is still a different field.
        assert_eq!(count_tokens("metrics().cache_hits.inc()", ".cache_hits"), 1);
        assert_eq!(count_tokens("m.cache_hits_by_tier.inc()", ".cache_hits"), 0);
    }

    #[test]
    fn a_recorder_called_only_through_an_alias_is_live() {
        // rate_limit_budget.rs imports the recorder aliased and only ever calls
        // the alias, so a search for the real symbol reported a metric that is
        // written on every auto-suspend as dead.
        let src = r#"
use sbproxy_observe::metrics::{record_rate_limit, record_rate_limit_suspend as record_suspend};

fn emit_suspend(ws: &str) {
    record_suspend(ws);
}
"#;
        assert_eq!(count_tokens(src, "record_rate_limit_suspend("), 0);
        assert_eq!(
            recorder_aliases(src, "record_rate_limit_suspend"),
            vec!["record_suspend".to_string()]
        );
        // The aliased call is what makes it live.
        assert_eq!(count_tokens(src, "record_suspend("), 1);
    }

    #[test]
    fn a_bare_symbol_reference_is_not_read_as_an_alias() {
        // `Writer::Recorder("record_rate_limit_suspend")` and `fn record_rate_limit_suspend(`
        // both contain the symbol but neither rebinds it, so neither yields an alias.
        let src = r#"
writer: Writer::Recorder("record_rate_limit_suspend"),
pub fn record_rate_limit_suspend(ws: &str) {}
"#;
        assert!(recorder_aliases(src, "record_rate_limit_suspend").is_empty());
    }

    #[test]
    fn a_span_macro_yields_its_literal_name() {
        // Every shape the workspace actually writes: a bare macro, a
        // path-qualified one, and a multi-line invocation whose name sits on
        // its own line.
        let src = r#"
fn a() { let _ = info_span!("ai.request", k = 1); }
fn b() { let _ = tracing::debug_span!("ai.provider.attempt"); }
fn c() {
    let _ = tracing::info_span!(
        "sbproxy.ai.usage_sink",
        "gen_ai.system" = provider,
    );
}
"#;
        let mut names = BTreeSet::new();
        span_names_in(src, &mut names);

        assert_eq!(
            names,
            ["ai.provider.attempt", "ai.request", "sbproxy.ai.usage_sink"]
                .iter()
                .map(|name| name.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn a_span_name_in_a_comment_or_a_lookalike_macro_is_not_an_emission() {
        // The two ways the old substring guard passed a dead name: the doc
        // comment that mentions it, and a macro whose name merely ends in
        // one of ours.
        let src = strip_comments(
            r#"
// info_span!("sbproxy.intake.accept") would be the shape.
fn a() { let _ = my_info_span!("sbproxy.policy.enforce"); }
fn b() { let _ = info_span!(name_from_config, k = 1); }
"#,
        );

        let mut names = BTreeSet::new();
        span_names_in(&src, &mut names);

        assert!(names.is_empty(), "nothing here opens a span: {names:?}");
    }

    #[test]
    fn resolve_symbol_does_not_let_a_definition_be_its_own_caller() {
        // The whole reason a constructor with no callers is detectable: the
        // `fn name(` that defines it is also a match for the `name(` needle.
        let defining = "pub fn provider_selection_span(p: &str) -> Span { info_span!(\"x\") }";
        let calling = "fn dispatch() { let s = provider_selection_span(\"openai\"); }";

        let texts = [defining, calling];
        let identifiers: Vec<BTreeSet<&str>> =
            texts.iter().map(|text| identifier_set(text)).collect();
        let define = "fn provider_selection_span(";
        let call = "provider_selection_span(";

        let (defined, calls) = resolve_symbol(
            &texts[..1],
            &identifiers[..1],
            "provider_selection_span",
            call,
            Some(define),
            true,
        );
        assert!(defined, "the definition is right there");
        assert_eq!(calls, 0, "a definition is not a call site");

        let (defined, calls) = resolve_symbol(
            &texts,
            &identifiers,
            "provider_selection_span",
            call,
            Some(define),
            true,
        );
        assert!(defined);
        assert_eq!(calls, 1, "only the real call site counts");
    }

    #[test]
    fn a_mesh_prefixed_reference_is_recognized() {
        // The mesh_ prefix is sanctioned alongside sbproxy_ (WOR-1900);
        // dashboards and alert rules reading mesh_* series are subject to
        // the same drift guard.
        let refs = references_in(
            r#"sum(rate(mesh_gossip_retry_total{target="node-b"}[5m]))"#,
            "deploy/alerts/mesh.yml",
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].metric, "mesh_gossip_retry_total");
        assert!(refs[0].labels.contains("target"));
    }

    #[test]
    fn a_sanctioned_prefix_mid_identifier_is_not_a_reference() {
        // `semcache_mesh_hits_total` contains "mesh_" but is not a mesh_
        // family; the boundary check must reject the mid-identifier match.
        let refs = references_in("rate(semcache_mesh_hits_total[5m])", "x.yml");
        assert_eq!(refs, vec![]);
    }

    #[test]
    fn a_static_writer_counts_uses_and_not_its_own_declaration() {
        // Mesh metrics are driven through the static itself, so the
        // registry names the static ident. Its declaration, rustdoc
        // cross-references, and the registry row's string literal must not
        // count; a real method call must.
        let src = r#"
/// See [`MESH_THING`] for the label contract.
pub static MESH_THING: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(Opts::new("mesh_thing_total", "x"), &["kind"])
        .expect("register mesh_thing_total")
});

fn live() {
    MESH_THING.with_label_values(&["kind"]).inc();
}
"#;
        assert!(is_metric_static("MESH_THING"));
        assert!(!is_metric_static("record_thing"));
        let text = blank_string_literals(&strip_comments(src));
        let uses = count_tokens(&text, "MESH_THING");
        let declarations = count_tokens(&text, "static MESH_THING:");
        assert_eq!(declarations, 1);
        assert_eq!(uses - declarations, 1, "only the method call is a use");
        // The registry row alone must not make a static look live.
        let row = blank_string_literals(&strip_comments(
            r#"writer: Writer::Recorder("MESH_THING"),"#,
        ));
        assert_eq!(count_tokens(&row, "MESH_THING"), 0);
    }

    #[test]
    fn a_selector_label_is_attributed_to_its_metric() {
        let refs = references_in(
            r#"sum(rate(sbproxy_requests_total{status_class!="5xx"}[5m]))"#,
            "deploy/alerts/recording-rules.yml",
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].metric, "sbproxy_requests_total");
        assert!(refs[0].labels.contains("status_class"));
    }

    #[test]
    fn a_grouping_label_is_attributed_when_the_line_names_one_metric() {
        let refs = references_in(
            "count(count by (route, status_class) (sbproxy_requests_total))",
            "deploy/alerts/recording-rules.yml",
        );
        assert_eq!(refs.len(), 1);
        assert!(refs[0].labels.contains("route"));
        assert!(refs[0].labels.contains("status_class"));
    }

    #[test]
    fn a_histogram_suffix_resolves_to_the_declared_family() {
        let refs = references_in(
            "histogram_quantile(0.99, sbproxy_request_duration_seconds_bucket)",
            "x.yml",
        );
        assert_eq!(refs[0].metric, "sbproxy_request_duration_seconds");
    }

    #[test]
    fn the_status_class_slo_is_rejected() {
        // The regression test for WOR-1894. This exact query pinned the
        // availability SLO at 1.0 through any outage.
        let metrics = [metric(
            "sbproxy_requests_total",
            Writer::Field("requests_total"),
            &["hostname", "method", "status"],
        )];
        let references = references_in(
            r#"sum(rate(sbproxy_requests_total{status_class!="5xx"}[5m]))"#,
            "deploy/alerts/recording-rules.yml",
        );

        let errors = verify_references(&metrics, &references, &[]);

        assert!(
            errors.iter().any(|e| e.message.contains("status_class")),
            "the label that never existed must fail the guard: {errors:?}"
        );
    }

    #[test]
    fn the_correct_slo_passes() {
        let metrics = [metric(
            "sbproxy_requests_total",
            Writer::Field("requests_total"),
            &["hostname", "method", "status"],
        )];
        let references = references_in(
            r#"sum(rate(sbproxy_requests_total{status=~"5.."}[5m]))"#,
            "deploy/alerts/recording-rules.yml",
        );

        assert_eq!(verify_references(&metrics, &references, &[]), vec![]);
    }

    #[test]
    fn a_dashboard_may_not_read_a_dead_metric() {
        let metrics = [metric("sbproxy_dead_total", Writer::Nothing, &[])];
        let references = references_in(
            "rate(sbproxy_dead_total[5m])",
            "dashboards/grafana/overview.json",
        );

        let errors = verify_references(&metrics, &references, &[]);

        assert!(errors.iter().any(|e| e.message.contains("flat zero")));
    }

    #[test]
    fn an_exemption_lets_a_known_dead_reference_through() {
        let metrics = [metric("sbproxy_dead_total", Writer::Nothing, &[])];
        let references = references_in(
            "rate(sbproxy_dead_total[5m])",
            "dashboards/grafana/overview.json",
        );
        let exemptions = [ReferenceExemption {
            metric: "sbproxy_dead_total",
            reason: "panel ships ahead of the writer; wired by WOR-1898",
        }];

        assert_eq!(
            verify_references(&metrics, &references, &exemptions),
            vec![]
        );
    }

    #[test]
    fn a_query_against_an_undeclared_metric_is_rejected() {
        let metrics = [metric(
            "sbproxy_ai_guardrail_blocks_total",
            Writer::Recorder("record_guardrail_block"),
            &[],
        )];
        // The real one: the rule says `_triggers_total`, the code says
        // `_blocks_total`, and the alert has never once evaluated.
        let references = references_in(
            "rate(sbproxy_ai_guardrail_triggers_total[1m]) > 10",
            "dashboards/prometheus/alerts.yml",
        );

        let errors = verify_references(&metrics, &references, &[]);

        assert!(errors
            .iter()
            .any(|e| e.message.contains("no crate declares")));
    }

    #[test]
    fn a_dashboard_variable_query_is_read_as_a_selector() {
        // The licensing-edits regression. Reading only `expr` could not see
        // this line, so the dropdown every panel on that dashboard filtered
        // through was populated from a metric no crate has ever declared.
        let metrics = [metric(
            "sbproxy_audit_emit_duration_seconds",
            Writer::Recorder("record_audit_emit_duration"),
            &["channel", "outcome"],
        )];
        let references = references_in(
            &promql_only(r#"  "query": "label_values(sbproxy_audit_emit_total, tenant_id)","#),
            "deploy/dashboards/licensing-edits.json",
        );

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].metric, "sbproxy_audit_emit_total");
        assert!(references[0].labels.contains("tenant_id"));

        let errors = verify_references(&metrics, &references, &[]);

        assert!(errors
            .iter()
            .any(|e| e.message.contains("no crate declares")));
    }

    #[test]
    fn a_variable_selector_keeps_its_filter_and_its_dropdown_label() {
        // Grafana escapes the selector's quotes, and the label is the last
        // argument rather than the second: both have to survive the rewrite.
        let references = references_in(
            &promql_only(
                r#"  "query": "label_values(sbproxy_requests_total{agent_class=~\"$agent_class\"}, agent_vendor)","#,
            ),
            "deploy/dashboards/per-agent.json",
        );

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].metric, "sbproxy_requests_total");
        assert!(references[0].labels.contains("agent_class"));
        assert!(references[0].labels.contains("agent_vendor"));
    }

    #[test]
    fn a_label_values_call_naming_no_metric_is_dropped() {
        // `label_values(<label>)` asks for a label across every family, so
        // there is nothing in it to hold against the registry.
        assert_eq!(promql_only(r#"  "query": "label_values(pillar)","#), "");
    }

    #[test]
    fn a_variable_that_is_not_promql_is_not_read_as_promql() {
        // licensing-edits' replacement dropdown, and the reason the guard did
        // not simply lose a reference when that metric name went away.
        let sql = r#"  "definition": "SELECT DISTINCT tenant_id FROM admin_audit_events","#;
        let prose = r#"  "description": "sbproxy_spans_emitted_total is declared nowhere.","#;

        assert_eq!(promql_only(sql), "");
        assert_eq!(promql_only(prose), "");
    }
}
