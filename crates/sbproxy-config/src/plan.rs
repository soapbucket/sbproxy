//! Plan / apply diff engine. Implements step 1 of the WOR-131 ADR
//! (`docs/adr-config-plan-apply.md`): a sync library API that walks two
//! parsed [`ConfigFile`] values and produces a stable, JSON-serialisable
//! [`PlanReport`] describing the differences.
//!
//! The CLI in `crates/sbproxy/src/main.rs` is a thin wrapper over
//! [`plan`]. The same library API is intended for in-process callers
//! (the K8s operator, future admin-socket plan-export) per ADR open
//! question 7.
//!
//! Scope today (WOR-180 steps 1 and 2):
//!
//! * Diff granularity is per top-level key of [`ConfigFile`]:
//!   each origin (keyed by hostname) plus a single `proxy` entry that
//!   collapses every server-level field into one change row,
//!   plus `access_log` and `agent_classes` as their own entries.
//! * Blast-radius mapping is the simple top-level mapping documented in
//!   the ADR and in `top_level_blast_radius` below; per-path
//!   refinement is step 4 of the WOR-180 sequence and is deferred.
//! * Plan-time semantic validation (orphan refs, missing secrets,
//!   unknown module types) is step 3 and is also deferred. This module
//!   only diffs; it never rejects.

use crate::types::ConfigFile;
use serde::Serialize;
use std::collections::BTreeSet;

/// Stable JSON envelope returned by [`plan`].
///
/// The envelope shape is the v1 contract for the CLI's `--format json`
/// output and any future plan-file consumer. Adding fields is allowed;
/// renaming or removing existing fields is a breaking change.
#[derive(Debug, Clone, Serialize)]
pub struct PlanReport {
    /// Plan envelope schema version. Currently `1`.
    pub plan_version: u32,
    /// Per-change rows in deterministic order: `proxy` first, then
    /// origins ordered by hostname, then `access_log`, then
    /// `agent_classes`. The order is part of the v1 contract so text
    /// rendering is reproducible across runs.
    pub entries: Vec<PlanEntry>,
    /// Summary counts grouped by [`PlanKind`]. Useful for the
    /// `terraform plan`-style footer.
    pub summary: PlanSummary,
    /// The largest blast radius across all entries. `Hitless` when
    /// there are no changes (matches the "no-op plan" exit-zero case).
    pub max_blast_radius: BlastRadius,
}

impl PlanReport {
    /// True when no entries are present (a no-op plan). The CLI maps
    /// this to exit code 0; `false` maps to exit code 2.
    pub fn is_noop(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One change row in the plan.
///
/// `path` is a JSONPath-shaped string rooted at the YAML document
/// (e.g. `proxy`, `origins.api.example.com`). `kind` is added /
/// changed / removed. `old` and `new` are the raw JSON values; for
/// `Added`, `old` is `None`; for `Removed`, `new` is `None`. For
/// `Changed`, both are `Some` and not byte-equal.
#[derive(Debug, Clone, Serialize)]
pub struct PlanEntry {
    /// Where in the document this change lives.
    pub path: String,
    /// Whether the entry was added, changed, or removed.
    pub kind: PlanKind,
    /// JSON snapshot of the value in the baseline. `None` for `Added`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<serde_json::Value>,
    /// JSON snapshot of the value in the proposed config. `None` for
    /// `Removed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<serde_json::Value>,
    /// Operational impact label. See [`BlastRadius`].
    pub blast_radius: BlastRadius,
    /// One-line human-readable explanation of why this entry is in the
    /// plan. Suitable for the text format and for log emission.
    pub reason: String,
}

/// What kind of change this entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanKind {
    /// Present in `proposed` but absent in `baseline`.
    Added,
    /// Present in both, but the JSON snapshots differ.
    Changed,
    /// Present in `baseline` but absent in `proposed`.
    Removed,
}

/// Operational impact of applying a single change.
///
/// Ordered by severity so the CLI can compute `max_blast_radius` with
/// `entries.iter().map(|e| e.blast_radius).max()`.
///
/// Per the ADR section "Blast-radius hint":
/// * `Hitless` change can be applied without re-routing any in-flight
///   or future request (log-level, access-log filter tweaks).
/// * `Reload` change requires `arc-swap` to publish a new pipeline.
///   In-flight requests finish on the old pipeline; new requests pick
///   up the new pipeline. This is what the existing hot-reload path
///   already does.
/// * `Restart` change requires the OS process to restart because the
///   listener or process-global state cannot be hot-swapped (bind
///   ports, agent-class resolver).
/// * `Breaking` change is `Restart`-class **and** would drop in-flight
///   connections beyond the existing graceful-shutdown budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BlastRadius {
    /// No re-routing required.
    Hitless,
    /// Hot-swap via arc-swap.
    Reload,
    /// Process restart required.
    Restart,
    /// Restart plus connection drops beyond graceful shutdown.
    Breaking,
}

/// Summary counts for [`PlanReport`]. Used to render the
/// `terraform plan`-style footer line.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PlanSummary {
    /// Number of [`PlanKind::Added`] entries.
    pub added: usize,
    /// Number of [`PlanKind::Changed`] entries.
    pub changed: usize,
    /// Number of [`PlanKind::Removed`] entries.
    pub removed: usize,
}

impl PlanSummary {
    fn record(&mut self, kind: PlanKind) {
        match kind {
            PlanKind::Added => self.added += 1,
            PlanKind::Changed => self.changed += 1,
            PlanKind::Removed => self.removed += 1,
        }
    }
}

/// Diff two parsed config files and return a [`PlanReport`].
///
/// Diff granularity is per top-level key of [`ConfigFile`]:
///
/// * `proxy` collapses to a single entry. Any server-level field
///   change produces one row labelled `Changed` with the full proxy
///   block as `old` / `new`. The blast radius is the worst-case across
///   server-level fields (`Restart`); finer per-field mapping is the
///   step 4 follow-up.
/// * `origins.<hostname>` produces one entry per origin. Adding,
///   removing, or changing an origin shows up as exactly one row.
///   Per-origin blast radius is `Reload` (every origin change is
///   hot-swappable today).
/// * `access_log` and `agent_classes` produce at most one entry each
///   when their JSON snapshots differ. `access_log` changes are
///   `Hitless`; `agent_classes` changes are `Restart` (the resolver
///   is constructed once per process at startup).
///
/// The function is sync, allocation-bounded, and never panics: every
/// `serde_json::to_value` failure is converted to a string-encoded
/// fallback so the CLI never sees a `Result::Err`.
pub fn plan(baseline: &ConfigFile, proposed: &ConfigFile) -> PlanReport {
    let mut entries: Vec<PlanEntry> = Vec::new();
    let mut summary = PlanSummary::default();

    // -- proxy block --
    let baseline_proxy = json_or_null(&baseline.proxy);
    let proposed_proxy = json_or_null(&proposed.proxy);
    if baseline_proxy != proposed_proxy {
        let blast = top_level_blast_radius("proxy");
        let entry = PlanEntry {
            path: "proxy".to_string(),
            kind: PlanKind::Changed,
            old: Some(baseline_proxy),
            new: Some(proposed_proxy),
            blast_radius: blast,
            reason: "proxy server-level settings changed".to_string(),
        };
        summary.record(entry.kind);
        entries.push(entry);
    }

    // -- origins (sorted by hostname for determinism) --
    let mut hostnames: BTreeSet<&str> = BTreeSet::new();
    for k in baseline.origins.keys() {
        hostnames.insert(k.as_str());
    }
    for k in proposed.origins.keys() {
        hostnames.insert(k.as_str());
    }

    for host in &hostnames {
        let host_owned: String = (*host).to_string();
        let path = format!("origins.{host_owned}");
        let blast = top_level_blast_radius("origins");

        match (baseline.origins.get(*host), proposed.origins.get(*host)) {
            (None, Some(new)) => {
                let entry = PlanEntry {
                    path,
                    kind: PlanKind::Added,
                    old: None,
                    new: Some(json_or_null(new)),
                    blast_radius: blast,
                    reason: format!("origin '{host_owned}' added"),
                };
                summary.record(entry.kind);
                entries.push(entry);
            }
            (Some(old), None) => {
                let entry = PlanEntry {
                    path,
                    kind: PlanKind::Removed,
                    old: Some(json_or_null(old)),
                    new: None,
                    blast_radius: blast,
                    reason: format!("origin '{host_owned}' removed"),
                };
                summary.record(entry.kind);
                entries.push(entry);
            }
            (Some(old), Some(new)) => {
                let old_json = json_or_null(old);
                let new_json = json_or_null(new);
                if old_json != new_json {
                    let reason = origin_change_reason(&host_owned, &old_json, &new_json);
                    let entry = PlanEntry {
                        path,
                        kind: PlanKind::Changed,
                        old: Some(old_json),
                        new: Some(new_json),
                        blast_radius: blast,
                        reason,
                    };
                    summary.record(entry.kind);
                    entries.push(entry);
                }
            }
            (None, None) => {}
        }
    }

    // -- access_log --
    let baseline_al = json_or_null(&baseline.access_log);
    let proposed_al = json_or_null(&proposed.access_log);
    if baseline_al != proposed_al {
        let kind = match (baseline.access_log.is_some(), proposed.access_log.is_some()) {
            (false, true) => PlanKind::Added,
            (true, false) => PlanKind::Removed,
            _ => PlanKind::Changed,
        };
        let blast = top_level_blast_radius("access_log");
        let entry = PlanEntry {
            path: "access_log".to_string(),
            kind,
            old: if matches!(kind, PlanKind::Added) {
                None
            } else {
                Some(baseline_al)
            },
            new: if matches!(kind, PlanKind::Removed) {
                None
            } else {
                Some(proposed_al)
            },
            blast_radius: blast,
            reason: "access_log block changed".to_string(),
        };
        summary.record(entry.kind);
        entries.push(entry);
    }

    // -- agent_classes --
    let baseline_ac = json_or_null(&baseline.agent_classes);
    let proposed_ac = json_or_null(&proposed.agent_classes);
    if baseline_ac != proposed_ac {
        let kind = match (
            baseline.agent_classes.is_some(),
            proposed.agent_classes.is_some(),
        ) {
            (false, true) => PlanKind::Added,
            (true, false) => PlanKind::Removed,
            _ => PlanKind::Changed,
        };
        let blast = top_level_blast_radius("agent_classes");
        let entry = PlanEntry {
            path: "agent_classes".to_string(),
            kind,
            old: if matches!(kind, PlanKind::Added) {
                None
            } else {
                Some(baseline_ac)
            },
            new: if matches!(kind, PlanKind::Removed) {
                None
            } else {
                Some(proposed_ac)
            },
            blast_radius: blast,
            reason: "agent_classes block changed".to_string(),
        };
        summary.record(entry.kind);
        entries.push(entry);
    }

    let max_blast_radius = entries
        .iter()
        .map(|e| e.blast_radius)
        .max()
        .unwrap_or(BlastRadius::Hitless);

    PlanReport {
        plan_version: 1,
        entries,
        summary,
        max_blast_radius,
    }
}

/// Top-level path to default blast radius mapping.
///
/// This is the simple, coarse mapping the ADR specifies for steps 1
/// and 2. The detailed per-field matrix in the ADR's "Blast-radius
/// hint" section is the step 4 follow-up.
///
/// | Top-level key      | Blast radius | Why |
/// |--------------------|--------------|-----|
/// | `proxy`            | `Restart`    | server-level changes can touch bind ports, `agent_classes`, the L2 driver, the messenger driver. The conservative bound is restart. |
/// | `origins`          | `Reload`     | every per-origin change is hot-swappable through `arc-swap` today. |
/// | `access_log`       | `Hitless`    | the access-log hook reads its config on every request; a swap is observed without re-routing. |
/// | `agent_classes`    | `Restart`    | the resolver is built once per process per the comment at `crates/sbproxy-core/src/reload.rs:194`. |
fn top_level_blast_radius(top_key: &str) -> BlastRadius {
    match top_key {
        "proxy" => BlastRadius::Restart,
        "origins" => BlastRadius::Reload,
        "access_log" => BlastRadius::Hitless,
        "agent_classes" => BlastRadius::Restart,
        // Unknown future top-level keys: assume reload-class. Adding a
        // new top-level key here is a step 4 follow-up that ships the
        // detailed mapping for that key alongside the schema change.
        _ => BlastRadius::Reload,
    }
}

/// Best-effort JSON snapshot of a config sub-tree.
///
/// `serde_json::to_value` should always succeed for our config types
/// since they all derive `Serialize`. Defending against the
/// theoretical failure case (e.g. a future field that produces a
/// non-finite float) keeps `plan` total: callers never have to handle
/// a "couldn't snapshot baseline" error path.
fn json_or_null<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

/// Heuristic one-liner describing the most-visible change between two
/// origin JSON snapshots. Falls back to the generic phrase when the
/// snapshots differ in a structurally-deep way the heuristic does not
/// recognise.
fn origin_change_reason(host: &str, old: &serde_json::Value, new: &serde_json::Value) -> String {
    if let (serde_json::Value::Object(old_obj), serde_json::Value::Object(new_obj)) = (old, new) {
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for k in old_obj.keys() {
            keys.insert(k.as_str());
        }
        for k in new_obj.keys() {
            keys.insert(k.as_str());
        }
        let differing: Vec<&str> = keys
            .iter()
            .filter(|k| old_obj.get(**k) != new_obj.get(**k))
            .copied()
            .collect();
        if !differing.is_empty() {
            let preview = differing
                .iter()
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if differing.len() > 3 { ", ..." } else { "" };
            return format!("origin '{host}' changed ({preview}{suffix})");
        }
    }
    format!("origin '{host}' changed")
}

/// Render a [`PlanReport`] as a Terraform-style human-readable text
/// block. The format is deliberately stable but not promised; tooling
/// should consume `--format json` instead.
pub fn render_text(report: &PlanReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if report.is_noop() {
        out.push_str("No changes. sbproxy config is in sync.\n");
        return out;
    }
    for e in &report.entries {
        let sigil = match e.kind {
            PlanKind::Added => "+",
            PlanKind::Changed => "~",
            PlanKind::Removed => "-",
        };
        let label = match e.blast_radius {
            BlastRadius::Hitless => "hitless",
            BlastRadius::Reload => "reload",
            BlastRadius::Restart => "restart",
            BlastRadius::Breaking => "breaking",
        };
        let _ = writeln!(&mut out, "  {sigil} {} [{label}] {}", e.path, e.reason);
    }
    let _ = writeln!(
        &mut out,
        "\nPlan: {} added, {} changed, {} removed. max-blast-radius: {}",
        report.summary.added,
        report.summary.changed,
        report.summary.removed,
        match report.max_blast_radius {
            BlastRadius::Hitless => "hitless",
            BlastRadius::Reload => "reload",
            BlastRadius::Restart => "restart",
            BlastRadius::Breaking => "breaking",
        }
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_config;

    fn parse(yaml: &str) -> ConfigFile {
        // Round-trip through `compile_config` to keep the parse path
        // identical to what the CLI does (env-var interpolation,
        // features-to-extensions migration, schema validation).
        // `compile_config` consumes the parsed `ConfigFile` though, so
        // we re-parse the post-migration YAML to recover the typed
        // form the diff walker wants.
        let _ = compile_config(yaml).expect("compile_config");
        serde_yaml::from_str::<ConfigFile>(yaml).expect("ConfigFile parse")
    }

    const ORIGIN_BASE: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;

    const ORIGIN_BASE_PLUS_RATELIMIT: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    rate_limits:
      tenant_burst: 200
      tenant_sustained: 100
      route_default: 50
"#;

    const ORIGIN_TWO: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
  www.example.com:
    action:
      type: static
      body: "hello"
"#;

    const PROXY_BIND_CHANGE: &str = r#"
proxy:
  http_bind_port: 9090
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;

    const ORIGIN_WITH_TRANSFORM: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    transforms:
      - type: gzip
"#;

    #[test]
    fn plan_no_changes_is_noop() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_BASE);
        let report = plan(&a, &b);
        assert!(report.is_noop(), "expected no changes, got {:?}", report);
        assert_eq!(report.max_blast_radius, BlastRadius::Hitless);
    }

    #[test]
    fn plan_added_origin() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Added);
        assert_eq!(entry.path, "origins.www.example.com");
        assert_eq!(entry.blast_radius, BlastRadius::Reload);
        assert!(entry.old.is_none());
        assert!(entry.new.is_some());
        assert_eq!(report.summary.added, 1);
    }

    #[test]
    fn plan_removed_origin() {
        let a = parse(ORIGIN_TWO);
        let b = parse(ORIGIN_BASE);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Removed);
        assert_eq!(entry.path, "origins.www.example.com");
        assert_eq!(entry.blast_radius, BlastRadius::Reload);
        assert!(entry.new.is_none());
        assert!(entry.old.is_some());
        assert_eq!(report.summary.removed, 1);
    }

    #[test]
    fn plan_changed_origin_emits_field_preview_in_reason() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_BASE_PLUS_RATELIMIT);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Changed);
        assert_eq!(entry.path, "origins.api.example.com");
        assert_eq!(entry.blast_radius, BlastRadius::Reload);
        assert!(
            entry.reason.contains("rate_limits"),
            "expected rate_limits in reason, got {:?}",
            entry.reason
        );
    }

    #[test]
    fn plan_proxy_change_is_restart_class() {
        let a = parse(ORIGIN_BASE);
        let b = parse(PROXY_BIND_CHANGE);
        let report = plan(&a, &b);
        // Both files have the same single origin, only proxy.http_bind_port
        // differs, so we expect exactly one Changed entry on `proxy`.
        let proxy_entries: Vec<_> = report
            .entries
            .iter()
            .filter(|e| e.path == "proxy")
            .collect();
        assert_eq!(proxy_entries.len(), 1);
        let proxy_entry = proxy_entries[0];
        assert_eq!(proxy_entry.kind, PlanKind::Changed);
        assert_eq!(proxy_entry.blast_radius, BlastRadius::Restart);
        assert_eq!(report.max_blast_radius, BlastRadius::Restart);
    }

    #[test]
    fn plan_added_transform_changes_origin() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_WITH_TRANSFORM);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Changed);
        assert_eq!(entry.path, "origins.api.example.com");
        assert_eq!(entry.blast_radius, BlastRadius::Reload);
        assert!(
            entry.reason.contains("transforms"),
            "expected 'transforms' in reason, got {:?}",
            entry.reason
        );
    }

    #[test]
    fn plan_json_envelope_is_stable() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        let json = serde_json::to_value(&report).expect("serialise");
        assert_eq!(json["plan_version"], 1);
        assert!(json["entries"].is_array());
        assert!(json["summary"].is_object());
        assert_eq!(json["max_blast_radius"], "reload");
        let entry = &json["entries"][0];
        assert_eq!(entry["kind"], "added");
        assert_eq!(entry["path"], "origins.www.example.com");
        assert_eq!(entry["blast_radius"], "reload");
    }

    #[test]
    fn render_text_noop_message() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_BASE);
        let report = plan(&a, &b);
        let text = render_text(&report);
        assert!(text.contains("No changes"), "got {text:?}");
    }

    #[test]
    fn render_text_added_origin_uses_plus_sigil() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        let text = render_text(&report);
        assert!(text.contains("+ origins.www.example.com"), "got {text:?}");
        assert!(text.contains("[reload]"), "got {text:?}");
    }
}
