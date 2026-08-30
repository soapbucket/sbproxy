//! Offline replay of recorded MCP tool-call samples against Cedar source.
//!
//! `sbproxy cedar replay` uses this module. A traffic sample is JSONL:
//! one [`ReplaySample`] per line. Each sample is the same principal /
//! action / resource triple the live hook builds (`Agent::"…"`,
//! `Action::"MCP::CallTool"`, `ToolInvocation::"<prefix>/<tool>"`).
//!
//! Two modes:
//!
//! - **Expected:** a sample with `expected` (`allow` / `deny` /
//!   `confirm`) is an assertion. A mismatch is a failed case.
//! - **Diff:** the same samples run against a baseline evaluator and a
//!   proposed evaluator. A row whose label changed is a policy-change
//!   preview, the analogue of enterprise `sbproxy-policy diff`.
//!
//! Samples never carry argument values. The live hook evaluates against
//! an empty Cedar context, so a recorded argument set would not change
//! the verdict.

use serde::{Deserialize, Serialize};

use super::{CedarEvaluator, CedarRequest};
use sbproxy_plugin::PolicyDecision;

/// Default action UID the live MCP hook uses.
pub const MCP_CALL_TOOL_ACTION: &str = r#"Action::"MCP::CallTool""#;

/// One recorded (or authored) tool-call sample.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReplaySample {
    /// Optional stable id for the report. When omitted, the line number
    /// (1-based, after skipping blanks and comments) is used.
    #[serde(default)]
    pub id: Option<String>,
    /// Principal UID, e.g. `Agent::"anonymous"`.
    pub principal: String,
    /// Action UID. Defaults to [`MCP_CALL_TOOL_ACTION`].
    #[serde(default)]
    pub action: Option<String>,
    /// Resource UID, e.g. `ToolInvocation::"demo/search_repos"`.
    pub resource: String,
    /// Optional assertion: `allow`, `deny`, or `confirm`.
    #[serde(default)]
    pub expected: Option<String>,
}

/// One evaluated sample.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReplayRow {
    /// Sample id.
    pub id: String,
    /// Principal UID.
    pub principal: String,
    /// Action UID actually evaluated.
    pub action: String,
    /// Resource UID.
    pub resource: String,
    /// Verdict label from the proposed (or only) evaluator.
    pub verdict: String,
    /// Confirm reason, when the verdict is `confirm`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Baseline verdict, when a baseline evaluator was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    /// Expected label, when the sample asserted one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// True when `expected` did not match `verdict`.
    pub expected_mismatch: bool,
    /// True when `baseline` and `verdict` differ.
    pub changed: bool,
}

/// Aggregate replay report.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReplayReport {
    /// Per-sample rows, in input order.
    pub rows: Vec<ReplayRow>,
    /// Count of rows whose expected label missed.
    pub expected_mismatches: usize,
    /// Count of rows whose verdict changed against the baseline.
    pub changed: usize,
}

impl ReplayReport {
    /// True when every assertion held and no baseline verdict moved.
    pub fn ok(&self) -> bool {
        self.expected_mismatches == 0 && self.changed == 0
    }
}

/// Parse a JSONL traffic sample. Blank lines and `#` comments are skipped.
///
/// # Errors
///
/// Returns when a non-comment line is not a JSON object that matches
/// [`ReplaySample`].
pub fn parse_jsonl(text: &str) -> Result<Vec<ReplaySample>, String> {
    let mut samples = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let sample: ReplaySample = serde_json::from_str(trimmed)
            .map_err(|error| format!("traffic sample line {}: {error}", idx + 1))?;
        samples.push(sample);
    }
    Ok(samples)
}

/// Evaluate `samples` against `proposed`. When `baseline` is `Some`,
/// each row also records that evaluator's label and `changed`.
pub fn replay(
    proposed: &CedarEvaluator,
    baseline: Option<&CedarEvaluator>,
    samples: &[ReplaySample],
) -> ReplayReport {
    let mut rows = Vec::with_capacity(samples.len());
    let mut expected_mismatches = 0;
    let mut changed = 0;
    for (idx, sample) in samples.iter().enumerate() {
        let action = sample
            .action
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(MCP_CALL_TOOL_ACTION);
        let request =
            CedarRequest::new(sample.principal.as_str(), action, sample.resource.as_str());
        let proposed_decision = proposed.evaluate(&request);
        let verdict = verdict_label(&proposed_decision);
        let reason = confirm_reason(&proposed_decision);
        let baseline_label = baseline.map(|ev| verdict_label(&ev.evaluate(&request)));
        let expected = sample.expected.as_deref().map(normalize_label);
        let expected_mismatch = expected.as_deref().is_some_and(|want| want != verdict);
        let row_changed = baseline_label.is_some_and(|was| was != verdict);
        if expected_mismatch {
            expected_mismatches += 1;
        }
        if row_changed {
            changed += 1;
        }
        let id = sample
            .id
            .clone()
            .unwrap_or_else(|| format!("line-{}", idx + 1));
        rows.push(ReplayRow {
            id,
            principal: sample.principal.clone(),
            action: action.to_string(),
            resource: sample.resource.clone(),
            verdict: verdict.to_string(),
            reason,
            baseline: baseline_label.map(str::to_string),
            expected,
            expected_mismatch,
            changed: row_changed,
        });
    }
    ReplayReport {
        rows,
        expected_mismatches,
        changed,
    }
}

/// Render a human report. One line per sample, then a summary.
pub fn format_text(report: &ReplayReport) -> String {
    let mut out = String::new();
    for row in &report.rows {
        let mut line = format!("{} {} -> {}", row.id, row.resource, row.verdict);
        if let Some(reason) = &row.reason {
            line.push_str(&format!(" ({reason})"));
        }
        if let Some(was) = &row.baseline {
            if row.changed {
                line.push_str(&format!("  [changed from {was}]"));
            }
        }
        if row.expected_mismatch {
            if let Some(want) = &row.expected {
                line.push_str(&format!("  [expected {want}]"));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!(
        "{} sample(s), {} changed, {} expected mismatch(es)\n",
        report.rows.len(),
        report.changed,
        report.expected_mismatches
    ));
    out
}

fn verdict_label(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow | PolicyDecision::AllowWithHeaders { .. } => "allow",
        PolicyDecision::Deny { .. } => "deny",
        PolicyDecision::Confirm { .. } => "confirm",
    }
}

fn confirm_reason(decision: &PolicyDecision) -> Option<String> {
    match decision {
        PolicyDecision::Confirm { reason, .. } => Some(reason.clone()),
        _ => None,
    }
}

fn normalize_label(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::{compile_all, schema::default_schema};

    const POLICIES: &str = r#"
permit(principal, action, resource);

forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/delete_repo"
);

@confirm("deploy needs a human")
forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/approve_deploy"
);
"#;

    const TIGHTER: &str = r#"
permit(principal, action, resource);

forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/delete_repo"
);

forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/search_repos"
);

@confirm("deploy needs a human")
forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/approve_deploy"
);
"#;

    fn evaluator(src: &str) -> CedarEvaluator {
        let (schema, _) = default_schema().expect("default MCP schema");
        let compiled = compile_all(&[("test", src)], Some(&schema)).expect("compile");
        CedarEvaluator::new(compiled.policy_set, Some(schema)).expect("evaluator")
    }

    fn sample(id: &str, resource: &str, expected: Option<&str>) -> ReplaySample {
        ReplaySample {
            id: Some(id.to_string()),
            principal: r#"Agent::"anonymous""#.to_string(),
            action: None,
            resource: resource.to_string(),
            expected: expected.map(str::to_string),
        }
    }

    #[test]
    fn allow_deny_and_confirm_labels_match_the_live_hook() {
        let ev = evaluator(POLICIES);
        let samples = vec![
            sample(
                "search",
                r#"ToolInvocation::"demo/search_repos""#,
                Some("allow"),
            ),
            sample(
                "delete",
                r#"ToolInvocation::"demo/delete_repo""#,
                Some("deny"),
            ),
            sample(
                "deploy",
                r#"ToolInvocation::"demo/approve_deploy""#,
                Some("confirm"),
            ),
        ];
        let report = replay(&ev, None, &samples);
        assert!(report.ok(), "{report:?}");
        assert_eq!(report.rows[0].verdict, "allow");
        assert_eq!(report.rows[1].verdict, "deny");
        assert_eq!(report.rows[2].verdict, "confirm");
        assert_eq!(
            report.rows[2].reason.as_deref(),
            Some("deploy needs a human")
        );
    }

    #[test]
    fn expected_mismatch_is_counted() {
        let ev = evaluator(POLICIES);
        let samples = vec![sample(
            "search",
            r#"ToolInvocation::"demo/search_repos""#,
            Some("deny"),
        )];
        let report = replay(&ev, None, &samples);
        assert!(!report.ok());
        assert_eq!(report.expected_mismatches, 1);
        assert!(report.rows[0].expected_mismatch);
    }

    #[test]
    fn baseline_diff_names_the_moved_verdict() {
        let baseline = evaluator(POLICIES);
        let proposed = evaluator(TIGHTER);
        let samples = vec![
            sample("search", r#"ToolInvocation::"demo/search_repos""#, None),
            sample("delete", r#"ToolInvocation::"demo/delete_repo""#, None),
        ];
        let report = replay(&proposed, Some(&baseline), &samples);
        assert_eq!(report.changed, 1);
        assert!(report.rows[0].changed);
        assert_eq!(report.rows[0].baseline.as_deref(), Some("allow"));
        assert_eq!(report.rows[0].verdict, "deny");
        assert!(!report.rows[1].changed);
    }

    #[test]
    fn jsonl_skips_comments_and_blank_lines() {
        let text = r#"
# search is allowed today
{"id":"search","principal":"Agent::\"anonymous\"","resource":"ToolInvocation::\"demo/search_repos\"","expected":"allow"}

{"id":"delete","principal":"Agent::\"anonymous\"","resource":"ToolInvocation::\"demo/delete_repo\""}
"#;
        let samples = parse_jsonl(text).expect("parse");
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].id.as_deref(), Some("search"));
    }

    #[test]
    fn jsonl_malformed_line_names_the_line_number() {
        let err = parse_jsonl("not json\n").expect_err("must fail");
        assert!(err.contains("line 1"), "{err}");
    }
}
