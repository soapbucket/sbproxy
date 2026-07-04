//! The compatibility oracle: compose the dimensions into one verdict.

use super::behavioral::behavioral_findings;
use super::semantics::{semantics_findings, Judge, SemanticsConfig};
use super::structural::structural_findings;
use super::{contract_digest, max_grade, CompatibilityVerdict, SemverGrade};
use serde_json::Value;

/// Inputs to the oracle. The response samples are optional: without them the
/// behavioral dimension is skipped and the verdict is structural only.
pub struct OracleInputs<'a> {
    /// Tool name.
    pub tool: &'a str,
    /// The old tool definition.
    pub old_tool: &'a Value,
    /// The new tool definition.
    pub new_tool: &'a Value,
    /// A captured response for the old version, when available.
    pub old_response: Option<&'a Value>,
    /// A captured response for the new version, when available.
    pub new_response: Option<&'a Value>,
}

/// Compose the structural and behavioral dimensions into one verdict. A
/// contract digest that moved with no graded finding is still at least a Patch.
pub fn evaluate_compatibility(inputs: &OracleInputs) -> CompatibilityVerdict {
    let from_digest = contract_digest(inputs.old_tool);
    let to_digest = contract_digest(inputs.new_tool);

    let mut findings = structural_findings(inputs.old_tool, inputs.new_tool);
    let behavioral_evaluated = match (inputs.old_response, inputs.new_response) {
        (Some(old), Some(new)) => {
            findings.extend(behavioral_findings(old, new));
            true
        }
        _ => false,
    };

    let mut grade = max_grade(&findings);
    if grade == SemverGrade::None && from_digest != to_digest {
        grade = SemverGrade::Patch;
    }

    CompatibilityVerdict {
        tool: inputs.tool.to_string(),
        from_digest,
        to_digest,
        grade,
        findings,
        behavioral_evaluated,
        needs_confirmation: false,
    }
}

/// Compose all dimensions, including the injected-judge description-semantics
/// dimension. The structural and behavioral dimensions run first (cheap and
/// deterministic); the judge runs only when the textual surface changed.
pub async fn evaluate_compatibility_full(
    inputs: &OracleInputs<'_>,
    cfg: &SemanticsConfig,
    judges: &[&dyn Judge],
) -> anyhow::Result<CompatibilityVerdict> {
    let mut verdict = evaluate_compatibility(inputs);
    let outcome = semantics_findings(inputs.old_tool, inputs.new_tool, cfg, judges).await?;
    verdict.findings.extend(outcome.findings);
    verdict.needs_confirmation = outcome.needs_confirmation;
    verdict.grade = max_grade(&verdict.findings).max(verdict.grade);
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inputs<'a>(old: &'a Value, new: &'a Value) -> OracleInputs<'a> {
        OracleInputs {
            tool: "t",
            old_tool: old,
            new_tool: new,
            old_response: None,
            new_response: None,
        }
    }

    #[test]
    fn identical_tool_is_no_change() {
        let t = json!({"name": "t", "description": "d"});
        let v = evaluate_compatibility(&inputs(&t, &t));
        assert_eq!(v.grade, SemverGrade::None);
        assert_eq!(v.from_digest, v.to_digest);
        assert!(!v.behavioral_evaluated);
    }

    #[test]
    fn breaking_input_change_is_major() {
        let old = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        let new = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "number"}}}});
        let v = evaluate_compatibility(&inputs(&old, &new));
        assert_eq!(v.grade, SemverGrade::Major);
        assert_ne!(v.from_digest, v.to_digest);
    }
}
