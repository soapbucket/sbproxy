//! Behavioral dimension: does the tool still return the same shape?
//!
//! The deterministic behavioral signal for a versioning oracle is the tool's
//! response shape across versions. We reduce each captured response to a
//! value-tolerant skeleton (keys and types, values excluded) and compare: a
//! value-only difference is not drift, a shape change is a Major behavioral
//! break.

use super::{Dimension, Finding, SemverGrade};
use serde_json::Value;

/// Grade the behavioral difference between two versions of the same tool from
/// one captured response each. A changed response shape is Major; a value-only
/// difference produces no finding.
pub fn behavioral_findings(old_response: &Value, new_response: &Value) -> Vec<Finding> {
    if skeleton(old_response) == skeleton(new_response) {
        return Vec::new();
    }
    vec![Finding {
        dimension: Dimension::Behavioral,
        grade: SemverGrade::Major,
        pointer: "response".to_string(),
        reason: "response shape changed under the same call".to_string(),
        security: false,
        confidence: None,
    }]
}

/// A value-tolerant structure skeleton: object keys (sorted) and value types,
/// with concrete values excluded so a healthy server does not drift just
/// because its data changed.
fn skeleton(value: &Value) -> String {
    let mut out = String::new();
    write_skeleton(value, &mut out);
    out
}

fn write_skeleton(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push('n'),
        Value::Bool(_) => out.push('b'),
        Value::Number(_) => out.push('#'),
        Value::String(_) => out.push('s'),
        Value::Array(items) => {
            out.push('[');
            if let Some(first) = items.first() {
                write_skeleton(first, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                out.push_str(key);
                out.push(':');
                write_skeleton(&map[key], out);
                out.push(',');
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn value_only_change_is_not_behavioral_drift() {
        let old = json!({"content": [{"type": "text", "text": "sunny"}]});
        let new = json!({"content": [{"type": "text", "text": "cloudy"}]});
        assert!(behavioral_findings(&old, &new).is_empty());
    }

    #[test]
    fn response_shape_change_is_major() {
        let old = json!({"content": [{"type": "text", "text": "x"}]});
        let new =
            json!({"content": [{"type": "text", "text": "x"}], "structuredContent": {"temp": 1}});
        let findings = behavioral_findings(&old, &new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].grade, SemverGrade::Major);
    }
}
