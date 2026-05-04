//! ML agent classifier output types (A5.2).
//!
//! These are the canonical type definitions for the Wave 5 ML agent
//! classifier verdict. They live in the OSS classifiers crate so the
//! OSS [`crate`]'s downstream consumers (`sbproxy-core::RequestContext`,
//! the CEL/Lua/JS scripting layers, the access log emitter, ...) can
//! hold the verdict without taking a dependency on the enterprise
//! classifier sidecar crate.
//!
//! The actual ONNX inference, feature builder, hot-swap registry, and
//! `BehavioralStore` plumbing live in the enterprise crate
//! `sbproxy-classifier::agent_classifier`. The OSS surface is purely
//! the value types: an enum for the four output classes plus a struct
//! that records confidence and provenance.
//!
//! # Closed-enum amendment
//!
//! [`MlClass`] is a closed enum per `docs/adr-schema-versioning.md`
//! Rule 4. Variants must not be reordered or removed. Adding a new
//! variant requires an ADR amendment and is a schema-breaking change.

use serde::{Deserialize, Serialize};

/// Predicted class for a request, output by the ML agent classifier
/// (A5.2). Stable across the Wave 5 series.
///
/// Variant ordering matches the trained ONNX model's softmax output
/// indices: `Human=0`, `LlmAgent=1`, `Scraper=2`, `Unknown=3`. Do not
/// reorder; the index is load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MlClass {
    /// Real human user driving a browser. The most consequential class
    /// to mis-predict on the false-positive side; the evaluation gate
    /// requires `human` precision >= 0.99.
    Human,
    /// LLM-driven agent making this request on behalf of a user prompt
    /// (e.g. Claude tool use, ChatGPT browsing).
    LlmAgent,
    /// Automated scraper / crawler harvesting content. Distinct from
    /// `LlmAgent` because the operator's intent is bulk extraction
    /// rather than real-time prompt fulfilment.
    Scraper,
    /// Classifier could not commit. Either softmax confidence is
    /// genuinely diffuse, or the ONNX runtime emitted an inference
    /// error and the timeout / panic recovery path filled in this
    /// sentinel.
    Unknown,
}

impl MlClass {
    /// Stable string label used in metrics, dashboards, and the audit
    /// log. Matches the `serde(rename_all = "kebab-case")` form so the
    /// JSON wire shape and the metric label string never drift apart.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::LlmAgent => "llm-agent",
            Self::Scraper => "scraper",
            Self::Unknown => "unknown",
        }
    }

    /// Decode a softmax argmax index. `0..=3` map to the four variants
    /// in declaration order; any other index returns [`MlClass::Unknown`]
    /// so the inference path cannot panic on a malformed model output.
    pub fn from_argmax_index(idx: usize) -> Self {
        match idx {
            0 => Self::Human,
            1 => Self::LlmAgent,
            2 => Self::Scraper,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for MlClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Output of one ML agent-classifier inference (A5.2).
///
/// The struct is shipped to scripting layers, the access log, and the
/// audit pipeline. The fields are deliberately small + Copy-friendly:
/// the `model_version` is a `&'static str` rather than `String` so the
/// struct fits cheaply on `RequestContext` without an extra allocation
/// per request.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MlClassification {
    /// The argmax class.
    pub class: MlClass,
    /// Maximum softmax probability across the four output indices, in
    /// `[0.0, 1.0]`. Used by the G1.4 override threshold (>= 0.9 for
    /// `Human`-only override per A5.2) and by response-phase CEL rules.
    pub confidence: f32,
    /// Identifier of the loaded model file (typically the SHA-256 hex
    /// prefix or a semver tag). `'static` because the registry holds
    /// the canonical string for the lifetime of the process and hands
    /// out a borrowed slice into it.
    pub model_version: &'static str,
    /// Feature schema version the model was trained against. Mismatch
    /// with the proxy's compiled-in `FEATURE_SCHEMA_VERSION` is a hard
    /// load error; the field is preserved on every verdict so
    /// downstream replay tools can confirm the version.
    pub feature_schema_version: u32,
}

impl MlClassification {
    /// Construct a "no verdict" stand-in returned by the inference
    /// timeout and panic-recovery paths. Confidence is `0.0` so any
    /// override threshold check is a no-op.
    pub fn unknown(model_version: &'static str, feature_schema_version: u32) -> Self {
        Self {
            class: MlClass::Unknown,
            confidence: 0.0,
            model_version,
            feature_schema_version,
        }
    }

    /// Confidence-gated test for the G1.4 ML-override condition per
    /// A5.2: only a `Human` verdict with confidence >= 0.9 should
    /// override the rule-based resolver.
    pub fn is_human_override(&self) -> bool {
        matches!(self.class, MlClass::Human) && self.confidence >= 0.9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_class_string_labels_match_spec() {
        assert_eq!(MlClass::Human.as_str(), "human");
        assert_eq!(MlClass::LlmAgent.as_str(), "llm-agent");
        assert_eq!(MlClass::Scraper.as_str(), "scraper");
        assert_eq!(MlClass::Unknown.as_str(), "unknown");
    }

    #[test]
    fn ml_class_argmax_decoding_is_total() {
        assert_eq!(MlClass::from_argmax_index(0), MlClass::Human);
        assert_eq!(MlClass::from_argmax_index(1), MlClass::LlmAgent);
        assert_eq!(MlClass::from_argmax_index(2), MlClass::Scraper);
        assert_eq!(MlClass::from_argmax_index(3), MlClass::Unknown);
        // Out-of-band index should not panic; falls back to Unknown.
        assert_eq!(MlClass::from_argmax_index(99), MlClass::Unknown);
    }

    #[test]
    fn human_override_requires_high_confidence() {
        let v = MlClassification {
            class: MlClass::Human,
            confidence: 0.95,
            model_version: "v1",
            feature_schema_version: 1,
        };
        assert!(v.is_human_override());

        let v_low = MlClassification {
            confidence: 0.85,
            ..v
        };
        assert!(!v_low.is_human_override());
    }

    #[test]
    fn non_human_class_never_overrides() {
        for class in [MlClass::Scraper, MlClass::LlmAgent, MlClass::Unknown] {
            let v = MlClassification {
                class,
                confidence: 0.99,
                model_version: "v1",
                feature_schema_version: 1,
            };
            assert!(
                !v.is_human_override(),
                "non-Human class {class:?} must not override"
            );
        }
    }

    #[test]
    fn ml_classification_serde_round_trip() {
        let v = MlClassification {
            class: MlClass::LlmAgent,
            confidence: 0.42,
            model_version: "v1.0.0",
            feature_schema_version: 1,
        };
        let json = serde_json::to_string(&v).unwrap();
        // kebab-case rename on MlClass.
        assert!(json.contains("\"llm-agent\""));
        // Round-trip is lossy on `model_version` because it is `&'static
        // str` on the struct; the test confirms the JSON shape rather
        // than full deserialisation.
        assert!(json.contains("\"confidence\":0.42"));
    }

    #[test]
    fn unknown_constructor_fills_zero_confidence() {
        let v = MlClassification::unknown("v1", 1);
        assert_eq!(v.class, MlClass::Unknown);
        assert_eq!(v.confidence, 0.0);
        assert_eq!(v.model_version, "v1");
        assert_eq!(v.feature_schema_version, 1);
        assert!(!v.is_human_override());
    }
}
