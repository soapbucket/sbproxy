//! Config shapes shared by the heuristic classifier and the normalizer.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `config.rs`, cut
//! down to the subset the heuristic-classification path uses: label
//! patterns, classification thresholds, and normalization rules. The
//! enterprise crate's full `config.rs` (949 lines) also covers ONNX model
//! loading, judge backends, and API-key auth, none of which this port needs
//! (see `docs/classifier-sidecar.md` for the scope this crate covers).

use serde::Deserialize;

/// One label a heuristic classifier can emit, with the regex patterns that
/// score it and a weight applied to the raw pattern-match score.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelConfig {
    /// Label name returned in a classification response.
    pub name: String,
    /// Case-sensitive regex patterns; each match adds to this label's score.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Multiplier applied to the raw pattern-match score before normalizing
    /// across labels.
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_weight() -> f64 {
    1.0
}

/// Tuning for the heuristic classifier's confidence fallback.
#[derive(Debug, Clone)]
pub struct ClassificationConfig {
    /// Below this score, no label matched with confidence; `default_label`
    /// is boosted instead of returning a near-zero-confidence guess.
    pub confidence_threshold: f64,
    /// Label boosted when nothing clears `confidence_threshold`.
    pub default_label: String,
    /// Score assigned to `default_label` on the fallback path, before
    /// re-normalizing across all labels.
    pub default_boost: f64,
}

impl Default for ClassificationConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: 0.15,
            default_label: "conversation".to_string(),
            default_boost: 0.5,
        }
    }
}

/// One text-normalization rule: a regex and its replacement, applied in
/// registration order.
#[derive(Debug, Clone, Deserialize)]
pub struct NormalizationRule {
    /// Rule name, for warn logs when the pattern fails to compile.
    pub name: String,
    /// Regex pattern.
    pub pattern: String,
    /// Replacement text; `$1`-style capture references are supported.
    pub replace: String,
    /// Disabled rules are parsed but never compiled or applied.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Normalization pipeline configuration for one tenant.
#[derive(Debug, Clone)]
pub struct NormalizationConfig {
    /// Apply Unicode NFKC before the rule list (collapses compatibility
    /// forms, e.g. full-width Latin to ASCII).
    pub unicode_nfkc: bool,
    /// Trim leading/trailing whitespace after the rule list runs.
    pub trim: bool,
    /// Regex substitution rules, applied in order.
    pub rules: Vec<NormalizationRule>,
}

impl Default for NormalizationConfig {
    fn default() -> Self {
        Self {
            unicode_nfkc: true,
            trim: true,
            rules: Vec::new(),
        }
    }
}
