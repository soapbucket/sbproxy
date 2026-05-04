//! Detector trait for the `prompt_injection_v2` policy.
//!
//! A detector inspects a prompt string and returns a numeric score plus
//! a categorical label. The trait is intentionally synchronous and
//! object-safe: detection runs on the request hot path and the policy
//! holds an `Arc<dyn Detector>`. Future detectors (e.g. an ONNX
//! classifier) can implement this trait and register themselves via
//! the inventory registry without touching the policy core.

use std::fmt;

/// Categorical label assigned by a detector.
///
/// The label and the score together describe how confident the
/// detector is that the prompt is an injection attempt. Policies map
/// these onto an action (`tag`, `block`, `log`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionLabel {
    /// No injection signals detected.
    Clean,
    /// One or more weak signals were detected. The caller may want to
    /// tag the request but typically should not block on this label
    /// alone.
    Suspicious,
    /// High-confidence injection match. Operators that opt into the
    /// `block` action will reject the request.
    Injection,
}

impl DetectionLabel {
    /// String form used in HTTP headers and structured logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Injection => "injection",
        }
    }
}

impl fmt::Display for DetectionLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result returned by a detector for a single prompt.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Confidence score in `[0.0, 1.0]`. A score at or above the
    /// policy's threshold triggers the configured action.
    pub score: f64,
    /// Categorical label.
    pub label: DetectionLabel,
    /// Optional human-readable reason. Heuristic detectors typically
    /// fill this with the matched pattern; classifier detectors may
    /// leave it `None`.
    pub reason: Option<String>,
}

impl DetectionResult {
    /// Convenience constructor for a `Clean` result with score 0.0.
    pub fn clean() -> Self {
        Self {
            score: 0.0,
            label: DetectionLabel::Clean,
            reason: None,
        }
    }
}

/// Trait implemented by every prompt-injection detector.
///
/// Implementations must be cheap to call (the policy invokes
/// `detect` on every matching request) and thread-safe. Async work
/// or remote calls belong in a wrapper that pre-loads state at
/// startup, not in `detect` itself.
pub trait Detector: Send + Sync + 'static {
    /// Inspect `prompt` and return a detection result.
    fn detect(&self, prompt: &str) -> DetectionResult;

    /// Stable detector name used in config (`detector: <name>`) and
    /// emitted in logs / metrics. Must be unique across registered
    /// detectors; the registry rejects duplicate names at startup.
    fn name(&self) -> &str;
}

/// Inventory entry registered by every detector implementation.
///
/// The factory function returns a fresh `Arc<dyn Detector>` on each
/// call so the policy can hold an owned handle. Detectors register at
/// link time via the `register_prompt_injection_detector!` macro
/// (exported at the crate root).
pub struct DetectorFactory {
    /// Stable name matching `Detector::name`. Configs reference this
    /// string via `detector: <name>`.
    pub name: &'static str,
    /// Constructor returning a ready-to-use detector instance.
    pub factory: fn() -> std::sync::Arc<dyn Detector>,
}

inventory::collect!(DetectorFactory);

/// Register a detector implementation at module scope.
///
/// `$name` is the stable string used in configs (must match the
/// `Detector::name` return value); `$factory` is a function item with
/// signature `fn() -> Arc<dyn Detector>`.
#[macro_export]
macro_rules! register_prompt_injection_detector {
    ($name:expr, $factory:expr) => {
        inventory::submit! {
            $crate::policy::prompt_injection_v2::DetectorFactory {
                name: $name,
                factory: || {
                    let f: fn() -> std::sync::Arc<dyn $crate::policy::prompt_injection_v2::Detector> = $factory;
                    f()
                },
            }
        }
    };
}

/// Resolve a detector by name from the inventory registry.
///
/// Returns `None` when no registered factory matches. The OSS build
/// always registers `heuristic-v1`; enterprise (or follow-up OSS PRs)
/// register additional names.
pub fn lookup_detector(name: &str) -> Option<std::sync::Arc<dyn Detector>> {
    for entry in inventory::iter::<DetectorFactory> {
        if entry.name == name {
            return Some((entry.factory)());
        }
    }
    None
}

/// List the names of every registered detector. Used by config
/// validation to produce a helpful error message when an unknown
/// detector is named.
pub fn registered_detector_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = inventory::iter::<DetectorFactory>
        .into_iter()
        .map(|f| f.name)
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_strings_round_trip() {
        assert_eq!(DetectionLabel::Clean.as_str(), "clean");
        assert_eq!(DetectionLabel::Suspicious.as_str(), "suspicious");
        assert_eq!(DetectionLabel::Injection.as_str(), "injection");
    }

    #[test]
    fn clean_result_has_zero_score() {
        let r = DetectionResult::clean();
        assert_eq!(r.score, 0.0);
        assert_eq!(r.label, DetectionLabel::Clean);
        assert!(r.reason.is_none());
    }
}
