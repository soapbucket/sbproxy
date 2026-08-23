//! Detector trait for the `prompt_injection_v2` policy.
//!
//! A detector inspects a prompt string and returns a numeric score plus
//! a categorical label. The trait is intentionally synchronous and
//! object-safe: detection runs on the request hot path and the policy
//! holds an `Arc<dyn Detector>`. Future detectors (e.g. an ONNX
//! classifier) can implement this trait and register themselves via
//! the inventory registry without touching the policy core.

use std::fmt;

use sha2::{Digest, Sha256};

/// Closed reason vocabulary for a detector that could not classify a prompt.
///
/// These values cross metrics, events, and the authenticated admin surface, so
/// they deliberately carry no model path, endpoint, prompt, or underlying
/// error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionFailureKind {
    /// Every running slot and bounded queue slot was occupied.
    QueueFull,
    /// Admission plus inference exceeded the configured deadline.
    Deadline,
    /// The bounded blocking worker panicked or was cancelled.
    Worker,
    /// Detection was called from a runtime that cannot safely block in place.
    Runtime,
    /// Tokenization, ONNX execution, or output validation failed.
    Inference,
    /// The primary sidecar transport, RPC, deadline, or protocol failed.
    Sidecar,
}

impl DetectionFailureKind {
    /// Stable low-cardinality label used on operational surfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::Deadline => "deadline",
            Self::Worker => "worker",
            Self::Runtime => "runtime",
            Self::Inference => "inference",
            Self::Sidecar => "sidecar",
        }
    }
}

impl fmt::Display for DetectionFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which classifier stage produced a closed failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionFailureOrigin {
    /// A directly configured detector failed.
    Detector,
    /// The configured sidecar failed before the local fallback ran.
    PrimarySidecar,
    /// The mandatory verified local fallback also failed.
    LocalFallback,
}

impl DetectionFailureOrigin {
    /// Stable low-cardinality label used on operational surfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detector => "detector",
            Self::PrimarySidecar => "primary_sidecar",
            Self::LocalFallback => "local_fallback",
        }
    }
}

/// One closed, attributable detector failure stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct DetectionFailureStage {
    /// Component that failed.
    pub origin: DetectionFailureOrigin,
    /// Closed reason for the failure.
    pub kind: DetectionFailureKind,
}

/// Typed classification failure preserved through a composite detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct DetectionFailure {
    terminal: DetectionFailureStage,
    primary: Option<DetectionFailureStage>,
}

impl DetectionFailure {
    /// Construct a failure from a directly configured detector.
    pub const fn direct(kind: DetectionFailureKind) -> Self {
        Self {
            terminal: DetectionFailureStage {
                origin: DetectionFailureOrigin::Detector,
                kind,
            },
            primary: None,
        }
    }

    /// Preserve a primary sidecar failure beside this terminal local-fallback
    /// failure. Composite adapters use this only after the primary sidecar
    /// has failed; both stages remain in the closed public vocabulary.
    pub const fn after_sidecar(mut self) -> Self {
        self.terminal.origin = DetectionFailureOrigin::LocalFallback;
        self.primary = Some(DetectionFailureStage {
            origin: DetectionFailureOrigin::PrimarySidecar,
            kind: DetectionFailureKind::Sidecar,
        });
        self
    }

    /// Terminal failure stage.
    pub const fn terminal(self) -> DetectionFailureStage {
        self.terminal
    }

    /// Earlier primary stage, present only when a sidecar and its mandatory
    /// local fallback both failed.
    pub const fn primary(self) -> Option<DetectionFailureStage> {
        self.primary
    }
}

impl fmt::Display for DetectionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(primary) = self.primary {
            write!(
                f,
                "classifier unavailable ({}:{}, {}:{})",
                primary.origin.as_str(),
                primary.kind,
                self.terminal.origin.as_str(),
                self.terminal.kind
            )
        } else {
            write!(
                f,
                "classifier unavailable ({}:{})",
                self.terminal.origin.as_str(),
                self.terminal.kind
            )
        }
    }
}

impl std::error::Error for DetectionFailure {}

/// Opaque identity for deterministic classifier semantics in the global
/// body-aware cache.
///
/// The digest must commit to every input that can change the raw score or
/// label. It is never serialized or displayed. A detector that cannot supply
/// a complete stable identity must return `None` from
/// [`Detector::cache_namespace`], which bypasses the cache.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DetectorCacheNamespace([u8; 32]);

impl DetectorCacheNamespace {
    /// Derive an opaque namespace from ordered, length-delimited semantic
    /// inputs. Callers should include a detector kind and explicit semantic
    /// version before model pins and classifier settings.
    pub fn derive(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"sbproxy.prompt-injection-v2.cache-namespace.v1");
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DetectorCacheNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DetectorCacheNamespace([opaque])")
    }
}

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

    /// Inspect `prompt` while preserving an unavailable classifier as a typed
    /// failure. Existing deterministic in-process extensions remain source
    /// compatible through this default implementation.
    fn try_detect(&self, prompt: &str) -> Result<DetectionResult, DetectionFailure> {
        Ok(self.detect(prompt))
    }

    /// Stable identity for deterministic cacheable classification semantics.
    ///
    /// The safe default is no cache. Remote detectors, composites with a
    /// remote primary, and extensions without a complete versioned identity
    /// must keep this default.
    fn cache_namespace(&self) -> Option<DetectorCacheNamespace> {
        None
    }

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
