//! Embedding-backed text classifier guardrail.
//!
//! Labels a prompt with a predicted class instead of blocking it. The
//! mesh reads labels from [`GuardrailBlock::name`], so the class name
//! lands directly in `ai.guardrails.labels` and the CEL policy plane can
//! branch on it with `route_to:<model>`. That makes this guardrail a
//! routing signal rather than a security control.
//!
//! The inference backend lives behind the [`TextClassifier`] trait
//! because the ONNX crate (`sbproxy-classifiers`) depends on this crate,
//! so the concrete implementation cannot live here without a dependency
//! cycle. `sbproxy-core` registers one at startup via
//! [`register_classifier_factory`], mirroring how the semantic cache's
//! in-process embedder is wired.
//!
//! A backend that fails to load leaves the guardrail inert: it returns
//! no label and the request keeps its original routing. This is
//! deliberate. `compile_pipeline` aborts the whole pipeline on any
//! guardrail error, so returning an error for a missing model file would
//! silently disable the PII and injection guards configured alongside
//! this one.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::warn;

use super::GuardrailBlock;
use crate::types::Message;

/// The winning class for one prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifierVerdict {
    /// Class label, used verbatim as the guardrail label.
    pub label: String,
    /// Confidence in `[0.0, 1.0]`.
    pub score: f32,
}

/// Inference backend that maps prompt text to a class.
///
/// `None` means no class cleared the configured thresholds, which the
/// guardrail reports as "no label" rather than as a failure.
pub trait TextClassifier: Send + Sync + std::fmt::Debug {
    /// Classify `text` and return the winning class, if any.
    fn classify(&self, text: &str) -> Option<ClassifierVerdict>;
}

/// Which slice of the prompt the classifier sees.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierScope {
    /// Only the last `user` message. The default, because embedding
    /// models truncate at a few hundred tokens and the operative
    /// request is almost always the final turn.
    #[default]
    LastUserMessage,
    /// The full concatenated prompt text.
    FullText,
}

fn default_min_score() -> f32 {
    0.30
}

fn default_min_margin() -> f32 {
    0.05
}

fn default_max_chars() -> usize {
    2000
}

/// Which inference backend decides the class.
///
/// A second backend (an OpenAI-compatible LLM endpoint) is coming; this
/// tagged shape lets a `classifier` entry name its backend explicitly
/// instead of the config format assuming the embedding one.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClassifierBackendConfig {
    /// Local sentence-embedding model with one centroid per class.
    Embedding(EmbeddingBackendConfig),
}

/// Config specific to the local sentence-embedding backend: an ONNX
/// model paired with a tokenizer, plus the cosine-similarity thresholds
/// that decide whether a class wins.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingBackendConfig {
    /// Filesystem path to the ONNX embedding model.
    pub model_path: String,
    /// Filesystem path to the matching Hugging Face `tokenizer.json`.
    pub tokenizer_path: String,
    /// Minimum cosine similarity the winning class must reach.
    #[serde(default = "default_min_score")]
    pub min_score: f32,
    /// Minimum gap between the best and second-best class. Guards
    /// against labeling a prompt that sits between two centroids.
    #[serde(default = "default_min_margin")]
    pub min_margin: f32,
    /// Optional override for the ONNX file size budget, in bytes.
    #[serde(default)]
    pub max_model_bytes: Option<u64>,
}

/// Declarative config for a `type: classifier` guardrail entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ClassifierConfig {
    /// Which inference backend decides the class.
    pub backend: ClassifierBackendConfig,
    /// Class label to example prompts, shared across whichever backend
    /// is configured. For the embedding backend, three to ten short,
    /// representative examples per class is the useful range.
    #[serde(default)]
    pub classes: BTreeMap<String, Vec<String>>,
    /// Which slice of the prompt to classify.
    #[serde(default)]
    pub scope: ClassifierScope,
    /// Hard character cap applied before tokenization. The embedder
    /// does not configure tokenizer truncation, so an uncapped prompt
    /// would build an oversized tensor.
    #[serde(default = "default_max_chars")]
    pub max_chars: usize,
}

/// Builds a backend for one [`ClassifierConfig`].
pub type ClassifierFactory =
    Box<dyn Fn(&ClassifierConfig) -> Result<Arc<dyn TextClassifier>> + Send + Sync>;

static FACTORY: OnceLock<ClassifierFactory> = OnceLock::new();

/// Register the process-wide classifier backend.
///
/// Called once at startup by `sbproxy-core`. A second call is ignored
/// and logged, so a reload cannot swap the backend out from under a
/// pipeline that is already holding one.
pub fn register_classifier_factory(factory: ClassifierFactory) {
    if FACTORY.set(factory).is_err() {
        warn!("classifier factory already registered; keeping the first one");
    }
}

/// Build a backend for `cfg` using the registered factory.
pub fn build_classifier(cfg: &ClassifierConfig) -> Result<Arc<dyn TextClassifier>> {
    let factory = FACTORY.get().ok_or_else(|| {
        anyhow!(
            "no classifier backend registered; this binary was built without \
             the `inprocess-classify` feature"
        )
    })?;
    factory(cfg)
}

/// Guardrail that labels a prompt with a classifier's predicted class.
#[derive(Debug)]
pub struct ClassifierGuardrail {
    cfg: ClassifierConfig,
    /// `None` when the backend failed to load. The guardrail then
    /// returns no label rather than erroring, so a bad model path
    /// cannot disable the guardrails configured next to it.
    backend: Option<Arc<dyn TextClassifier>>,
}

impl ClassifierGuardrail {
    /// Build from an already-resolved backend. Used by tests and by
    /// [`ClassifierGuardrail::from_config`].
    pub fn with_backend(cfg: ClassifierConfig, backend: Option<Arc<dyn TextClassifier>>) -> Self {
        Self { cfg, backend }
    }

    /// Build from a raw config value using the registered factory.
    ///
    /// A malformed config is an error. A backend that will not load is
    /// warned about and degrades to an inert guardrail.
    pub fn from_config(config: &serde_json::Value) -> Result<Self> {
        let cfg: ClassifierConfig = serde_json::from_value(config.clone())?;
        if cfg.classes.is_empty() {
            return Err(anyhow!(
                "classifier guardrail needs at least one entry under `classes`"
            ));
        }
        if cfg.max_chars == 0 {
            return Err(anyhow!(
                "classifier guardrail `max_chars` must be above zero"
            ));
        }
        let backend = match build_classifier(&cfg) {
            Ok(b) => Some(b),
            Err(e) => {
                // Only one backend variant exists today, so this
                // destructure is irrefutable.
                let ClassifierBackendConfig::Embedding(embedding) = &cfg.backend;
                warn!(
                    error = %e,
                    model_path = %embedding.model_path,
                    "classifier guardrail backend unavailable; guardrail is inert \
                     and prompts keep their original routing"
                );
                None
            }
        };
        Ok(Self { cfg, backend })
    }

    /// The text this guardrail classifies, honoring `scope` and
    /// `max_chars`. Falls back to `content` when the scoped lookup
    /// finds nothing usable, for example a multimodal content array
    /// that is not a plain string.
    fn subject(&self, content: &str, messages: &[Message]) -> String {
        let raw = match self.cfg.scope {
            ClassifierScope::FullText => content,
            ClassifierScope::LastUserMessage => messages
                .iter()
                .rev()
                .find(|m| m.role == "user")
                .and_then(|m| m.content.as_str())
                .unwrap_or(content),
        };
        raw.chars().take(self.cfg.max_chars).collect()
    }

    /// Classify the prompt and report the winning class as the label.
    pub fn check_messages(&self, content: &str, messages: &[Message]) -> Option<GuardrailBlock> {
        let backend = self.backend.as_ref()?;
        let subject = self.subject(content, messages);
        if subject.trim().is_empty() {
            return None;
        }
        let verdict = backend.classify(&subject)?;
        Some(GuardrailBlock {
            reason: format!("classifier: {} (score {:.3})", verdict.label, verdict.score),
            name: verdict.label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Message;
    use std::sync::Arc;

    fn msg(role: &str, content: &str) -> Message {
        Message {
            role: role.to_string(),
            content: serde_json::Value::String(content.to_string()),
        }
    }

    /// Backend that returns `label` whenever the text it sees contains
    /// `needle`, so tests can assert exactly which slice of the prompt
    /// reached the classifier.
    #[derive(Debug)]
    struct Fake {
        needle: &'static str,
        label: &'static str,
    }

    impl TextClassifier for Fake {
        fn classify(&self, text: &str) -> Option<ClassifierVerdict> {
            text.contains(self.needle).then(|| ClassifierVerdict {
                label: self.label.to_string(),
                score: 0.91,
            })
        }
    }

    fn cfg(scope: ClassifierScope) -> ClassifierConfig {
        ClassifierConfig {
            backend: ClassifierBackendConfig::Embedding(EmbeddingBackendConfig {
                model_path: "/unused/model.onnx".to_string(),
                tokenizer_path: "/unused/tokenizer.json".to_string(),
                min_score: 0.30,
                min_margin: 0.05,
                max_model_bytes: None,
            }),
            classes: std::collections::BTreeMap::new(),
            scope,
            max_chars: 2000,
        }
    }

    #[test]
    fn emits_predicted_class_as_the_label() {
        let g = ClassifierGuardrail::with_backend(
            cfg(ClassifierScope::LastUserMessage),
            Some(Arc::new(Fake {
                needle: "readme",
                label: "documentation",
            })),
        );
        let messages = vec![msg("user", "write the readme section")];
        let block = g.check_messages("write the readme section", &messages);
        assert_eq!(block.expect("should classify").name, "documentation");
    }

    #[test]
    fn last_user_message_scope_ignores_earlier_turns() {
        let g = ClassifierGuardrail::with_backend(
            cfg(ClassifierScope::LastUserMessage),
            Some(Arc::new(Fake {
                needle: "readme",
                label: "documentation",
            })),
        );
        // "readme" appears only in the FIRST user turn. Under
        // last_user_message scope the classifier must not see it.
        let messages = vec![
            msg("user", "update the readme"),
            msg("assistant", "done"),
            msg("user", "now refactor the parser"),
        ];
        let joined = "update the readme done now refactor the parser";
        assert!(g.check_messages(joined, &messages).is_none());
    }

    #[test]
    fn full_text_scope_sees_the_whole_prompt() {
        let g = ClassifierGuardrail::with_backend(
            cfg(ClassifierScope::FullText),
            Some(Arc::new(Fake {
                needle: "readme",
                label: "documentation",
            })),
        );
        let messages = vec![
            msg("user", "update the readme"),
            msg("user", "now refactor the parser"),
        ];
        let joined = "update the readme now refactor the parser";
        assert_eq!(
            g.check_messages(joined, &messages)
                .expect("should classify")
                .name,
            "documentation"
        );
    }

    #[test]
    fn truncates_to_max_chars_before_calling_the_backend() {
        let mut c = cfg(ClassifierScope::FullText);
        c.max_chars = 10;
        let g = ClassifierGuardrail::with_backend(
            c,
            Some(Arc::new(Fake {
                needle: "readme",
                label: "documentation",
            })),
        );
        // "readme" sits past the 10-char cap, so it must be cut off.
        let long = format!("{}readme", "x".repeat(50));
        assert!(g.check_messages(&long, &[]).is_none());
    }

    #[test]
    fn inert_backend_never_labels() {
        let g = ClassifierGuardrail::with_backend(cfg(ClassifierScope::FullText), None);
        assert!(g.check_messages("write the readme", &[]).is_none());
    }

    #[test]
    fn empty_subject_is_not_classified() {
        let g = ClassifierGuardrail::with_backend(
            cfg(ClassifierScope::FullText),
            Some(Arc::new(Fake {
                needle: "",
                label: "documentation",
            })),
        );
        assert!(g.check_messages("   ", &[]).is_none());
    }
}
