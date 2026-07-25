//! Embedding-backed text classifier guardrail.
//!
//! Labels a prompt with a predicted class instead of blocking it. The
//! mesh carries the [`GuardrailLabel`] into `ai.guardrails.labels`, so
//! the CEL policy plane can branch on it with `route_to:<model>`. That
//! makes this guardrail a routing signal rather than a security control.
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
//! deliberate because artifact availability only affects the optional
//! routing signal. Structural configuration errors fail while compiling
//! the AI action, and neighboring security guardrails remain active.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::warn;

use super::GuardrailLabel;
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
/// `Ok(None)` means no class cleared the configured thresholds, which
/// the guardrail reports as "no label" rather than as a failure.
/// `Err` is reserved for backend or inference failures so enforcing
/// callers can fail closed without confusing the failure with a normal
/// threshold abstention.
pub trait TextClassifier: Send + Sync + std::fmt::Debug {
    /// Classify `text` and return the winning class, if any.
    fn classify(&self, text: &str) -> Result<Option<ClassifierVerdict>>;
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassifierBackendConfig {
    /// Local sentence-embedding model with one centroid per class.
    Embedding(EmbeddingBackendConfig),
}

/// Config specific to the local sentence-embedding backend: an ONNX
/// model paired with a tokenizer, plus the cosine-similarity thresholds
/// that decide whether a class wins.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Hard character cap applied to request subjects and configured
    /// examples before tokenization. The embedder does not configure
    /// tokenizer truncation, so an uncapped string would build an
    /// oversized tensor.
    #[serde(default = "default_max_chars")]
    pub max_chars: usize,
}

impl ClassifierConfig {
    /// Borrow at most `max_chars` Unicode scalar values from `text`.
    ///
    /// Both request subjects and configured centroid examples use this
    /// method so neither path can hand an oversized string to a tokenizer.
    pub fn bounded_text<'a>(&self, text: &'a str) -> &'a str {
        text.char_indices()
            .nth(self.max_chars)
            .map_or(text, |(end, _)| &text[..end])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let ClassifierBackendConfig::Embedding(backend) = &self.backend;
        if backend.model_path.trim().is_empty() {
            return Err(anyhow!(
                "classifier guardrail backend `model_path` must not be blank"
            ));
        }
        if backend.tokenizer_path.trim().is_empty() {
            return Err(anyhow!(
                "classifier guardrail backend `tokenizer_path` must not be blank"
            ));
        }
        if !(0.0..=1.0).contains(&backend.min_score) {
            return Err(anyhow!(
                "classifier guardrail backend `min_score` must be finite and in [0, 1]"
            ));
        }
        if !(0.0..=2.0).contains(&backend.min_margin) {
            return Err(anyhow!(
                "classifier guardrail backend `min_margin` must be finite and in [0, 2]"
            ));
        }
        if self.classes.is_empty() {
            return Err(anyhow!(
                "classifier guardrail needs at least one entry under `classes`"
            ));
        }
        if self.max_chars == 0 {
            return Err(anyhow!(
                "classifier guardrail `max_chars` must be above zero"
            ));
        }
        for (label, examples) in &self.classes {
            if label.trim().is_empty() {
                return Err(anyhow!(
                    "classifier guardrail class label must not be blank"
                ));
            }
            if examples.is_empty() {
                return Err(anyhow!(
                    "classifier guardrail class `{label}` needs at least one example"
                ));
            }
            for (index, example) in examples.iter().enumerate() {
                if example.trim().is_empty() {
                    return Err(anyhow!(
                        "classifier guardrail class `{label}` example {index} must not be blank"
                    ));
                }
                if example.chars().count() > self.max_chars {
                    return Err(anyhow!(
                        "classifier guardrail class `{label}` example {index} exceeds \
                         `max_chars` ({})",
                        self.max_chars
                    ));
                }
            }
        }
        Ok(())
    }
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
        let cfg = parse_config(config)?;
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
        self.cfg.bounded_text(raw).to_owned()
    }

    /// Classify the prompt and report the winning class as the label.
    pub fn check_messages(&self, content: &str, messages: &[Message]) -> Option<GuardrailLabel> {
        match self.classify_messages(content, messages) {
            Ok(label) => label,
            Err(error) => {
                warn!(%error, "classifier inference failed; no routing label emitted");
                None
            }
        }
    }

    pub(crate) fn classify_messages(
        &self,
        content: &str,
        messages: &[Message],
    ) -> Result<Option<GuardrailLabel>> {
        let Some(backend) = self.backend.as_ref() else {
            return Ok(None);
        };
        let subject = self.subject(content, messages);
        if subject.trim().is_empty() {
            return Ok(None);
        }
        let Some(verdict) = backend.classify(&subject)? else {
            return Ok(None);
        };
        Ok(Some(GuardrailLabel {
            reason: format!("classifier: {} (score {:.3})", verdict.label, verdict.score),
            name: verdict.label,
        }))
    }

    pub(crate) fn scope(&self) -> ClassifierScope {
        self.cfg.scope
    }
}

/// Parse and validate a classifier entry without loading its model.
///
/// The AI handler calls this while compiling configuration, including
/// validation-only plans where no runtime classifier factory is installed.
/// Artifact availability remains a runtime concern and still degrades only
/// this routing labeler to inert.
pub(crate) fn parse_config(config: &serde_json::Value) -> Result<ClassifierConfig> {
    let mut fields = config
        .as_object()
        .ok_or_else(|| anyhow!("classifier guardrail config must be an object"))?
        .clone();
    match fields.remove("type") {
        Some(serde_json::Value::String(kind)) if kind == "classifier" => {}
        _ => {
            return Err(anyhow!(
                "classifier guardrail config must declare `type: classifier`"
            ));
        }
    }
    let cfg: ClassifierConfig = serde_json::from_value(serde_json::Value::Object(fields))?;
    cfg.validate()?;
    Ok(cfg)
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
        fn classify(&self, text: &str) -> Result<Option<ClassifierVerdict>> {
            Ok(text.contains(self.needle).then(|| ClassifierVerdict {
                label: self.label.to_string(),
                score: 0.91,
            }))
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

    fn raw_cfg(max_chars: usize, classes: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "type": "classifier",
            "backend": {
                "kind": "embedding",
                "model_path": "/models/model.onnx",
                "tokenizer_path": "/models/tokenizer.json",
                "min_score": 0.30,
                "min_margin": 0.05
            },
            "classes": classes,
            "scope": "last_user_message",
            "max_chars": max_chars
        })
    }

    #[test]
    fn parse_config_rejects_an_unknown_top_level_field() {
        let mut raw = raw_cfg(20, serde_json::json!({"documentation": ["write docs"]}));
        raw.as_object_mut()
            .expect("object")
            .insert("max_charz".to_string(), serde_json::json!(20));

        let error = parse_config(&raw)
            .expect_err("misspelled classifier fields must fail before publication")
            .to_string();
        assert!(error.contains("unknown field") && error.contains("max_charz"));
    }

    #[test]
    fn parse_config_rejects_an_unknown_backend_field() {
        let mut raw = raw_cfg(20, serde_json::json!({"documentation": ["write docs"]}));
        raw["backend"]["min_socre"] = serde_json::json!(0.30);

        let error = parse_config(&raw)
            .expect_err("misspelled backend fields must fail before publication")
            .to_string();
        assert!(error.contains("unknown field") && error.contains("min_socre"));
    }

    #[test]
    fn parse_config_rejects_blank_artifact_paths() {
        for field in ["model_path", "tokenizer_path"] {
            let mut raw = raw_cfg(20, serde_json::json!({"documentation": ["write docs"]}));
            raw["backend"][field] = serde_json::json!(" \t ");

            let error = parse_config(&raw)
                .expect_err("blank artifact paths must fail before publication")
                .to_string();
            assert!(error.contains(field), "unexpected error: {error}");
        }
    }

    #[test]
    fn parse_config_rejects_blank_class_labels() {
        let raw = raw_cfg(20, serde_json::json!({"  ": ["write docs"]}));

        let error = parse_config(&raw)
            .expect_err("blank labels must fail before publication")
            .to_string();
        assert!(error.contains("label") && error.contains("blank"));
    }

    #[test]
    fn parse_config_rejects_empty_or_blank_examples() {
        let unusable = [
            serde_json::json!({"documentation": []}),
            serde_json::json!({"documentation": [" \n "]}),
        ];
        for classes in unusable {
            let error = parse_config(&raw_cfg(20, classes))
                .expect_err("every class needs a usable example")
                .to_string();
            assert!(error.contains("example"), "unexpected error: {error}");
        }
    }

    #[test]
    fn parse_config_rejects_out_of_range_thresholds() {
        let cases = [
            ("min_score", -0.01),
            ("min_score", 1.01),
            ("min_margin", -0.01),
            ("min_margin", 2.01),
        ];
        for (field, value) in cases {
            let mut raw = raw_cfg(20, serde_json::json!({"documentation": ["write docs"]}));
            raw["backend"][field] = serde_json::json!(value);

            let error = parse_config(&raw)
                .expect_err("impossible thresholds must fail before publication")
                .to_string();
            assert!(error.contains(field), "unexpected error: {error}");
        }
    }

    #[test]
    fn config_validation_rejects_non_finite_thresholds() {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            for field in ["min_score", "min_margin"] {
                let mut config = cfg(ClassifierScope::LastUserMessage);
                let ClassifierBackendConfig::Embedding(backend) = &mut config.backend;
                match field {
                    "min_score" => backend.min_score = value,
                    "min_margin" => backend.min_margin = value,
                    _ => unreachable!(),
                }

                let error = config
                    .validate()
                    .expect_err("non-finite thresholds must be structurally invalid")
                    .to_string();
                assert!(error.contains(field), "unexpected error: {error}");
            }
        }
    }

    #[test]
    fn parse_config_accepts_an_example_at_the_exact_character_cap() {
        let parsed = parse_config(&raw_cfg(4, serde_json::json!({"documentation": ["éabc"]})))
            .expect("four Unicode characters should fit a four-character cap");
        assert_eq!(parsed.classes["documentation"][0].chars().count(), 4);
    }

    #[test]
    fn parse_config_rejects_an_example_over_the_character_cap() {
        let error = parse_config(&raw_cfg(4, serde_json::json!({"documentation": ["éabcd"]})))
            .expect_err("five Unicode characters must not pass a four-character cap")
            .to_string();
        assert!(error.contains("max_chars") && error.contains("documentation"));
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
