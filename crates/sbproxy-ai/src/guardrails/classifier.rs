//! Text classifier guardrail.
//!
//! Labels a prompt with a predicted class instead of blocking it. The
//! mesh reads labels from [`GuardrailBlock::name`], so the class name
//! lands directly in `ai.guardrails.labels` and the CEL policy plane can
//! branch on it with `route_to:<model>`. That makes this guardrail a
//! routing signal rather than a security control.
//!
//! Two backends exist, and they sit on two different seams because they
//! have two different costs:
//!
//! - [`TextClassifier`] is synchronous, for a backend that computes an
//!   answer locally. The embedding backend (a local ONNX model with
//!   per-class centroids) implements it. It lives in `sbproxy-core`
//!   rather than here because the ONNX crate (`sbproxy-classifiers`)
//!   depends on this crate, so naming its types here would be a
//!   dependency cycle; `sbproxy-core` registers a factory at startup via
//!   [`register_classifier_factory`], mirroring how the semantic cache's
//!   in-process embedder is wired.
//! - [`AsyncTextClassifier`] is asynchronous, for a backend that has to
//!   talk to something over the network. The LLM backend
//!   ([`super::llm_classifier::LlmClassifier`]) implements it. It has no
//!   ONNX dependency, so it lives next to this trait.
//!
//! The two seams are deliberately separate rather than one async trait.
//! The synchronous guardrail cascade
//! ([`super::mesh::GuardrailMesh::evaluate_input`]) runs on a proxy
//! worker thread; making the local, microsecond-scale embedding path
//! await would buy nothing and cost every caller a boxed future. The
//! async backends instead run in a second pass from
//! [`super::mesh::GuardrailMesh::evaluate_input_async`], which the AI
//! dispatch path (already async) calls.
//!
//! A backend that fails to load leaves the guardrail inert: it returns
//! no label and the request keeps its original routing. This is
//! deliberate. `compile_pipeline` aborts the whole pipeline on any
//! guardrail error, so returning an error for a missing model file would
//! silently disable the PII and injection guards configured alongside
//! this one. Config that cannot be right on any host (a malformed URL, a
//! missing API key) is still a hard error, because there is no artifact
//! that might legitimately be absent.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::warn;

use super::llm_classifier::{LlmBackendConfig, LlmClassifier};
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

/// Inference backend that maps prompt text to a class over I/O.
///
/// Same contract as [`TextClassifier`] (`None` means no class won, which
/// is an outcome and not a failure), but awaitable, so a backend that
/// has to make a network call can do so without blocking a proxy worker
/// thread. Implementations must not block either: a network call belongs
/// behind a timeout, and a failed call reports `None`.
#[async_trait]
pub trait AsyncTextClassifier: Send + Sync + std::fmt::Debug {
    /// Classify `text` and return the winning class, if any.
    async fn classify(&self, text: &str) -> Option<ClassifierVerdict>;
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
/// The tagged shape lets a `classifier` entry name its backend
/// explicitly (`kind: embedding` or `kind: llm`) instead of the config
/// format assuming one of them.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClassifierBackendConfig {
    /// Local sentence-embedding model with one centroid per class.
    Embedding(EmbeddingBackendConfig),
    /// An OpenAI-compatible `/chat/completions` endpoint asked to name
    /// the class. Covers hosted providers and local runtimes alike.
    Llm(LlmBackendConfig),
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

/// The resolved backend behind one classifier guardrail.
///
/// Which variant is in play decides which entry point produces the
/// label: [`ClassifierGuardrail::check_messages`] serves the sync
/// backend and [`ClassifierGuardrail::check_messages_async`] serves the
/// async one. Each returns `None` for the other's variant, so a
/// guardrail evaluated on both paths emits its label exactly once.
#[derive(Debug, Clone)]
enum ClassifierBackend {
    /// No backend loaded. The guardrail returns no label rather than
    /// erroring, so a bad model path cannot disable the guardrails
    /// configured next to it.
    Inert,
    /// A local, synchronous backend (the embedding one).
    Sync(Arc<dyn TextClassifier>),
    /// A backend that has to be awaited (the LLM one).
    Async(Arc<dyn AsyncTextClassifier>),
}

/// Guardrail that labels a prompt with a classifier's predicted class.
#[derive(Debug)]
pub struct ClassifierGuardrail {
    cfg: ClassifierConfig,
    backend: ClassifierBackend,
}

impl ClassifierGuardrail {
    /// Build from an already-resolved synchronous backend. `None`
    /// yields an inert guardrail. Used by tests and by
    /// [`ClassifierGuardrail::from_config`].
    pub fn with_backend(cfg: ClassifierConfig, backend: Option<Arc<dyn TextClassifier>>) -> Self {
        let backend = match backend {
            Some(b) => ClassifierBackend::Sync(b),
            None => ClassifierBackend::Inert,
        };
        Self { cfg, backend }
    }

    /// Build from an already-resolved asynchronous backend. Used by
    /// tests and by [`ClassifierGuardrail::from_config`].
    pub fn with_async_backend(
        cfg: ClassifierConfig,
        backend: Arc<dyn AsyncTextClassifier>,
    ) -> Self {
        Self {
            cfg,
            backend: ClassifierBackend::Async(backend),
        }
    }

    /// Whether this guardrail has to be awaited to produce a label.
    ///
    /// The mesh uses this to decide which pass evaluates it. A `false`
    /// here means the synchronous cascade already covered it.
    pub fn is_async(&self) -> bool {
        matches!(self.backend, ClassifierBackend::Async(_))
    }

    /// Build from a raw config value.
    ///
    /// A malformed config is an error. An embedding backend that will
    /// not load is warned about and degrades to an inert guardrail,
    /// because the model file may legitimately be absent on one host
    /// and failing here would abort the whole pipeline. An LLM backend
    /// has no such artifact: everything that can go wrong at
    /// construction is config the operator has to fix, so it fails loud.
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
        let backend = match &cfg.backend {
            ClassifierBackendConfig::Embedding(embedding) => match build_classifier(&cfg) {
                Ok(b) => ClassifierBackend::Sync(b),
                Err(e) => {
                    warn!(
                        error = %e,
                        model_path = %embedding.model_path,
                        "classifier guardrail backend unavailable; guardrail is inert \
                         and prompts keep their original routing"
                    );
                    ClassifierBackend::Inert
                }
            },
            ClassifierBackendConfig::Llm(llm) => {
                ClassifierBackend::Async(Arc::new(LlmClassifier::from_config(llm, &cfg.classes)?))
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
    ///
    /// An async backend returns `None` here: the synchronous cascade
    /// cannot await, so [`Self::check_messages_async`] covers it in the
    /// mesh's second pass instead.
    pub fn check_messages(&self, content: &str, messages: &[Message]) -> Option<GuardrailBlock> {
        let ClassifierBackend::Sync(backend) = &self.backend else {
            return None;
        };
        let subject = self.subject(content, messages);
        if subject.trim().is_empty() {
            return None;
        }
        Some(Self::to_block(backend.classify(&subject)?))
    }

    /// Classify the prompt over an async backend.
    ///
    /// A sync or inert backend returns `None` here, so a guardrail
    /// evaluated on both mesh passes contributes its label exactly once.
    pub async fn check_messages_async(
        &self,
        content: &str,
        messages: &[Message],
    ) -> Option<GuardrailBlock> {
        let ClassifierBackend::Async(backend) = &self.backend else {
            return None;
        };
        let subject = self.subject(content, messages);
        if subject.trim().is_empty() {
            return None;
        }
        Some(Self::to_block(backend.classify(&subject).await?))
    }

    /// Wrap a verdict as the guardrail block whose `name` the mesh
    /// publishes as the label.
    fn to_block(verdict: ClassifierVerdict) -> GuardrailBlock {
        GuardrailBlock {
            reason: format!("classifier: {} (score {:.3})", verdict.label, verdict.score),
            name: verdict.label,
        }
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

    /// The async counterpart of [`Fake`], with no I/O at all: the point
    /// is the seam, not the network.
    #[derive(Debug)]
    struct FakeAsync {
        needle: &'static str,
        label: &'static str,
    }

    #[async_trait]
    impl AsyncTextClassifier for FakeAsync {
        async fn classify(&self, text: &str) -> Option<ClassifierVerdict> {
            text.contains(self.needle).then(|| ClassifierVerdict {
                label: self.label.to_string(),
                score: 1.0,
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

    fn async_guardrail(scope: ClassifierScope) -> ClassifierGuardrail {
        ClassifierGuardrail::with_async_backend(
            cfg(scope),
            Arc::new(FakeAsync {
                needle: "readme",
                label: "documentation",
            }),
        )
    }

    #[tokio::test]
    async fn async_backend_emits_its_label_on_the_async_path() {
        let g = async_guardrail(ClassifierScope::FullText);
        assert!(g.is_async());
        let block = g
            .check_messages_async("write the readme section", &[])
            .await
            .expect("should classify");
        assert_eq!(block.name, "documentation");
    }

    #[test]
    fn async_backend_is_inert_on_the_sync_path() {
        // The sync cascade cannot await, so it must contribute nothing
        // here rather than double-counting or blocking.
        let g = async_guardrail(ClassifierScope::FullText);
        assert!(g.check_messages("write the readme section", &[]).is_none());
    }

    #[tokio::test]
    async fn sync_backend_is_inert_on_the_async_path() {
        // The mirror of the rule above: the sync cascade already
        // collected this one, so the async pass must not repeat it.
        let g = ClassifierGuardrail::with_backend(
            cfg(ClassifierScope::FullText),
            Some(Arc::new(Fake {
                needle: "readme",
                label: "documentation",
            })),
        );
        assert!(!g.is_async());
        assert!(g
            .check_messages_async("write the readme section", &[])
            .await
            .is_none());
    }

    #[tokio::test]
    async fn async_backend_honors_scope_and_max_chars() {
        // Same subject-selection rules as the sync path: "readme" sits
        // only in the earlier turn, so last_user_message scope hides it.
        let g = async_guardrail(ClassifierScope::LastUserMessage);
        let messages = vec![
            msg("user", "update the readme"),
            msg("assistant", "done"),
            msg("user", "now refactor the parser"),
        ];
        let joined = "update the readme done now refactor the parser";
        assert!(g.check_messages_async(joined, &messages).await.is_none());
    }

    #[tokio::test]
    async fn async_backend_with_an_empty_subject_is_not_classified() {
        let g = ClassifierGuardrail::with_async_backend(
            cfg(ClassifierScope::FullText),
            Arc::new(FakeAsync {
                needle: "",
                label: "documentation",
            }),
        );
        assert!(g.check_messages_async("   ", &[]).await.is_none());
    }

    #[test]
    fn llm_backend_config_parses_from_the_tagged_enum() {
        let entry = serde_json::json!({
            "backend": {
                "kind": "llm",
                "base_url": "http://localhost:11434/v1/chat/completions",
                "model": "qwen3-coder:30b",
            },
            "classes": {"coding": ["refactor the parser"]},
        });
        let parsed: ClassifierConfig = serde_json::from_value(entry).expect("parses");
        match parsed.backend {
            ClassifierBackendConfig::Llm(llm) => {
                assert_eq!(llm.model, "qwen3-coder:30b");
                assert_eq!(llm.timeout_ms, 2_000);
                assert_eq!(llm.cache_capacity, 1_024);
                assert!(llm.fail_open);
            }
            other => panic!("expected the llm variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn llm_backend_with_an_unresolved_api_key_fails_to_compile() {
        // A hard config error, not a silent unauthenticated call.
        let entry = serde_json::json!({
            "type": "classifier",
            "backend": {
                "kind": "llm",
                "base_url": "http://localhost:11434/v1/chat/completions",
                "model": "qwen3-coder:30b",
                "api_key": "${SBPROXY_TEST_CLASSIFIER_ABSENT_KEY}",
            },
            "classes": {"coding": ["refactor the parser"]},
        });
        assert!(ClassifierGuardrail::from_config(&entry).is_err());
    }
}
