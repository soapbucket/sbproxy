// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The model catalog (WOR-1662).
//!
//! A catalog maps a short, stable `catalog_id` (for example
//! `qwen3-32b`) to the data the resolver needs: the Hugging Face
//! repo, the official quant variants, the parameter shape, license,
//! model family, and a coarse VRAM hint. It is the data half of
//! catalog resolution; the fit planner ([`crate::fit`]) does the
//! precise VRAM math, and the engine supervisor does the spawning.
//!
//! The built-in catalog is a committed YAML document embedded at
//! build time so a default deployment resolves the certified models
//! with no external fetch. An operator can also point at their own
//! catalog file, and can always bypass the catalog with an explicit
//! `hf:Org/Repo:QUANT` reference.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The committed default catalog, seeded with the certified-first
/// models from the design doc. Parsed once via [`Catalog::builtin`].
pub const BUILTIN_CATALOG_YAML: &str = include_str!("../data/models.yaml");

const MAX_CATALOG_ID_BYTES: usize = 128;
const MAX_CATALOG_REVISION_BYTES: usize = 128;
const MAX_CATALOG_MODELS: usize = 1_024;
const MAX_CATALOG_VARIANTS_PER_MODEL: usize = 128;
const MAX_CATALOG_ENGINES_PER_VARIANT: usize = 16;

/// A quant family a catalog entry can be served in. Kept as a plain
/// string so the catalog can name engine-specific quants
/// (`Q4_K_M`, `FP8`, `AWQ`, `GPTQ`, `bf16`) without this crate
/// enumerating every one; [`crate::fit::Quant`] classifies them for
/// the capability gate.
pub type QuantName = String;

/// The task a served model performs (WOR-1908).
///
/// A catalog is chat-only today, but the model host must be able to
/// express an embedder, a reranker, and the other non-chat surfaces so
/// the fit planner, engine launch, and capability negotiation branch on
/// the actual task rather than assuming autoregressive chat. Only
/// [`Modality::Chat`] decodes token by token and holds a KV cache; every
/// other modality is a single forward pass. Defaults to `Chat`, so a
/// pre-modality catalog entry parses and behaves exactly as before.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Autoregressive chat / text generation (the default). Decodes one
    /// token at a time and accumulates a KV cache.
    #[default]
    Chat,
    /// Text embeddings: one forward pass to a vector, no KV cache.
    Embedding,
    /// Reranking / scoring: one forward pass to a relevance score.
    Rerank,
    /// Speech to text (transcription).
    SpeechToText,
    /// Text to speech (synthesis).
    TextToSpeech,
    /// Image generation.
    Image,
}

impl Modality {
    /// Whether this modality serves by autoregressive decode and thus
    /// accumulates a KV cache. Only [`Modality::Chat`] does; an embedder
    /// or reranker runs a single forward pass and holds no KV cache, so
    /// the fit planner must not charge it KV-cache VRAM (WOR-1908).
    pub fn uses_kv_cache(self) -> bool {
        matches!(self, Modality::Chat)
    }

    /// The bytes-per-KV-element the fit planner should charge for this
    /// modality, given the caller's KV-quant default. A non-decode
    /// modality has no KV cache, so it charges `Some(0.0)` (a zero KV
    /// term) regardless of any KV-quant lever; a chat model keeps the
    /// caller's `default`. This is how "the planner does not apply
    /// KV-cache math to a non-decode model" is realized without a second
    /// estimator.
    pub fn kv_bytes_per_element_override(self, default: Option<f64>) -> Option<f64> {
        if self.uses_kv_cache() {
            default
        } else {
            Some(0.0)
        }
    }

    /// The vLLM `--task` value for this modality, or `None` when vLLM
    /// serves it in the default (chat/generate) mode. vLLM will not serve
    /// an embedder or reranker unless launched with the matching task, so
    /// this is a runtime-owned launch argument, never an operator knob.
    pub fn vllm_task_arg(self) -> Option<&'static str> {
        match self {
            Modality::Chat => None,
            Modality::Embedding => Some("embed"),
            Modality::Rerank => Some("score"),
            // Speech and image serving are follow-on work (WOR-1675 and
            // beyond); no vLLM task mapping is claimed here yet.
            Modality::SpeechToText | Modality::TextToSpeech | Modality::Image => None,
        }
    }

    /// A stable lowercase label for status JSON, `models list`, and doctor.
    pub fn label(self) -> &'static str {
        match self {
            Modality::Chat => "chat",
            Modality::Embedding => "embedding",
            Modality::Rerank => "rerank",
            Modality::SpeechToText => "speech_to_text",
            Modality::TextToSpeech => "text_to_speech",
            Modality::Image => "image",
        }
    }

    /// True for the default (`Chat`) modality. Used by
    /// `skip_serializing_if` so an unset modality stays absent from the
    /// serialized catalog, keeping existing YAML and schema output stable.
    pub fn is_default(&self) -> bool {
        matches!(self, Modality::Chat)
    }
}

/// One catalog entry: everything the resolver knows about a model id
/// before any GPU is consulted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogEntry {
    /// Hugging Face repo, e.g. `Qwen/Qwen3-32B`.
    #[serde(default)]
    pub hf_repo: String,
    /// Quant variants published for this model, most-preferred first.
    /// The fit planner picks the best one the GPU can actually run.
    #[serde(default)]
    pub quants: Vec<QuantName>,
    /// Human-readable parameter shape, e.g. `32B` or `30B-A3B` (MoE).
    pub params: String,
    /// SPDX-ish license id, e.g. `apache-2.0`.
    pub license: String,
    /// Model family, e.g. `qwen`, `llama`, `glm`.
    pub family: String,
    /// Coarse minimum-VRAM hint in GiB for the smallest listed quant.
    /// A pre-flight sanity bound only; the fit planner computes the
    /// real requirement from model metadata.
    #[serde(default)]
    pub min_vram_hint_gib: f64,

    // --- Catalog v2 logical-model fields (WOR-1837). ---
    /// Maximum context length declared for this logical model.
    #[serde(default)]
    pub context_length: u64,
    /// Immutable artifact variants in deterministic preference order.
    #[serde(default)]
    pub variants: Vec<crate::artifact_spec::ArtifactVariant>,
    /// Permit pickle checkpoints for this logical model. False by
    /// default because pickle can execute code while loading.
    #[serde(default)]
    pub allow_pickle: bool,
    /// The task this model serves (WOR-1908). Defaults to
    /// [`Modality::Chat`], so existing chat entries are unchanged; an
    /// embedder or reranker declares it here so the fit planner, engine
    /// launch, and capability negotiation branch on the real task.
    #[serde(default, skip_serializing_if = "Modality::is_default")]
    pub modality: Modality,

    // --- Manifest fields (WOR-1681). All optional so the built-in
    // certified catalog and any pre-manifest file still parse. When
    // set on an operator manifest they carry everything needed to
    // fetch and verify the weights. ---
    /// Weight source scheme, e.g. `hf:Qwen/Qwen3-32B`, `file:/models/x`,
    /// or `ms:...` (ModelScope, reserved). `None` derives `hf:{hf_repo}`.
    #[serde(default)]
    pub source: Option<String>,
    /// Repo revision to pin (a branch, tag, or commit). `None` is
    /// `main`. `weights` verifies it; this lets config express it.
    #[serde(default)]
    pub revision: Option<String>,
    /// Per-file sha256 digests (filename -> lowercase hex). A curated
    /// manifest with digests doubles as a supply-chain allowlist.
    #[serde(default)]
    pub sha256: BTreeMap<String, String>,
    /// Hugging Face token for a gated repo, as an unresolved
    /// `SecretResolver` reference (`${ENV}`, `secret:`, `vault://`,
    /// ...). Resolved at the wiring layer, not here.
    #[serde(default)]
    pub hf_token: Option<String>,
    /// Default engine for this model (overridable per serve entry).
    #[serde(default)]
    pub engine: crate::config::EngineChoice,
    /// When to fetch the weights. Defaults to on-demand (first request).
    #[serde(default)]
    pub pull: PullPolicy,
}

/// When the weight manager fetches a model's weights (WOR-1681).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PullPolicy {
    /// Fetch at server boot (warm before the first request).
    OnBoot,
    /// Fetch on the first request that needs the model (default).
    #[default]
    OnDemand,
    /// Never fetch automatically; the operator warms the cache with
    /// `sbproxy models pull`.
    Manual,
}

/// The resolved target of a model reference: a concrete repo + a
/// chosen quant, ready for the fit planner and weight manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRef {
    /// Hugging Face repo the weights come from.
    pub hf_repo: String,
    /// The quant to fetch/serve. Empty means "the repo's default".
    pub quant: QuantName,
    /// The catalog id this resolved from, or `None` for a raw
    /// `hf:` reference that bypassed the catalog.
    pub catalog_id: Option<String>,
}

/// The certified-model registry.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Catalog {
    /// Catalog document schema. Missing means legacy v1.
    #[serde(default = "default_catalog_schema_version")]
    pub schema_version: u32,
    /// Versioned catalog identity pinned into resolved artifacts.
    #[serde(default)]
    pub catalog_revision: String,
    /// catalog_id -> entry. A `BTreeMap` so serialization is
    /// deterministic (stable diffs, reproducible schema).
    #[serde(default)]
    pub models: BTreeMap<String, CatalogEntry>,
}

fn default_catalog_schema_version() -> u32 {
    1
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            schema_version: default_catalog_schema_version(),
            catalog_revision: String::new(),
            models: BTreeMap::new(),
        }
    }
}

/// Catalog parse or semantic-validation failure.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// YAML could not be deserialized.
    #[error("parse catalog YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    /// The catalog parsed but violates its schema contract.
    #[error("invalid catalog: {0}")]
    Invalid(String),
}

/// Nonfatal migration information produced while loading a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogDiagnostic {
    /// A legacy entry remains usable through `Catalog::resolve` but
    /// lacks the exact files required for managed artifact resolution.
    PreviewIncomplete {
        /// Logical model ID.
        model: String,
        /// Exact missing contract.
        reason: String,
    },
}

impl std::fmt::Display for CatalogDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreviewIncomplete { model, reason } => write!(
                formatter,
                "model '{model}' remains preview-only until migrated to catalog v2: {reason}"
            ),
        }
    }
}

/// Catalog plus nonfatal v1 migration diagnostics.
#[derive(Debug, Clone)]
pub struct CatalogLoad {
    /// Normalized catalog.
    pub catalog: Catalog,
    /// Ordered migration diagnostics.
    pub diagnostics: Vec<CatalogDiagnostic>,
}

/// Why catalog v2 could not select one executable artifact.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArtifactResolveError {
    /// Logical model is absent.
    #[error("model '{0}' is not in the catalog")]
    UnknownModel(String),
    /// Homogeneous replicas require an immutable variant pin.
    #[error("deployment of model '{model}' has {replicas} replicas; pin a variant or enable heterogeneous_variants")]
    VariantPinRequired {
        /// Logical model ID.
        model: String,
        /// Requested replicas.
        replicas: u32,
    },
    /// Explicit variant does not exist.
    #[error("model '{model}' has no variant '{variant}' (available: {available})")]
    UnknownVariant {
        /// Logical model ID.
        model: String,
        /// Requested variant ID.
        variant: String,
        /// Declared variant IDs.
        available: String,
    },
    /// Legacy entry cannot produce an exact verified artifact.
    #[error("model '{model}' has no complete catalog v2 artifact variant: {reason}")]
    IncompleteCatalogV2 {
        /// Logical model ID.
        model: String,
        /// Missing metadata.
        reason: String,
    },
    /// No declared variant can execute on this worker.
    #[error("model '{model}' has no compatible artifact variant: {reasons}")]
    NoCompatibleVariant {
        /// Logical model ID.
        model: String,
        /// Per-variant rejection summary.
        reasons: String,
    },
    /// Canonical digest generation failed.
    #[error("resolve model '{model}': {reason}")]
    Digest {
        /// Logical model ID.
        model: String,
        /// Serialization failure.
        reason: String,
    },
}

/// Why a model reference could not be resolved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    /// The catalog id is not in the catalog.
    #[error("model '{0}' is not in the catalog; use an explicit hf:Org/Repo:QUANT reference or add it to the catalog")]
    UnknownModel(String),
    /// An `hf:` reference was malformed.
    #[error("malformed hf reference '{0}'; expected hf:Org/Repo or hf:Org/Repo:QUANT")]
    MalformedHfRef(String),
    /// The requested quant is not one the catalog lists for the model.
    #[error("model '{model}' has no quant '{quant}' (available: {available})")]
    UnknownQuant {
        /// The catalog id.
        model: String,
        /// The requested quant.
        quant: String,
        /// Comma-joined list of the quants the entry lists.
        available: String,
    },
}

impl Catalog {
    /// Parse the committed built-in catalog.
    ///
    /// # Panics
    /// Only if the embedded YAML is malformed, which a unit test
    /// guards against, so a release build never hits it.
    pub fn builtin() -> Self {
        Self::from_yaml(BUILTIN_CATALOG_YAML)
            .expect("built-in model catalog YAML parses (guarded by a unit test)")
    }

    /// Parse a catalog from YAML (an operator-supplied file).
    pub fn from_yaml(yaml: &str) -> Result<Self, CatalogError> {
        Ok(Self::from_yaml_with_diagnostics(yaml)?.catalog)
    }

    /// Parse and normalize a catalog while retaining actionable legacy
    /// migration diagnostics.
    pub fn from_yaml_with_diagnostics(yaml: &str) -> Result<CatalogLoad, CatalogError> {
        let mut catalog: Self = serde_yaml::from_str(yaml)?;
        let diagnostics = catalog.normalize_and_validate()?;
        Ok(CatalogLoad {
            catalog,
            diagnostics,
        })
    }

    /// Number of models in the catalog.
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// True when the catalog has no entries.
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// Look up a catalog entry by id.
    pub fn get(&self, catalog_id: &str) -> Option<&CatalogEntry> {
        self.models.get(catalog_id)
    }

    /// Resolve one immutable artifact variant that can execute on the
    /// supplied worker. Variant order is deterministic, with
    /// safetensors preferred over pickle regardless of declaration
    /// order. Replicated homogeneous deployments must pin a variant.
    pub fn resolve_artifact(
        &self,
        request: &crate::artifact_spec::ResolveArtifactRequest,
        worker: &crate::artifact_spec::WorkerProfile,
    ) -> Result<crate::artifact_spec::ResolvedArtifact, ArtifactResolveError> {
        use crate::artifact_spec::{
            compatible_engine, worker_meets_requirements, ArtifactFormat, ResolvedArtifact,
        };

        let entry = self
            .models
            .get(&request.model)
            .ok_or_else(|| ArtifactResolveError::UnknownModel(request.model.clone()))?;
        if request.replicas > 1 && request.variant.is_none() && !request.heterogeneous_variants {
            return Err(ArtifactResolveError::VariantPinRequired {
                model: request.model.clone(),
                replicas: request.replicas,
            });
        }
        if entry.variants.is_empty() {
            return Err(ArtifactResolveError::IncompleteCatalogV2 {
                model: request.model.clone(),
                reason:
                    "exact files, sizes, digests, source revision, and requirements are missing"
                        .to_string(),
            });
        }

        let mut candidates: Vec<(usize, &crate::artifact_spec::ArtifactVariant)> =
            match &request.variant {
                Some(wanted) => {
                    let variant = entry
                        .variants
                        .iter()
                        .find(|variant| variant.id == *wanted)
                        .ok_or_else(|| ArtifactResolveError::UnknownVariant {
                            model: request.model.clone(),
                            variant: wanted.clone(),
                            available: entry
                                .variants
                                .iter()
                                .map(|variant| variant.id.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        })?;
                    vec![(0, variant)]
                }
                None => entry.variants.iter().enumerate().collect(),
            };
        if request.variant.is_none() {
            candidates.sort_by_key(|(index, variant)| {
                (matches!(variant.format, ArtifactFormat::Pickle), *index)
            });
        }

        let mut reasons = Vec::new();
        for (_, variant) in candidates {
            if variant.format == ArtifactFormat::Pickle && !entry.allow_pickle {
                reasons.push(format!(
                    "{}: pickle requires allow_pickle: true",
                    variant.id
                ));
                continue;
            }
            if let Err(reason) = worker_meets_requirements(variant, worker) {
                reasons.push(format!("{}: {reason}", variant.id));
                continue;
            }
            let Some(engine) = compatible_engine(variant, request.engine, worker) else {
                reasons.push(format!(
                    "{}: no compatible selected engine on worker",
                    variant.id
                ));
                continue;
            };
            return ResolvedArtifact::from_variant(
                &self.catalog_revision,
                &request.model,
                variant,
                engine,
                entry.context_length,
                &entry.license,
                entry.allow_pickle,
                entry.modality,
            )
            .map_err(|reason| ArtifactResolveError::Digest {
                model: request.model.clone(),
                reason,
            });
        }

        Err(ArtifactResolveError::NoCompatibleVariant {
            model: request.model.clone(),
            reasons: reasons.join("; "),
        })
    }

    /// Resolve a model reference to a concrete repo + quant.
    ///
    /// Accepts two forms:
    /// - a catalog id (`qwen3-32b`), optionally with an explicit
    ///   quant suffix (`qwen3-32b:FP8`), validated against the entry;
    /// - a raw `hf:Org/Repo` or `hf:Org/Repo:QUANT`, which bypasses
    ///   the catalog entirely.
    ///
    /// With no explicit quant, a catalog id resolves to the entry's
    /// most-preferred (first) quant, and a raw `hf:` ref resolves to
    /// the repo default (empty quant); the fit planner then does the
    /// capability-aware selection over the entry's full quant list.
    pub fn resolve(&self, reference: &str) -> Result<ModelRef, ResolveError> {
        if let Some(rest) = reference.strip_prefix("hf:") {
            return resolve_hf_ref(rest);
        }

        // A catalog id, optionally `id:QUANT`.
        let (id, explicit_quant) = split_quant(reference);
        let entry = self
            .models
            .get(id)
            .ok_or_else(|| ResolveError::UnknownModel(id.to_string()))?;

        let quant = match explicit_quant {
            Some(q) => {
                if !entry.quants.iter().any(|listed| listed == q) {
                    return Err(ResolveError::UnknownQuant {
                        model: id.to_string(),
                        quant: q.to_string(),
                        available: entry.quants.join(", "),
                    });
                }
                q.to_string()
            }
            None => entry.quants.first().cloned().unwrap_or_default(),
        };

        Ok(ModelRef {
            hf_repo: entry.hf_repo.clone(),
            quant,
            catalog_id: Some(id.to_string()),
        })
    }

    fn normalize_and_validate(&mut self) -> Result<Vec<CatalogDiagnostic>, CatalogError> {
        if !matches!(self.schema_version, 1 | 2) {
            return Err(CatalogError::Invalid(format!(
                "unsupported schema_version {}; expected 1 or 2",
                self.schema_version
            )));
        }
        if self.schema_version == 2 && self.catalog_revision.trim().is_empty() {
            return Err(CatalogError::Invalid(
                "catalog v2 requires a non-empty catalog_revision".to_string(),
            ));
        }
        if self.schema_version == 1 && self.catalog_revision.is_empty() {
            self.catalog_revision = "legacy-v1".to_string();
        }
        if self.catalog_revision.len() > MAX_CATALOG_REVISION_BYTES {
            return Err(CatalogError::Invalid(format!(
                "catalog_revision exceeds {MAX_CATALOG_REVISION_BYTES} bytes"
            )));
        }
        if self.models.len() > MAX_CATALOG_MODELS {
            return Err(CatalogError::Invalid(format!(
                "catalog contains more than {MAX_CATALOG_MODELS} models"
            )));
        }

        let mut diagnostics = Vec::new();
        for (model, entry) in &mut self.models {
            if model.len() > MAX_CATALOG_ID_BYTES {
                return Err(CatalogError::Invalid(format!(
                    "model ID exceeds {MAX_CATALOG_ID_BYTES} bytes"
                )));
            }
            if !crate::artifact_spec::valid_identifier(model) {
                return Err(CatalogError::Invalid(format!(
                    "model '{model}' has an invalid logical ID"
                )));
            }
            if entry.params.trim().is_empty()
                || entry.license.trim().is_empty()
                || entry.family.trim().is_empty()
            {
                return Err(CatalogError::Invalid(format!(
                    "model '{model}' requires params, license, and family"
                )));
            }

            if entry.variants.is_empty() {
                if entry.hf_repo.trim().is_empty() || entry.quants.is_empty() {
                    return Err(CatalogError::Invalid(format!(
                        "model '{model}' has neither catalog v2 variants nor a complete v1 hf_repo/quants entry"
                    )));
                }
                diagnostics.push(CatalogDiagnostic::PreviewIncomplete {
                    model: model.clone(),
                    reason: "exact variant files and byte sizes are absent".to_string(),
                });
                continue;
            }
            if entry.context_length == 0 {
                return Err(CatalogError::Invalid(format!(
                    "model '{model}' with catalog v2 variants requires context_length"
                )));
            }
            if entry.variants.len() > MAX_CATALOG_VARIANTS_PER_MODEL {
                return Err(CatalogError::Invalid(format!(
                    "model '{model}' contains more than {MAX_CATALOG_VARIANTS_PER_MODEL} variants"
                )));
            }

            let mut variant_ids = BTreeSet::new();
            for variant in &entry.variants {
                if variant.id.len() > MAX_CATALOG_ID_BYTES {
                    return Err(CatalogError::Invalid(format!(
                        "model '{model}' variant ID exceeds {MAX_CATALOG_ID_BYTES} bytes"
                    )));
                }
                if variant.engines.len() > MAX_CATALOG_ENGINES_PER_VARIANT {
                    return Err(CatalogError::Invalid(format!(
                        "model '{model}' variant '{}' contains more than {MAX_CATALOG_ENGINES_PER_VARIANT} engines",
                        variant.id
                    )));
                }
                if !variant_ids.insert(variant.id.as_str()) {
                    return Err(CatalogError::Invalid(format!(
                        "model '{model}' has duplicate variant '{}'",
                        variant.id
                    )));
                }
                crate::artifact_spec::validate_variant(model, variant)
                    .map_err(CatalogError::Invalid)?;
            }
            fill_legacy_projection(model, entry);
        }
        Ok(diagnostics)
    }
}

/// Keep the legacy resolver and pull planner usable for complete v2
/// entries while callers migrate to [`Catalog::resolve_artifact`]. The
/// values are projections of the first declared exact variant, never a
/// second source of catalog truth.
fn fill_legacy_projection(model: &str, entry: &mut CatalogEntry) {
    let Some(variant) = entry.variants.first() else {
        return;
    };

    if entry.hf_repo.is_empty() {
        entry.hf_repo = variant
            .source
            .strip_prefix("hf:")
            .map(str::to_string)
            .unwrap_or_else(|| format!("local/{model}"));
    }
    if entry.quants.is_empty() {
        for variant in &entry.variants {
            if !entry.quants.contains(&variant.quant) {
                entry.quants.push(variant.quant.clone());
            }
        }
    }
    if entry.min_vram_hint_gib <= 0.0 {
        const BYTES_PER_GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        entry.min_vram_hint_gib = variant.requirements.min_memory_bytes as f64 / BYTES_PER_GIB;
    }
    if entry.source.is_none() {
        entry.source = Some(variant.source.clone());
    }
    if entry.revision.is_none() {
        entry.revision = Some(variant.revision.clone());
    }
    if entry.sha256.is_empty() {
        entry.sha256.extend(
            variant
                .files
                .iter()
                .map(|file| (file.path.clone(), file.sha256.clone())),
        );
    }
    if entry.engine == crate::config::EngineChoice::Auto {
        entry.engine = match variant.engines.first() {
            Some(crate::config::EngineKind::Vllm) => crate::config::EngineChoice::Vllm,
            Some(crate::config::EngineKind::SGLang) => crate::config::EngineChoice::SGLang,
            Some(crate::config::EngineKind::LlamaCpp) => crate::config::EngineChoice::LlamaCpp,
            Some(crate::config::EngineKind::Embedded) => crate::config::EngineChoice::Embedded,
            None => crate::config::EngineChoice::Auto,
        };
    }
}

/// Parse the `Org/Repo` or `Org/Repo:QUANT` tail of an `hf:` ref.
fn resolve_hf_ref(rest: &str) -> Result<ModelRef, ResolveError> {
    let (repo, quant) = split_quant(rest);
    // A repo must be `Org/Repo`: exactly one slash, both sides
    // non-empty. This is a shape check, not an existence check.
    let mut parts = repo.split('/');
    let org = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if org.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err(ResolveError::MalformedHfRef(format!("hf:{rest}")));
    }
    Ok(ModelRef {
        hf_repo: repo.to_string(),
        quant: quant.map(str::to_string).unwrap_or_default(),
        catalog_id: None,
    })
}

/// Split a `base:QUANT` string on the LAST colon into `(base, quant)`.
/// Splitting on the last colon leaves any colons inside the base
/// (there are none in a catalog id or `Org/Repo`, but this is the
/// safe rule) intact.
fn split_quant(s: &str) -> (&str, Option<&str>) {
    match s.rsplit_once(':') {
        Some((base, quant)) if !quant.is_empty() => (base, Some(quant)),
        _ => (s, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_parses_and_is_nonempty() {
        let cat = Catalog::builtin();
        assert!(!cat.is_empty(), "built-in catalog must seed models");
        // Every entry must carry the fields the resolver + planner need.
        for (id, e) in &cat.models {
            assert!(!e.hf_repo.is_empty(), "{id} missing hf_repo");
            assert!(e.hf_repo.contains('/'), "{id} hf_repo not Org/Repo");
            assert!(!e.quants.is_empty(), "{id} must list at least one quant");
            assert!(!e.license.is_empty(), "{id} missing license");
            assert!(e.min_vram_hint_gib > 0.0, "{id} needs a vram hint");
        }
    }

    fn sample() -> Catalog {
        Catalog::from_yaml(
            "\
models:
  qwen3-32b:
    hf_repo: Qwen/Qwen3-32B
    quants: [FP8, Q4_K_M]
    params: 32B
    license: apache-2.0
    family: qwen
    min_vram_hint_gib: 20.0
",
        )
        .expect("parse")
    }

    #[test]
    fn modality_defaults_to_chat_and_is_absent_from_serialized_entries() {
        // WOR-1908: an entry with no modality parses as Chat and round-trips
        // without emitting a modality key, so existing catalogs are byte-stable.
        let cat = sample();
        let entry = cat.get("qwen3-32b").expect("entry");
        assert_eq!(entry.modality, Modality::Chat);
        let yaml = serde_yaml::to_string(entry).expect("serialize");
        assert!(
            !yaml.contains("modality"),
            "a default (chat) modality must not appear in serialized output: {yaml}"
        );
    }

    #[test]
    fn modality_kv_and_task_semantics() {
        // Only chat decodes and holds a KV cache.
        assert!(Modality::Chat.uses_kv_cache());
        assert!(!Modality::Embedding.uses_kv_cache());
        // A non-decode modality zeroes the KV term regardless of the lever;
        // chat passes the caller's default through untouched.
        assert_eq!(
            Modality::Chat.kv_bytes_per_element_override(Some(0.5)),
            Some(0.5)
        );
        assert_eq!(Modality::Chat.kv_bytes_per_element_override(None), None);
        assert_eq!(
            Modality::Embedding.kv_bytes_per_element_override(Some(0.5)),
            Some(0.0)
        );
        // vLLM task mapping: embed/score for the two supported non-chat tasks.
        assert_eq!(Modality::Chat.vllm_task_arg(), None);
        assert_eq!(Modality::Embedding.vllm_task_arg(), Some("embed"));
        assert_eq!(Modality::Rerank.vllm_task_arg(), Some("score"));
    }

    #[test]
    fn modality_parses_from_catalog_yaml() {
        let cat = Catalog::from_yaml(
            "\
models:
  bge-small:
    hf_repo: BAAI/bge-small-en-v1.5
    quants: [bf16]
    params: 33M
    license: mit
    family: bge
    min_vram_hint_gib: 1.0
    modality: embedding
",
        )
        .expect("parse");
        assert_eq!(cat.get("bge-small").unwrap().modality, Modality::Embedding);
    }

    #[test]
    fn resolve_catalog_id_uses_preferred_quant() {
        let r = sample().resolve("qwen3-32b").expect("resolve");
        assert_eq!(r.hf_repo, "Qwen/Qwen3-32B");
        assert_eq!(r.quant, "FP8");
        assert_eq!(r.catalog_id.as_deref(), Some("qwen3-32b"));
    }

    #[test]
    fn resolve_catalog_id_with_explicit_quant() {
        let r = sample().resolve("qwen3-32b:Q4_K_M").expect("resolve");
        assert_eq!(r.quant, "Q4_K_M");
    }

    #[test]
    fn resolve_unknown_quant_is_error() {
        let err = sample().resolve("qwen3-32b:AWQ").unwrap_err();
        assert!(matches!(err, ResolveError::UnknownQuant { .. }));
    }

    #[test]
    fn resolve_unknown_model_is_error() {
        let err = sample().resolve("does-not-exist").unwrap_err();
        assert_eq!(err, ResolveError::UnknownModel("does-not-exist".into()));
    }

    #[test]
    fn resolve_raw_hf_ref_bypasses_catalog() {
        let r = sample().resolve("hf:Org/Model:Q5_K_M").expect("resolve");
        assert_eq!(r.hf_repo, "Org/Model");
        assert_eq!(r.quant, "Q5_K_M");
        assert_eq!(r.catalog_id, None);
    }

    #[test]
    fn resolve_raw_hf_ref_without_quant() {
        let r = sample().resolve("hf:Org/Model").expect("resolve");
        assert_eq!(r.hf_repo, "Org/Model");
        assert_eq!(r.quant, "");
    }

    #[test]
    fn malformed_hf_refs_rejected() {
        for bad in ["hf:noslash", "hf:/leadingslash", "hf:too/many/slashes"] {
            assert!(
                matches!(sample().resolve(bad), Err(ResolveError::MalformedHfRef(_))),
                "{bad} should be malformed"
            );
        }
    }
}
