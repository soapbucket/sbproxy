// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Catalog v2 artifact contracts and worker compatibility (WOR-1837).

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EngineChoice, EngineKind, SupportLevel};

/// On-disk weight representation consumed by a managed engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// Safe, non-executable tensor container.
    Safetensors,
    /// llama.cpp's self-contained model format.
    Gguf,
    /// Python pickle checkpoint, gated behind explicit model opt-in.
    Pickle,
}

/// Accelerator family a variant can execute on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKind {
    /// Host CPU and system RAM.
    Cpu,
    /// Apple Metal with unified memory.
    Metal,
    /// NVIDIA CUDA.
    Cuda,
}

/// Comparable CUDA compute capability.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ComputeCapability {
    /// Major capability number.
    pub major: u32,
    /// Minor capability number.
    pub minor: u32,
}

/// Exact immutable file belonging to an artifact variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactFile {
    /// Repository-relative path preserved in the local snapshot.
    pub path: String,
    /// Lowercase SHA-256 digest of the file bytes.
    pub sha256: String,
    /// Exact byte length.
    pub size_bytes: u64,
}

/// Hardware requirements for an artifact variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VariantRequirements {
    /// Accelerator families that can execute this variant.
    pub accelerators: BTreeSet<AcceleratorKind>,
    /// Minimum CUDA compute capability, when CUDA is selected.
    #[serde(default)]
    pub min_compute_capability: Option<ComputeCapability>,
    /// Minimum worker memory available to model serving.
    #[serde(default)]
    pub min_memory_bytes: u64,
}

/// One immutable executable variant of a logical model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactVariant {
    /// Stable variant identifier within the logical model.
    pub id: String,
    /// Weight file format.
    pub format: ArtifactFormat,
    /// Human-readable quantization name.
    pub quant: String,
    /// Managed engines capable of consuming the exact artifact.
    pub engines: Vec<EngineKind>,
    /// `hf:Org/Repo` or `file:/absolute/path` source.
    pub source: String,
    /// Immutable source revision.
    pub revision: String,
    /// Complete files needed by the engine snapshot.
    pub files: Vec<ArtifactFile>,
    /// Worker compatibility requirements.
    pub requirements: VariantRequirements,
    /// Product support level for this exact variant.
    pub stability: SupportLevel,
    /// Evidence or certification identifier.
    pub certification: String,
}

/// Worker facts used for deterministic artifact compatibility checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerProfile {
    /// Accelerator selected for this replica.
    pub accelerator: AcceleratorKind,
    /// CUDA compute capability when the accelerator is CUDA.
    pub compute_capability: Option<ComputeCapability>,
    /// Memory available to model serving.
    pub memory_bytes: u64,
    /// Managed engines executable on this worker.
    pub engines: BTreeSet<EngineKind>,
}

impl WorkerProfile {
    /// Project discovered host devices into the catalog v2 worker
    /// contract, selecting the device with the most free serving
    /// memory. All allowlisted engines remain candidates; catalog and
    /// explicit engine selection narrow them deterministically.
    pub fn from_descriptors(descriptors: &[crate::GpuDescriptor]) -> Result<Self, String> {
        let descriptor = descriptors
            .iter()
            .max_by_key(|descriptor| descriptor.free_vram_bytes)
            .ok_or_else(|| "no model-serving worker is available".to_string())?;
        let accelerator = match descriptor.vendor {
            crate::GpuVendor::Nvidia => AcceleratorKind::Cuda,
            crate::GpuVendor::Apple => AcceleratorKind::Metal,
            crate::GpuVendor::Cpu => AcceleratorKind::Cpu,
            crate::GpuVendor::Amd => {
                return Err("catalog v2 does not yet define a ROCm accelerator contract".to_string())
            }
        };
        let compute_capability = descriptor
            .compute_capability
            .map(|(major, minor)| ComputeCapability { major, minor });
        Ok(Self {
            accelerator,
            compute_capability,
            memory_bytes: descriptor.free_vram_bytes,
            engines: BTreeSet::from([EngineKind::Vllm, EngineKind::LlamaCpp, EngineKind::Embedded]),
        })
    }
}

/// Requested logical model and variant-selection policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveArtifactRequest {
    /// Logical catalog model ID.
    pub model: String,
    /// Explicit variant ID, or automatic selection when absent.
    pub variant: Option<String>,
    /// Explicit engine or automatic compatible selection.
    pub engine: EngineChoice,
    /// Desired replica count.
    pub replicas: u32,
    /// Permit each worker to select a different compatible variant.
    pub heterogeneous_variants: bool,
}

/// One fully resolved immutable artifact and selected engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedArtifact {
    /// Catalog revision used for selection.
    pub catalog_revision: String,
    /// Logical model ID.
    pub logical_model: String,
    /// Selected variant ID.
    pub variant_id: String,
    /// Canonical digest of the immutable artifact identity.
    pub artifact_digest: String,
    /// Weight file format.
    pub format: ArtifactFormat,
    /// Quantization name.
    pub quant: String,
    /// Selected managed engine.
    pub engine: EngineKind,
    /// Exact source.
    pub source: String,
    /// Exact source revision.
    pub revision: String,
    /// Exact artifact files.
    pub files: Vec<ArtifactFile>,
    /// Declared maximum context length.
    pub context_length: u64,
    /// Logical model license identifier.
    pub license: String,
    /// Variant support level.
    pub stability: SupportLevel,
    /// Logical-model policy explicitly permits pickle execution risk.
    pub pickle_allowed: bool,
    /// The task this model serves (WOR-1908). Carried from the catalog
    /// entry so the fit planner and engine launch branch on it. It is a
    /// property of the logical model, not the immutable bytes, so it is
    /// deliberately excluded from the hashed digest material and does not
    /// change `artifact_digest`.
    pub modality: crate::catalog::Modality,
}

#[derive(Serialize)]
struct ArtifactDigestMaterial<'a> {
    catalog_revision: &'a str,
    logical_model: &'a str,
    variant_id: &'a str,
    format: ArtifactFormat,
    quant: &'a str,
    source: &'a str,
    revision: &'a str,
    files: &'a [ArtifactFile],
}

impl ResolvedArtifact {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_variant(
        catalog_revision: &str,
        logical_model: &str,
        variant: &ArtifactVariant,
        engine: EngineKind,
        context_length: u64,
        license: &str,
        pickle_allowed: bool,
        modality: crate::catalog::Modality,
    ) -> Result<Self, String> {
        let material = ArtifactDigestMaterial {
            catalog_revision,
            logical_model,
            variant_id: &variant.id,
            format: variant.format,
            quant: &variant.quant,
            source: &variant.source,
            revision: &variant.revision,
            files: &variant.files,
        };
        let canonical = serde_json_canonicalizer::to_vec(&material)
            .map_err(|error| format!("canonicalize artifact identity: {error}"))?;
        let artifact_digest = hex::encode(Sha256::digest(canonical));
        Ok(Self {
            catalog_revision: catalog_revision.to_string(),
            logical_model: logical_model.to_string(),
            variant_id: variant.id.clone(),
            artifact_digest,
            format: variant.format,
            quant: variant.quant.clone(),
            engine,
            source: variant.source.clone(),
            revision: variant.revision.clone(),
            files: variant.files.clone(),
            context_length,
            license: license.to_string(),
            stability: variant.stability,
            pickle_allowed,
            modality,
        })
    }
}

pub(crate) fn forced_engine(choice: EngineChoice) -> Option<EngineKind> {
    match choice {
        EngineChoice::Auto => None,
        EngineChoice::Vllm => Some(EngineKind::Vllm),
        EngineChoice::LlamaCpp => Some(EngineKind::LlamaCpp),
        EngineChoice::Embedded => Some(EngineKind::Embedded),
    }
}

pub(crate) fn compatible_engine(
    variant: &ArtifactVariant,
    requested: EngineChoice,
    worker: &WorkerProfile,
) -> Option<EngineKind> {
    if let Some(forced) = forced_engine(requested) {
        return (variant.engines.contains(&forced) && worker.engines.contains(&forced))
            .then_some(forced);
    }
    variant
        .engines
        .iter()
        .copied()
        .find(|engine| worker.engines.contains(engine))
}

pub(crate) fn worker_meets_requirements(
    variant: &ArtifactVariant,
    worker: &WorkerProfile,
) -> Result<(), String> {
    if !variant
        .requirements
        .accelerators
        .contains(&worker.accelerator)
    {
        return Err(format!(
            "accelerator {:?} is not in {:?}",
            worker.accelerator, variant.requirements.accelerators
        ));
    }
    if worker.memory_bytes < variant.requirements.min_memory_bytes {
        return Err(format!(
            "worker has {} bytes but variant needs {}",
            worker.memory_bytes, variant.requirements.min_memory_bytes
        ));
    }
    if worker.accelerator == AcceleratorKind::Cuda {
        if let Some(required) = variant.requirements.min_compute_capability {
            match worker.compute_capability {
                Some(actual) if actual >= required => {}
                Some(actual) => {
                    return Err(format!(
                        "CUDA compute capability {}.{} is below {}.{}",
                        actual.major, actual.minor, required.major, required.minor
                    ));
                }
                None => return Err("CUDA compute capability is unknown".to_string()),
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_variant(
    logical_model: &str,
    variant: &ArtifactVariant,
) -> Result<(), String> {
    let context = || format!("model '{logical_model}' variant '{}'", variant.id);
    if !valid_identifier(&variant.id) {
        return Err(format!("{} has an invalid id", context()));
    }
    if variant.quant.trim().is_empty() {
        return Err(format!("{} has an empty quant", context()));
    }
    if variant.engines.is_empty() {
        return Err(format!("{} has no compatible engines", context()));
    }
    if variant.source.trim().is_empty() {
        return Err(format!("{} has an empty source", context()));
    }
    let scheme = crate::SourceScheme::parse(&variant.source)
        .map_err(|error| format!("{} source: {error}", context()))?;
    scheme
        .require_supported()
        .map_err(|error| format!("{} source: {error}", context()))?;
    if variant.revision.trim().is_empty() {
        return Err(format!("{} has an empty revision", context()));
    }
    if variant.stability == SupportLevel::Stable
        && matches!(scheme, crate::SourceScheme::Hf { .. })
        && !is_hex_len(&variant.revision, 40)
    {
        return Err(format!(
            "{} stable Hugging Face revision must be a 40-character commit",
            context()
        ));
    }
    if variant.files.is_empty() {
        return Err(format!("{} has no exact files", context()));
    }
    if variant.requirements.accelerators.is_empty() {
        return Err(format!("{} has no accelerator requirements", context()));
    }
    if variant.certification.trim().is_empty() {
        return Err(format!("{} has no certification identifier", context()));
    }

    let mut paths = BTreeSet::new();
    for file in &variant.files {
        if !valid_relative_path(&file.path) {
            return Err(format!(
                "{} file path '{}' is not a safe relative path",
                context(),
                file.path
            ));
        }
        if !paths.insert(&file.path) {
            return Err(format!(
                "{} contains duplicate file path '{}'",
                context(),
                file.path
            ));
        }
        if !is_hex_len(&file.sha256, 64) {
            return Err(format!(
                "{} file '{}' has an invalid sha256",
                context(),
                file.path
            ));
        }
        if file.size_bytes == 0 {
            return Err(format!(
                "{} file '{}' has a zero byte size",
                context(),
                file.path
            ));
        }
    }

    let format_file_present = match variant.format {
        ArtifactFormat::Safetensors => variant
            .files
            .iter()
            .any(|file| file.path.ends_with(".safetensors")),
        ArtifactFormat::Gguf => variant
            .files
            .iter()
            .any(|file| file.path.ends_with(".gguf")),
        ArtifactFormat::Pickle => variant.files.iter().any(|file| {
            file.path.ends_with(".bin") || file.path.ends_with(".pt") || file.path.ends_with(".pth")
        }),
    };
    if !format_file_present {
        return Err(format!(
            "{} has no file matching format {:?}",
            context(),
            variant.format
        ));
    }
    Ok(())
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn valid_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
    {
        return false;
    }
    value
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
