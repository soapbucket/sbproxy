// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Model lockfile (WOR-1864 slice 1).
//!
//! `sbproxy models lock` writes `sbproxy-models.lock`: the exactly
//! resolved serving stack (model, variant, artifact digest, source,
//! revision, per-file digests, engine) captured at lock time from
//! [`crate::Catalog::resolve_artifact`]. `sbproxy models verify-lock`
//! reads that lock back and diffs it against the verified local cache
//! inventory ([`crate::ArtifactManager::cached_artifacts`]), reporting
//! per-model drift. `sbproxy serve --locked` enforces the lock before
//! boot via [`verify_for_serve`]: the verify-lock diff plus resolution
//! pinning, refusing to start listeners on any drift.
//!
//! The lockfile is JSON with models sorted by name (then variant), so
//! writing the same resolved stack twice produces byte-identical files
//! and diffs stay reviewable.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{ArtifactCacheMetadata, ArtifactFile, EngineKind, ResolvedArtifact};

/// Lockfile document schema version.
pub const LOCKFILE_SCHEMA_VERSION: u32 = 1;

/// Default lockfile filename, written next to the active config.
pub const LOCKFILE_NAME: &str = "sbproxy-models.lock";

/// Lockfile read or write failure.
#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    /// Filesystem operation failed.
    #[error("lockfile I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Lockfile JSON could not be encoded or decoded.
    #[error("lockfile encode/decode failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// The lockfile violated the schema contract.
    #[error("lockfile is invalid: {0}")]
    Invalid(String),
}

/// The engine identity a locked model was resolved against: always the
/// selected [`EngineKind`], plus the version or container image when
/// the config pins one. Unpinned engines lock the kind alone, which is
/// honest: there is no exact engine build to hold the operator to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedEngine {
    /// Selected managed engine.
    pub kind: EngineKind,
    /// Pinned engine version, when the config pins one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Pinned engine container image, when the config pins one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// One exactly resolved model captured in the lockfile. Mirrors the
/// identity fields of [`ResolvedArtifact`] (and therefore of the cache's
/// [`ArtifactCacheMetadata`]) rather than inventing new ones, so a lock
/// entry compares directly against both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedModel {
    /// Logical model ID.
    pub name: String,
    /// Selected variant ID.
    pub variant_id: String,
    /// Canonical digest of the immutable artifact identity.
    pub artifact_digest: String,
    /// Exact source without credentials.
    pub source: String,
    /// Exact source revision.
    pub revision: String,
    /// Exact files with per-file digests.
    pub files: Vec<ArtifactFile>,
    /// Engine the model was resolved against, with pins when configured.
    pub engine: LockedEngine,
}

impl From<&ResolvedArtifact> for LockedModel {
    fn from(artifact: &ResolvedArtifact) -> Self {
        Self {
            name: artifact.logical_model.clone(),
            variant_id: artifact.variant_id.clone(),
            artifact_digest: artifact.artifact_digest.clone(),
            source: artifact.source.clone(),
            revision: artifact.revision.clone(),
            files: artifact.files.clone(),
            engine: LockedEngine {
                kind: artifact.engine,
                version: None,
                image: None,
            },
        }
    }
}

impl LockedModel {
    /// Attach the pinned engine version and image, when the config pins
    /// them. Absent pins stay `None` and are omitted from the file.
    pub fn with_engine_pin(mut self, version: Option<String>, image: Option<String>) -> Self {
        self.engine.version = version;
        self.engine.image = image;
        self
    }
}

/// The full `sbproxy-models.lock` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockfile {
    /// Lockfile document schema version.
    pub schema_version: u32,
    /// Lock time as Unix milliseconds.
    pub generated_at_ms: u64,
    /// Catalog revision every entry was resolved from.
    pub catalog_revision: String,
    /// Locked models, sorted by name (then variant) for stable diffs.
    pub models: Vec<LockedModel>,
}

impl Lockfile {
    /// Build a lockfile at the current schema version, sorting `models`
    /// by name (then variant) so serialization is deterministic.
    pub fn new(generated_at_ms: u64, catalog_revision: String, models: Vec<LockedModel>) -> Self {
        let mut lockfile = Self {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            generated_at_ms,
            catalog_revision,
            models,
        };
        lockfile.sort_models();
        lockfile
    }

    fn sort_models(&mut self) {
        self.models
            .sort_by(|a, b| (&a.name, &a.variant_id).cmp(&(&b.name, &b.variant_id)));
    }
}

/// One detected divergence between the lockfile and the local verified
/// cache. Cache entries absent from the lockfile are deliberately not
/// drift: the lock pins what must be present, not what else may be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockDrift {
    /// The locked model has no verified cache entry at all.
    Missing {
        /// Logical model ID from the lock entry.
        name: String,
        /// Locked variant ID.
        variant_id: String,
        /// The digest the cache is missing.
        artifact_digest: String,
    },
    /// The model is cached, but as a different artifact digest.
    DigestMismatch {
        /// Logical model ID from the lock entry.
        name: String,
        /// Locked variant ID.
        variant_id: String,
        /// The digest the lockfile pins.
        locked_digest: String,
        /// The digest actually present in the cache.
        cached_digest: String,
    },
    /// A configured serve/deployment entry resolved to an artifact
    /// digest the lockfile does not pin. Only the serve-time check
    /// ([`verify_for_serve`]) reports this: resolution moving off the
    /// lock is drift even when the cache agrees with the lockfile.
    Unlocked {
        /// Logical model ID of the configured entry.
        name: String,
        /// Resolved variant ID of the configured entry.
        variant_id: String,
        /// The resolved digest the lockfile is missing.
        artifact_digest: String,
    },
}

impl LockDrift {
    /// Logical model ID the drift is about.
    pub fn name(&self) -> &str {
        match self {
            Self::Missing { name, .. }
            | Self::DigestMismatch { name, .. }
            | Self::Unlocked { name, .. } => name,
        }
    }

    /// Locked variant ID the drift is about.
    pub fn variant_id(&self) -> &str {
        match self {
            Self::Missing { variant_id, .. }
            | Self::DigestMismatch { variant_id, .. }
            | Self::Unlocked { variant_id, .. } => variant_id,
        }
    }
}

impl std::fmt::Display for LockDrift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing {
                artifact_digest, ..
            } => write!(
                formatter,
                "missing from the verified cache (want sha256:{artifact_digest})"
            ),
            Self::DigestMismatch {
                locked_digest,
                cached_digest,
                ..
            } => write!(
                formatter,
                "digest mismatch: locked sha256:{locked_digest}, cached sha256:{cached_digest}"
            ),
            Self::Unlocked {
                artifact_digest, ..
            } => write!(
                formatter,
                "not pinned by the lockfile (resolved sha256:{artifact_digest})"
            ),
        }
    }
}

/// Write `lockfile` to `path` atomically (temp file + rename in the
/// same directory), normalizing model order first so repeated locks of
/// the same stack are byte-identical.
pub fn write_lockfile(path: &Path, lockfile: &Lockfile) -> Result<(), LockfileError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LockfileError::Invalid("lockfile path has no file name".to_string()))?
        .to_string();
    let mut normalized = lockfile.clone();
    normalized.sort_models();
    let mut bytes = serde_json::to_vec_pretty(&normalized)?;
    bytes.push(b'\n');
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    for attempt in 0..16u8 {
        let temporary = parent.join(format!(".{file_name}.{}.{attempt}.tmp", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&temporary, path)
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&temporary);
                }
                return result.map_err(LockfileError::Io);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(LockfileError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate lockfile temporary file",
    )))
}

/// Read and validate a lockfile written by [`write_lockfile`].
pub fn read_lockfile(path: &Path) -> Result<Lockfile, LockfileError> {
    let bytes = std::fs::read(path)?;
    let lockfile: Lockfile = serde_json::from_slice(&bytes)?;
    if lockfile.schema_version != LOCKFILE_SCHEMA_VERSION {
        return Err(LockfileError::Invalid(format!(
            "unsupported lockfile schema {}",
            lockfile.schema_version
        )));
    }
    Ok(lockfile)
}

/// Diff a lockfile against the verified cache inventory. Every locked
/// model is checked: present with the locked digest is clean, present
/// under a different digest is [`LockDrift::DigestMismatch`], absent is
/// [`LockDrift::Missing`]. Cached artifacts the lockfile does not
/// mention are never reported. Results follow lockfile model order.
pub fn diff_against_cache(lockfile: &Lockfile, cached: &[ArtifactCacheMetadata]) -> Vec<LockDrift> {
    let mut drifts = Vec::new();
    for model in &lockfile.models {
        if cached
            .iter()
            .any(|entry| entry.artifact_digest == model.artifact_digest)
        {
            continue;
        }
        // Report the same-variant cache entry when one exists; any entry
        // for the same logical model otherwise.
        let candidate = cached
            .iter()
            .filter(|entry| entry.logical_model == model.name)
            .max_by_key(|entry| entry.variant_id == model.variant_id);
        match candidate {
            Some(entry) => drifts.push(LockDrift::DigestMismatch {
                name: model.name.clone(),
                variant_id: model.variant_id.clone(),
                locked_digest: model.artifact_digest.clone(),
                cached_digest: entry.artifact_digest.clone(),
            }),
            None => drifts.push(LockDrift::Missing {
                name: model.name.clone(),
                variant_id: model.variant_id.clone(),
                artifact_digest: model.artifact_digest.clone(),
            }),
        }
    }
    drifts
}

/// Serve-time lockfile enforcement (WOR-1864): the union of
/// [`diff_against_cache`] and resolution pinning. On top of the
/// lockfile-versus-cache diff, every entry of `configured` (the
/// serve/deployment entries resolved on this host, carried as the
/// same [`LockedModel`] identity `models lock` writes) must resolve
/// to an artifact digest the lockfile pins; one that does not is
/// [`LockDrift::Unlocked`]. Lockfile-side drift comes first in
/// lockfile model order, then configured-side drift in `configured`
/// order, with duplicate configured digests reported once. An empty
/// result means serving is faithful to the lock.
pub fn verify_for_serve(
    lockfile: &Lockfile,
    cached: &[ArtifactCacheMetadata],
    configured: &[LockedModel],
) -> Vec<LockDrift> {
    let mut drifts = diff_against_cache(lockfile, cached);
    for model in configured {
        if lockfile
            .models
            .iter()
            .any(|locked| locked.artifact_digest == model.artifact_digest)
        {
            continue;
        }
        let already_reported = drifts.iter().any(|drift| {
            matches!(
                drift,
                LockDrift::Unlocked {
                    artifact_digest, ..
                } if *artifact_digest == model.artifact_digest
            )
        });
        if already_reported {
            continue;
        }
        drifts.push(LockDrift::Unlocked {
            name: model.name.clone(),
            variant_id: model.variant_id.clone(),
            artifact_digest: model.artifact_digest.clone(),
        });
    }
    drifts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactFormat, SupportLevel};

    fn locked(name: &str, variant: &str, digest: &str) -> LockedModel {
        LockedModel {
            name: name.to_string(),
            variant_id: variant.to_string(),
            artifact_digest: digest.to_string(),
            source: format!("hf:Org/{name}"),
            revision: "v1.0".to_string(),
            files: vec![ArtifactFile {
                path: "model.safetensors".to_string(),
                sha256: "ab".repeat(32),
                size_bytes: 4,
            }],
            engine: LockedEngine {
                kind: EngineKind::Vllm,
                version: None,
                image: None,
            },
        }
    }

    fn cached(name: &str, variant: &str, digest: &str) -> ArtifactCacheMetadata {
        ArtifactCacheMetadata {
            schema_version: 1,
            artifact_digest: digest.to_string(),
            catalog_revision: "2026-07".to_string(),
            logical_model: name.to_string(),
            variant_id: variant.to_string(),
            format: ArtifactFormat::Safetensors,
            quant: "fp16".to_string(),
            source: format!("hf:Org/{name}"),
            revision: "v1.0".to_string(),
            files: vec![ArtifactFile {
                path: "model.safetensors".to_string(),
                sha256: "ab".repeat(32),
                size_bytes: 4,
            }],
            total_size_bytes: 4,
            context_length: 4096,
            license: "apache-2.0".to_string(),
            stability: SupportLevel::Preview,
            pickle_allowed: false,
            trust: "verified".to_string(),
            created_at_ms: 1,
            last_accessed_ms: 1,
        }
    }

    #[test]
    fn write_read_roundtrip_and_sorted_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(LOCKFILE_NAME);
        // Built out of order; new() sorts by name.
        let lockfile = Lockfile::new(
            1_700_000_000_000,
            "2026-07".to_string(),
            vec![
                locked("zephyr-7b", "cuda-fp16", &"cc".repeat(32)),
                locked("aria-2b", "cuda-fp16", &"aa".repeat(32)),
            ],
        );
        write_lockfile(&path, &lockfile).expect("write");
        let read = read_lockfile(&path).expect("read");
        assert_eq!(read, lockfile);
        let names: Vec<_> = read.models.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["aria-2b", "zephyr-7b"]);
    }

    #[test]
    fn serialization_is_stable_across_input_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = locked("aria-2b", "cuda-fp16", &"aa".repeat(32));
        let z = locked("zephyr-7b", "cuda-fp16", &"cc".repeat(32));
        let forward = Lockfile::new(7, "2026-07".to_string(), vec![a.clone(), z.clone()]);
        let reversed = Lockfile::new(7, "2026-07".to_string(), vec![z, a]);
        let forward_path = dir.path().join("forward.lock");
        let reversed_path = dir.path().join("reversed.lock");
        write_lockfile(&forward_path, &forward).expect("write forward");
        write_lockfile(&reversed_path, &reversed).expect("write reversed");
        let forward_bytes = std::fs::read(&forward_path).expect("read forward");
        let reversed_bytes = std::fs::read(&reversed_path).expect("read reversed");
        assert_eq!(forward_bytes, reversed_bytes);
    }

    #[test]
    fn read_rejects_unknown_schema_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(LOCKFILE_NAME);
        let mut lockfile = Lockfile::new(1, "2026-07".to_string(), Vec::new());
        lockfile.schema_version = 99;
        write_lockfile(&path, &lockfile).expect("write");
        let error = read_lockfile(&path).expect_err("schema 99 must be rejected");
        assert!(matches!(error, LockfileError::Invalid(_)), "got: {error}");
    }

    #[test]
    fn diff_reports_missing_and_digest_mismatch_only() {
        let lockfile = Lockfile::new(
            1,
            "2026-07".to_string(),
            vec![
                locked("aria-2b", "cuda-fp16", &"aa".repeat(32)),
                locked("mira-9b", "cuda-fp16", &"bb".repeat(32)),
                locked("zephyr-7b", "cuda-fp16", &"cc".repeat(32)),
            ],
        );
        let cache = vec![
            // aria-2b matches its locked digest: clean.
            cached("aria-2b", "cuda-fp16", &"aa".repeat(32)),
            // mira-9b is cached under a different digest: mismatch.
            cached("mira-9b", "cuda-fp16", &"dd".repeat(32)),
            // zephyr-7b is absent entirely: missing.
            // An extra unlocked model is fine and never reported.
            cached("extra-1b", "cuda-fp16", &"ee".repeat(32)),
        ];
        let drifts = diff_against_cache(&lockfile, &cache);
        assert_eq!(drifts.len(), 2);
        assert_eq!(
            drifts[0],
            LockDrift::DigestMismatch {
                name: "mira-9b".to_string(),
                variant_id: "cuda-fp16".to_string(),
                locked_digest: "bb".repeat(32),
                cached_digest: "dd".repeat(32),
            }
        );
        assert_eq!(
            drifts[1],
            LockDrift::Missing {
                name: "zephyr-7b".to_string(),
                variant_id: "cuda-fp16".to_string(),
                artifact_digest: "cc".repeat(32),
            }
        );
        // Accessors name the model for CLI grouping.
        assert_eq!(drifts[0].name(), "mira-9b");
        assert_eq!(drifts[0].variant_id(), "cuda-fp16");
    }

    #[test]
    fn verify_for_serve_flags_configured_model_the_lockfile_does_not_pin() {
        // Lock and cache agree on aria-2b, but the config also resolves
        // mira-9b, which the lockfile never pinned: resolution drift.
        let lockfile = Lockfile::new(
            1,
            "2026-07".to_string(),
            vec![locked("aria-2b", "cuda-fp16", &"aa".repeat(32))],
        );
        let cache = vec![cached("aria-2b", "cuda-fp16", &"aa".repeat(32))];
        let configured = vec![
            locked("aria-2b", "cuda-fp16", &"aa".repeat(32)),
            locked("mira-9b", "cuda-fp16", &"bb".repeat(32)),
            // The same unlocked digest twice reports once.
            locked("mira-9b", "cuda-fp16", &"bb".repeat(32)),
        ];
        let drifts = verify_for_serve(&lockfile, &cache, &configured);
        assert_eq!(
            drifts,
            vec![LockDrift::Unlocked {
                name: "mira-9b".to_string(),
                variant_id: "cuda-fp16".to_string(),
                artifact_digest: "bb".repeat(32),
            }]
        );
        // Accessors and the display line feed the serve refusal output.
        assert_eq!(drifts[0].name(), "mira-9b");
        assert_eq!(drifts[0].variant_id(), "cuda-fp16");
        assert_eq!(
            drifts[0].to_string(),
            format!(
                "not pinned by the lockfile (resolved sha256:{})",
                "bb".repeat(32)
            )
        );
    }

    #[test]
    fn verify_for_serve_clean_when_configured_locked_and_cached() {
        let lockfile = Lockfile::new(
            1,
            "2026-07".to_string(),
            vec![locked("aria-2b", "cuda-fp16", &"aa".repeat(32))],
        );
        let cache = vec![cached("aria-2b", "cuda-fp16", &"aa".repeat(32))];
        let configured = vec![locked("aria-2b", "cuda-fp16", &"aa".repeat(32))];
        assert!(verify_for_serve(&lockfile, &cache, &configured).is_empty());
    }

    #[test]
    fn verify_for_serve_unions_cache_drift_with_resolution_drift() {
        // zephyr-7b is locked but not cached (cache drift) and the
        // configured extra-1b is not locked (resolution drift): both
        // surface, lockfile-side first.
        let lockfile = Lockfile::new(
            1,
            "2026-07".to_string(),
            vec![locked("zephyr-7b", "cuda-fp16", &"cc".repeat(32))],
        );
        let configured = vec![locked("extra-1b", "cuda-fp16", &"ee".repeat(32))];
        let drifts = verify_for_serve(&lockfile, &[], &configured);
        assert_eq!(
            drifts,
            vec![
                LockDrift::Missing {
                    name: "zephyr-7b".to_string(),
                    variant_id: "cuda-fp16".to_string(),
                    artifact_digest: "cc".repeat(32),
                },
                LockDrift::Unlocked {
                    name: "extra-1b".to_string(),
                    variant_id: "cuda-fp16".to_string(),
                    artifact_digest: "ee".repeat(32),
                },
            ]
        );
    }

    #[test]
    fn locked_model_from_resolved_artifact_carries_identity() {
        let artifact = ResolvedArtifact {
            catalog_revision: "2026-07".to_string(),
            logical_model: "aria-2b".to_string(),
            variant_id: "cuda-fp16".to_string(),
            artifact_digest: "aa".repeat(32),
            format: ArtifactFormat::Safetensors,
            quant: "fp16".to_string(),
            engine: EngineKind::Vllm,
            source: "hf:Org/aria-2b".to_string(),
            revision: "v1.0".to_string(),
            files: vec![ArtifactFile {
                path: "model.safetensors".to_string(),
                sha256: "ab".repeat(32),
                size_bytes: 4,
            }],
            context_length: 4096,
            license: "apache-2.0".to_string(),
            stability: SupportLevel::Preview,
            pickle_allowed: false,
            modality: crate::catalog::Modality::Chat,
        };
        let model = LockedModel::from(&artifact).with_engine_pin(Some("0.8.5".to_string()), None);
        assert_eq!(model.name, "aria-2b");
        assert_eq!(model.artifact_digest, "aa".repeat(32));
        assert_eq!(model.files, artifact.files);
        assert_eq!(model.engine.kind, EngineKind::Vllm);
        assert_eq!(model.engine.version.as_deref(), Some("0.8.5"));
        assert_eq!(model.engine.image, None);
    }
}
