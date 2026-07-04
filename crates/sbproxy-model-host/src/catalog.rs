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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The committed default catalog, seeded with the certified-first
/// models from the design doc. Parsed once via [`Catalog::builtin`].
pub const BUILTIN_CATALOG_YAML: &str = include_str!("../data/models.yaml");

/// A quant family a catalog entry can be served in. Kept as a plain
/// string so the catalog can name engine-specific quants
/// (`Q4_K_M`, `FP8`, `AWQ`, `GPTQ`, `bf16`) without this crate
/// enumerating every one; [`crate::fit::Quant`] classifies them for
/// the capability gate.
pub type QuantName = String;

/// One catalog entry: everything the resolver knows about a model id
/// before any GPU is consulted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogEntry {
    /// Hugging Face repo, e.g. `Qwen/Qwen3-32B`.
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
    pub min_vram_hint_gib: f64,

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
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Catalog {
    /// catalog_id -> entry. A `BTreeMap` so serialization is
    /// deterministic (stable diffs, reproducible schema).
    #[serde(default)]
    pub models: BTreeMap<String, CatalogEntry>,
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
        serde_yaml::from_str(BUILTIN_CATALOG_YAML)
            .expect("built-in model catalog YAML parses (guarded by a unit test)")
    }

    /// Parse a catalog from YAML (an operator-supplied file).
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
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
