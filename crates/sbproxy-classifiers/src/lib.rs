//! Pure-Rust ONNX inference + tokenizer wrapper for sbproxy detectors.
//!
//! This crate is intentionally narrow: it exposes a single
//! [`OnnxClassifier`] type that loads a Hugging Face style tokenizer and
//! an ONNX classification model, runs a forward pass on a text prompt,
//! and returns a label + confidence score. The actual policy wiring
//! (e.g. the `prompt_injection_v2` detector) lives elsewhere; this
//! crate is deliberately framework-agnostic so it can be reused for
//! other classification tasks (DLP categories, topic routing, etc.).
//!
//! # Why `tract-onnx`?
//!
//! The pure-Rust `tract-onnx` runtime is used instead of `ort`
//! (Microsoft ONNX Runtime). `tract-onnx` requires no system C++
//! libraries, compiles cleanly in containers and CI sandboxes, and
//! cross-compiles to musl / arm64 without extra setup. The trade-off
//! is somewhat slower inference than the C++ runtime, which is
//! acceptable for the small classifier models used by sbproxy
//! detectors.
//!
//! # Offline-first downloads
//!
//! [`OnnxClassifier::download_and_load`] caches model files on disk
//! and validates SHA-256 hashes (when provided). Subsequent loads use
//! the cached copy and skip the network entirely. This matches the
//! "graceful degradation when the network is unavailable" requirement
//! the proxy operates under.
//!
//! # Threading
//!
//! [`OnnxClassifier`] is `Send + Sync` once loaded, so callers can
//! place it behind an [`std::sync::Arc`] and share it across worker
//! threads without an outer lock.

#![deny(missing_docs)]

pub mod agent_class;
pub mod agent_classifier_types;
pub mod known_models;

pub use agent_class::{
    AgentClass, AgentClassCatalog, AgentId, AgentIdSource, AgentPurpose, DEFAULT_CATALOG_YAML,
};
pub use agent_classifier_types::{MlClass, MlClassification};
pub use known_models::{lookup as lookup_known_model, KnownModel, KNOWN_MODELS};

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;
use tract_onnx::prelude::*;

/// Type alias for the optimised, runnable tract graph held inside
/// [`OnnxClassifier`]. The full path is unwieldy and trips
/// `clippy::type_complexity`.
type RunnableOnnxModel =
    SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// A loaded ONNX classifier paired with its tokenizer.
///
/// Construction is the slow path: parsing + optimising the ONNX graph
/// can take hundreds of milliseconds. `classify` itself is cheap
/// enough to call on the request hot path for short prompts (a few
/// hundred BPE tokens).
pub struct OnnxClassifier {
    model: RunnableOnnxModel,
    tokenizer: Tokenizer,
    /// Optional list of human-readable labels indexed by output class.
    /// When `None`, labels are reported as `"class_<index>"`.
    labels: Option<Vec<String>>,
}

/// Result of running [`OnnxClassifier::classify`] on a prompt.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassificationOutput {
    /// Human-readable label of the highest-scoring class.
    pub label: String,
    /// Confidence score in `[0.0, 1.0]` (post-softmax).
    pub score: f32,
}

impl OnnxClassifier {
    /// Load a classifier from local files. Does not touch the network.
    ///
    /// `model_path` must be a `.onnx` file. `tokenizer_path` is a
    /// Hugging Face `tokenizer.json`. Both are validated at load time;
    /// any error returned here means the model is unusable and the
    /// caller should fall back to a heuristic.
    pub fn load(model_path: &Path, tokenizer_path: &Path) -> Result<Self> {
        Self::load_with_labels(model_path, tokenizer_path, None)
    }

    /// Like [`OnnxClassifier::load`] but with an explicit label list.
    ///
    /// The label list maps the model's softmax output index to a
    /// human-readable string. Pass `None` to fall back to
    /// `"class_<index>"`.
    pub fn load_with_labels(
        model_path: &Path,
        tokenizer_path: &Path,
        labels: Option<Vec<String>>,
    ) -> Result<Self> {
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| anyhow!("failed to load tokenizer at {tokenizer_path:?}: {e}"))?;

        // Optimised typed-graph runner is what we keep around per
        // process. `into_optimized()` runs the graph optimiser once at
        // load; `into_runnable()` wraps it in a SimplePlan we can call
        // `run` on.
        let model = tract_onnx::onnx()
            .model_for_path(model_path)
            .with_context(|| format!("failed to parse ONNX model at {model_path:?}"))?
            .into_optimized()
            .context("failed to optimise ONNX model")?
            .into_runnable()
            .context("failed to make ONNX model runnable")?;

        Ok(Self {
            model,
            tokenizer,
            labels,
        })
    }

    /// Tokenise `text`, run the model, and return the top class.
    ///
    /// Returns the highest-scoring class as a [`ClassificationOutput`].
    /// The score is the softmax probability of that class, in
    /// `[0.0, 1.0]`.
    pub fn classify(&self, text: &str) -> Result<ClassificationOutput> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenizer encode failed: {e}"))?;

        let ids: Vec<i64> = encoding.get_ids().iter().map(|i| *i as i64).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|m| *m as i64)
            .collect();
        let seq_len = ids.len();
        if seq_len == 0 {
            return Err(anyhow!("tokenizer produced empty encoding"));
        }

        // Most HF classifier ONNX exports take `input_ids` and
        // `attention_mask`; some also need `token_type_ids`. We try to
        // honour whichever the model declares.
        let input_ids =
            tract_ndarray::Array2::from_shape_vec((1, seq_len), ids).map_err(|e| anyhow!(e))?;
        let attention_mask = tract_ndarray::Array2::from_shape_vec((1, seq_len), mask.clone())
            .map_err(|e| anyhow!(e))?;

        // The runnable plan exposes the input names so we can target
        // the right slot regardless of model export quirks.
        let input_names: Vec<String> = self
            .model
            .model()
            .input_outlets()?
            .iter()
            .map(|outlet| self.model.model().node(outlet.node).name.clone())
            .collect();

        let mut inputs: TVec<TValue> = tvec!();
        for name in &input_names {
            let lower = name.to_ascii_lowercase();
            if lower.contains("input_ids") || lower == "ids" {
                inputs.push(input_ids.clone().into_tensor().into());
            } else if lower.contains("attention_mask") || lower.contains("mask") {
                inputs.push(attention_mask.clone().into_tensor().into());
            } else if lower.contains("token_type_ids") {
                let zeros: Vec<i64> = vec![0; seq_len];
                let token_type_ids = tract_ndarray::Array2::from_shape_vec((1, seq_len), zeros)
                    .map_err(|e| anyhow!(e))?;
                inputs.push(token_type_ids.into_tensor().into());
            } else {
                // Fallback: feed input_ids. Better than failing for a
                // model whose first input is just named "x".
                inputs.push(input_ids.clone().into_tensor().into());
            }
        }

        let outputs = self
            .model
            .run(inputs)
            .map_err(|e| anyhow!("ONNX inference failed: {e}"))?;
        let logits = outputs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("ONNX model returned no outputs"))?;
        let logits = logits
            .to_array_view::<f32>()
            .map_err(|e| anyhow!("output tensor was not f32: {e}"))?;

        // Find the last axis (the class axis). Most classifier
        // exports produce shape `[1, num_classes]`.
        let flat: Vec<f32> = logits.iter().copied().collect();
        if flat.is_empty() {
            return Err(anyhow!("ONNX model returned empty logits"));
        }
        let probs = softmax(&flat);
        let (idx, &score) = probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or_else(|| anyhow!("could not pick argmax"))?;

        let label = self
            .labels
            .as_ref()
            .and_then(|labels| labels.get(idx).cloned())
            .unwrap_or_else(|| format!("class_{idx}"));

        Ok(ClassificationOutput { label, score })
    }

    /// Download model + tokenizer to `cache_dir` and load.
    ///
    /// Files are stored under `cache_dir` keyed by URL hash so multiple
    /// classifiers can share the same cache. When `expected_sha256` is
    /// provided, downloads are validated and rejected on mismatch (the
    /// security posture is "trust pinned hashes, never the network").
    /// Cached files are reused as-is when they already exist; pass
    /// `expected_sha256` to also re-validate the cached copy.
    pub fn download_and_load(
        model_url: &str,
        tokenizer_url: &str,
        expected_sha256: Option<(&str, &str)>,
        cache_dir: &Path,
    ) -> Result<Self> {
        fs::create_dir_all(cache_dir)
            .with_context(|| format!("creating model cache dir {cache_dir:?}"))?;

        let (model_hash, tokenizer_hash) = match expected_sha256 {
            Some((m, t)) => (Some(m), Some(t)),
            None => (None, None),
        };

        let model_path = ensure_cached_file(cache_dir, "model", model_url, model_hash, ".onnx")?;
        let tokenizer_path = ensure_cached_file(
            cache_dir,
            "tokenizer",
            tokenizer_url,
            tokenizer_hash,
            ".json",
        )?;

        Self::load(&model_path, &tokenizer_path)
    }
}

/// Compute the softmax of `logits`. Stable: subtracts the max before
/// exponentiating.
fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum == 0.0 {
        return vec![0.0; exps.len()];
    }
    exps.into_iter().map(|x| x / sum).collect()
}

/// Resolve `cache_dir/<prefix>-<url-hash><suffix>`, downloading
/// `url` into it on first use. When `expected_sha256` is provided, the
/// final file's hash is validated; on mismatch the file is removed and
/// the function errors out so the caller can fall back.
fn ensure_cached_file(
    cache_dir: &Path,
    prefix: &str,
    url: &str,
    expected_sha256: Option<&str>,
    suffix: &str,
) -> Result<PathBuf> {
    let url_hash = {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        hex::encode(h.finalize())
    };
    let filename = format!("{prefix}-{}{suffix}", &url_hash[..16]);
    let path = cache_dir.join(filename);

    if path.exists() {
        if let Some(expected) = expected_sha256 {
            match validate_sha256(&path, expected) {
                Ok(()) => {
                    tracing::debug!(
                        path = %path.display(),
                        "reusing validated cached model file",
                    );
                    return Ok(path);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "cached model file failed sha256; redownloading",
                    );
                    let _ = fs::remove_file(&path);
                }
            }
        } else {
            return Ok(path);
        }
    }

    tracing::info!(url = url, path = %path.display(), "downloading model file");
    let mut resp = reqwest::blocking::get(url)
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()
        .with_context(|| format!("downloading {url}"))?;
    let mut buf = Vec::new();
    resp.read_to_end(&mut buf)
        .with_context(|| format!("reading body for {url}"))?;

    let mut f = fs::File::create(&path).with_context(|| format!("creating cache file {path:?}"))?;
    f.write_all(&buf)
        .with_context(|| format!("writing cache file {path:?}"))?;
    f.sync_all().ok();

    if let Some(expected) = expected_sha256 {
        if let Err(e) = validate_sha256(&path, expected) {
            let _ = fs::remove_file(&path);
            return Err(e).with_context(|| format!("downloaded file failed sha256: {url}"));
        }
    }

    Ok(path)
}

fn validate_sha256(path: &Path, expected_hex: &str) -> Result<()> {
    let mut f =
        fs::File::open(path).with_context(|| format!("opening {path:?} for sha256 check"))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .with_context(|| format!("reading {path:?} for sha256 check"))?;
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let actual = hex::encode(hasher.finalize());
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(anyhow!(
            "sha256 mismatch: expected {expected_hex}, got {actual}"
        ))
    }
}

/// Default cache directory: `<user-cache-dir>/sbproxy/models/` when
/// available, falling back to `./.sbproxy-cache/models/`.
pub fn default_model_cache_dir() -> PathBuf {
    if let Some(cache) = dirs::cache_dir() {
        cache.join("sbproxy").join("models")
    } else {
        PathBuf::from(".sbproxy-cache").join("models")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_err_on_missing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let model = tmp.path().join("does-not-exist.onnx");
        let tok = tmp.path().join("does-not-exist.json");
        let err = match OnnxClassifier::load(&model, &tok) {
            Ok(_) => panic!("expected error for missing files"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("tokenizer") || msg.contains("does-not-exist"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn validate_sha256_accepts_match() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.bin");
        fs::write(&path, b"hello").unwrap();
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        validate_sha256(
            &path,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();
    }

    #[test]
    fn validate_sha256_rejects_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.bin");
        fs::write(&path, b"hello").unwrap();
        let err = validate_sha256(&path, "deadbeef").unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn softmax_sums_to_one() {
        let p = softmax(&[1.0, 2.0, 3.0]);
        let total: f32 = p.iter().sum();
        assert!((total - 1.0).abs() < 1e-5);
        // Argmax preserved.
        assert!(p[2] > p[1] && p[1] > p[0]);
    }

    #[test]
    fn softmax_handles_empty_logits() {
        // Should not panic.
        let p = softmax(&[]);
        assert!(p.is_empty());
    }

    #[test]
    fn default_cache_dir_resolves() {
        let p = default_model_cache_dir();
        assert!(p.ends_with("models"));
    }
}
