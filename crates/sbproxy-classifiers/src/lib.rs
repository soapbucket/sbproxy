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
//! # Supply-chain hardening
//!
//! Two optional load-time guards harden the supply-chain story for
//! operators who do not fully trust the upstream model host:
//!
//! - **Size budget.** Both the ONNX file and the tokenizer file are
//!   rejected at load time if they exceed [`MAX_MODEL_BYTES_DEFAULT`]
//!   (200 MB). The budget is configurable via [`LoadOptions`] so
//!   operators running larger models can opt in to a higher ceiling.
//!   This is a hard error, not a warning: a runaway download can
//!   exhaust disk and memory before tract / tokenizers ever sees the
//!   file.
//! - **Detached Ed25519 signatures.** When a signature URL and
//!   verifying key are configured via [`LoadOptions::with_signatures`],
//!   the detector fetches the detached signature alongside the artifact
//!   and verifies it against an operator-supplied public key before
//!   handing the bytes to tract. The signed payload is the SHA-256 of
//!   the artifact (32 bytes), so memory stays bounded regardless of
//!   model size.
//!
//! The trust model is OPERATOR-trusted: the OSS crate ships no vendor
//! key. Operators that want signatures supply their own key and rotate
//! it themselves. See `docs/adr-classifier-supply-chain-oss.md` for the
//! reasoning and how this differs from the enterprise vendor-trusted
//! path.
//!
//! # Threading
//!
//! [`OnnxClassifier`] is `Send + Sync` once loaded, so callers can
//! place it behind an [`std::sync::Arc`] and share it across worker
//! threads without an outer lock.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod agent_class;
pub mod agent_classifier_types;
pub mod judge_rpc;
pub mod known_models;

pub use agent_class::{
    AgentClass, AgentClassCatalog, AgentId, AgentIdSource, AgentPurpose, DEFAULT_CATALOG_YAML,
};
pub use agent_classifier_types::{MlClass, MlClassification};
pub use judge_rpc::{
    build_judge_client, JudgeClientLike, JudgeRpcConfig, JudgeRpcConfigError, JudgeRpcService,
    DEFAULT_BUDGET_TOKENS,
};
pub use known_models::{lookup as lookup_known_model, KnownModel, KNOWN_MODELS};

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;
use tract_onnx::prelude::*;

/// Default upper bound on the size of either an ONNX model file or a
/// tokenizer file (200 MB).
///
/// The classifiers used by sbproxy detectors are small (DeBERTa-base is
/// roughly 350 MB unquantised, ~70 MB after the int8 ONNX export, and
/// the matching tokenizer is well under 5 MB). 200 MB is a generous
/// ceiling that still rejects the kind of runaway download that could
/// exhaust the cache disk before tract or tokenizers sees the file.
///
/// Operators running a larger custom model can lift this via
/// [`LoadOptions::with_max_model_bytes`] /
/// [`LoadOptions::with_max_tokenizer_bytes`]. The default is the same
/// 200 MB ceiling the enterprise classifier uses.
pub const MAX_MODEL_BYTES_DEFAULT: u64 = 200 * 1024 * 1024;

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

/// Optional supply-chain guards applied at load time.
///
/// Construct with [`LoadOptions::default`] for today's behaviour (size
/// budget enforced at [`MAX_MODEL_BYTES_DEFAULT`], no signature
/// verification). Use the builder methods to opt in to detached
/// Ed25519 signature verification or to widen the size budget.
///
/// All-or-nothing rule: signature verification needs a *pair* of
/// signature URLs (one for the model, one for the tokenizer). The
/// caller is responsible for the all-or-nothing check on the URL
/// pair; this type only carries already-paired data plus the verifying
/// key. The detector layer in `sbproxy-modules` handles the config
/// surface check.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// Hard upper bound on the ONNX model file size in bytes. `None`
    /// means use [`MAX_MODEL_BYTES_DEFAULT`].
    max_model_bytes: Option<u64>,
    /// Hard upper bound on the tokenizer file size in bytes. `None`
    /// means use [`MAX_MODEL_BYTES_DEFAULT`].
    max_tokenizer_bytes: Option<u64>,
    /// Detached-signature URL pair plus the verifying key. `None`
    /// disables signature verification (today's default).
    signatures: Option<SignatureConfig>,
}

/// The signature half of [`LoadOptions`].
///
/// The caller has already validated that both URLs are present (the
/// all-or-nothing rule lives in the detector config layer).
#[derive(Debug, Clone)]
pub struct SignatureConfig {
    /// HTTPS URL of the detached Ed25519 signature for the ONNX file.
    /// The signature is taken over `SHA-256(model_bytes)` (32 bytes
    /// in, 64-byte signature out) so memory does not scale with model
    /// size.
    model_signature_url: String,
    /// HTTPS URL of the detached Ed25519 signature for the tokenizer
    /// file. Same shape as `model_signature_url`.
    tokenizer_signature_url: String,
    /// 32-byte Ed25519 verifying key. The detector config layer parses
    /// the operator's PEM or hex string into this fixed-size form.
    verifying_key: [u8; PUBLIC_KEY_LENGTH],
}

impl LoadOptions {
    /// Override the model size budget. Pass `0` to mean "no limit"; any
    /// other value is enforced as a hard upper bound.
    pub fn with_max_model_bytes(mut self, bytes: u64) -> Self {
        self.max_model_bytes = Some(bytes);
        self
    }

    /// Override the tokenizer size budget. Pass `0` to mean "no limit";
    /// any other value is enforced as a hard upper bound.
    pub fn with_max_tokenizer_bytes(mut self, bytes: u64) -> Self {
        self.max_tokenizer_bytes = Some(bytes);
        self
    }

    /// Enable detached-signature verification. The caller has already
    /// resolved both signature URLs and parsed the operator's key.
    pub fn with_signatures(
        mut self,
        model_signature_url: impl Into<String>,
        tokenizer_signature_url: impl Into<String>,
        verifying_key: [u8; PUBLIC_KEY_LENGTH],
    ) -> Self {
        self.signatures = Some(SignatureConfig {
            model_signature_url: model_signature_url.into(),
            tokenizer_signature_url: tokenizer_signature_url.into(),
            verifying_key,
        });
        self
    }

    fn effective_model_limit(&self) -> u64 {
        self.max_model_bytes.unwrap_or(MAX_MODEL_BYTES_DEFAULT)
    }

    fn effective_tokenizer_limit(&self) -> u64 {
        self.max_tokenizer_bytes.unwrap_or(MAX_MODEL_BYTES_DEFAULT)
    }
}

/// Parse an Ed25519 verifying key from either an inline PEM SPKI block
/// or a 64-character hex string of the raw 32-byte key.
///
/// The PEM path expects the `PUBLIC KEY` armor, which is the standard
/// `openssl genpkey -algorithm Ed25519` output. The DER inside is a
/// 44-byte SubjectPublicKeyInfo whose last 32 bytes are the raw key;
/// the leading 12 bytes are the fixed Ed25519 algorithm identifier
/// `30 2a 30 05 06 03 2b 65 70 03 21 00`.
///
/// The hex path is offered as a convenience for operators who already
/// have a raw key (e.g. dumped via `xxd`) and want to inline it without
/// generating an SPKI wrapper.
pub fn parse_ed25519_pubkey(input: &str) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
    let trimmed = input.trim();
    if trimmed.contains("-----BEGIN") {
        let der = pem_decode(trimmed, "PUBLIC KEY")?;
        // SubjectPublicKeyInfo for Ed25519 is exactly 44 bytes:
        // 12 bytes of fixed prefix then 32 bytes of key. Anything else
        // is either a different algorithm or a malformed file.
        const ED25519_SPKI_PREFIX: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        if der.len() != ED25519_SPKI_PREFIX.len() + PUBLIC_KEY_LENGTH {
            return Err(anyhow!(
                "ed25519 PEM SPKI must be {} bytes, got {}",
                ED25519_SPKI_PREFIX.len() + PUBLIC_KEY_LENGTH,
                der.len()
            ));
        }
        if der[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
            return Err(anyhow!(
                "PEM SPKI prefix is not Ed25519; expected algorithm OID 1.3.101.112"
            ));
        }
        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(&der[ED25519_SPKI_PREFIX.len()..]);
        Ok(key)
    } else {
        let bytes = hex::decode(trimmed)
            .with_context(|| "ed25519 public key is neither PEM nor 64-char hex")?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(anyhow!(
                "ed25519 public key must be {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            ));
        }
        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}

/// Minimal PEM decoder. We don't pull a dedicated `pem` crate just for
/// this one armor type.
fn pem_decode(input: &str, want_label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {want_label}-----");
    let end = format!("-----END {want_label}-----");
    let start = input
        .find(&begin)
        .ok_or_else(|| anyhow!("PEM is missing {begin}"))?;
    let after_begin = start + begin.len();
    let end_idx = input[after_begin..]
        .find(&end)
        .ok_or_else(|| anyhow!("PEM is missing {end}"))?;
    let body = &input[after_begin..after_begin + end_idx];
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STANDARD
        .decode(cleaned.as_bytes())
        .with_context(|| "decoding PEM body as base64")
}

impl OnnxClassifier {
    /// Load a classifier from local files. Does not touch the network.
    ///
    /// `model_path` must be a `.onnx` file. `tokenizer_path` is a
    /// Hugging Face `tokenizer.json`. Both are validated at load time;
    /// any error returned here means the model is unusable and the
    /// caller should fall back to a heuristic.
    ///
    /// The default 200 MB size budget is enforced on both files; use
    /// [`OnnxClassifier::load_with_options`] to override it.
    pub fn load(model_path: &Path, tokenizer_path: &Path) -> Result<Self> {
        Self::load_with_options(model_path, tokenizer_path, None, &LoadOptions::default())
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
        Self::load_with_options(model_path, tokenizer_path, labels, &LoadOptions::default())
    }

    /// Load a classifier from local files with explicit
    /// supply-chain guards.
    ///
    /// The size-budget fields on [`LoadOptions`] are checked before
    /// either file is parsed; this is the load-time enforcement that
    /// makes a runaway artifact a hard error rather than a memory
    /// blow-up inside tract or tokenizers. Signature configuration on
    /// [`LoadOptions`] is ignored on this code path because there is
    /// no signature bytes source for already-on-disk files; the
    /// download path applies signature checks. Callers that pre-stage
    /// the cache out of band must verify signatures themselves before
    /// calling `load_with_options`.
    pub fn load_with_options(
        model_path: &Path,
        tokenizer_path: &Path,
        labels: Option<Vec<String>>,
        options: &LoadOptions,
    ) -> Result<Self> {
        check_size_budget(model_path, "model", options.effective_model_limit())?;
        check_size_budget(
            tokenizer_path,
            "tokenizer",
            options.effective_tokenizer_limit(),
        )?;

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
    ///
    /// The default 200 MB size budget is enforced; use
    /// [`OnnxClassifier::download_and_load_with_options`] to widen it
    /// or to enable detached-signature verification.
    pub fn download_and_load(
        model_url: &str,
        tokenizer_url: &str,
        expected_sha256: Option<(&str, &str)>,
        cache_dir: &Path,
    ) -> Result<Self> {
        Self::download_and_load_with_options(
            model_url,
            tokenizer_url,
            expected_sha256,
            cache_dir,
            &LoadOptions::default(),
        )
    }

    /// Download model + tokenizer to `cache_dir` and load, applying
    /// optional supply-chain guards.
    ///
    /// In addition to today's SHA-256 pin behaviour, this entry point:
    ///
    /// - Enforces the size budget on each downloaded file (default
    ///   200 MB, configurable on [`LoadOptions`]). The check runs
    ///   right after the bytes hit disk and before tract / tokenizers
    ///   sees them, so a runaway artifact becomes a hard error.
    /// - When [`LoadOptions::with_signatures`] is set, fetches a
    ///   detached Ed25519 signature alongside each artifact and
    ///   verifies it against the operator's public key. Failure here
    ///   removes the cached file and returns an error so the caller
    ///   can fall back.
    pub fn download_and_load_with_options(
        model_url: &str,
        tokenizer_url: &str,
        expected_sha256: Option<(&str, &str)>,
        cache_dir: &Path,
        options: &LoadOptions,
    ) -> Result<Self> {
        fs::create_dir_all(cache_dir)
            .with_context(|| format!("creating model cache dir {cache_dir:?}"))?;

        let (model_hash, tokenizer_hash) = match expected_sha256 {
            Some((m, t)) => (Some(m), Some(t)),
            None => (None, None),
        };

        let model_path = ensure_cached_file(
            cache_dir,
            "model",
            model_url,
            model_hash,
            ".onnx",
            options.effective_model_limit(),
        )?;
        let tokenizer_path = ensure_cached_file(
            cache_dir,
            "tokenizer",
            tokenizer_url,
            tokenizer_hash,
            ".json",
            options.effective_tokenizer_limit(),
        )?;

        if let Some(sig) = options.signatures.as_ref() {
            if let Err(e) = verify_artifact_signature(
                &model_path,
                &sig.model_signature_url,
                &sig.verifying_key,
                cache_dir,
                "model",
            ) {
                let _ = fs::remove_file(&model_path);
                return Err(e).context("model signature verification failed");
            }
            if let Err(e) = verify_artifact_signature(
                &tokenizer_path,
                &sig.tokenizer_signature_url,
                &sig.verifying_key,
                cache_dir,
                "tokenizer",
            ) {
                let _ = fs::remove_file(&tokenizer_path);
                return Err(e).context("tokenizer signature verification failed");
            }
        }

        Self::load_with_options(&model_path, &tokenizer_path, None, options)
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
///
/// `max_bytes` is an upper bound on the file size; `0` means no
/// bound. Files larger than the bound are rejected even when their
/// SHA-256 matches, so a downstream operator who pinned a hash but
/// forgot to set the size budget still gets the budget for free.
fn ensure_cached_file(
    cache_dir: &Path,
    prefix: &str,
    url: &str,
    expected_sha256: Option<&str>,
    suffix: &str,
    max_bytes: u64,
) -> Result<PathBuf> {
    let url_hash = {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        hex::encode(h.finalize())
    };
    let filename = format!("{prefix}-{}{suffix}", &url_hash[..16]);
    let path = cache_dir.join(filename);

    if path.exists() {
        // Re-check the size budget on the cached copy too: a file may
        // have grown past the operator's new ceiling on a config edit.
        if let Err(e) = check_size_budget(&path, prefix, max_bytes) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "cached file exceeds size budget; removing",
            );
            let _ = fs::remove_file(&path);
        } else if let Some(expected) = expected_sha256 {
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
    let mut resp = download_client()
        .with_context(|| format!("building HTTP client to download {url}"))?
        .get(url)
        .send()
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()
        .with_context(|| format!("downloading {url}"))?;
    // Cap the in-memory buffer to the size budget so a hostile origin
    // cannot exhaust memory with an unbounded body. `take` enforces the
    // ceiling at the read layer; we still validate after the fact.
    let mut buf = Vec::new();
    let cap = if max_bytes == 0 { u64::MAX } else { max_bytes };
    // +1 so the post-write check below distinguishes "exactly at limit"
    // from "tried to overflow"; the validate step rejects either way.
    let read_cap = cap.saturating_add(1);
    resp.by_ref()
        .take(read_cap)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading body for {url}"))?;

    let mut f = fs::File::create(&path).with_context(|| format!("creating cache file {path:?}"))?;
    f.write_all(&buf)
        .with_context(|| format!("writing cache file {path:?}"))?;
    f.sync_all().ok();

    if let Err(e) = check_size_budget(&path, prefix, max_bytes) {
        let _ = fs::remove_file(&path);
        return Err(e).with_context(|| format!("downloaded file exceeds size budget: {url}"));
    }

    if let Some(expected) = expected_sha256 {
        if let Err(e) = validate_sha256(&path, expected) {
            let _ = fs::remove_file(&path);
            return Err(e).with_context(|| format!("downloaded file failed sha256: {url}"));
        }
    }

    Ok(path)
}

/// Reject `path` if its on-disk size exceeds `max_bytes`. `max_bytes`
/// of `0` is treated as "no limit" so callers that explicitly opt out
/// of the budget still get the rest of the load-time pipeline.
fn check_size_budget(path: &Path, kind: &str, max_bytes: u64) -> Result<()> {
    if max_bytes == 0 {
        return Ok(());
    }
    let meta = fs::metadata(path)
        .with_context(|| format!("stat {kind} file at {} for size budget", path.display()))?;
    let len = meta.len();
    if len > max_bytes {
        return Err(anyhow!(
            "{kind} file {} is {} bytes; exceeds the {} byte budget",
            path.display(),
            len,
            max_bytes
        ));
    }
    Ok(())
}

/// Fetch the detached signature at `signature_url`, then verify it
/// against `SHA-256(artifact_bytes)` with the supplied verifying key.
///
/// The signature is expected to be 64 raw bytes (Ed25519 signature
/// length). To keep operator-side tooling simple, signatures provided
/// as a base64 or hex string are also accepted: we try to decode the
/// downloaded body as base64, then hex, then fall back to treating it
/// as the raw 64-byte signature.
fn verify_artifact_signature(
    artifact_path: &Path,
    signature_url: &str,
    verifying_key: &[u8; PUBLIC_KEY_LENGTH],
    cache_dir: &Path,
    kind: &str,
) -> Result<()> {
    let sig_bytes = fetch_signature_bytes(signature_url, cache_dir, kind)?;

    let mut hasher = Sha256::new();
    let mut f = fs::File::open(artifact_path)
        .with_context(|| format!("opening {kind} for signature verification"))?;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut chunk)
            .with_context(|| format!("reading {kind} for signature verification"))?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    let digest = hasher.finalize();

    let key = VerifyingKey::from_bytes(verifying_key)
        .map_err(|e| anyhow!("invalid Ed25519 verifying key: {e}"))?;
    let sig_arr: [u8; SIGNATURE_LENGTH] = sig_bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "{kind} signature is {} bytes; Ed25519 signatures are {} bytes",
            sig_bytes.len(),
            SIGNATURE_LENGTH
        )
    })?;
    let signature = Signature::from_bytes(&sig_arr);
    key.verify(digest.as_slice(), &signature)
        .map_err(|e| anyhow!("{kind} signature did not verify against the configured key: {e}"))?;
    tracing::info!(
        kind = kind,
        artifact = %artifact_path.display(),
        "ed25519 signature verified",
    );
    Ok(())
}

/// Fetch the signature body from `url`, caching it in `cache_dir`
/// alongside the artifact. Accepts the body as raw 64 bytes, a base64
/// string, or a hex string; whichever decodes to 64 bytes wins.
fn fetch_signature_bytes(url: &str, cache_dir: &Path, kind: &str) -> Result<Vec<u8>> {
    let url_hash = {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        hex::encode(h.finalize())
    };
    let path = cache_dir.join(format!("{kind}-sig-{}.bin", &url_hash[..16]));

    let raw = if path.exists() {
        fs::read(&path).with_context(|| format!("reading cached {kind} signature {path:?}"))?
    } else {
        tracing::info!(url = url, "downloading detached signature");
        let mut resp = download_client()
            .with_context(|| format!("building HTTP client to download signature {url}"))?
            .get(url)
            .send()
            .with_context(|| format!("downloading signature {url}"))?
            .error_for_status()
            .with_context(|| format!("downloading signature {url}"))?;
        // Hard cap at 4 KiB. A signature is 64 bytes raw, ~88 bytes
        // base64, ~128 bytes hex; 4 KiB is generous and rules out a
        // hostile signature server returning gigabytes.
        let mut buf = Vec::new();
        resp.by_ref()
            .take(4096)
            .read_to_end(&mut buf)
            .with_context(|| format!("reading signature body for {url}"))?;
        if let Err(e) = fs::write(&path, &buf) {
            tracing::warn!(error = %e, path = %path.display(), "could not cache signature");
        }
        buf
    };

    decode_signature_bytes(&raw)
}

/// Try the three reasonable transport encodings (raw, base64, hex) for
/// a 64-byte Ed25519 signature.
fn decode_signature_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() == SIGNATURE_LENGTH {
        return Ok(raw.to_vec());
    }
    let trimmed = std::str::from_utf8(raw).ok().map(str::trim);
    if let Some(text) = trimmed {
        if let Ok(decoded) = BASE64_STANDARD.decode(text) {
            if decoded.len() == SIGNATURE_LENGTH {
                return Ok(decoded);
            }
        }
        if let Ok(decoded) = hex::decode(text) {
            if decoded.len() == SIGNATURE_LENGTH {
                return Ok(decoded);
            }
        }
    }
    Err(anyhow!(
        "detached signature must be 64 raw bytes, base64, or hex; got {} bytes",
        raw.len()
    ))
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

/// Build a blocking HTTP client for model / signature downloads with finite
/// timeouts, so a hung origin cannot stall startup indefinitely (WOR-602).
///
/// A connect timeout bounds a no-response-on-connect hang; a generous total
/// timeout bounds a stalled mid-download while still allowing large models.
fn download_client() -> reqwest::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(300))
        .build()
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

    #[test]
    fn check_size_budget_rejects_oversized_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big.bin");
        fs::write(&path, vec![0u8; 1024]).unwrap();
        let err = check_size_budget(&path, "model", 512).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds") && msg.contains("512"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn check_size_budget_accepts_file_at_or_under_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.bin");
        fs::write(&path, vec![0u8; 1024]).unwrap();
        // Exactly at the limit is fine; over it is not.
        check_size_budget(&path, "model", 1024).unwrap();
        check_size_budget(&path, "model", 2048).unwrap();
    }

    #[test]
    fn check_size_budget_zero_means_unbounded() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("any.bin");
        fs::write(&path, vec![0u8; 4096]).unwrap();
        // 0 = no limit; 4 KiB through 0 is fine.
        check_size_budget(&path, "model", 0).unwrap();
    }

    #[test]
    fn load_with_options_rejects_oversized_tokenizer() {
        let tmp = tempfile::tempdir().unwrap();
        let model = tmp.path().join("a.onnx");
        let tok = tmp.path().join("a.json");
        // The exact contents do not matter: the size budget is checked
        // before either parser runs, so an oversized file errors out
        // before tract / tokenizers ever sees the bytes.
        fs::write(&model, vec![0u8; 16]).unwrap();
        fs::write(&tok, vec![0u8; 1024]).unwrap();
        let opts = LoadOptions::default()
            .with_max_model_bytes(1024)
            .with_max_tokenizer_bytes(512);
        let err = match OnnxClassifier::load_with_options(&model, &tok, None, &opts) {
            Ok(_) => panic!("expected size-budget rejection"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("tokenizer") && msg.contains("exceeds"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn load_options_default_uses_200mb_limit() {
        let opts = LoadOptions::default();
        assert_eq!(opts.effective_model_limit(), MAX_MODEL_BYTES_DEFAULT);
        assert_eq!(opts.effective_tokenizer_limit(), MAX_MODEL_BYTES_DEFAULT);
        assert_eq!(MAX_MODEL_BYTES_DEFAULT, 200 * 1024 * 1024);
    }

    #[test]
    fn parse_ed25519_pubkey_accepts_hex() {
        let raw = [7u8; PUBLIC_KEY_LENGTH];
        let parsed = parse_ed25519_pubkey(&hex::encode(raw)).unwrap();
        assert_eq!(parsed, raw);
    }

    #[test]
    fn parse_ed25519_pubkey_rejects_short_hex() {
        let err = parse_ed25519_pubkey("aabb").unwrap_err();
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn parse_ed25519_pubkey_round_trips_pem_spki() {
        // Build the canonical Ed25519 SPKI for a known raw key, wrap
        // it in PEM, and round-trip back. This is the same shape
        // `openssl genpkey -algorithm Ed25519 -outform PEM -pubout`
        // produces.
        let raw = [9u8; PUBLIC_KEY_LENGTH];
        let mut der = Vec::with_capacity(44);
        der.extend_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]);
        der.extend_from_slice(&raw);
        let b64 = BASE64_STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        let parsed = parse_ed25519_pubkey(&pem).unwrap();
        assert_eq!(parsed, raw);
    }

    #[test]
    fn parse_ed25519_pubkey_rejects_non_ed25519_pem() {
        // Right length, wrong algorithm OID prefix.
        let mut der = vec![0u8; 44];
        der[0] = 0x30;
        let b64 = BASE64_STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        let err = parse_ed25519_pubkey(&pem).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Ed25519") || msg.contains("OID"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn decode_signature_bytes_accepts_raw() {
        let raw = vec![0u8; SIGNATURE_LENGTH];
        let out = decode_signature_bytes(&raw).unwrap();
        assert_eq!(out.len(), SIGNATURE_LENGTH);
    }

    #[test]
    fn decode_signature_bytes_accepts_base64() {
        let raw = vec![0u8; SIGNATURE_LENGTH];
        let b64 = BASE64_STANDARD.encode(&raw);
        let out = decode_signature_bytes(b64.as_bytes()).unwrap();
        assert_eq!(out.len(), SIGNATURE_LENGTH);
    }

    #[test]
    fn decode_signature_bytes_accepts_hex() {
        let raw = vec![0u8; SIGNATURE_LENGTH];
        let h = hex::encode(&raw);
        let out = decode_signature_bytes(h.as_bytes()).unwrap();
        assert_eq!(out.len(), SIGNATURE_LENGTH);
    }

    #[test]
    fn decode_signature_bytes_rejects_wrong_length() {
        let err = decode_signature_bytes(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("64"));
    }

    #[test]
    fn verify_artifact_signature_accepts_valid_pair() {
        use ed25519_dalek::{Signer, SigningKey};

        let tmp = tempfile::tempdir().unwrap();
        let artifact = tmp.path().join("model.onnx");
        let payload = b"any-classifier-payload";
        fs::write(&artifact, payload).unwrap();

        // Generate a key pair deterministically; sign SHA-256(payload).
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let digest = hasher.finalize();
        let sig = signing.sign(digest.as_slice());

        // Stage the signature locally so the function does not have to
        // hit the network. The signature URL hash determines the cache
        // filename; pre-write the cached form.
        let sig_url = "https://example.invalid/sig.bin";
        let mut h = Sha256::new();
        h.update(sig_url.as_bytes());
        let url_hash = hex::encode(h.finalize());
        let sig_path = tmp
            .path()
            .join(format!("model-sig-{}.bin", &url_hash[..16]));
        fs::write(&sig_path, sig.to_bytes()).unwrap();

        verify_artifact_signature(&artifact, sig_url, &pubkey, tmp.path(), "model").unwrap();
    }

    #[test]
    fn verify_artifact_signature_rejects_wrong_key() {
        use ed25519_dalek::{Signer, SigningKey};

        let tmp = tempfile::tempdir().unwrap();
        let artifact = tmp.path().join("model.onnx");
        fs::write(&artifact, b"payload").unwrap();

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(b"payload");
        let digest = hasher.finalize();
        let sig = signing.sign(digest.as_slice());

        let sig_url = "https://example.invalid/sig.bin";
        let mut h = Sha256::new();
        h.update(sig_url.as_bytes());
        let url_hash = hex::encode(h.finalize());
        let sig_path = tmp
            .path()
            .join(format!("model-sig-{}.bin", &url_hash[..16]));
        fs::write(&sig_path, sig.to_bytes()).unwrap();

        // Verify with a *different* key; must reject.
        let wrong = SigningKey::from_bytes(&[99u8; 32])
            .verifying_key()
            .to_bytes();
        let err =
            verify_artifact_signature(&artifact, sig_url, &wrong, tmp.path(), "model").unwrap_err();
        assert!(err.to_string().contains("did not verify"));
    }
}
