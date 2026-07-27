//! Embedding-backed classifier backend for the AI guardrail pipeline.
//!
//! Implements `sbproxy_ai::guardrails::TextClassifier` on top of the
//! in-process MiniLM embedder. Classification is nearest-centroid: each
//! configured class contributes example prompts, those are embedded once
//! at load time and averaged into a unit vector, and a prompt is labeled
//! with the class whose centroid it is closest to.
//!
//! This lives in `sbproxy-core` rather than `sbproxy-ai` because
//! `sbproxy-classifiers` depends on `sbproxy-ai`, so the ONNX types
//! cannot be named from inside `sbproxy-ai` without a dependency cycle.
//! The same constraint put the semantic cache's embedder here.
//!
//! Embeddings from `OnnxEmbedder::embed` are already L2-normalized, so a
//! dot product is the cosine similarity and no extra division is needed.

#[cfg(any(feature = "inprocess-classify", test))]
use sbproxy_ai::guardrails::ClassifierVerdict;

// The centroid scoring path is only reachable when the embedder is
// compiled in, and every caller sits behind `inprocess-classify`. Gating
// these to match says that plainly, rather than suppressing the lint and
// leaving a reader to wonder whether the code is reachable at all.
/// Dot product of two equal-length vectors.
#[cfg(any(feature = "inprocess-classify", test))]
fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Average `vectors` into a single unit vector.
///
/// Every vector must be non-empty, finite, and have the same dimension.
/// Returns `None` when the input is malformed or when the sum has no
/// direction, which is the case for an all-zero input.
///
/// Summing and then normalizing is equivalent to averaging and then
/// normalizing, so the element count never enters the arithmetic.
#[cfg(any(feature = "inprocess-classify", test))]
pub(super) fn build_centroid(vectors: &[Vec<f32>]) -> Option<Vec<f32>> {
    let dim = vectors.first()?.len();
    if dim == 0 {
        return None;
    }
    let mut sum = vec![0f32; dim];
    for v in vectors {
        if v.len() != dim || v.iter().any(|value| !value.is_finite()) {
            return None;
        }
        for (s, x) in sum.iter_mut().zip(v.iter()) {
            *s += x;
        }
    }
    let norm = dot(&sum, &sum).sqrt();
    if !norm.is_finite() || norm <= f32::EPSILON {
        return None;
    }
    for s in sum.iter_mut() {
        *s /= norm;
    }
    Some(sum)
}

/// Pick the centroid closest to `embedding`.
///
/// Returns `None` unless the best class clears `min_score` and beats the
/// runner-up by at least `min_margin`. The margin check is what keeps a
/// prompt sitting between two classes from being labeled arbitrarily; a
/// single configured class has no runner-up and so skips that check.
#[cfg(any(feature = "inprocess-classify", test))]
pub(super) fn nearest_centroid(
    embedding: &[f32],
    centroids: &[(String, Vec<f32>)],
    min_score: f32,
    min_margin: f32,
) -> Option<ClassifierVerdict> {
    if embedding.is_empty() {
        return None;
    }
    let mut scored: Vec<(f32, &String)> = centroids
        .iter()
        .filter(|(_, c)| c.len() == embedding.len())
        .map(|(label, c)| (dot(embedding, c), label))
        .collect();
    if scored.is_empty() {
        return None;
    }
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    let (best, label) = (scored[0].0, scored[0].1);
    // NaN compares false against everything, so it needs an explicit check.
    if best.is_nan() || best < min_score {
        return None;
    }
    if let Some((second, _)) = scored.get(1) {
        // NaN compares false against everything, so it needs an explicit check.
        if (best - second).is_nan() || best - second < min_margin {
            return None;
        }
    }
    Some(ClassifierVerdict {
        label: label.clone(),
        score: best,
    })
}

/// Validate one query embedding before applying score and margin thresholds.
///
/// Structural embedding defects are classifier errors. A valid vector that
/// does not clear the configured thresholds remains an ordinary abstention.
#[cfg(any(feature = "inprocess-classify", test))]
fn classify_embedding(
    embedding: &[f32],
    centroids: &[(String, Vec<f32>)],
    min_score: f32,
    min_margin: f32,
) -> anyhow::Result<Option<ClassifierVerdict>> {
    let expected_dimension = centroids
        .first()
        .map(|(_, centroid)| centroid.len())
        .filter(|dimension| *dimension > 0)
        .ok_or_else(|| anyhow::anyhow!("classifier has no usable centroid dimension"))?;
    if embedding.is_empty() {
        anyhow::bail!("classifier query embedding is empty");
    }
    if embedding.iter().any(|value| !value.is_finite()) {
        anyhow::bail!("classifier query embedding contains a non-finite value");
    }
    let norm = dot(embedding, embedding).sqrt();
    if !norm.is_finite() || norm <= f32::EPSILON {
        anyhow::bail!("classifier query embedding has no usable direction");
    }
    if embedding.len() != expected_dimension {
        anyhow::bail!(
            "classifier query embedding dimension {} does not match {expected_dimension}",
            embedding.len()
        );
    }
    if centroids.iter().any(|(_, centroid)| {
        centroid.len() != expected_dimension || centroid.iter().any(|value| !value.is_finite())
    }) {
        anyhow::bail!("classifier contains a malformed centroid");
    }
    Ok(nearest_centroid(
        embedding, centroids, min_score, min_margin,
    ))
}

/// Nearest-centroid classifier over the in-process MiniLM embedder.
#[cfg(feature = "inprocess-classify")]
struct CentroidClassifier {
    /// Loaded ONNX model + tokenizer, shared with any other classifier
    /// configured against the same model and tokenizer path pair.
    embedder: std::sync::Arc<sbproxy_classifiers::OnnxEmbedder>,
    /// Per-class unit centroids, in configuration order.
    centroids: Vec<(String, Vec<f32>)>,
    /// Minimum cosine similarity the winning class must reach.
    min_score: f32,
    /// Minimum gap between the best and second-best class.
    min_margin: f32,
    /// Human-readable model identifier used in inference metrics.
    model_label: String,
}

// Hand-written because neither the tract model nor the tokenizer inside
// `OnnxEmbedder` implements `Debug`, and the `Guardrail` enum requires it.
#[cfg(feature = "inprocess-classify")]
impl std::fmt::Debug for CentroidClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CentroidClassifier")
            .field("classes", &self.centroids.len())
            .field("min_score", &self.min_score)
            .field("min_margin", &self.min_margin)
            .finish()
    }
}

#[cfg(feature = "inprocess-classify")]
impl sbproxy_ai::guardrails::TextClassifier for CentroidClassifier {
    fn classify(&self, text: &str) -> anyhow::Result<Option<ClassifierVerdict>> {
        let started = std::time::Instant::now();
        let classified = self.embedder.embed(text).and_then(|output| {
            classify_embedding(
                &output.values,
                &self.centroids,
                self.min_score,
                self.min_margin,
            )
        });
        let result = if classified.is_ok() { "ok" } else { "error" };
        sbproxy_observe::metrics::record_inference(
            "classify",
            "inprocess",
            &self.model_label,
            result,
            started.elapsed().as_secs_f64(),
        );
        match classified {
            Ok(verdict) => Ok(verdict),
            Err(e) => {
                tracing::warn!(error = %e, "classifier embedding failed; no label emitted");
                Err(e)
            }
        }
    }
}

#[cfg(feature = "inprocess-classify")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ArtifactIdentity {
    /// Absolute configured pathname before resolving symlinks. This lets a
    /// reload retire the previous generation when the same symlink is
    /// repointed to a different canonical file.
    source_path: std::path::PathBuf,
    canonical_path: std::path::PathBuf,
    byte_len: u64,
    sha256: [u8; 32],
}

#[cfg(feature = "inprocess-classify")]
#[derive(Debug)]
struct ArtifactSnapshot {
    identity: ArtifactIdentity,
    bytes: Vec<u8>,
}

#[cfg(feature = "inprocess-classify")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EmbedderCacheKey {
    model: ArtifactIdentity,
    tokenizer: ArtifactIdentity,
    max_model_bytes: Option<u64>,
}

#[cfg(feature = "inprocess-classify")]
#[derive(Debug)]
struct EmbedderArtifactSnapshots {
    key: EmbedderCacheKey,
    model: ArtifactSnapshot,
    tokenizer: ArtifactSnapshot,
}

#[cfg(feature = "inprocess-classify")]
fn cache_entry_is_stale(cached: &EmbedderCacheKey, current: &EmbedderCacheKey) -> bool {
    let same_model_source = cached.model.source_path == current.model.source_path
        || cached.model.canonical_path == current.model.canonical_path;
    let same_tokenizer_source = cached.tokenizer.source_path == current.tokenizer.source_path
        || cached.tokenizer.canonical_path == current.tokenizer.canonical_path;
    let replaced_model = same_model_source && cached.model != current.model;
    let replaced_tokenizer = same_tokenizer_source && cached.tokenizer != current.tokenizer;
    replaced_model || replaced_tokenizer
}

#[cfg(feature = "inprocess-classify")]
fn artifact_snapshot(
    path: &std::path::Path,
    kind: &str,
    max_bytes: u64,
) -> anyhow::Result<ArtifactSnapshot> {
    use anyhow::{anyhow, Context};
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let source_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve the current directory for classifier artifacts")?
            .join(path)
    };
    let canonical_path = std::fs::canonicalize(&source_path)
        .with_context(|| format!("failed to resolve classifier {kind} at {source_path:?}"))?;
    // Open once, then derive both the digest and the exact parser input from
    // this handle. A rename can replace `canonical_path` after this point
    // without changing the generation represented by `file`.
    let mut file = std::fs::File::open(&canonical_path)
        .with_context(|| format!("failed to open classifier {kind} at {canonical_path:?}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect classifier {kind} at {canonical_path:?}"))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "classifier {kind} at {canonical_path:?} is not a regular file"
        ));
    }
    let byte_len = metadata.len();
    if max_bytes != 0 && byte_len > max_bytes {
        return Err(anyhow!(
            "classifier {kind} at {canonical_path:?} is {byte_len} bytes, \
             exceeding the configured {max_bytes}-byte limit"
        ));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let initial_capacity = usize::try_from(byte_len.min(1024 * 1024))
        .context("classifier artifact length does not fit in memory")?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    let mut bytes_read = 0_u64;
    loop {
        let count = file.read(&mut buffer).with_context(|| {
            format!("failed to snapshot classifier {kind} at {canonical_path:?}")
        })?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("classifier {kind} size overflow while reading"))?;
        if max_bytes != 0 && bytes_read > max_bytes {
            return Err(anyhow!(
                "classifier {kind} at {canonical_path:?} grew beyond the configured \
                 {max_bytes}-byte limit while it was read"
            ));
        }
        hasher.update(&buffer[..count]);
        bytes.extend_from_slice(&buffer[..count]);
    }
    let after_metadata = file
        .metadata()
        .with_context(|| format!("failed to re-inspect classifier {kind} at {canonical_path:?}"))?;
    if bytes_read != byte_len || after_metadata.len() != byte_len {
        return Err(anyhow!(
            "classifier {kind} at {canonical_path:?} changed while its snapshot was read"
        ));
    }

    Ok(ArtifactSnapshot {
        identity: ArtifactIdentity {
            source_path,
            canonical_path,
            byte_len,
            sha256: hasher.finalize().into(),
        },
        bytes,
    })
}

#[cfg(feature = "inprocess-classify")]
fn embedder_artifact_snapshots(
    cfg: &sbproxy_ai::guardrails::EmbeddingBackendConfig,
) -> anyhow::Result<EmbedderArtifactSnapshots> {
    let model_limit = cfg
        .max_model_bytes
        .unwrap_or(sbproxy_classifiers::MAX_MODEL_BYTES_DEFAULT);
    let model = artifact_snapshot(std::path::Path::new(&cfg.model_path), "model", model_limit)?;
    let tokenizer = artifact_snapshot(
        std::path::Path::new(&cfg.tokenizer_path),
        "tokenizer",
        sbproxy_classifiers::MAX_MODEL_BYTES_DEFAULT,
    )?;
    let key = EmbedderCacheKey {
        model: model.identity.clone(),
        tokenizer: tokenizer.identity.clone(),
        max_model_bytes: cfg.max_model_bytes,
    };
    Ok(EmbedderArtifactSnapshots {
        key,
        model,
        tokenizer,
    })
}

#[cfg(all(feature = "inprocess-classify", test))]
fn embedder_cache_key(
    cfg: &sbproxy_ai::guardrails::EmbeddingBackendConfig,
) -> anyhow::Result<EmbedderCacheKey> {
    Ok(embedder_artifact_snapshots(cfg)?.key)
}

#[cfg(feature = "inprocess-classify")]
fn load_embedder_from_snapshots_with<T>(
    snapshots: &EmbedderArtifactSnapshots,
    options: &sbproxy_classifiers::LoadOptions,
    loader: impl FnOnce(&[u8], &[u8], &sbproxy_classifiers::LoadOptions) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    loader(&snapshots.model.bytes, &snapshots.tokenizer.bytes, options)
}

/// Load the embedder for `cfg`, reusing an already-loaded one when the
/// same immutable artifacts and size policy have been seen before.
///
/// Loading parses the ONNX graph and can take hundreds of milliseconds,
/// so two origins that point at the same model share one instance.
#[cfg(feature = "inprocess-classify")]
fn shared_embedder(
    cfg: &sbproxy_ai::guardrails::EmbeddingBackendConfig,
) -> anyhow::Result<std::sync::Arc<sbproxy_classifiers::OnnxEmbedder>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock, Weak};

    /// Already-loaded embedders keyed by artifact content and the requested
    /// model-size policy. Paths alone are insufficient: a hot reload can
    /// replace either artifact in place, and a stricter origin must not reuse
    /// a model that bypassed its own limit. Weak values ensure the cache never
    /// pins a model after every reload-managed pipeline using it is gone.
    type EmbedderCache = HashMap<EmbedderCacheKey, Weak<sbproxy_classifiers::OnnxEmbedder>>;

    static CACHE: OnceLock<Mutex<EmbedderCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // Capture the exact bytes and derive their identity before any cache
    // lookup. The eventual parser consumes these buffers rather than
    // reopening the configured pathname.
    let snapshots = embedder_artifact_snapshots(cfg)?;
    let key = snapshots.key.clone();
    if let Ok(mut map) = cache.lock() {
        // Drop an older generation at these paths before looking up the
        // current identity. Existing pipelines keep their Arc until their
        // in-flight requests finish, while the process-global cache no longer
        // pins the stale files.
        map.retain(|cached, embedder| {
            !cache_entry_is_stale(cached, &key) && embedder.strong_count() > 0
        });
        if let Some(embedder) = map.get(&key).and_then(Weak::upgrade) {
            return Ok(embedder);
        }
        // The file-size policy was checked before this lookup. Reusing the
        // same immutable artifacts across two acceptable limits is safe and
        // avoids parsing the ONNX graph twice; record the current policy as
        // an alias so subsequent lookups are exact.
        if let Some(existing) = map.iter().find_map(|(cached, embedder)| {
            (cached.model == key.model && cached.tokenizer == key.tokenizer)
                .then(|| embedder.upgrade())
                .flatten()
        }) {
            map.insert(key, Arc::downgrade(&existing));
            return Ok(existing);
        }
    }
    let mut options = sbproxy_classifiers::LoadOptions::default();
    if let Some(bytes) = cfg.max_model_bytes {
        options = options.with_max_model_bytes(bytes);
    }
    let embedder = Arc::new(load_embedder_from_snapshots_with(
        &snapshots,
        &options,
        sbproxy_classifiers::OnnxEmbedder::load_from_bytes_with_options,
    )?);
    if let Ok(mut map) = cache.lock() {
        map.insert(key, Arc::downgrade(&embedder));
    }
    Ok(embedder)
}

/// Build a classifier backend for `cfg`.
///
/// Embed every configured example and require each class to produce a unit
/// centroid. A malformed example rejects construction because skipping it
/// would silently change the configured classifier.
#[cfg(feature = "inprocess-classify")]
fn embed_class_examples(
    cfg: &sbproxy_ai::guardrails::ClassifierConfig,
    label: &str,
    examples: &[String],
    mut embed: impl FnMut(&str) -> anyhow::Result<Vec<f32>>,
) -> anyhow::Result<Vec<Vec<f32>>> {
    let mut vectors = Vec::with_capacity(examples.len());
    let mut expected_dimension = None;
    for (index, example) in examples.iter().enumerate() {
        let bounded = cfg.bounded_text(example);
        let values = embed(bounded).map_err(|error| {
            anyhow::anyhow!("classifier class `{label}` example {index} embedding failed: {error}")
        })?;
        if values.is_empty() {
            anyhow::bail!("classifier class `{label}` example {index} embedding is empty");
        }
        if values.iter().any(|value| !value.is_finite()) {
            anyhow::bail!(
                "classifier class `{label}` example {index} embedding contains a non-finite value"
            );
        }
        match expected_dimension {
            Some(dimension) if values.len() != dimension => {
                anyhow::bail!(
                    "classifier class `{label}` example {index} embedding dimension {} \
                     does not match {dimension}",
                    values.len()
                );
            }
            None => expected_dimension = Some(values.len()),
            Some(_) => {}
        }
        vectors.push(values);
    }
    Ok(vectors)
}

#[cfg(feature = "inprocess-classify")]
fn build_class_centroids(
    cfg: &sbproxy_ai::guardrails::ClassifierConfig,
    mut embed: impl FnMut(&str) -> anyhow::Result<Vec<f32>>,
) -> anyhow::Result<Vec<(String, Vec<f32>)>> {
    let mut centroids = Vec::with_capacity(cfg.classes.len());
    let mut expected_dimension = None;
    for (label, examples) in &cfg.classes {
        let vectors = embed_class_examples(cfg, label, examples, &mut embed)?;
        let centroid = build_centroid(&vectors)
            .ok_or_else(|| anyhow::anyhow!("classifier class `{label}` has no usable centroid"))?;
        match expected_dimension {
            Some(dimension) if centroid.len() != dimension => {
                anyhow::bail!(
                    "classifier class `{label}` centroid dimension {} does not match {dimension}",
                    centroid.len()
                );
            }
            None => expected_dimension = Some(centroid.len()),
            Some(_) => {}
        }
        centroids.push((label.clone(), centroid));
    }
    Ok(centroids)
}

#[cfg(feature = "inprocess-classify")]
fn build_backend(
    cfg: &sbproxy_ai::guardrails::ClassifierConfig,
) -> anyhow::Result<std::sync::Arc<dyn sbproxy_ai::guardrails::TextClassifier>> {
    // Only one backend variant exists today, so this destructure is
    // irrefutable.
    let sbproxy_ai::guardrails::ClassifierBackendConfig::Embedding(backend) = &cfg.backend;
    let embedder = shared_embedder(backend)?;
    let centroids = build_class_centroids(cfg, |example| {
        embedder.embed(example).map(|output| output.values)
    })?;
    let model_label = std::path::Path::new(&backend.model_path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "inprocess".to_string());
    tracing::info!(
        classes = centroids.len(),
        model = %model_label,
        "classifier guardrail backend ready"
    );
    Ok(std::sync::Arc::new(CentroidClassifier {
        embedder,
        centroids,
        min_score: backend.min_score,
        min_margin: backend.min_margin,
        model_label,
    }))
}

/// Stand-in used when the binary is built without `inprocess-classify`.
#[cfg(not(feature = "inprocess-classify"))]
fn build_backend(
    _cfg: &sbproxy_ai::guardrails::ClassifierConfig,
) -> anyhow::Result<std::sync::Arc<dyn sbproxy_ai::guardrails::TextClassifier>> {
    anyhow::bail!("this binary was built without the `inprocess-classify` feature")
}

/// Register the classifier backend for the process.
///
/// Registered unconditionally so that a binary built without the feature
/// reports a precise reason instead of the generic "no backend
/// registered" message.
pub(crate) fn install_classifier_factory() {
    sbproxy_ai::guardrails::register_classifier_factory(Box::new(build_backend));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn centroid_of_one_vector_is_that_vector_normalized() {
        let c = build_centroid(&[vec![3.0, 4.0]]).expect("centroid");
        // 3-4-5 triangle: normalizing gives 0.6, 0.8.
        assert!((c[0] - 0.6).abs() < 1e-6, "got {c:?}");
        assert!((c[1] - 0.8).abs() < 1e-6, "got {c:?}");
    }

    #[test]
    fn centroid_averages_then_normalizes() {
        let c = build_centroid(&[vec![1.0, 0.0], vec![0.0, 1.0]]).expect("centroid");
        let inv = 1.0f32 / 2.0f32.sqrt();
        assert!((c[0] - inv).abs() < 1e-6, "got {c:?}");
        assert!((c[1] - inv).abs() < 1e-6, "got {c:?}");
    }

    #[test]
    fn centroid_rejects_empty_and_degenerate_input() {
        assert!(build_centroid(&[]).is_none());
        assert!(build_centroid(&[vec![]]).is_none());
        // A zero vector has no direction, so it cannot be normalized.
        assert!(build_centroid(&[vec![0.0, 0.0]]).is_none());
    }

    #[test]
    fn centroid_rejects_vectors_of_the_wrong_dimension() {
        assert!(build_centroid(&[vec![1.0, 0.0], vec![1.0, 0.0, 0.0]]).is_none());
    }

    #[test]
    fn centroid_rejects_nan_input() {
        // A NaN-poisoned norm must not slip past the EPSILON guard, since
        // every comparison against NaN is false.
        assert!(build_centroid(&[vec![f32::NAN, 0.0]]).is_none());
    }

    #[test]
    fn nearest_centroid_picks_the_closest_class() {
        let centroids = vec![
            (label("documentation"), vec![1.0, 0.0]),
            (label("coding"), vec![0.0, 1.0]),
        ];
        let v = nearest_centroid(&[0.99, 0.14], &centroids, 0.30, 0.05).expect("verdict");
        assert_eq!(v.label, "documentation");
        assert!(v.score > 0.9, "got {}", v.score);
    }

    #[test]
    fn nearest_centroid_rejects_a_weak_best_score() {
        let centroids = vec![
            (label("documentation"), vec![1.0, 0.0]),
            (label("coding"), vec![0.0, 1.0]),
        ];
        // Best cosine is 0.2, below the 0.30 floor.
        assert!(nearest_centroid(&[0.2, 0.1], &centroids, 0.30, 0.05).is_none());
    }

    #[test]
    fn nearest_centroid_rejects_an_ambiguous_prompt() {
        let centroids = vec![
            (label("documentation"), vec![1.0, 0.0]),
            (label("coding"), vec![0.0, 1.0]),
        ];
        // Exactly between the two centroids: both score ~0.707, so the
        // margin is ~0 and no class wins.
        let inv = 1.0f32 / 2.0f32.sqrt();
        assert!(nearest_centroid(&[inv, inv], &centroids, 0.30, 0.05).is_none());
    }

    #[test]
    fn nearest_centroid_allows_a_single_class_with_no_runner_up() {
        let centroids = vec![(label("documentation"), vec![1.0, 0.0])];
        let v = nearest_centroid(&[1.0, 0.0], &centroids, 0.30, 0.05).expect("verdict");
        assert_eq!(v.label, "documentation");
    }

    #[test]
    fn nearest_centroid_still_applies_the_floor_to_a_single_class() {
        let centroids = vec![(label("documentation"), vec![1.0, 0.0])];
        // Only one configured class, so the margin check is skipped, but
        // the score floor still applies. 0.2 is below the 0.30 floor.
        assert!(nearest_centroid(&[0.2, 0.0], &centroids, 0.30, 0.05).is_none());
    }

    #[test]
    fn nearest_centroid_rejects_a_nan_embedding() {
        let centroids = vec![
            (label("documentation"), vec![1.0, 0.0]),
            (label("coding"), vec![0.0, 1.0]),
        ];
        // A NaN-poisoned query must not be able to defeat the score or
        // margin guards, since every comparison against NaN is false.
        assert!(nearest_centroid(&[f32::NAN, 0.0], &centroids, 0.30, 0.05).is_none());
    }

    #[test]
    fn nearest_centroid_handles_empty_input() {
        assert!(nearest_centroid(&[], &[], 0.30, 0.05).is_none());
        assert!(nearest_centroid(&[1.0, 0.0], &[], 0.30, 0.05).is_none());
    }

    #[test]
    fn nearest_centroid_skips_dimension_mismatches() {
        let centroids = vec![
            (label("bad"), vec![1.0, 0.0, 0.0]),
            (label("good"), vec![1.0, 0.0]),
        ];
        let v = nearest_centroid(&[1.0, 0.0], &centroids, 0.30, 0.05).expect("verdict");
        assert_eq!(v.label, "good");
    }

    #[test]
    fn malformed_request_embeddings_are_classifier_errors() {
        let centroids = vec![
            (label("documentation"), vec![1.0, 0.0]),
            (label("coding"), vec![0.0, 1.0]),
        ];
        for malformed in [
            Vec::new(),
            vec![0.0, 0.0],
            vec![f32::NAN, 0.0],
            vec![f32::INFINITY, 0.0],
            vec![1.0, 0.0, 0.0],
        ] {
            assert!(
                classify_embedding(&malformed, &centroids, 0.30, 0.05).is_err(),
                "malformed request embedding must not become a threshold abstention: {malformed:?}"
            );
        }
    }

    #[test]
    fn legitimate_threshold_and_margin_abstentions_remain_ok_none() {
        let centroids = vec![
            (label("documentation"), vec![1.0, 0.0]),
            (label("coding"), vec![0.0, 1.0]),
        ];
        assert_eq!(
            classify_embedding(&[0.2, 0.1], &centroids, 0.30, 0.05)
                .expect("a weak finite embedding is not a backend error"),
            None
        );
        let inv = 1.0f32 / 2.0f32.sqrt();
        assert_eq!(
            classify_embedding(&[inv, inv], &centroids, 0.30, 0.05)
                .expect("an ambiguous finite embedding is not a backend error"),
            None
        );
    }

    #[cfg(feature = "inprocess-classify")]
    fn classifier_config_with_max_chars(
        max_chars: usize,
    ) -> sbproxy_ai::guardrails::ClassifierConfig {
        sbproxy_ai::guardrails::ClassifierConfig {
            backend: sbproxy_ai::guardrails::ClassifierBackendConfig::Embedding(
                sbproxy_ai::guardrails::EmbeddingBackendConfig {
                    model_path: "/unused/model.onnx".to_string(),
                    tokenizer_path: "/unused/tokenizer.json".to_string(),
                    min_score: 0.30,
                    min_margin: 0.05,
                    max_model_bytes: None,
                },
            ),
            classes: std::collections::BTreeMap::from([(
                "documentation".to_string(),
                vec!["write docs".to_string()],
            )]),
            scope: sbproxy_ai::guardrails::ClassifierScope::LastUserMessage,
            max_chars,
        }
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn centroid_example_at_exact_character_cap_is_unchanged() {
        let cfg = classifier_config_with_max_chars(4);
        let examples = vec!["éabc".to_string()];
        let mut seen = Vec::new();

        let vectors = embed_class_examples(&cfg, "documentation", &examples, |text| {
            seen.push(text.to_string());
            Ok(vec![1.0])
        })
        .expect("valid example embeddings");

        assert_eq!(seen, ["éabc"]);
        assert_eq!(vectors, [vec![1.0]]);
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn centroid_example_over_character_cap_is_truncated_before_embedding() {
        let cfg = classifier_config_with_max_chars(4);
        let examples = vec!["éabcd".to_string()];
        let mut seen = Vec::new();

        let vectors = embed_class_examples(&cfg, "documentation", &examples, |text| {
            seen.push(text.to_string());
            Ok(vec![1.0])
        })
        .expect("valid example embeddings");

        assert_eq!(seen, ["éabc"]);
        assert_eq!(vectors, [vec![1.0]]);
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn classifier_construction_requires_a_centroid_for_every_configured_class() {
        let mut cfg = classifier_config_with_max_chars(2000);
        cfg.classes.insert(
            "safe".to_string(),
            vec!["ordinary conversation".to_string()],
        );

        let error = build_class_centroids(&cfg, |text| {
            if text == "ordinary conversation" {
                anyhow::bail!("fixture embedding failure");
            }
            Ok(vec![1.0, 0.0])
        })
        .expect_err("a missing required centroid must fail classifier construction");

        assert!(
            error.to_string().contains("safe"),
            "error must identify the class without a usable centroid: {error}"
        );
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn classifier_construction_rejects_mismatched_class_dimensions() {
        let mut cfg = classifier_config_with_max_chars(2000);
        cfg.classes.insert(
            "safe".to_string(),
            vec!["ordinary conversation".to_string()],
        );

        let error = build_class_centroids(&cfg, |text| {
            if text == "ordinary conversation" {
                Ok(vec![1.0, 0.0, 0.0])
            } else {
                Ok(vec![1.0, 0.0])
            }
        })
        .expect_err("all configured class centroids must have the same dimension");

        assert!(
            error.to_string().contains("dimension"),
            "error must explain the malformed centroid dimensions: {error}"
        );
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn classifier_construction_rejects_an_empty_example_embedding() {
        let mut cfg = classifier_config_with_max_chars(2000);
        cfg.classes.insert(
            "safe".to_string(),
            vec![
                "ordinary conversation".to_string(),
                "empty vector".to_string(),
            ],
        );

        let error = build_class_centroids(&cfg, |text| {
            if text == "empty vector" {
                Ok(Vec::new())
            } else {
                Ok(vec![1.0, 0.0])
            }
        })
        .expect_err("one empty example embedding must reject the configured class");

        assert!(
            error.to_string().contains("safe") && error.to_string().contains("example 1"),
            "error must identify the malformed configured example: {error}"
        );
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn classifier_construction_rejects_a_non_finite_example_embedding() {
        let mut cfg = classifier_config_with_max_chars(2000);
        cfg.classes.insert(
            "safe".to_string(),
            vec![
                "ordinary conversation".to_string(),
                "infinite vector".to_string(),
            ],
        );

        let error = build_class_centroids(&cfg, |text| {
            if text == "infinite vector" {
                Ok(vec![f32::INFINITY, 0.0])
            } else {
                Ok(vec![1.0, 0.0])
            }
        })
        .expect_err("one non-finite example embedding must reject the configured class");

        assert!(
            error.to_string().contains("safe") && error.to_string().contains("example 1"),
            "error must identify the malformed configured example: {error}"
        );
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn classifier_construction_rejects_a_wrong_dimension_example_within_its_class() {
        let mut cfg = classifier_config_with_max_chars(2000);
        cfg.classes.insert(
            "safe".to_string(),
            vec![
                "ordinary conversation".to_string(),
                "wrong dimension".to_string(),
            ],
        );

        let error = build_class_centroids(&cfg, |text| {
            if text == "wrong dimension" {
                Ok(vec![1.0, 0.0, 0.0])
            } else {
                Ok(vec![1.0, 0.0])
            }
        })
        .expect_err("one wrong-dimension example must reject the configured class");

        assert!(
            error.to_string().contains("safe") && error.to_string().contains("example 1"),
            "error must identify the malformed configured example: {error}"
        );
    }

    #[test]
    fn factory_rejects_a_config_whose_model_is_missing() {
        // The factory must return an error rather than panicking, because
        // the guardrail turns that error into an inert guardrail.
        let cfg = sbproxy_ai::guardrails::ClassifierConfig {
            backend: sbproxy_ai::guardrails::ClassifierBackendConfig::Embedding(
                sbproxy_ai::guardrails::EmbeddingBackendConfig {
                    model_path: "/nonexistent/model.onnx".to_string(),
                    tokenizer_path: "/nonexistent/tokenizer.json".to_string(),
                    min_score: 0.30,
                    min_margin: 0.05,
                    max_model_bytes: None,
                },
            ),
            classes: std::collections::BTreeMap::from([(
                "documentation".to_string(),
                vec!["write the readme".to_string()],
            )]),
            scope: sbproxy_ai::guardrails::ClassifierScope::LastUserMessage,
            max_chars: 2000,
        };
        assert!(build_backend(&cfg).is_err());
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn embedder_cache_key_includes_the_requested_model_size_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let model = dir.path().join("model.onnx");
        let tokenizer = dir.path().join("tokenizer.json");
        std::fs::write(&model, b"small-model").expect("model fixture");
        std::fs::write(&tokenizer, b"tokenizer").expect("tokenizer fixture");

        let permissive = sbproxy_ai::guardrails::EmbeddingBackendConfig {
            model_path: model.display().to_string(),
            tokenizer_path: tokenizer.display().to_string(),
            min_score: 0.30,
            min_margin: 0.05,
            max_model_bytes: Some(100),
        };
        let mut strict = permissive.clone();
        strict.max_model_bytes = Some(5);

        let permissive_key = embedder_cache_key(&permissive).expect("permissive key");
        assert!(
            embedder_cache_key(&strict).is_err(),
            "a stricter limit must be enforced before a cache lookup can reuse the model"
        );
        assert_eq!(permissive_key.max_model_bytes, Some(100));
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn embedder_cache_key_changes_when_an_artifact_changes_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let model = dir.path().join("model.onnx");
        let tokenizer = dir.path().join("tokenizer.json");
        std::fs::write(&model, b"model-v1").expect("model fixture");
        std::fs::write(&tokenizer, b"tokenizer").expect("tokenizer fixture");
        let cfg = sbproxy_ai::guardrails::EmbeddingBackendConfig {
            model_path: model.display().to_string(),
            tokenizer_path: tokenizer.display().to_string(),
            min_score: 0.30,
            min_margin: 0.05,
            max_model_bytes: Some(100),
        };

        let before = embedder_cache_key(&cfg).expect("first key");
        std::fs::write(&model, b"model-v2").expect("replace model fixture");
        let after = embedder_cache_key(&cfg).expect("second key");

        assert_ne!(
            before, after,
            "replacing a model at the same path must invalidate cached state"
        );
        assert!(
            cache_entry_is_stale(&before, &after),
            "the cache must release the superseded artifact generation"
        );
    }

    #[cfg(feature = "inprocess-classify")]
    #[test]
    fn embedder_loader_consumes_the_fingerprinted_snapshot_during_aba_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let model = dir.path().join("model.onnx");
        let replacement = dir.path().join("model-b.onnx");
        let restoration = dir.path().join("model-a-restored.onnx");
        let tokenizer = dir.path().join("tokenizer.json");
        std::fs::write(&model, b"model-a").expect("model A fixture");
        std::fs::write(&replacement, b"model-b").expect("model B fixture");
        std::fs::write(&restoration, b"model-a").expect("restored model A fixture");
        std::fs::write(&tokenizer, b"tokenizer-a").expect("tokenizer fixture");
        let cfg = sbproxy_ai::guardrails::EmbeddingBackendConfig {
            model_path: model.display().to_string(),
            tokenizer_path: tokenizer.display().to_string(),
            min_score: 0.30,
            min_margin: 0.05,
            max_model_bytes: Some(100),
        };

        let snapshots =
            embedder_artifact_snapshots(&cfg).expect("capture fingerprinted artifact bytes");
        let consumed = load_embedder_from_snapshots_with(
            &snapshots,
            &sbproxy_classifiers::LoadOptions::default(),
            |model_bytes, tokenizer_bytes, _| {
                std::fs::remove_file(&model).expect("remove model A");
                std::fs::rename(&replacement, &model).expect("install model B");
                assert_eq!(
                    std::fs::read(&model).expect("read path during load"),
                    b"model-b"
                );
                std::fs::remove_file(&model).expect("remove model B");
                std::fs::rename(&restoration, &model).expect("restore model A");
                Ok((model_bytes.to_vec(), tokenizer_bytes.to_vec()))
            },
        )
        .expect("snapshot consumer");

        assert_eq!(consumed.0, b"model-a");
        assert_eq!(consumed.1, b"tokenizer-a");
        assert_eq!(
            snapshots.key,
            embedder_cache_key(&cfg).expect("identity after ABA restoration"),
            "the A-to-B-to-A path identity is intentionally unchanged"
        );
    }
}
