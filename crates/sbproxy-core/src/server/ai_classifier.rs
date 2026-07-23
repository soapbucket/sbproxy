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

use sbproxy_ai::guardrails::ClassifierVerdict;

/// Dot product of two equal-length vectors.
fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Average `vectors` into a single unit vector.
///
/// Vectors whose dimension does not match the first entry are skipped.
/// Returns `None` when there is nothing usable to average or when the
/// sum has no direction, which is the case for an all-zero input.
///
/// Summing and then normalizing is equivalent to averaging and then
/// normalizing, so the element count never enters the arithmetic.
pub(super) fn build_centroid(vectors: &[Vec<f32>]) -> Option<Vec<f32>> {
    let dim = vectors.first()?.len();
    if dim == 0 {
        return None;
    }
    let mut sum = vec![0f32; dim];
    let mut used = 0usize;
    for v in vectors.iter().filter(|v| v.len() == dim) {
        for (s, x) in sum.iter_mut().zip(v.iter()) {
            *s += x;
        }
        used += 1;
    }
    if used == 0 {
        return None;
    }
    let norm = dot(&sum, &sum).sqrt();
    // NaN compares false against everything, so it needs an explicit check.
    if norm.is_nan() || norm <= f32::EPSILON {
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
    fn classify(&self, text: &str) -> Option<ClassifierVerdict> {
        let started = std::time::Instant::now();
        let embedded = self.embedder.embed(text);
        let result = if embedded.is_ok() { "ok" } else { "error" };
        sbproxy_observe::metrics::record_inference(
            "classify",
            "inprocess",
            &self.model_label,
            result,
            started.elapsed().as_secs_f64(),
        );
        let out = match embedded {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "classifier embedding failed; no label emitted");
                return None;
            }
        };
        nearest_centroid(
            &out.values,
            &self.centroids,
            self.min_score,
            self.min_margin,
        )
    }
}

/// Load the embedder for `cfg`, reusing an already-loaded one when the
/// same model and tokenizer pair has been seen before.
///
/// Loading parses the ONNX graph and can take hundreds of milliseconds,
/// so two origins that point at the same model share one instance.
#[cfg(feature = "inprocess-classify")]
fn shared_embedder(
    cfg: &sbproxy_ai::guardrails::EmbeddingBackendConfig,
) -> anyhow::Result<std::sync::Arc<sbproxy_classifiers::OnnxEmbedder>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    /// Already-loaded embedders keyed by their (model_path, tokenizer_path)
    /// pair, so two classifier origins pointed at the same files share one
    /// loaded model instead of parsing the ONNX graph twice.
    type EmbedderCache = HashMap<(String, String), Arc<sbproxy_classifiers::OnnxEmbedder>>;

    static CACHE: OnceLock<Mutex<EmbedderCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (cfg.model_path.clone(), cfg.tokenizer_path.clone());
    if let Ok(map) = cache.lock() {
        if let Some(e) = map.get(&key) {
            return Ok(Arc::clone(e));
        }
    }
    let mut options = sbproxy_classifiers::LoadOptions::default();
    if let Some(bytes) = cfg.max_model_bytes {
        options = options.with_max_model_bytes(bytes);
    }
    let embedder = Arc::new(sbproxy_classifiers::OnnxEmbedder::load_with_options(
        std::path::Path::new(&cfg.model_path),
        std::path::Path::new(&cfg.tokenizer_path),
        &options,
    )?);
    if let Ok(mut map) = cache.lock() {
        map.insert(key, Arc::clone(&embedder));
    }
    Ok(embedder)
}

/// Build a classifier backend for `cfg`.
///
/// Embeds every example prompt once and folds each class into a unit
/// centroid. A class whose examples all fail to embed is dropped with a
/// warning rather than failing the whole load, so one bad example does
/// not cost the operator the other classes.
#[cfg(feature = "inprocess-classify")]
fn build_backend(
    cfg: &sbproxy_ai::guardrails::ClassifierConfig,
) -> anyhow::Result<std::sync::Arc<dyn sbproxy_ai::guardrails::TextClassifier>> {
    // This factory only serves the embedding backend. The LLM backend
    // is async and is built inside sbproxy-ai, so it never reaches
    // here; the guard exists so a future third variant fails loudly
    // instead of being silently treated as an embedding one.
    let sbproxy_ai::guardrails::ClassifierBackendConfig::Embedding(backend) = &cfg.backend else {
        anyhow::bail!("the in-process classifier factory only builds `kind: embedding` backends");
    };
    let embedder = shared_embedder(backend)?;
    let mut centroids: Vec<(String, Vec<f32>)> = Vec::new();
    for (label, examples) in &cfg.classes {
        let vectors: Vec<Vec<f32>> = examples
            .iter()
            .filter_map(|e| match embedder.embed(e) {
                Ok(o) => Some(o.values),
                Err(err) => {
                    tracing::warn!(error = %err, class = %label, "skipping unembeddable example");
                    None
                }
            })
            .collect();
        match build_centroid(&vectors) {
            Some(c) => centroids.push((label.clone(), c)),
            None => tracing::warn!(class = %label, "class has no usable examples; dropping it"),
        }
    }
    if centroids.is_empty() {
        anyhow::bail!("classifier has no usable class centroids");
    }
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
    fn centroid_skips_vectors_of_the_wrong_dimension() {
        let c = build_centroid(&[vec![1.0, 0.0], vec![1.0, 0.0, 0.0]]).expect("centroid");
        assert_eq!(c.len(), 2);
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
}
