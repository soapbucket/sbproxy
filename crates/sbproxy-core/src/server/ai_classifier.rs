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
    if norm <= f32::EPSILON {
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
    if best < min_score {
        return None;
    }
    if let Some((second, _)) = scored.get(1) {
        if best - second < min_margin {
            return None;
        }
    }
    Some(ClassifierVerdict {
        label: label.clone(),
        score: best,
    })
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
}
