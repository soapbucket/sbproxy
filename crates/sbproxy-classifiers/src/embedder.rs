// SPDX-License-Identifier: Apache-2.0
//! ONNX sentence-embedding support for the tract engine.
//!
//! Mirrors [`crate::OnnxClassifier`]'s loader, size-budget, and cache
//! conventions but produces an L2-normalized mean-pooled sentence vector
//! instead of a class label. Used by the OSS classifier sidecar's `Embed`
//! RPC and by the in-process embedding option for the AI gateway semantic
//! cache. Runs on pure-Rust `tract`, so it cross-compiles and air-gaps the
//! same way the classifier does.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tokenizers::Tokenizer;
use tract_onnx::prelude::*;

use crate::{check_size_budget, LoadOptions, RunnableOnnxModel};

/// Mean-pool a `[seq_len, dim]` hidden-state matrix (row-major, flat) over
/// tokens, weighting each token by its attention mask. Tokens with mask 0
/// are excluded (they are padding). Returns a `dim`-length vector. If every
/// token is masked out, returns an all-zero vector of length `dim`.
pub(crate) fn mean_pool(hidden: &[f32], mask: &[i64], seq_len: usize, dim: usize) -> Vec<f32> {
    let mut acc = vec![0.0f32; dim];
    let mut count = 0.0f32;
    for t in 0..seq_len {
        if mask.get(t).copied().unwrap_or(0) == 0 {
            continue;
        }
        count += 1.0;
        let base = t * dim;
        for d in 0..dim {
            acc[d] += hidden[base + d];
        }
    }
    if count > 0.0 {
        for v in &mut acc {
            *v /= count;
        }
    }
    acc
}

/// L2-normalize a vector in place. A zero vector is left unchanged so the
/// caller never divides by zero.
pub(crate) fn l2_normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Result of [`OnnxEmbedder::embed`]: an L2-normalized sentence vector.
#[derive(Debug, Clone)]
pub struct EmbeddingOutput {
    /// L2-normalized embedding. Its length is the model's hidden size
    /// (384 for `all-MiniLM-L6-v2`).
    pub values: Vec<f32>,
}

/// A loaded ONNX sentence-embedding model paired with its tokenizer.
///
/// Construction is the slow path (parse + optimise the graph). `embed`
/// is cheap enough to call on the request hot path for short prompts.
pub struct OnnxEmbedder {
    model: RunnableOnnxModel,
    tokenizer: Tokenizer,
}

impl OnnxEmbedder {
    /// Load with default [`LoadOptions`] (200 MB budget, no signatures).
    pub fn load(model_path: &Path, tokenizer_path: &Path) -> Result<Self> {
        Self::load_with_options(model_path, tokenizer_path, &LoadOptions::default())
    }

    /// Load an embedding model + tokenizer, enforcing the size budget.
    pub fn load_with_options(
        model_path: &Path,
        tokenizer_path: &Path,
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
        let model = tract_onnx::onnx()
            .model_for_path(model_path)
            .with_context(|| format!("failed to parse ONNX model at {model_path:?}"))?
            .into_optimized()
            .context("failed to optimise ONNX model")?
            .into_runnable()
            .context("failed to make ONNX model runnable")?;
        Ok(Self { model, tokenizer })
    }

    /// Embed one text into an L2-normalized vector.
    ///
    /// Tokenises `text`, runs the model, mean-pools the last hidden state
    /// over tokens weighted by the attention mask, then L2-normalizes so
    /// the dot product of two embeddings is their cosine similarity.
    pub fn embed(&self, text: &str) -> Result<EmbeddingOutput> {
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

        let input_ids =
            tract_ndarray::Array2::from_shape_vec((1, seq_len), ids).map_err(|e| anyhow!(e))?;
        let attention_mask = tract_ndarray::Array2::from_shape_vec((1, seq_len), mask.clone())
            .map_err(|e| anyhow!(e))?;

        // Route inputs by declared name, matching OnnxClassifier::classify so
        // exports that take input_ids / attention_mask / token_type_ids all work.
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
                inputs.push(input_ids.clone().into_tensor().into());
            }
        }

        let outputs = self
            .model
            .run(inputs)
            .map_err(|e| anyhow!("ONNX inference failed: {e}"))?;
        // Sentence-transformer exports put the token embeddings first:
        // last_hidden_state with shape [1, seq_len, dim].
        let hidden = outputs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("ONNX model returned no outputs"))?;
        let view = hidden
            .to_array_view::<f32>()
            .map_err(|e| anyhow!("output tensor was not f32: {e}"))?;
        let shape = view.shape();
        if shape.len() != 3 || shape[0] != 1 {
            return Err(anyhow!(
                "expected [1, seq, dim] hidden state, got shape {shape:?}"
            ));
        }
        let dim = shape[2];
        let flat: Vec<f32> = view.iter().copied().collect();
        let mut pooled = mean_pool(&flat, &mask, seq_len, dim);
        l2_normalize(&mut pooled);
        Ok(EmbeddingOutput { values: pooled })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_pool_averages_unmasked_tokens() {
        // 2 tokens, dim 2. token0=[1,3] token1=[3,7], both unmasked.
        let hidden = vec![1.0, 3.0, 3.0, 7.0];
        let mask = vec![1i64, 1];
        assert_eq!(mean_pool(&hidden, &mask, 2, 2), vec![2.0, 5.0]);
    }

    #[test]
    fn mean_pool_excludes_masked_tokens() {
        let hidden = vec![1.0, 1.0, 9.0, 9.0]; // token1 is padding
        let mask = vec![1i64, 0];
        assert_eq!(mean_pool(&hidden, &mask, 2, 2), vec![1.0, 1.0]);
    }

    #[test]
    fn mean_pool_all_masked_is_zero() {
        let hidden = vec![5.0, 5.0];
        let mask = vec![0i64];
        assert_eq!(mean_pool(&hidden, &mask, 1, 2), vec![0.0, 0.0]);
    }

    #[test]
    fn l2_normalize_gives_unit_length() {
        let mut v = vec![3.0, 4.0];
        l2_normalize(&mut v);
        let norm = (v[0] * v[0] + v[1] * v[1]).sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
        assert!((v[0] - 0.6).abs() < 1e-6 && (v[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn l2_normalize_zero_vector_unchanged() {
        let mut v = vec![0.0, 0.0];
        l2_normalize(&mut v);
        assert_eq!(v, vec![0.0, 0.0]);
    }

    // Gated: needs a downloaded MiniLM model. Run locally with
    //   SBPROXY_TEST_EMBED_MODEL=/path/model.onnx
    //   SBPROXY_TEST_EMBED_TOKENIZER=/path/tokenizer.json
    #[test]
    fn embed_real_model_is_normalized_and_self_similar() {
        let (Ok(m), Ok(t)) = (
            std::env::var("SBPROXY_TEST_EMBED_MODEL"),
            std::env::var("SBPROXY_TEST_EMBED_TOKENIZER"),
        ) else {
            eprintln!("skipping: set SBPROXY_TEST_EMBED_MODEL/_TOKENIZER to run");
            return;
        };
        let emb = OnnxEmbedder::load(Path::new(&m), Path::new(&t)).unwrap();
        let a = emb.embed("the cat sat on the mat").unwrap();
        let norm: f32 = a.values.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-3, "vector must be L2-normalized");
        let b = emb.embed("the cat sat on the mat").unwrap();
        let cos: f32 = a.values.iter().zip(&b.values).map(|(x, y)| x * y).sum();
        assert!(
            cos > 0.999,
            "identical text cosine should be ~1.0, got {cos}"
        );
    }
}
