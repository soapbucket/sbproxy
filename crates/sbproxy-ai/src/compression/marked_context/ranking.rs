//! Deterministic retrieval ranking primitives are implemented in Task 3.

use super::RetrievalBlock;
use crate::compression::RetrievalRanking;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RankedChunk {
    pub index: usize,
    pub score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RankError {
    MissingSuppliedScore,
}

pub(crate) fn rank_chunks(
    block: &RetrievalBlock,
    mode: RetrievalRanking,
) -> Result<Vec<RankedChunk>, RankError> {
    match mode {
        RetrievalRanking::Auto
            if block
                .chunks()
                .iter()
                .all(|chunk| chunk.supplied_score().is_some()) =>
        {
            rank_supplied(block)
        }
        RetrievalRanking::Auto | RetrievalRanking::Lexical => Ok(rank_lexical(block)),
        RetrievalRanking::Supplied => rank_supplied(block),
    }
}

fn rank_supplied(block: &RetrievalBlock) -> Result<Vec<RankedChunk>, RankError> {
    let mut ranked = block
        .chunks()
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            chunk
                .supplied_score()
                .map(|score| RankedChunk { index, score })
                .ok_or(RankError::MissingSuppliedScore)
        })
        .collect::<Result<Vec<_>, _>>()?;
    sort_ranked(block, &mut ranked);
    Ok(ranked)
}

fn rank_lexical(block: &RetrievalBlock) -> Vec<RankedChunk> {
    let query_terms = term_counts(block.query());
    let document_terms = block
        .chunks()
        .iter()
        .map(|chunk| term_counts(chunk.body()))
        .collect::<Vec<_>>();

    let mut vocabulary = BTreeSet::new();
    vocabulary.extend(query_terms.keys().cloned());
    for terms in &document_terms {
        vocabulary.extend(terms.keys().cloned());
    }

    let mut document_frequency = vocabulary
        .iter()
        .cloned()
        .map(|term| (term, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for terms in &document_terms {
        let present_terms = terms.keys().cloned().collect::<BTreeSet<_>>();
        for term in present_terms {
            if let Some(frequency) = document_frequency.get_mut(&term) {
                *frequency += 1;
            }
        }
    }

    let document_count = document_terms.len() as f64;
    let inverse_document_frequency = vocabulary
        .iter()
        .map(|term| {
            let frequency = document_frequency.get(term).copied().unwrap_or(0) as f64;
            let idf = ((document_count + 1.0) / (frequency + 1.0)).ln() + 1.0;
            (term.clone(), idf)
        })
        .collect::<BTreeMap<_, _>>();

    let mut ranked = document_terms
        .iter()
        .enumerate()
        .map(|(index, terms)| RankedChunk {
            index,
            score: cosine_similarity(
                &query_terms,
                terms,
                &vocabulary,
                &inverse_document_frequency,
            ),
        })
        .collect::<Vec<_>>();
    sort_ranked(block, &mut ranked);
    ranked
}

fn term_counts(text: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for term in text
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
    {
        *counts.entry(term).or_insert(0) += 1;
    }
    counts
}

fn cosine_similarity(
    query_terms: &BTreeMap<String, usize>,
    document_terms: &BTreeMap<String, usize>,
    vocabulary: &BTreeSet<String>,
    inverse_document_frequency: &BTreeMap<String, f64>,
) -> f64 {
    let mut dot_product = 0.0;
    let mut query_norm_squared = 0.0;
    let mut document_norm_squared = 0.0;

    for term in vocabulary {
        let idf = inverse_document_frequency.get(term).copied().unwrap_or(1.0);
        let query_weight = query_terms.get(term).copied().unwrap_or(0) as f64 * idf;
        let document_weight = document_terms.get(term).copied().unwrap_or(0) as f64 * idf;
        dot_product += query_weight * document_weight;
        query_norm_squared += query_weight * query_weight;
        document_norm_squared += document_weight * document_weight;
    }

    if query_norm_squared == 0.0 || document_norm_squared == 0.0 {
        return 0.0;
    }
    let denominator = query_norm_squared.sqrt() * document_norm_squared.sqrt();
    let score = dot_product / denominator;
    if score.is_finite() {
        score.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn sort_ranked(block: &RetrievalBlock, ranked: &mut [RankedChunk]) {
    ranked.sort_by(|left, right| {
        right.score.total_cmp(&left.score).then_with(|| {
            block.chunks()[left.index]
                .original_ordinal()
                .cmp(&block.chunks()[right.index].original_ordinal())
        })
    });
}

#[cfg(test)]
mod tests {
    use super::{rank_chunks, RankError};
    use crate::compression::marked_context::{
        ChunkFormat, LineEnding, RetrievalBlock, RetrievalChunk,
    };
    use crate::compression::RetrievalRanking;

    fn block(
        query: &str,
        chunks: impl IntoIterator<Item = (&'static str, Option<f64>, usize)>,
    ) -> RetrievalBlock {
        let chunks = chunks
            .into_iter()
            .enumerate()
            .map(
                |(index, (body, supplied_score, original_ordinal))| RetrievalChunk {
                    id: format!("chunk-{index}"),
                    supplied_score,
                    supplied_score_rendering: supplied_score.map(|score| score.to_string()),
                    format: ChunkFormat::Text,
                    body: body.to_string(),
                    original_ordinal,
                    original_rendering: String::new(),
                    changed: false,
                },
            )
            .collect();
        RetrievalBlock {
            query: query.to_string(),
            chunks,
            line_ending: LineEnding::Lf,
            changed: false,
        }
    }

    #[test]
    fn supplied_sorts_descending_and_breaks_ties_by_original_ordinal() {
        let block = block(
            "query",
            [
                ("first", Some(0.9), 7),
                ("second", Some(0.2), 1),
                ("third", Some(0.9), 3),
            ],
        );

        let ranked = rank_chunks(&block, RetrievalRanking::Supplied).expect("complete scores");

        assert_eq!(
            ranked.iter().map(|chunk| chunk.index).collect::<Vec<_>>(),
            vec![2, 0, 1]
        );
        assert_eq!(
            ranked.iter().map(|chunk| chunk.score).collect::<Vec<_>>(),
            vec![0.9, 0.9, 0.2]
        );
    }

    #[test]
    fn supplied_requires_every_chunk_score() {
        let block = block("query", [("first", Some(0.8), 0), ("second", None, 1)]);

        assert_eq!(
            rank_chunks(&block, RetrievalRanking::Supplied),
            Err(RankError::MissingSuppliedScore)
        );
    }

    #[test]
    fn auto_uses_supplied_scores_only_when_the_block_is_complete() {
        let complete = block(
            "alpha",
            [("alpha", Some(0.1), 0), ("unrelated", Some(0.9), 1)],
        );
        let partial = block("alpha", [("alpha", Some(0.0), 0), ("unrelated", None, 1)]);

        let supplied = rank_chunks(&complete, RetrievalRanking::Auto).expect("complete scores");
        let lexical = rank_chunks(&partial, RetrievalRanking::Auto).expect("lexical fallback");

        assert_eq!(supplied[0].index, 1);
        assert_eq!(supplied[0].score.to_bits(), 0.9_f64.to_bits());
        assert_eq!(lexical[0].index, 0);
        assert!(lexical[0].score > 0.0);
    }

    #[test]
    fn lexical_ignores_supplied_scores() {
        let block = block(
            "alpha",
            [("alpha", Some(0.0), 0), ("unrelated", Some(1.0), 1)],
        );

        let ranked = rank_chunks(&block, RetrievalRanking::Lexical).expect("lexical ranking");

        assert_eq!(ranked[0].index, 0);
        assert!((ranked[0].score - 1.0).abs() < 1e-15);
        assert_eq!(ranked[1].score.to_bits(), 0.0_f64.to_bits());
    }

    #[test]
    fn lexical_tokenization_lowercases_unicode_alphanumeric_terms_and_splits_others() {
        let block = block(
            "CAFÉ_東京—42",
            [("café 東京 42", None, 0), ("cafe tokyo forty-two", None, 1)],
        );

        let ranked = rank_chunks(&block, RetrievalRanking::Lexical).expect("lexical ranking");

        assert_eq!(ranked[0].index, 0);
        assert!((ranked[0].score - 1.0).abs() < 1e-15);
    }

    #[test]
    fn lexical_uses_the_exact_smoothed_idf_formula() {
        let block = block(
            "common rare",
            [("common rare", None, 0), ("common", None, 1)],
        );

        let ranked = rank_chunks(&block, RetrievalRanking::Lexical).expect("lexical ranking");
        let common_only = ranked
            .iter()
            .find(|chunk| chunk.index == 1)
            .expect("common-only chunk");
        let rare_idf = (3.0_f64 / 2.0).ln() + 1.0;
        let expected = 1.0 / (1.0 + rare_idf * rare_idf).sqrt();

        assert!((common_only.score - expected).abs() < 1e-15);
    }

    #[test]
    fn zero_vector_query_has_finite_zero_scores_in_stable_ordinal_order() {
        let block = block(
            "-_!",
            [("alpha", None, 8), ("beta", None, 2), ("gamma", None, 5)],
        );

        let ranked = rank_chunks(&block, RetrievalRanking::Lexical).expect("lexical ranking");

        assert_eq!(
            ranked.iter().map(|chunk| chunk.index).collect::<Vec<_>>(),
            vec![1, 2, 0]
        );
        assert!(ranked
            .iter()
            .all(|chunk| chunk.score.is_finite() && chunk.score.to_bits() == 0.0_f64.to_bits()));
    }

    #[test]
    fn lexical_scores_and_order_are_bitwise_identical_across_repeated_runs() {
        let block = block(
            "Rust safety 東京 2026",
            [
                ("rust memory safety", None, 0),
                ("東京 release notes 2026", None, 1),
                ("safety rust rust 2026", None, 2),
                ("unrelated", None, 3),
            ],
        );
        let baseline = rank_chunks(&block, RetrievalRanking::Lexical).expect("baseline ranking");
        let baseline_bits = baseline
            .iter()
            .map(|chunk| (chunk.index, chunk.score.to_bits()))
            .collect::<Vec<_>>();

        assert!(baseline.iter().all(|chunk| chunk.score.is_finite()));
        for _ in 0..128 {
            let repeated =
                rank_chunks(&block, RetrievalRanking::Lexical).expect("repeated ranking");
            assert_eq!(
                repeated
                    .iter()
                    .map(|chunk| (chunk.index, chunk.score.to_bits()))
                    .collect::<Vec<_>>(),
                baseline_bits
            );
        }
    }
}
