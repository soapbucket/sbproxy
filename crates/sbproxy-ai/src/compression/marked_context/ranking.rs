//! Deterministic retrieval ranking primitives are implemented in Task 3.

use super::RetrievalBlock;
use crate::compression::RetrievalRanking;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RankedChunk {
    pub index: usize,
    pub score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RankedSentence {
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
    let document_bodies = block
        .chunks()
        .iter()
        .map(|chunk| chunk.body())
        .collect::<Vec<_>>();
    let scores = lexical_scores(block.query(), &document_bodies);
    let mut ranked = scores
        .into_iter()
        .enumerate()
        .map(|(index, score)| RankedChunk { index, score })
        .collect::<Vec<_>>();
    sort_ranked(block, &mut ranked);
    ranked
}

/// Segment no more than `max_sentences`, stopping as soon as another is found.
pub(crate) fn segment_sentences_bounded(text: &str, max_sentences: usize) -> Option<Vec<&str>> {
    fn push_trimmed<'a>(
        text: &'a str,
        start: usize,
        end: usize,
        max_sentences: usize,
        output: &mut Vec<&'a str>,
    ) -> bool {
        let sentence = text[start..end].trim();
        if !sentence.is_empty() {
            if output.len() == max_sentences {
                return false;
            }
            output.push(sentence);
        }
        true
    }

    let mut characters = text.char_indices().peekable();
    let mut sentences = Vec::new();
    let mut start = 0;

    while let Some((index, character)) = characters.next() {
        if character == '\n' {
            if !push_trimmed(text, start, index, max_sentences, &mut sentences) {
                return None;
            }
            start = index + character.len_utf8();
            continue;
        }
        if !matches!(character, '.' | '?' | '!') {
            continue;
        }

        let mut end = index + character.len_utf8();
        while characters.peek().is_some_and(|(_, character)| {
            matches!(*character, '"' | '\'' | '”' | '’' | ')' | ']' | '}')
        }) {
            let (index, character) = characters.next().expect("peeked character exists");
            end = index + character.len_utf8();
        }
        let is_boundary = characters
            .peek()
            .is_none_or(|(_, character)| character.is_whitespace());
        if is_boundary {
            if !push_trimmed(text, start, end, max_sentences, &mut sentences) {
                return None;
            }
            start = end;
        }
    }
    if !push_trimmed(text, start, text.len(), max_sentences, &mut sentences) {
        return None;
    }
    Some(sentences)
}

/// Rank sentences by deterministic TF-IDF cosine relevance to one query.
pub(crate) fn rank_sentences(query: &str, sentences: &[&str]) -> Vec<RankedSentence> {
    let scores = lexical_scores(query, sentences);
    let mut ranked = scores
        .into_iter()
        .enumerate()
        .map(|(index, score)| RankedSentence { index, score })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.index.cmp(&right.index))
    });
    ranked
}

fn lexical_scores(query: &str, documents: &[&str]) -> Vec<f64> {
    let query_terms = term_counts(query);
    let document_terms = documents
        .iter()
        .map(|document| term_counts(document))
        .collect::<Vec<_>>();
    let mut document_frequency = BTreeMap::<&str, usize>::new();
    for terms in &document_terms {
        for term in terms.keys() {
            *document_frequency.entry(term.as_str()).or_default() += 1;
        }
    }

    let document_count = document_terms.len() as f64;
    let query_norm_squared = query_terms
        .iter()
        .map(|(term, count)| {
            let idf = inverse_document_frequency(
                document_count,
                document_frequency
                    .get(term.as_str())
                    .copied()
                    .unwrap_or_default(),
            );
            let weight = *count as f64 * idf;
            weight * weight
        })
        .sum::<f64>();

    document_terms
        .iter()
        .map(|terms| {
            cosine_similarity(
                &query_terms,
                terms,
                &document_frequency,
                document_count,
                query_norm_squared,
            )
        })
        .collect()
}

fn inverse_document_frequency(document_count: f64, document_frequency: usize) -> f64 {
    ((document_count + 1.0) / (document_frequency as f64 + 1.0)).ln() + 1.0
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
    document_frequency: &BTreeMap<&str, usize>,
    document_count: f64,
    query_norm_squared: f64,
) -> f64 {
    let mut dot_product = 0.0;
    let mut document_norm_squared = 0.0;

    for (term, count) in document_terms {
        let idf = inverse_document_frequency(
            document_count,
            document_frequency
                .get(term.as_str())
                .copied()
                .unwrap_or_default(),
        );
        let document_weight = *count as f64 * idf;
        document_norm_squared += document_weight * document_weight;
        if let Some(query_count) = query_terms.get(term) {
            let query_weight = *query_count as f64 * idf;
            dot_product += query_weight * document_weight;
        }
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
    use super::{rank_chunks, rank_sentences, segment_sentences_bounded, RankError};
    use crate::compression::config::MAX_QUERY_SELECT_SENTENCES;
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

    #[test]
    fn sentence_segmentation_is_deterministic_and_keeps_terminal_punctuation() {
        let text =
            "  First sentence.  \"Second question?\"\nThird line!\r\nFinal fragment without punctuation  ";

        let sentences =
            segment_sentences_bounded(text, usize::MAX).expect("unbounded segmentation");

        assert_eq!(
            sentences,
            [
                "First sentence.",
                "\"Second question?\"",
                "Third line!",
                "Final fragment without punctuation"
            ]
        );
    }

    #[test]
    fn sentence_ranking_uses_block_wide_tfidf_and_stable_source_ties() {
        let sentences = [
            "Rust ownership prevents memory races.",
            "Gardening needs water and sunlight.",
            "Memory safety comes from Rust ownership.",
            "A completely unrelated sentence.",
        ];

        let ranked = rank_sentences("How does Rust ownership improve memory safety?", &sentences);

        assert_eq!(
            ranked
                .iter()
                .map(|sentence| sentence.index)
                .collect::<Vec<_>>(),
            [2, 0, 1, 3]
        );
        assert!(ranked[0].score > ranked[1].score);
        assert_eq!(ranked[2].score.to_bits(), 0.0_f64.to_bits());
        assert_eq!(ranked[3].score.to_bits(), 0.0_f64.to_bits());
    }

    #[test]
    fn sentence_ranking_stays_sparse_at_the_closed_sentence_bound() {
        let mut query = (0..10_000)
            .map(|index| format!("query_term_{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        query.push_str(" needle");
        let sentences = vec!["needle"; MAX_QUERY_SELECT_SENTENCES];

        let ranked = rank_sentences(&query, &sentences);

        assert_eq!(ranked.len(), MAX_QUERY_SELECT_SENTENCES);
        assert_eq!(ranked[0].index, 0);
        assert_eq!(
            ranked[MAX_QUERY_SELECT_SENTENCES - 1].index,
            MAX_QUERY_SELECT_SENTENCES - 1
        );
        assert!(ranked.iter().all(|sentence| sentence.score > 0.0));
    }
}
