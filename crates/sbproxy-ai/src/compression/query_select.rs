//! Query-aware sentence selection for explicitly marked retrieval context.

use crate::compression::config::MAX_QUERY_SELECT_SENTENCES;
use crate::compression::marked_context::ranking::{rank_sentences, segment_sentences_bounded};
use crate::compression::marked_context::{
    parse_marked_messages, ChunkFormat, MarkedContextError, RetrievalBlock, RetrievalChunk,
};
use crate::compression::{
    CompressionBackend, CompressionDecision, CompressionLever, CompressionRequest, LeverKind,
    QuerySelectConfig, SkipReason,
};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;

/// Stateless query-aware sentence selection over marked retrieval blocks.
#[derive(Debug, Clone)]
pub struct QuerySelectLever {
    config: QuerySelectConfig,
}

impl QuerySelectLever {
    /// Construct a query-selection lever from validated configuration.
    pub const fn new(config: QuerySelectConfig) -> Self {
        Self { config }
    }

    fn select_block(&self, model: &str, block: &mut RetrievalBlock) -> BlockOutcome {
        let mut sentences = Vec::new();
        for (chunk_index, chunk) in block.chunks().iter().enumerate() {
            let remaining = MAX_QUERY_SELECT_SENTENCES - sentences.len();
            let Some(chunk_sentences) = segment_sentences_bounded(chunk.body(), remaining) else {
                return BlockOutcome::TooLarge;
            };
            sentences.extend(chunk_sentences.into_iter().enumerate().map(
                |(sentence_index, text)| SourceSentence {
                    chunk_index,
                    sentence_index,
                    text: text.to_string(),
                },
            ));
        }
        let sentence_text = sentences
            .iter()
            .map(|sentence| sentence.text.as_str())
            .collect::<Vec<_>>();
        let ranked = rank_sentences(block.query(), &sentence_text);

        let mut selected = Vec::new();
        match self.config {
            QuerySelectConfig::Sentences { max_sentences } => {
                selected.extend(
                    ranked
                        .into_iter()
                        .filter(|sentence| sentence.score > 0.0)
                        .take(max_sentences),
                );
            }
            QuerySelectConfig::TargetTokens { target_tokens } => {
                let mut used_tokens = 0_u64;
                let mut selected_per_chunk = BTreeMap::<usize, usize>::new();
                for sentence in ranked.into_iter().filter(|sentence| sentence.score > 0.0) {
                    let source = &sentences[sentence.index];
                    let mut sentence_tokens =
                        crate::token_estimate::estimate_text_tokens(model, &source.text);
                    if selected_per_chunk
                        .get(&source.chunk_index)
                        .is_some_and(|count| *count > 0)
                    {
                        sentence_tokens = sentence_tokens.saturating_add(
                            crate::token_estimate::estimate_text_tokens(model, " "),
                        );
                    }
                    if used_tokens.saturating_add(sentence_tokens) <= target_tokens {
                        used_tokens += sentence_tokens;
                        *selected_per_chunk.entry(source.chunk_index).or_default() += 1;
                        selected.push(sentence);
                    }
                }
            }
        }

        if selected.is_empty() {
            return BlockOutcome::NoSelectedSentences;
        }

        let mut by_chunk = BTreeMap::<usize, Vec<_>>::new();
        for ranked in selected {
            by_chunk
                .entry(sentences[ranked.index].chunk_index)
                .or_default()
                .push((ranked.index, ranked.score));
        }

        let mut selected_chunks = by_chunk
            .into_iter()
            .map(|(chunk_index, mut selected_sentences)| {
                selected_sentences
                    .sort_by_key(|(sentence_index, _)| sentences[*sentence_index].sentence_index);
                let source_sentence_count = sentences
                    .iter()
                    .filter(|sentence| sentence.chunk_index == chunk_index)
                    .count();
                let chunk = if selected_sentences.len() == source_sentence_count {
                    block.chunks()[chunk_index].clone()
                } else {
                    let body = selected_sentences
                        .iter()
                        .map(|(sentence_index, _)| sentences[*sentence_index].text.as_str())
                        .collect::<Vec<_>>()
                        .join(" ");
                    block.chunks()[chunk_index].with_body_and_format(body, ChunkFormat::Text)
                };
                let score = selected_sentences
                    .iter()
                    .map(|(_, score)| *score)
                    .fold(0.0_f64, f64::max);
                SelectedChunk {
                    chunk,
                    score,
                    source_ordinal: block.chunks()[chunk_index].original_ordinal(),
                }
            })
            .collect::<Vec<_>>();
        selected_chunks.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.source_ordinal.cmp(&right.source_ordinal))
        });

        let edge_ordered = (0..selected_chunks.len())
            .step_by(2)
            .chain(
                (0..selected_chunks.len())
                    .rev()
                    .filter(|index| index % 2 == 1),
            )
            .map(|index| selected_chunks[index].chunk.clone())
            .collect::<Vec<_>>();
        if edge_ordered.as_slice() == block.chunks() {
            return BlockOutcome::NotNeeded;
        }
        block.replace_chunks(edge_ordered);
        BlockOutcome::Changed
    }
}

#[derive(Debug)]
struct SourceSentence {
    chunk_index: usize,
    sentence_index: usize,
    text: String,
}

#[derive(Debug)]
struct SelectedChunk {
    chunk: RetrievalChunk,
    score: f64,
    source_ordinal: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockOutcome {
    Changed,
    NoSelectedSentences,
    NotNeeded,
    TooLarge,
}

#[async_trait]
impl CompressionLever for QuerySelectLever {
    fn kind(&self) -> LeverKind {
        LeverKind::QuerySelect
    }

    fn backend(&self) -> Option<CompressionBackend> {
        None
    }

    async fn compress(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionDecision {
        let mut marked = match parse_marked_messages(messages) {
            Ok(Some(marked)) => marked,
            Ok(None) => {
                return CompressionDecision::Skipped {
                    reason: SkipReason::MissingQuery,
                };
            }
            Err(MarkedContextError::Malformed) => {
                return CompressionDecision::Skipped {
                    reason: SkipReason::MalformedMarkedContext,
                };
            }
            Err(MarkedContextError::TooLarge) => {
                return CompressionDecision::Skipped {
                    reason: SkipReason::MarkedContextTooLarge,
                };
            }
        };

        if marked
            .blocks_mut()
            .any(|block| block.query().trim().is_empty())
        {
            return CompressionDecision::Skipped {
                reason: SkipReason::MissingQuery,
            };
        }
        if marked.blocks_mut().any(|block| {
            block
                .chunks()
                .iter()
                .any(|chunk| chunk.format() != ChunkFormat::Text)
        }) {
            return CompressionDecision::Skipped {
                reason: SkipReason::UnsafeStructuredShape,
            };
        }

        let mut changed = false;
        let mut no_selected_sentences = false;
        for block in marked.blocks_mut() {
            match self.select_block(request.model(), block) {
                BlockOutcome::Changed => changed = true,
                BlockOutcome::NoSelectedSentences => no_selected_sentences = true,
                BlockOutcome::NotNeeded => {}
                BlockOutcome::TooLarge => {
                    return CompressionDecision::Skipped {
                        reason: SkipReason::MarkedContextTooLarge,
                    };
                }
            }
        }

        if changed {
            CompressionDecision::Candidate {
                messages: marked.into_messages(),
            }
        } else {
            CompressionDecision::Skipped {
                reason: if no_selected_sentences {
                    SkipReason::NoSelectedChunks
                } else {
                    SkipReason::NotNeeded
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::QuerySelectLever;
    use crate::compression::config::MAX_QUERY_SELECT_SENTENCES;
    use crate::compression::{
        inspect_marked_context, CompressionCommitRule, CompressionDecision, CompressionLever,
        CompressionRequest, CompressionRunner, LeverKind, LeverOutcome, QuerySelectConfig,
        SkipReason, WindowFitConfig, WindowFitLever,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn message(role: &str, content: impl Into<String>) -> Value {
        json!({"role": role, "content": content.into()})
    }

    fn chunk(id: &str, format: &str, body: &str) -> String {
        format!("<sbproxy-chunk id=\"{id}\" format=\"{format}\">\n{body}\n</sbproxy-chunk>")
    }

    fn block(query: &str, chunks: &[String]) -> String {
        let mut rendered =
            format!("<sbproxy-retrieval>\n<sbproxy-query>\n{query}\n</sbproxy-query>\n");
        for chunk in chunks {
            rendered.push_str(chunk);
            rendered.push('\n');
        }
        rendered.push_str("</sbproxy-retrieval>");
        rendered
    }

    fn sentence_lever(max_sentences: usize) -> QuerySelectLever {
        QuerySelectLever::new(QuerySelectConfig::Sentences { max_sentences })
    }

    fn candidate_messages(decision: CompressionDecision) -> Vec<Value> {
        match decision {
            CompressionDecision::Candidate { messages } => messages,
            other => panic!("expected candidate, got {other:?}"),
        }
    }

    fn snapshot_chunks(messages: &[Value]) -> Vec<(String, String)> {
        inspect_marked_context(messages)
            .expect("valid marked context")
            .expect("marked context present")
            .blocks[0]
            .chunks
            .iter()
            .map(|chunk| (chunk.id.clone(), chunk.body.clone()))
            .collect()
    }

    #[test]
    fn identifies_as_stateless_query_select_with_strict_reduction() {
        let lever = sentence_lever(3);

        assert_eq!(lever.kind(), LeverKind::QuerySelect);
        assert_eq!(lever.backend(), None);
        assert_eq!(lever.commit_rule(), CompressionCommitRule::StrictReduction);
    }

    #[tokio::test]
    async fn removes_irrelevant_sentences_and_keeps_source_order_within_each_chunk() {
        let messages = vec![message(
            "user",
            block(
                "How do alpha and gamma explain the answer?",
                &[
                    chunk(
                        "mixed",
                        "text",
                        "Alpha starts the answer. Bananas grow in warm climates. Gamma alpha completes the answer.",
                    ),
                    chunk("irrelevant", "text", "Knitting uses yarn. Water boils."),
                ],
            ),
        )];

        let output = candidate_messages(
            sentence_lever(2)
                .compress(&CompressionRequest::new("gpt-4"), &messages)
                .await,
        );

        assert_eq!(
            snapshot_chunks(&output),
            [(
                "mixed".to_string(),
                "Alpha starts the answer. Gamma alpha completes the answer.".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn arranges_selected_chunks_in_lost_in_the_middle_edge_order() {
        let chunks = [
            ("one", "alpha"),
            ("two", "alpha beta"),
            ("three", "alpha beta gamma"),
            ("four", "alpha beta gamma delta"),
            ("five", "alpha beta gamma delta epsilon"),
            ("six", "alpha beta gamma delta epsilon zeta"),
        ]
        .map(|(id, body)| chunk(id, "text", body));
        let messages = vec![message("tool", block("alpha", &chunks))];

        let output = candidate_messages(
            sentence_lever(6)
                .compress(&CompressionRequest::new("gpt-4"), &messages)
                .await,
        );

        assert_eq!(
            snapshot_chunks(&output)
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            ["one", "three", "five", "six", "four", "two"]
        );
    }

    #[tokio::test]
    async fn target_token_budget_is_model_aware_and_never_exceeded() {
        let selected = "Alpha beta is the direct answer.";
        let budget = crate::token_estimate::estimate_text_tokens("gpt-4", selected);
        let messages = vec![message(
            "user",
            block(
                "alpha beta answer",
                &[chunk(
                    "one",
                    "text",
                    "Alpha beta is the direct answer. Alpha is a secondary detail.",
                )],
            ),
        )];
        let lever = QuerySelectLever::new(QuerySelectConfig::TargetTokens {
            target_tokens: budget,
        });

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new("gpt-4"), &messages)
                .await,
        );
        let chunks = snapshot_chunks(&output);

        assert_eq!(chunks[0].1, selected);
        assert!(crate::token_estimate::estimate_text_tokens("gpt-4", &chunks[0].1) <= budget);
    }

    #[tokio::test]
    async fn target_token_budget_accounts_for_joined_sentence_separators() {
        let model = "unknown-model";
        let messages = vec![message(
            "user",
            block("alpha", &[chunk("one", "text", "alpha. alpha.")]),
        )];
        let lever = QuerySelectLever::new(QuerySelectConfig::TargetTokens { target_tokens: 2 });

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(model), &messages)
                .await,
        );
        let chunks = snapshot_chunks(&output);

        assert_eq!(chunks[0].1, "alpha.");
        assert!(crate::token_estimate::estimate_text_tokens(model, &chunks[0].1) <= 2);
    }

    #[tokio::test]
    async fn max_sentence_mode_fails_open_for_an_over_limit_block() {
        let body = "alpha. ".repeat(MAX_QUERY_SELECT_SENTENCES + 1);
        let messages = vec![message(
            "user",
            block("alpha", &[chunk("one", "text", &body)]),
        )];

        let decision = sentence_lever(1)
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await;

        assert_eq!(
            decision,
            CompressionDecision::Skipped {
                reason: SkipReason::MarkedContextTooLarge
            }
        );
    }

    #[tokio::test]
    async fn target_token_mode_fails_open_for_an_over_limit_block() {
        let body = "alpha. ".repeat(MAX_QUERY_SELECT_SENTENCES + 1);
        let messages = vec![message(
            "user",
            block("alpha", &[chunk("one", "text", &body)]),
        )];
        let lever = QuerySelectLever::new(QuerySelectConfig::TargetTokens { target_tokens: 1 });

        let decision = lever
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await;

        assert_eq!(
            decision,
            CompressionDecision::Skipped {
                reason: SkipReason::MarkedContextTooLarge
            }
        );
    }

    #[tokio::test]
    async fn missing_blank_malformed_and_structured_context_skip_without_mutation() {
        let no_markers = vec![message("user", "ordinary question")];
        assert_eq!(
            sentence_lever(2)
                .compress(&CompressionRequest::new("gpt-4"), &no_markers)
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::MissingQuery
            }
        );

        let blank = vec![message(
            "user",
            block("   ", &[chunk("one", "text", "alpha")]),
        )];
        assert_eq!(
            sentence_lever(2)
                .compress(&CompressionRequest::new("gpt-4"), &blank)
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::MalformedMarkedContext
            }
        );

        let malformed = vec![message(
            "user",
            "<sbproxy-retrieval>\n<sbproxy-query>\nalpha\n</sbproxy-query>",
        )];
        assert_eq!(
            sentence_lever(2)
                .compress(&CompressionRequest::new("gpt-4"), &malformed)
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::MalformedMarkedContext
            }
        );

        let structured = vec![message(
            "tool",
            block(
                "alpha",
                &[
                    chunk("text", "text", "alpha answer. irrelevant."),
                    chunk("json", "json", r#"{"alpha":"answer"}"#),
                ],
            ),
        )];
        assert_eq!(
            sentence_lever(1)
                .compress(&CompressionRequest::new("gpt-4"), &structured)
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::UnsafeStructuredShape
            }
        );
    }

    #[tokio::test]
    async fn blank_query_skip_allows_ordered_window_fit_fallback() {
        let oversized = format!(
            "{}\n{}",
            block(" ", &[chunk("one", "text", "alpha")]),
            "old ".repeat(1_000)
        );
        let newest = message("user", "newest answer");
        let messages = vec![message("user", oversized), newest.clone()];
        let runner = CompressionRunner::with_model_counter(vec![
            Arc::new(sentence_lever(2)),
            Arc::new(WindowFitLever::new(WindowFitConfig {
                completion_reserve_tokens: 1_024,
                input_budget_tokens: Some(64),
            })),
        ]);

        let run = runner
            .run(&CompressionRequest::new("unknown-model"), &messages)
            .await;

        assert_eq!(run.messages, [newest]);
        assert_eq!(run.lever_results[0].lever, LeverKind::QuerySelect);
        assert_eq!(
            run.lever_results[0].outcome,
            LeverOutcome::Skipped {
                reason: SkipReason::MalformedMarkedContext
            }
        );
        assert_eq!(run.lever_results[1].lever, LeverKind::WindowFit);
        assert_eq!(run.lever_results[1].outcome, LeverOutcome::Applied);
    }
}
