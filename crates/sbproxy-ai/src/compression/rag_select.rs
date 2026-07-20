//! Retrieval-aware selection for explicitly marked context.

use crate::compression::marked_context::ranking::{rank_chunks, RankError};
use crate::compression::marked_context::{parse_marked_messages, MarkedContextError};
use crate::compression::{
    CompressionBackend, CompressionDecision, CompressionLever, CompressionRequest, LeverKind,
    RagSelectConfig, SkipReason,
};
use async_trait::async_trait;
use serde_json::Value;

/// Stateless retrieval-aware selection over explicitly marked context blocks.
#[derive(Debug, Clone)]
pub struct RagSelectLever {
    config: RagSelectConfig,
}

impl RagSelectLever {
    /// Construct a retrieval selection lever from validated configuration.
    pub const fn new(config: RagSelectConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl CompressionLever for RagSelectLever {
    fn kind(&self) -> LeverKind {
        LeverKind::RagSelect
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
                    reason: SkipReason::NoMarkedContext,
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

        let minimum_score = f64::from(self.config.min_relevance_percent) / 100.0;
        let mut missing_relevance_score = false;
        let mut no_selected_chunks = false;
        let mut below_threshold = false;

        for block in marked.blocks_mut() {
            if crate::token_estimate::estimate_text_tokens(request.model(), &block.render())
                < self.config.min_tokens
            {
                below_threshold = true;
                continue;
            }

            let ranked = match rank_chunks(block, self.config.ranking) {
                Ok(ranked) => ranked,
                Err(RankError::MissingSuppliedScore) => {
                    missing_relevance_score = true;
                    continue;
                }
            };
            let selected = ranked
                .into_iter()
                .filter(|ranked| ranked.score >= minimum_score)
                .take(self.config.max_chunks)
                .map(|ranked| block.chunks()[ranked.index].clone())
                .collect::<Vec<_>>();

            if selected.is_empty() {
                no_selected_chunks = true;
                if self.config.drop_empty {
                    block.replace_chunks(Vec::new());
                }
                continue;
            }
            block.replace_chunks(selected);
        }

        let candidate = marked.into_messages();
        if candidate != messages {
            return CompressionDecision::Candidate {
                messages: candidate,
            };
        }

        let reason = if missing_relevance_score {
            SkipReason::MissingRelevanceScore
        } else if no_selected_chunks {
            SkipReason::NoSelectedChunks
        } else if below_threshold {
            SkipReason::BelowThreshold
        } else {
            SkipReason::NotNeeded
        };
        CompressionDecision::Skipped { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::RagSelectLever;
    use crate::compression::marked_context::MAX_CHUNKS_PER_BLOCK;
    use crate::compression::{
        inspect_marked_context, CompressionCommitRule, CompressionDecision, CompressionLever,
        CompressionRequest, CompressionRunner, LeverKind, LeverOutcome, RagSelectConfig,
        RetrievalRanking, SkipReason, TokenCounter,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn message(role: &str, content: impl Into<String>) -> Value {
        json!({"role": role, "content": content.into()})
    }

    fn chunk(id: &str, score: Option<f64>, body: &str) -> String {
        let score = score
            .map(|score| format!(" score=\"{score}\""))
            .unwrap_or_default();
        format!("<sbproxy-chunk id=\"{id}\"{score} format=\"text\">\n{body}\n</sbproxy-chunk>")
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

    fn config(
        min_tokens: u64,
        ranking: RetrievalRanking,
        max_chunks: usize,
        min_relevance_percent: u8,
        drop_empty: bool,
    ) -> RagSelectConfig {
        RagSelectConfig {
            min_tokens,
            ranking,
            max_chunks,
            min_relevance_percent,
            drop_empty,
        }
    }

    fn candidate_messages(decision: CompressionDecision) -> Vec<Value> {
        match decision {
            CompressionDecision::Candidate { messages } => messages,
            other => panic!("expected candidate, got {other:?}"),
        }
    }

    fn assert_skip(decision: CompressionDecision, reason: SkipReason) {
        assert_eq!(decision, CompressionDecision::Skipped { reason });
    }

    #[test]
    fn identifies_as_stateless_rag_select_with_strict_reduction() {
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Auto, 2, 0, false));

        assert_eq!(lever.kind(), LeverKind::RagSelect);
        assert_eq!(lever.backend(), None);
        assert_eq!(lever.commit_rule(), CompressionCommitRule::StrictReduction);
    }

    #[tokio::test]
    async fn changes_only_marked_user_and_tool_string_content() {
        let source = block(
            "question",
            &[
                chunk("low", Some(0.2), "discard"),
                chunk("high", Some(0.9), "retain"),
            ],
        );
        let selected = block("question", &[chunk("high", Some(0.9), "retain")]);
        let messages = vec![
            message("system", &source),
            message("assistant", &source),
            json!({"role": "user", "content": [{"type": "text", "text": source}]}),
            json!({"role": "user", "content": format!("prefix\n{source}\nsuffix"), "extra": 7}),
            json!({"role": "tool", "content": source, "tool_call_id": "call-1"}),
        ];
        let original = messages.clone();
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 0, false));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(messages, original);
        assert_eq!(output[0], messages[0]);
        assert_eq!(output[1], messages[1]);
        assert_eq!(output[2], messages[2]);
        assert_eq!(output[3]["content"], format!("prefix\n{selected}\nsuffix"));
        assert_eq!(output[3]["extra"], 7);
        assert_eq!(output[4]["content"], selected);
        assert_eq!(output[4]["tool_call_id"], "call-1");
    }

    #[tokio::test]
    async fn min_tokens_measures_each_complete_rendered_block() {
        let model = "unknown-self-hosted-model";
        let source = block(
            "q",
            &[chunk("low", Some(0.1), "x"), chunk("high", Some(0.9), "y")],
        );
        let body_tokens = crate::token_estimate::estimate_text_tokens(model, "x");
        let block_tokens = crate::token_estimate::estimate_text_tokens(model, &source);
        assert!(block_tokens > body_tokens);
        let lever = RagSelectLever::new(config(
            block_tokens,
            RetrievalRanking::Supplied,
            1,
            0,
            false,
        ));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(model), &[message("user", source)])
                .await,
        );
        let snapshot = inspect_marked_context(&output)
            .expect("valid marked context")
            .expect("one block");

        assert_eq!(snapshot.blocks[0].chunks.len(), 1);
        assert_eq!(snapshot.blocks[0].chunks[0].id, "high");
    }

    #[tokio::test]
    async fn filters_by_minimum_relevance_then_caps_and_renders_in_ranked_order() {
        let source = block(
            "q",
            &[
                chunk("below", Some(0.49), "below"),
                chunk("top", Some(0.9), "top"),
                chunk("cutoff", Some(0.5), "cutoff"),
                chunk("third", Some(0.7), "third"),
            ],
        );
        let messages = vec![message("user", &source)];
        let request = CompressionRequest::new("unknown-model");

        let threshold_only =
            RagSelectLever::new(config(1, RetrievalRanking::Supplied, 10, 50, false));
        let threshold_output =
            candidate_messages(threshold_only.compress(&request, &messages).await);
        let threshold_snapshot = inspect_marked_context(&threshold_output)
            .expect("valid marked context")
            .expect("one block");
        assert_eq!(
            threshold_snapshot.blocks[0]
                .chunks
                .iter()
                .map(|chunk| chunk.id.as_str())
                .collect::<Vec<_>>(),
            vec!["top", "third", "cutoff"]
        );

        let capped = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 2, 50, false));
        let capped_output = candidate_messages(capped.compress(&request, &messages).await);
        let capped_snapshot = inspect_marked_context(&capped_output)
            .expect("valid marked context")
            .expect("one block");
        assert_eq!(
            capped_snapshot.blocks[0]
                .chunks
                .iter()
                .map(|chunk| chunk.id.as_str())
                .collect::<Vec<_>>(),
            vec!["top", "third"]
        );
    }

    #[tokio::test]
    async fn drop_empty_retains_the_retrieval_wrapper_and_query() {
        let source = block("keep this query", &[chunk("low", Some(0.2), "discard")]);
        let messages = vec![message("user", format!("before\n{source}\nafter"))];
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 2, 90, true));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(
            output[0]["content"],
            format!("before\n{}\nafter", block("keep this query", &[]))
        );
    }

    #[tokio::test]
    async fn drop_empty_false_leaves_an_empty_selection_unchanged() {
        let source = block("query", &[chunk("low", Some(0.2), "discard")]);
        let messages = vec![message("user", source)];
        let original = messages.clone();
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 2, 90, false));

        let decision = lever
            .compress(&CompressionRequest::new("unknown-model"), &messages)
            .await;

        assert_skip(decision, SkipReason::NoSelectedChunks);
        assert_eq!(messages, original);
    }

    #[tokio::test]
    async fn missing_supplied_score_preserves_that_block_while_other_blocks_change() {
        let unrankable = block(
            "unrankable",
            &[
                chunk("scored", Some(0.8), "one"),
                chunk("missing", None, "two"),
            ],
        );
        let rankable = block(
            "rankable",
            &[
                chunk("low", Some(0.1), "three"),
                chunk("high", Some(0.9), "four"),
            ],
        );
        let messages = vec![message(
            "tool",
            format!("prefix\n{unrankable}\nmiddle\n{rankable}\nsuffix"),
        )];
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 0, false));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );
        let content = output[0]["content"].as_str().expect("string content");
        let snapshot = inspect_marked_context(&output)
            .expect("valid marked context")
            .expect("two blocks");

        assert!(content.contains(&unrankable));
        assert_eq!(snapshot.blocks[0].chunks.len(), 2);
        assert_eq!(snapshot.blocks[1].chunks.len(), 1);
        assert_eq!(snapshot.blocks[1].chunks[0].id, "high");
    }

    #[tokio::test]
    async fn missing_supplied_score_is_reported_when_no_block_can_change() {
        let source = block(
            "query",
            &[
                chunk("scored", Some(0.8), "one"),
                chunk("missing", None, "two"),
            ],
        );
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 0, false));

        let decision = lever
            .compress(
                &CompressionRequest::new("unknown-model"),
                &[message("user", source)],
            )
            .await;

        assert_skip(decision, SkipReason::MissingRelevanceScore);
    }

    #[tokio::test]
    async fn reports_closed_parser_and_eligibility_skip_reasons() {
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 0, false));
        assert_skip(
            lever
                .compress(
                    &CompressionRequest::new("unknown-model"),
                    &[message("user", "ordinary text")],
                )
                .await,
            SkipReason::NoMarkedContext,
        );
        assert_skip(
            lever
                .compress(
                    &CompressionRequest::new("unknown-model"),
                    &[message("user", "<sbproxy-retrieval>")],
                )
                .await,
            SkipReason::MalformedMarkedContext,
        );

        let too_many_chunks = (0..=MAX_CHUNKS_PER_BLOCK)
            .map(|index| chunk(&format!("chunk-{index}"), Some(0.5), "body"))
            .collect::<Vec<_>>();
        assert_skip(
            lever
                .compress(
                    &CompressionRequest::new("unknown-model"),
                    &[message("user", block("query", &too_many_chunks))],
                )
                .await,
            SkipReason::MarkedContextTooLarge,
        );

        let source = block("query", &[chunk("one", Some(1.0), "body")]);
        let block_tokens = crate::token_estimate::estimate_text_tokens("unknown-model", &source);
        let below = RagSelectLever::new(config(
            block_tokens + 1,
            RetrievalRanking::Supplied,
            1,
            0,
            false,
        ));
        assert_skip(
            below
                .compress(
                    &CompressionRequest::new("unknown-model"),
                    &[message("user", source)],
                )
                .await,
            SkipReason::BelowThreshold,
        );
    }

    #[tokio::test]
    async fn content_free_reason_precedence_prefers_missing_then_no_selection() {
        let missing = block(
            "missing",
            &[
                chunk("scored", Some(1.0), "one"),
                chunk("unscored", None, "two"),
            ],
        );
        let no_selection = block("no selection", &[chunk("low", Some(0.5), "three")]);
        let unchanged = block("unchanged", &[chunk("perfect", Some(1.0), "four")]);
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 100, false));
        let request = CompressionRequest::new("unknown-model");

        assert_skip(
            lever
                .compress(
                    &request,
                    &[
                        message("user", missing),
                        message("tool", &no_selection),
                        message("user", &unchanged),
                    ],
                )
                .await,
            SkipReason::MissingRelevanceScore,
        );
        assert_skip(
            lever
                .compress(
                    &request,
                    &[message("tool", no_selection), message("user", unchanged)],
                )
                .await,
            SkipReason::NoSelectedChunks,
        );
    }

    #[tokio::test]
    async fn transforms_multiple_blocks_independently() {
        let first = block(
            "first",
            &[
                chunk("first-low", Some(0.1), "one"),
                chunk("first-high", Some(0.9), "two"),
            ],
        );
        let second = block(
            "second",
            &[
                chunk("second-high", Some(0.8), "three"),
                chunk("second-low", Some(0.2), "four"),
            ],
        );
        let messages = vec![message("user", format!("{first}\nliteral\n{second}"))];
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 0, false));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );
        let snapshot = inspect_marked_context(&output)
            .expect("valid marked context")
            .expect("two blocks");

        assert_eq!(snapshot.blocks.len(), 2);
        assert_eq!(snapshot.blocks[0].chunks[0].id, "first-high");
        assert_eq!(snapshot.blocks[1].chunks[0].id, "second-high");
    }

    #[tokio::test]
    async fn repeated_application_is_stable_and_inputs_remain_immutable() {
        let source = block(
            "query",
            &[
                chunk("low", Some(0.2), "one"),
                chunk("high", Some(0.8), "two"),
            ],
        );
        let messages = vec![message("user", source)];
        let original = messages.clone();
        let lever = RagSelectLever::new(config(1, RetrievalRanking::Supplied, 1, 0, false));
        let request = CompressionRequest::new("unknown-model");

        let once = candidate_messages(lever.compress(&request, &messages).await);
        let once_original = once.clone();
        let twice = lever.compress(&request, &once).await;

        assert_eq!(messages, original);
        assert_eq!(once, once_original);
        assert_skip(twice, SkipReason::NotNeeded);
    }

    struct ConstantTokenCounter;

    impl TokenCounter for ConstantTokenCounter {
        fn count(&self, _model: &str, _messages: &[Value]) -> u64 {
            100
        }
    }

    #[tokio::test]
    async fn runner_rejects_a_changed_token_equal_candidate_as_no_savings() {
        let source = block(
            "query",
            &[
                chunk("low", Some(0.2), "one"),
                chunk("high", Some(0.8), "two"),
            ],
        );
        let messages = vec![message("user", source)];
        let config = config(1, RetrievalRanking::Supplied, 1, 0, false);
        let lever = RagSelectLever::new(config);
        let request = CompressionRequest::new("unknown-model");
        assert!(matches!(
            lever.compress(&request, &messages).await,
            CompressionDecision::Candidate { .. }
        ));
        let runner = CompressionRunner::new(vec![Arc::new(lever)], Arc::new(ConstantTokenCounter));

        let run = runner.run(&request, &messages).await;

        assert_eq!(run.messages, messages);
        assert_eq!(run.tokens_saved, 0);
        assert_eq!(
            run.lever_results[0].outcome,
            LeverOutcome::Skipped {
                reason: SkipReason::NoSavings
            }
        );
    }
}
