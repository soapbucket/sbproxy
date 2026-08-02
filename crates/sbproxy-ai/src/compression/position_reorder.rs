//! Relevance-based chunk placement for lost-in-the-middle mitigation.

use crate::compression::marked_context::ranking::{rank_chunks, RankError, RankedChunk};
use crate::compression::marked_context::{
    parse_marked_messages, MarkedContextError, RetrievalBlock,
};
use crate::compression::{
    CompressionBackend, CompressionCommitRule, CompressionDecision, CompressionLever,
    CompressionRequest, LeverKind, PositionReorderConfig, SkipReason,
};
use async_trait::async_trait;
use serde_json::Value;
use std::cmp::Ordering;

/// Stateless relevance-based position reordering over marked retrieval blocks.
#[derive(Debug, Clone)]
pub struct PositionReorderLever {
    config: PositionReorderConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockOutcome {
    Changed,
    AlreadyOrdered,
    MissingRelevanceScore,
}

impl PositionReorderLever {
    /// Construct a position-reordering lever from validated configuration.
    pub const fn new(config: PositionReorderConfig) -> Self {
        Self { config }
    }

    fn reorder_block(&self, block: &mut RetrievalBlock) -> BlockOutcome {
        let ranked = match rank_chunks(block, self.config.ranking) {
            Ok(ranked) => ranked,
            Err(RankError::MissingSuppliedScore) => {
                return BlockOutcome::MissingRelevanceScore;
            }
        };
        let target = edge_order(&ranked);

        let ids_match = target
            .iter()
            .map(|ranked| block.chunks()[ranked.index].id())
            .eq(block.chunks().iter().map(|chunk| chunk.id()));
        if ids_match || score_sequences_match(block, &ranked, &target) {
            return BlockOutcome::AlreadyOrdered;
        }

        let reordered = target
            .iter()
            .map(|ranked| block.chunks()[ranked.index].clone())
            .collect();
        block.replace_chunks(reordered);
        BlockOutcome::Changed
    }
}

fn edge_order(ranked: &[RankedChunk]) -> Vec<RankedChunk> {
    ranked
        .iter()
        .step_by(2)
        .chain(
            ranked
                .iter()
                .enumerate()
                .rev()
                .filter_map(|(index, ranked)| (index % 2 == 1).then_some(ranked)),
        )
        .copied()
        .collect()
}

fn score_sequences_match(
    block: &RetrievalBlock,
    ranked: &[RankedChunk],
    target: &[RankedChunk],
) -> bool {
    let mut current_scores = vec![0.0; block.chunks().len()];
    for ranked in ranked {
        current_scores[ranked.index] = ranked.score;
    }
    current_scores
        .iter()
        .zip(target)
        .all(|(current, target)| current.total_cmp(&target.score) == Ordering::Equal)
}

#[async_trait]
impl CompressionLever for PositionReorderLever {
    fn kind(&self) -> LeverKind {
        LeverKind::PositionReorder
    }

    fn backend(&self) -> Option<CompressionBackend> {
        None
    }

    fn commit_rule(&self) -> CompressionCommitRule {
        CompressionCommitRule::NonExpanding
    }

    async fn compress(
        &self,
        _request: &CompressionRequest<'_>,
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

        let mut changed = false;
        let mut missing_relevance_score = false;
        for block in marked.blocks_mut() {
            match self.reorder_block(block) {
                BlockOutcome::Changed => changed = true,
                BlockOutcome::AlreadyOrdered => {}
                BlockOutcome::MissingRelevanceScore => missing_relevance_score = true,
            }
        }

        if changed {
            return CompressionDecision::Candidate {
                messages: marked.into_messages(),
            };
        }

        CompressionDecision::Skipped {
            reason: if missing_relevance_score {
                SkipReason::MissingRelevanceScore
            } else {
                SkipReason::AlreadyOrdered
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PositionReorderLever;
    use crate::compression::marked_context::MAX_CHUNKS_PER_BLOCK;
    use crate::compression::{
        inspect_marked_context, CompressionCommitRule, CompressionDecision, CompressionLever,
        CompressionRequest, LeverKind, PositionReorderConfig, RetrievalRanking, SkipReason,
    };
    use serde_json::{json, Value};

    fn message(role: &str, content: impl Into<String>) -> Value {
        json!({"role": role, "content": content.into()})
    }

    fn chunk(id: &str, score: Option<&str>, format: &str, body: &str, eol: &str) -> String {
        let score = score
            .map(|score| format!(" score=\"{score}\""))
            .unwrap_or_default();
        format!(
            "<sbproxy-chunk id=\"{id}\"{score} format=\"{format}\">{eol}{body}{eol}</sbproxy-chunk>"
        )
    }

    fn block(query: &str, chunks: &[String], eol: &str) -> String {
        let mut rendered = format!(
            "<sbproxy-retrieval>{eol}<sbproxy-query>{eol}{query}{eol}</sbproxy-query>{eol}"
        );
        for chunk in chunks {
            rendered.push_str(chunk);
            rendered.push_str(eol);
        }
        rendered.push_str("</sbproxy-retrieval>");
        rendered
    }

    fn supplied_lever() -> PositionReorderLever {
        PositionReorderLever::new(PositionReorderConfig {
            ranking: RetrievalRanking::Supplied,
        })
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

    fn block_ids(messages: &[Value], block_index: usize) -> Vec<String> {
        inspect_marked_context(messages)
            .expect("valid marked context")
            .expect("marked context present")
            .blocks[block_index]
            .chunks
            .iter()
            .map(|chunk| chunk.id.clone())
            .collect()
    }

    fn ranked_block(size: usize) -> String {
        let chunks = (1..=size)
            .map(|rank| {
                let score = format!("{:.6}", (size + 1 - rank) as f64 / size as f64);
                chunk(
                    &rank.to_string(),
                    Some(&score),
                    "text",
                    &format!("body-{rank}"),
                    "\n",
                )
            })
            .collect::<Vec<_>>();
        block("rank these", &chunks, "\n")
    }

    #[test]
    fn identifies_as_stateless_position_reorder_with_non_expanding_commit() {
        let lever = supplied_lever();

        assert_eq!(lever.kind(), LeverKind::PositionReorder);
        assert_eq!(lever.backend(), None);
        assert_eq!(lever.commit_rule(), CompressionCommitRule::NonExpanding);
    }

    #[tokio::test]
    async fn even_ranked_sequence_places_odd_ranks_first_and_even_ranks_in_reverse() {
        let messages = vec![message("user", ranked_block(6))];

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(block_ids(&output, 0), ["1", "3", "5", "6", "4", "2"]);
    }

    #[tokio::test]
    async fn odd_ranked_sequence_places_odd_ranks_first_and_even_ranks_in_reverse() {
        let messages = vec![message("tool", ranked_block(5))];

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(block_ids(&output, 0), ["1", "3", "5", "4", "2"]);
    }

    #[tokio::test]
    async fn reordering_preserves_chunk_tags_attributes_and_bodies_byte_for_byte() {
        let eol = "\r\n";
        let chunks = vec![
            chunk("one", Some("1.0"), "text", "first\r\nbody", eol),
            chunk("two", Some("8e-1"), "json", "{\"two\": 2}\r\n", eol),
            chunk(
                "three",
                Some("0.6"),
                "sbproxy_table_v1",
                "[\"column\"]\r\n[\"value\"]",
                eol,
            ),
            chunk("four", Some("0.4"), "text", "\0opaque 🙂", eol),
        ];
        let source = block("preserve bytes", &chunks, eol);
        let messages = vec![
            json!({"role": "system", "content": source, "metadata": {"keep": true}}),
            json!({
                "role": "tool",
                "content": format!("prefix{eol}{source}{eol}suffix\0"),
                "tool_call_id": "call-1",
            }),
        ];
        let expected = block(
            "preserve bytes",
            &[
                chunks[0].clone(),
                chunks[2].clone(),
                chunks[3].clone(),
                chunks[1].clone(),
            ],
            eol,
        );

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(output[0], messages[0]);
        assert_eq!(
            output[1]["content"],
            format!("prefix{eol}{expected}{eol}suffix\0")
        );
        assert_eq!(output[1]["tool_call_id"], "call-1");
        for original_chunk in &chunks {
            assert_eq!(
                output[1]["content"]
                    .as_str()
                    .expect("string content")
                    .matches(original_chunk)
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn multiple_blocks_reorder_independently() {
        let first = ranked_block(4);
        let second_chunks = vec![
            chunk("second-low", Some("0.1"), "text", "low", "\n"),
            chunk("second-best", Some("1"), "text", "best", "\n"),
            chunk("second-mid", Some("0.5"), "text", "mid", "\n"),
        ];
        let second = block("second", &second_chunks, "\n");
        let messages = vec![message(
            "user",
            format!("before\n{first}\nbetween\n{second}\nafter"),
        )];

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(block_ids(&output, 0), ["1", "3", "4", "2"]);
        assert_eq!(
            block_ids(&output, 1),
            ["second-best", "second-low", "second-mid"]
        );
    }

    #[tokio::test]
    async fn missing_supplied_scores_leave_that_block_unchanged_when_another_changes() {
        let unrankable_chunks = vec![
            chunk("scored", Some("0.8"), "text", "one", "\n"),
            chunk("missing", None, "text", "two", "\n"),
        ];
        let unrankable = block("unrankable", &unrankable_chunks, "\n");
        let rankable = ranked_block(4);
        let messages = vec![message(
            "tool",
            format!("prefix\n{unrankable}\nmiddle\n{rankable}\nsuffix"),
        )];

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert!(output[0]["content"]
            .as_str()
            .expect("string content")
            .contains(&unrankable));
        assert_eq!(block_ids(&output, 0), ["scored", "missing"]);
        assert_eq!(block_ids(&output, 1), ["1", "3", "4", "2"]);
    }

    #[tokio::test]
    async fn missing_supplied_score_takes_precedence_when_no_block_changes() {
        let missing = block(
            "missing",
            &[
                chunk("scored", Some("0.8"), "text", "one", "\n"),
                chunk("unscored", None, "text", "two", "\n"),
            ],
            "\n",
        );
        let already_ordered = block(
            "ordered",
            &[
                chunk("rank-1", Some("1"), "text", "one", "\n"),
                chunk("rank-3", Some("0.8"), "text", "three", "\n"),
                chunk("rank-4", Some("0.7"), "text", "four", "\n"),
                chunk("rank-2", Some("0.9"), "text", "two", "\n"),
            ],
            "\n",
        );
        let messages = vec![message("user", missing), message("tool", already_ordered)];
        let original = messages.clone();

        let decision = supplied_lever()
            .compress(&CompressionRequest::new("unknown-model"), &messages)
            .await;

        assert_skip(decision, SkipReason::MissingRelevanceScore);
        assert_eq!(messages, original);
    }

    #[tokio::test]
    async fn supplied_score_ties_keep_their_original_ordinal_ranking() {
        let source = block(
            "ties",
            &[
                chunk("best", Some("0.95"), "text", "best", "\n"),
                chunk("tie-first", Some("0.8"), "text", "first", "\n"),
                chunk("low", Some("0.1"), "text", "low", "\n"),
                chunk("tie-second", Some("0.8"), "text", "second", "\n"),
                chunk("middle", Some("0.5"), "text", "middle", "\n"),
            ],
            "\n",
        );
        let messages = vec![message("user", source)];

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(
            block_ids(&output, 0),
            ["best", "tie-second", "low", "middle", "tie-first"]
        );
    }

    #[tokio::test]
    async fn supplied_score_tie_output_applies_once_then_skips_after_reparse() {
        let source = block(
            "ties",
            &[
                chunk("best", Some("0.95"), "text", "best", "\n"),
                chunk("tie-first", Some("0.8"), "text", "first", "\n"),
                chunk("low", Some("0.1"), "text", "low", "\n"),
                chunk("tie-second", Some("0.8"), "text", "second", "\n"),
                chunk("middle", Some("0.5"), "text", "middle", "\n"),
            ],
            "\n",
        );
        let messages = vec![message("user", source)];
        let lever = supplied_lever();
        let request = CompressionRequest::new("unknown-model");

        let once = candidate_messages(lever.compress(&request, &messages).await);
        let twice = lever.compress(&request, &once).await;

        assert_eq!(
            block_ids(&once, 0),
            ["best", "tie-second", "low", "middle", "tie-first"]
        );
        assert_skip(twice, SkipReason::AlreadyOrdered);
    }

    #[tokio::test]
    async fn score_equivalence_uses_exact_total_order_comparison() {
        let source = block(
            "signed zero",
            &[
                chunk("top", Some("1"), "text", "top", "\n"),
                chunk("positive-zero", Some("0"), "text", "positive", "\n"),
                chunk("negative-zero", Some("-0"), "text", "negative", "\n"),
            ],
            "\n",
        );
        let messages = vec![message("user", source)];

        let output = candidate_messages(
            supplied_lever()
                .compress(&CompressionRequest::new("unknown-model"), &messages)
                .await,
        );

        assert_eq!(
            block_ids(&output, 0),
            ["top", "negative-zero", "positive-zero"]
        );
    }

    #[tokio::test]
    async fn already_edge_ordered_blocks_skip_as_already_ordered() {
        let ordered = block(
            "ordered",
            &[
                chunk("rank-1", Some("1"), "text", "one", "\n"),
                chunk("rank-3", Some("0.8"), "text", "three", "\n"),
                chunk("rank-5", Some("0.6"), "text", "five", "\n"),
                chunk("rank-6", Some("0.5"), "text", "six", "\n"),
                chunk("rank-4", Some("0.7"), "text", "four", "\n"),
                chunk("rank-2", Some("0.9"), "text", "two", "\n"),
            ],
            "\n",
        );

        let decision = supplied_lever()
            .compress(
                &CompressionRequest::new("unknown-model"),
                &[message("user", ordered)],
            )
            .await;

        assert_skip(decision, SkipReason::AlreadyOrdered);
    }

    #[tokio::test]
    async fn distinct_score_second_run_is_idempotent() {
        let messages = vec![message("user", ranked_block(6))];
        let lever = supplied_lever();
        let request = CompressionRequest::new("unknown-model");

        let once = candidate_messages(lever.compress(&request, &messages).await);
        let twice = lever.compress(&request, &once).await;

        assert_eq!(block_ids(&once, 0), ["1", "3", "5", "6", "4", "2"]);
        assert_skip(twice, SkipReason::AlreadyOrdered);
    }

    #[tokio::test]
    async fn parser_failures_skip_and_preserve_the_full_request() {
        let lever = supplied_lever();
        let request = CompressionRequest::new("unknown-model");

        let malformed = vec![
            json!({"role": "system", "content": "protected", "extra": [1, 2]}),
            message("user", "before\n<sbproxy-retrieval>\nafter"),
        ];
        let malformed_original = malformed.clone();
        assert_skip(
            lever.compress(&request, &malformed).await,
            SkipReason::MalformedMarkedContext,
        );
        assert_eq!(malformed, malformed_original);

        let too_many_chunks = (0..=MAX_CHUNKS_PER_BLOCK)
            .map(|index| chunk(&format!("chunk-{index}"), Some("0.5"), "text", "body", "\n"))
            .collect::<Vec<_>>();
        let too_large = vec![message("tool", block("bounded", &too_many_chunks, "\n"))];
        let too_large_original = too_large.clone();
        assert_skip(
            lever.compress(&request, &too_large).await,
            SkipReason::MarkedContextTooLarge,
        );
        assert_eq!(too_large, too_large_original);
    }
}
