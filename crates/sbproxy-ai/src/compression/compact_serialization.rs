//! Deterministic compact serialization of explicitly marked JSON chunks.

use crate::compression::marked_context::table::encode_table;
use crate::compression::marked_context::{
    parse_marked_messages, ChunkFormat, MarkedContextError, RetrievalChunk,
};
use crate::compression::{
    CompactSerializationConfig, CompressionBackend, CompressionDecision, CompressionLever,
    CompressionRequest, FailureReason, LeverKind, SkipReason,
};
use async_trait::async_trait;
use serde_json::Value;

/// Stateless compact serialization of explicitly marked JSON chunks.
#[derive(Debug, Clone)]
pub struct CompactSerializationLever {
    config: CompactSerializationConfig,
}

enum ChunkOutcome {
    Changed(RetrievalChunk),
    UnsafeStructuredShape,
    BelowThreshold,
    NotNeeded,
    InternalFailure,
}

impl CompactSerializationLever {
    /// Construct a compact serialization lever from validated configuration.
    pub const fn new(config: CompactSerializationConfig) -> Self {
        Self { config }
    }

    fn compact_chunk(&self, model: &str, chunk: &RetrievalChunk) -> ChunkOutcome {
        if chunk.format() != ChunkFormat::Json {
            return ChunkOutcome::NotNeeded;
        }

        let original_tokens = crate::token_estimate::estimate_text_tokens(model, &chunk.render());
        if original_tokens < self.config.min_tokens {
            return ChunkOutcome::BelowThreshold;
        }

        let value = match serde_json::from_str::<Value>(chunk.body()) {
            Ok(value) => value,
            Err(_) => return ChunkOutcome::UnsafeStructuredShape,
        };
        let minified = match serde_json::to_string(&value) {
            Ok(minified) => minified,
            Err(_) => return ChunkOutcome::InternalFailure,
        };
        let json_candidate = chunk.with_body_and_format(minified, ChunkFormat::Json);
        let json_tokens =
            crate::token_estimate::estimate_text_tokens(model, &json_candidate.render());

        let mut best = chunk.clone();
        let mut best_tokens = original_tokens;
        if json_tokens < best_tokens {
            best = json_candidate;
            best_tokens = json_tokens;
        }

        if self.config.tabular.enabled {
            if let Some(body) = encode_table(&value, self.config.tabular.min_rows) {
                let table_candidate = chunk.with_body_and_format(body, ChunkFormat::SbproxyTableV1);
                let table_tokens =
                    crate::token_estimate::estimate_text_tokens(model, &table_candidate.render());
                if table_tokens < best_tokens {
                    best = table_candidate;
                }
            }
        }

        if best == *chunk {
            ChunkOutcome::NotNeeded
        } else {
            ChunkOutcome::Changed(best)
        }
    }
}

#[async_trait]
impl CompressionLever for CompactSerializationLever {
    fn kind(&self) -> LeverKind {
        LeverKind::CompactSerialization
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

        let mut unsafe_structured_shape = false;
        let mut below_threshold = false;
        for block in marked.blocks_mut() {
            let mut replacement = Vec::with_capacity(block.chunks().len());
            for chunk in block.chunks() {
                match self.compact_chunk(request.model(), chunk) {
                    ChunkOutcome::Changed(changed) => replacement.push(changed),
                    ChunkOutcome::UnsafeStructuredShape => {
                        unsafe_structured_shape = true;
                        replacement.push(chunk.clone());
                    }
                    ChunkOutcome::BelowThreshold => {
                        below_threshold = true;
                        replacement.push(chunk.clone());
                    }
                    ChunkOutcome::NotNeeded => replacement.push(chunk.clone()),
                    ChunkOutcome::InternalFailure => {
                        return CompressionDecision::Failed {
                            reason: FailureReason::Internal,
                        };
                    }
                }
            }
            block.replace_chunks(replacement);
        }

        let candidate = marked.into_messages();
        if candidate != messages {
            return CompressionDecision::Candidate {
                messages: candidate,
            };
        }

        let reason = if unsafe_structured_shape {
            SkipReason::UnsafeStructuredShape
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
    use super::CompactSerializationLever;
    use crate::compression::marked_context::table::encode_table;
    use crate::compression::{
        decode_sbproxy_table_v1, inspect_marked_context, CompactSerializationConfig,
        CompressionCommitRule, CompressionDecision, CompressionLever, CompressionRequest,
        CompressionRunner, LeverKind, LeverOutcome, RetrievalChunkSnapshot, SkipReason,
        TabularSerializationConfig,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    const HEURISTIC_MODEL: &str = "unknown-self-hosted-model";

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

    fn config(
        min_tokens: u64,
        tabular_enabled: bool,
        tabular_min_rows: usize,
    ) -> CompactSerializationConfig {
        CompactSerializationConfig {
            min_tokens,
            tabular: TabularSerializationConfig {
                enabled: tabular_enabled,
                min_rows: tabular_min_rows,
            },
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

    fn snapshot_chunk(messages: &[Value], id: &str) -> RetrievalChunkSnapshot {
        inspect_marked_context(messages)
            .expect("valid marked context")
            .expect("marked context present")
            .blocks
            .into_iter()
            .flat_map(|block| block.chunks)
            .find(|chunk| chunk.id == id)
            .unwrap_or_else(|| panic!("missing chunk {id}"))
    }

    fn uniform_rows(count: usize) -> Value {
        Value::Array(
            (0..count)
                .map(|index| {
                    json!({
                        "container_name": format!("worker-{index:03}"),
                        "namespace_name": "production-services",
                        "ready_for_traffic": index % 2 == 0,
                        "restart_count": index % 7,
                        "status_reason": "ImagePullBackOff"
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn identifies_as_stateless_compact_serialization_with_strict_reduction() {
        let lever = CompactSerializationLever::new(config(1, true, 2));

        assert_eq!(lever.kind(), LeverKind::CompactSerialization);
        assert_eq!(lever.backend(), None);
        assert_eq!(lever.commit_rule(), CompressionCommitRule::StrictReduction);
    }

    #[tokio::test]
    async fn changes_only_marked_json_and_preserves_all_other_material_exactly() {
        let value = json!({
            "answer": [1, 2, 3],
            "detail": {"ready": true, "label": "kept whitespace"}
        });
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        let marked = block(
            "compact the JSON only",
            &[
                chunk("json", "json", &pretty),
                chunk("text", "text", &pretty),
                chunk("table", "sbproxy_table_v1", "[\"a\"]\n1"),
            ],
        );
        let messages = vec![
            message("system", &marked),
            message("developer", &marked),
            message("assistant", &marked),
            json!({"role": "user", "content": [{"type": "text", "text": marked}]}),
            message("tool", "ordinary unmarked content\t\n"),
            json!({
                "role": "user",
                "content": format!("literal prefix\0\n{marked}\nliteral suffix 🙂\0"),
                "extra": {"preserve": true}
            }),
        ];
        let original = messages.clone();
        let lever = CompactSerializationLever::new(config(1, false, 8));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
        );

        assert_eq!(messages, original, "the caller input is immutable");
        assert_eq!(&output[..5], &messages[..5]);
        assert_eq!(output[5]["extra"], messages[5]["extra"]);
        let content = output[5]["content"].as_str().unwrap();
        assert!(content.starts_with("literal prefix\0\n"));
        assert!(content.ends_with("\nliteral suffix 🙂\0"));
        let json_chunk = snapshot_chunk(&output, "json");
        assert_eq!(json_chunk.format, "json");
        assert_eq!(json_chunk.body, value.to_string());
        assert_eq!(snapshot_chunk(&output, "text").body, pretty);
        assert_eq!(
            snapshot_chunk(&output, "table"),
            snapshot_chunk(&messages, "table")
        );
    }

    #[tokio::test]
    async fn min_tokens_counts_each_complete_rendered_chunk_at_the_boundary() {
        let large_value = json!({
            "answer": "x".repeat(160),
            "nested": {"ready": true, "values": [1, 2, 3, 4]}
        });
        let large_body = serde_json::to_string_pretty(&large_value).unwrap();
        let small_value = json!({"x": 1});
        let small_body = serde_json::to_string_pretty(&small_value).unwrap();
        let large_chunk = chunk("large", "json", &large_body);
        let small_chunk = chunk("small", "json", &small_body);
        let large_tokens =
            crate::token_estimate::estimate_text_tokens(HEURISTIC_MODEL, &large_chunk);
        let small_tokens =
            crate::token_estimate::estimate_text_tokens(HEURISTIC_MODEL, &small_chunk);
        let body_tokens = crate::token_estimate::estimate_text_tokens(HEURISTIC_MODEL, &large_body);
        assert!(large_tokens > body_tokens);
        assert!(small_tokens < large_tokens);
        let messages = vec![message(
            "tool",
            block("per chunk", &[large_chunk, small_chunk]),
        )];

        let at_boundary = CompactSerializationLever::new(config(large_tokens, false, 8));
        let output = candidate_messages(
            at_boundary
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
        );
        assert_eq!(
            snapshot_chunk(&output, "large").body,
            large_value.to_string()
        );
        assert_eq!(snapshot_chunk(&output, "small").body, small_body);

        let below = CompactSerializationLever::new(config(large_tokens + 1, false, 8));
        assert_skip(
            below
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
            SkipReason::BelowThreshold,
        );
    }

    #[tokio::test]
    async fn nested_and_heterogeneous_json_minify_but_never_table_encode() {
        let nested = json!({"outer": {"inner": [1, 2, 3]}, "ready": true});
        let heterogeneous = json!([{"a": 1}, {"b": 2}]);
        let messages = vec![message(
            "user",
            block(
                "safe fallback",
                &[
                    chunk(
                        "nested",
                        "json",
                        &serde_json::to_string_pretty(&nested).unwrap(),
                    ),
                    chunk(
                        "heterogeneous",
                        "json",
                        &serde_json::to_string_pretty(&heterogeneous).unwrap(),
                    ),
                ],
            ),
        )];
        let lever = CompactSerializationLever::new(config(1, true, 2));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
        );

        for (id, value) in [("nested", nested), ("heterogeneous", heterogeneous)] {
            let chunk = snapshot_chunk(&output, id);
            assert_eq!(chunk.format, "json");
            assert_eq!(chunk.body, value.to_string());
        }
    }

    #[tokio::test]
    async fn disabled_tabular_and_zero_column_rows_fall_back_to_minified_json() {
        let uniform = uniform_rows(8);
        let uniform_messages = vec![message(
            "tool",
            block(
                "disabled",
                &[chunk(
                    "uniform",
                    "json",
                    &serde_json::to_string_pretty(&uniform).unwrap(),
                )],
            ),
        )];
        let disabled = CompactSerializationLever::new(config(1, false, 2));
        let disabled_output = candidate_messages(
            disabled
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &uniform_messages)
                .await,
        );
        let uniform_chunk = snapshot_chunk(&disabled_output, "uniform");
        assert_eq!(uniform_chunk.format, "json");
        assert_eq!(uniform_chunk.body, uniform.to_string());

        let empty_rows = json!([{}, {}, {}, {}]);
        let empty_messages = vec![message(
            "tool",
            block(
                "zero columns",
                &[chunk(
                    "empty-rows",
                    "json",
                    &serde_json::to_string_pretty(&empty_rows).unwrap(),
                )],
            ),
        )];
        let enabled = CompactSerializationLever::new(config(1, true, 2));
        let empty_output = candidate_messages(
            enabled
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &empty_messages)
                .await,
        );
        let empty_chunk = snapshot_chunk(&empty_output, "empty-rows");
        assert_eq!(empty_chunk.format, "json");
        assert_eq!(empty_chunk.body, empty_rows.to_string());
    }

    #[tokio::test]
    async fn chooses_the_lowest_complete_chunk_token_count_and_changes_format_only_for_table() {
        let model = "gpt-4o";
        let value = uniform_rows(24);
        let original_body = serde_json::to_string_pretty(&value).unwrap();
        let json_body = value.to_string();
        let table_body = encode_table(&value, 2).unwrap();
        let original_rendered = chunk("wide", "json", &original_body);
        let json_rendered = chunk("wide", "json", &json_body);
        let table_rendered = chunk("wide", "sbproxy_table_v1", &table_body);
        let original_tokens =
            crate::token_estimate::estimate_text_tokens(model, &original_rendered);
        let json_tokens = crate::token_estimate::estimate_text_tokens(model, &json_rendered);
        let table_tokens = crate::token_estimate::estimate_text_tokens(model, &table_rendered);
        assert!(json_tokens < original_tokens);
        assert!(table_tokens < json_tokens);
        let messages = vec![message(
            "tool",
            block("choose smallest", &[original_rendered]),
        )];
        let lever = CompactSerializationLever::new(config(1, true, 2));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(model), &messages)
                .await,
        );
        let selected = snapshot_chunk(&output, "wide");

        assert_eq!(selected.format, "sbproxy_table_v1");
        assert_eq!(selected.body, table_body);
        assert_eq!(decode_sbproxy_table_v1(&selected.body).unwrap(), value);
    }

    #[tokio::test]
    async fn minified_json_wins_a_complete_chunk_token_tie_with_table() {
        let value = json!([{"abcde": 1}, {"abcde": 2}]);
        let original_body = serde_json::to_string_pretty(&value).unwrap();
        let json_body = value.to_string();
        let table_body = encode_table(&value, 2).unwrap();
        let id = "tie";
        let original_tokens = crate::token_estimate::estimate_text_tokens(
            HEURISTIC_MODEL,
            &chunk(id, "json", &original_body),
        );
        let json_tokens = crate::token_estimate::estimate_text_tokens(
            HEURISTIC_MODEL,
            &chunk(id, "json", &json_body),
        );
        let table_tokens = crate::token_estimate::estimate_text_tokens(
            HEURISTIC_MODEL,
            &chunk(id, "sbproxy_table_v1", &table_body),
        );
        assert_eq!(json_tokens, table_tokens);
        assert!(json_tokens < original_tokens);
        let messages = vec![message(
            "tool",
            block("tie", &[chunk(id, "json", &original_body)]),
        )];
        let lever = CompactSerializationLever::new(config(1, true, 2));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
        );
        let selected = snapshot_chunk(&output, id);

        assert_eq!(selected.format, "json");
        assert_eq!(selected.body, json_body);
    }

    #[tokio::test]
    async fn requires_a_strict_complete_chunk_improvement_over_original() {
        let value = json!({"a": 1});
        let minified = value.to_string();
        let spaced = "{\"a\": 1}";
        let id = (1..=64)
            .map(|length| "s".repeat(length))
            .find(|id| {
                crate::token_estimate::estimate_text_tokens(
                    HEURISTIC_MODEL,
                    &chunk(id, "json", spaced),
                ) == crate::token_estimate::estimate_text_tokens(
                    HEURISTIC_MODEL,
                    &chunk(id, "json", &minified),
                )
            })
            .expect("fixture must expose an original/minified heuristic tie");
        let messages = vec![message(
            "user",
            block("strict", &[chunk(&id, "json", spaced)]),
        )];
        let original = messages.clone();
        let lever = CompactSerializationLever::new(config(1, false, 8));

        let decision = lever
            .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
            .await;

        assert_skip(decision, SkipReason::NotNeeded);
        assert_eq!(messages, original);
    }

    #[tokio::test]
    async fn invalid_json_is_unsafe_only_when_no_other_chunk_changes() {
        let valid = json!({"answer": "x".repeat(80), "ready": true});
        let pretty = serde_json::to_string_pretty(&valid).unwrap();
        let invalid = "{ this is not valid JSON and must remain exact }";
        let messages = vec![message(
            "tool",
            block(
                "mixed",
                &[
                    chunk("invalid", "json", invalid),
                    chunk("valid", "json", &pretty),
                ],
            ),
        )];
        let lever = CompactSerializationLever::new(config(1, true, 2));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
        );
        assert_eq!(snapshot_chunk(&output, "invalid").body, invalid);
        assert_eq!(snapshot_chunk(&output, "valid").body, valid.to_string());

        assert_skip(
            lever
                .compress(
                    &CompressionRequest::new(HEURISTIC_MODEL),
                    &[message(
                        "tool",
                        block("invalid only", &[chunk("invalid", "json", invalid)]),
                    )],
                )
                .await,
            SkipReason::UnsafeStructuredShape,
        );
    }

    #[tokio::test]
    async fn parser_failures_and_no_marked_context_precede_any_transformation() {
        let lever = CompactSerializationLever::new(config(1, true, 2));
        let request = CompressionRequest::new(HEURISTIC_MODEL);
        assert_skip(
            lever
                .compress(&request, &[message("user", "ordinary text")])
                .await,
            SkipReason::NoMarkedContext,
        );

        let valid = block("valid first", &[chunk("valid", "json", "{ \"a\": 1 }")]);
        let malformed_messages = vec![
            message("user", valid),
            message("tool", "<sbproxy-retrieval>"),
        ];
        let original = malformed_messages.clone();
        assert_skip(
            lever.compress(&request, &malformed_messages).await,
            SkipReason::MalformedMarkedContext,
        );
        assert_eq!(malformed_messages, original);

        let too_many = (0..=crate::compression::marked_context::MAX_CHUNKS_PER_BLOCK)
            .map(|index| chunk(&format!("chunk-{index}"), "json", "{}"))
            .collect::<Vec<_>>();
        assert_skip(
            lever
                .compress(&request, &[message("tool", block("bounded", &too_many))])
                .await,
            SkipReason::MarkedContextTooLarge,
        );
    }

    #[tokio::test]
    async fn no_change_precedence_is_unsafe_then_below_threshold_then_not_needed() {
        let not_needed_body = json!({"payload": "x".repeat(400)}).to_string();
        let invalid_body = format!("not-json {}", "z".repeat(1_000));
        let below_body = "{\n  \"a\": 1\n}";
        let threshold = crate::token_estimate::estimate_text_tokens(
            HEURISTIC_MODEL,
            &chunk("not-needed", "json", &not_needed_body),
        );
        assert!(
            crate::token_estimate::estimate_text_tokens(
                HEURISTIC_MODEL,
                &chunk("invalid", "json", &invalid_body)
            ) >= threshold
        );
        assert!(
            crate::token_estimate::estimate_text_tokens(
                HEURISTIC_MODEL,
                &chunk("below", "json", below_body)
            ) < threshold
        );
        let lever = CompactSerializationLever::new(config(threshold, false, 8));
        let request = CompressionRequest::new(HEURISTIC_MODEL);

        assert_skip(
            lever
                .compress(
                    &request,
                    &[message(
                        "tool",
                        block(
                            "precedence",
                            &[
                                chunk("below", "json", below_body),
                                chunk("not-needed", "json", &not_needed_body),
                                chunk("invalid", "json", &invalid_body),
                            ],
                        ),
                    )],
                )
                .await,
            SkipReason::UnsafeStructuredShape,
        );
        assert_skip(
            lever
                .compress(
                    &request,
                    &[message(
                        "tool",
                        block(
                            "precedence",
                            &[
                                chunk("below", "json", below_body),
                                chunk("not-needed", "json", &not_needed_body),
                            ],
                        ),
                    )],
                )
                .await,
            SkipReason::BelowThreshold,
        );
        assert_skip(
            lever
                .compress(
                    &request,
                    &[message(
                        "tool",
                        block(
                            "precedence",
                            &[chunk("not-needed", "json", &not_needed_body)],
                        ),
                    )],
                )
                .await,
            SkipReason::NotNeeded,
        );
    }

    #[tokio::test]
    async fn transforms_multiple_eligible_chunks_independently() {
        let nested = json!({"nested": {"values": [1, 2, 3]}, "label": "x".repeat(40)});
        let rows = uniform_rows(12);
        let messages = vec![
            message(
                "user",
                block(
                    "first",
                    &[chunk(
                        "nested",
                        "json",
                        &serde_json::to_string_pretty(&nested).unwrap(),
                    )],
                ),
            ),
            message(
                "tool",
                block(
                    "second",
                    &[chunk(
                        "rows",
                        "json",
                        &serde_json::to_string_pretty(&rows).unwrap(),
                    )],
                ),
            ),
        ];
        let lever = CompactSerializationLever::new(config(1, true, 2));

        let output = candidate_messages(
            lever
                .compress(&CompressionRequest::new("gpt-4o"), &messages)
                .await,
        );

        let nested_chunk = snapshot_chunk(&output, "nested");
        assert_eq!(nested_chunk.format, "json");
        assert_eq!(nested_chunk.body, nested.to_string());
        let rows_chunk = snapshot_chunk(&output, "rows");
        assert_eq!(rows_chunk.format, "sbproxy_table_v1");
        assert_eq!(decode_sbproxy_table_v1(&rows_chunk.body).unwrap(), rows);
    }

    #[tokio::test]
    async fn already_minified_and_already_tabular_chunks_are_idempotent() {
        let minified = json!({"a": [1, 2, 3], "ready": true}).to_string();
        let table = "[\"a\"]\n1\n2";
        let messages = vec![message(
            "tool",
            block(
                "stable",
                &[
                    chunk("json", "json", &minified),
                    chunk("table", "sbproxy_table_v1", table),
                ],
            ),
        )];
        let original = messages.clone();
        let lever = CompactSerializationLever::new(config(1, false, 2));

        assert_skip(
            lever
                .compress(&CompressionRequest::new(HEURISTIC_MODEL), &messages)
                .await,
            SkipReason::NotNeeded,
        );
        assert_eq!(messages, original);

        let rows = uniform_rows(10);
        let pretty_messages = vec![message(
            "tool",
            block(
                "table once",
                &[chunk(
                    "rows",
                    "json",
                    &serde_json::to_string_pretty(&rows).unwrap(),
                )],
            ),
        )];
        let table_lever = CompactSerializationLever::new(config(1, true, 2));
        let once = candidate_messages(
            table_lever
                .compress(&CompressionRequest::new("gpt-4o"), &pretty_messages)
                .await,
        );
        assert_skip(
            table_lever
                .compress(&CompressionRequest::new("gpt-4o"), &once)
                .await,
            SkipReason::NotNeeded,
        );
    }

    #[tokio::test]
    async fn uniform_200_row_tool_result_round_trips_and_saves_thirty_percent() {
        let source = uniform_rows(200);
        let messages = vec![json!({
            "role": "tool",
            "tool_call_id": "call-200",
            "content": block(
                "list failing containers",
                &[chunk(
                    "tool-result-200",
                    "json",
                    &serde_json::to_string_pretty(&source).unwrap(),
                )],
            )
        })];
        let lever = CompactSerializationLever::new(config(1, true, 200));
        let runner = CompressionRunner::with_model_counter(vec![Arc::new(lever)]);

        let run = runner
            .run(&CompressionRequest::new("gpt-4o"), &messages)
            .await;

        assert_eq!(run.lever_results[0].outcome, LeverOutcome::Applied);
        assert!(run.initial_tokens > run.final_tokens);
        let savings_ratio = run.tokens_saved as f64 / run.initial_tokens as f64;
        assert!(
            savings_ratio >= 0.30,
            "expected at least 30% savings, got {savings_ratio:.3} ({} -> {})",
            run.initial_tokens,
            run.final_tokens
        );
        assert_eq!(run.messages[0]["tool_call_id"], messages[0]["tool_call_id"]);
        let encoded = snapshot_chunk(&run.messages, "tool-result-200");
        assert_eq!(encoded.format, "sbproxy_table_v1");
        assert_eq!(decode_sbproxy_table_v1(&encoded.body).unwrap(), source);
    }
}
