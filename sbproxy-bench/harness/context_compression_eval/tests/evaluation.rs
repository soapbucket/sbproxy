use context_compression_eval::{
    build_stateless_levers, evaluate_cases, AcceptanceSpec, EvalCase, EvalConfig, QualitySpec,
    Recommendation,
};
use sbproxy_ai::compression::{
    CompactSerializationConfig, CompressionLeverConfig, PositionReorderConfig, RagSelectConfig,
    RetrievalRanking, SummarizerConfig, SummaryBufferConfig, TabularSerializationConfig,
    WindowFitConfig,
};
use serde_json::json;

fn window_fit_pipeline(input_budget_tokens: u64) -> Vec<CompressionLeverConfig> {
    vec![CompressionLeverConfig::WindowFit(WindowFitConfig {
        completion_reserve_tokens: 8_000,
        input_budget_tokens: Some(input_budget_tokens),
    })]
}

fn long_case() -> EvalCase {
    EvalCase {
        schema_version: 1,
        id: "ruler-retrieval-1".to_string(),
        corpus: "ruler_smoke".to_string(),
        target_model: "gpt-4".to_string(),
        messages: vec![
            json!({"role": "system", "content": "Answer only from supplied evidence."}),
            json!({"role": "user", "content": "old context ".repeat(300)}),
            json!({"role": "assistant", "content": "old response ".repeat(300)}),
            json!({"role": "user", "content": "EVIDENCE::project-orbit=blue. What is the project color?"}),
        ],
        quality: QualitySpec::EvidenceRetention {
            required_evidence: vec!["EVIDENCE::project-orbit=blue".to_string()],
        },
        acceptance: AcceptanceSpec::default(),
    }
}

fn marked_message(query: &str, chunks: &[(&str, f64, &str, &str)]) -> serde_json::Value {
    let mut content = format!("<sbproxy-retrieval>\n<sbproxy-query>\n{query}\n</sbproxy-query>\n");
    for (id, score, format, body) in chunks {
        content.push_str(&format!(
            "<sbproxy-chunk id=\"{id}\" score=\"{score}\" format=\"{format}\">\n{body}\n</sbproxy-chunk>\n"
        ));
    }
    content.push_str("</sbproxy-retrieval>");
    json!({"role": "user", "content": content})
}

fn all_stateless_configs() -> Vec<CompressionLeverConfig> {
    vec![
        CompressionLeverConfig::RagSelect(RagSelectConfig {
            min_tokens: 1,
            ranking: RetrievalRanking::Supplied,
            max_chunks: 8,
            min_relevance_percent: 0,
            drop_empty: false,
        }),
        CompressionLeverConfig::CompactSerialization(CompactSerializationConfig {
            min_tokens: 1,
            tabular: TabularSerializationConfig {
                enabled: true,
                min_rows: 2,
            },
        }),
        CompressionLeverConfig::PositionReorder(PositionReorderConfig {
            ranking: RetrievalRanking::Supplied,
        }),
        CompressionLeverConfig::WindowFit(WindowFitConfig {
            completion_reserve_tokens: 8_000,
            input_budget_tokens: Some(192),
        }),
    ]
}

#[tokio::test]
async fn rejects_an_empty_case_suite() {
    let error = evaluate_cases(
        &[],
        &EvalConfig {
            profile: "empty-suite".to_string(),
            levers: Vec::new(),
            measure_latency: false,
        },
    )
    .await
    .expect_err("an empty suite must not produce acceptance evidence");

    assert_eq!(error.to_string(), "evaluation requires at least one case");
}

#[tokio::test]
async fn evaluates_identical_arms_through_real_window_fit() {
    let report = evaluate_cases(
        &[long_case()],
        &EvalConfig {
            profile: "window_fit-smoke-v1".to_string(),
            levers: window_fit_pipeline(192),
            measure_latency: false,
        },
    )
    .await
    .expect("evaluation succeeds");

    let case = &report.cases[0];
    assert_eq!(case.quality_metric, "evidence_retention");
    assert_eq!(case.off.input_tokens, case.on.input_tokens);
    assert_eq!(case.off.input_tokens, case.off.output_tokens);
    assert!(case.on.output_tokens < case.off.output_tokens);
    assert_eq!(
        case.tokens_saved,
        case.off.output_tokens - case.on.output_tokens
    );
    assert!(case.savings_ratio > 0.0);
    assert_eq!(case.off.quality_score, Some(1.0));
    assert_eq!(case.on.quality_score, Some(1.0));
    assert_eq!(case.quality_delta, Some(0.0));
    assert_eq!(case.outcome, "applied");
    assert_eq!(case.reason, None);
    assert_eq!(case.levers.len(), 1);
    assert_eq!(case.levers[0].lever, "window_fit");
    assert_eq!(case.levers[0].outcome, "applied");
    assert_eq!(case.levers[0].before_tokens, case.off.output_tokens);
    assert_eq!(case.levers[0].after_tokens, case.on.output_tokens);
    assert_eq!(case.levers[0].tokens_saved, case.tokens_saved);
    assert_eq!(case.added_compression_latency_micros, None);
    assert_eq!(report.schema_version, 4);
    assert_eq!(report.verified_provenance, None);
    assert_eq!(report.pipeline, window_fit_pipeline(192));
    assert_eq!(report.overall.applied_count, 1);
    assert_eq!(report.overall.skipped_count, 0);
    assert_eq!(report.overall.fallback_count, 0);
    assert_eq!(report.overall.skip_rate, 0.0);
    assert_eq!(report.overall.recommendation, Recommendation::Build);
}

#[tokio::test]
async fn explicit_input_budget_evaluates_unknown_target_models() {
    let mut case = long_case();
    case.id = "private-model-budget".to_string();
    case.target_model = "operator-private-model".to_string();

    let report = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "window-fit-explicit-budget-v1".to_string(),
            levers: vec![CompressionLeverConfig::WindowFit(WindowFitConfig {
                completion_reserve_tokens: 0,
                input_budget_tokens: Some(192),
            })],
            measure_latency: false,
        },
    )
    .await
    .expect("explicit input budget supports unknown target models");

    assert_eq!(report.cases[0].outcome, "applied");
    assert!(report.cases[0].on.output_tokens <= 192);
    assert!(report.cases[0].tokens_saved > 0);
    assert_eq!(report.cases[0].on.quality_score, Some(1.0));
}

#[tokio::test]
async fn rejects_zero_input_budget() {
    let error = evaluate_cases(
        &[long_case()],
        &EvalConfig {
            profile: "window_fit_zero_budget".to_string(),
            levers: vec![CompressionLeverConfig::WindowFit(WindowFitConfig {
                completion_reserve_tokens: 0,
                input_budget_tokens: Some(0),
            })],
            measure_latency: false,
        },
    )
    .await
    .expect_err("zero is not a valid production input budget");

    assert!(error
        .to_string()
        .contains("evaluation input budget must be greater than zero"));
}

#[tokio::test]
async fn rejects_savings_without_quality_evidence() {
    let mut case = long_case();
    case.id = "missing-quality".to_string();
    case.quality = QualitySpec::EvidenceRetention {
        required_evidence: Vec::new(),
    };

    let error = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "window_fit-smoke-v1".to_string(),
            levers: window_fit_pipeline(192),
            measure_latency: false,
        },
    )
    .await
    .expect_err("savings without a quality result must be invalid");

    assert!(error
        .to_string()
        .contains("required_evidence must contain at least one nonblank value"));
}

#[tokio::test]
async fn rejects_empty_or_blank_declared_quality_evidence_before_scoring() {
    let invalid = [
        (
            QualitySpec::EvidenceRetention {
                required_evidence: Vec::new(),
            },
            "required_evidence must contain at least one nonblank value",
        ),
        (
            QualitySpec::EvidenceRetention {
                required_evidence: vec!["  \n".to_string()],
            },
            "required_evidence must not contain blank values",
        ),
        (
            QualitySpec::ExactMatch {
                reference_answers: Vec::new(),
                off_prediction: String::new(),
                on_prediction: String::new(),
            },
            "reference_answers must contain at least one nonblank value",
        ),
        (
            QualitySpec::ExactMatch {
                reference_answers: vec![" \t".to_string()],
                off_prediction: String::new(),
                on_prediction: String::new(),
            },
            "reference_answers must not contain blank values",
        ),
        (
            QualitySpec::StructuredEquivalence {
                chunk_id: " \n".to_string(),
            },
            "chunk_id must not be blank",
        ),
        (
            QualitySpec::EdgePlacement {
                chunk_id: String::new(),
            },
            "chunk_id must not be blank",
        ),
    ];

    for (quality, expected) in invalid {
        let mut case = long_case();
        case.id = "invalid-quality".to_string();
        case.quality = quality;
        let error = evaluate_cases(
            &[case],
            &EvalConfig {
                profile: "quality-validation".to_string(),
                levers: Vec::new(),
                measure_latency: false,
            },
        )
        .await
        .expect_err("empty quality evidence must fail before scoring");
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[tokio::test]
async fn rejects_missing_structural_quality_target_even_without_savings() {
    let mut case = long_case();
    case.id = "missing-structural-target".to_string();
    case.quality = QualitySpec::StructuredEquivalence {
        chunk_id: "does-not-exist".to_string(),
    };

    let error = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "missing-structural-target".to_string(),
            levers: Vec::new(),
            measure_latency: false,
        },
    )
    .await
    .expect_err("every case needs complete off/on quality scores");

    assert!(error
        .to_string()
        .contains("does not produce complete off/on quality scores"));
}

#[tokio::test]
async fn non_expanding_only_acceptance_does_not_self_certify_build() {
    let mut case = long_case();
    case.id = "incomplete-acceptance".to_string();
    case.acceptance = AcceptanceSpec {
        require_non_expanding: true,
        ..AcceptanceSpec::default()
    };

    let report = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "incomplete-acceptance".to_string(),
            levers: Vec::new(),
            measure_latency: false,
        },
    )
    .await
    .expect("valid quality still produces a report");

    assert!(report.cases[0].acceptance_passed);
    assert_eq!(report.overall.recommendation, Recommendation::Defer);
}

#[tokio::test]
async fn scores_imported_predictions_against_reference_answers() {
    let mut case = long_case();
    case.id = "imported-predictions".to_string();
    case.quality = QualitySpec::ExactMatch {
        reference_answers: vec!["blue".to_string(), "project orbit is blue".to_string()],
        off_prediction: " Blue ".to_string(),
        on_prediction: "green".to_string(),
    };

    let report = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "window_fit-smoke-v1".to_string(),
            levers: window_fit_pipeline(192),
            measure_latency: false,
        },
    )
    .await
    .expect("imported predictions produce quality scores");

    assert_eq!(report.cases[0].off.quality_score, Some(1.0));
    assert_eq!(report.cases[0].quality_metric, "exact_match_accuracy");
    assert_eq!(report.cases[0].on.quality_score, Some(0.0));
    assert_eq!(report.cases[0].quality_delta, Some(-1.0));
    assert_eq!(report.overall.recommendation, Recommendation::Defer);
}

#[tokio::test]
async fn observed_mode_reports_added_compression_latency() {
    let report = evaluate_cases(
        &[long_case()],
        &EvalConfig {
            profile: "window_fit-smoke-v1".to_string(),
            levers: window_fit_pipeline(192),
            measure_latency: true,
        },
    )
    .await
    .expect("observed evaluation succeeds");

    assert_eq!(report.latency_mode, "observed_wall_clock");
    assert!(report.cases[0].added_compression_latency_micros.is_some());
    assert!(report.overall.added_compression_latency_micros.is_some());
}

#[test]
fn builds_each_stateless_production_lever_in_declared_order() {
    let configs = vec![
        CompressionLeverConfig::RagSelect(RagSelectConfig {
            min_tokens: 1,
            ranking: RetrievalRanking::Lexical,
            max_chunks: 2,
            min_relevance_percent: 0,
            drop_empty: false,
        }),
        CompressionLeverConfig::CompactSerialization(CompactSerializationConfig {
            min_tokens: 1,
            tabular: TabularSerializationConfig {
                enabled: true,
                min_rows: 2,
            },
        }),
        CompressionLeverConfig::PositionReorder(PositionReorderConfig {
            ranking: RetrievalRanking::Supplied,
        }),
        CompressionLeverConfig::WindowFit(WindowFitConfig {
            completion_reserve_tokens: 8_000,
            input_budget_tokens: Some(192),
        }),
    ];

    let levers = build_stateless_levers(&configs).expect("stateless production levers build");
    let kinds = levers
        .iter()
        .map(|lever| lever.kind().as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        kinds,
        vec![
            "rag_select",
            "compact_serialization",
            "position_reorder",
            "window_fit"
        ]
    );
}

#[tokio::test]
async fn rejects_stateful_summary_buffer_without_exposing_content() {
    let config = EvalConfig {
        profile: "unsupported-stateful".to_string(),
        levers: vec![CompressionLeverConfig::SummaryBuffer(SummaryBufferConfig {
            min_tokens: 1_000,
            retain_recent_messages: 2,
            target_summary_tokens: 200,
            summarizer: SummarizerConfig {
                provider: "internal".to_string(),
                model: "summary-model".to_string(),
                timeout_secs: 5,
            },
        })],
        measure_latency: false,
    };

    let error = evaluate_cases(&[long_case()], &config)
        .await
        .expect_err("stateful levers are outside the deterministic harness");

    assert_eq!(
        error.to_string(),
        "stateful levers are not supported by the deterministic harness"
    );
    assert!(!error.to_string().contains("project-orbit"));
}

#[tokio::test]
async fn reports_every_combined_lever_and_uses_the_run_outcome() {
    let report = evaluate_cases(
        &[long_case()],
        &EvalConfig {
            profile: "phase1-pipeline-smoke-v1".to_string(),
            levers: all_stateless_configs(),
            measure_latency: false,
        },
    )
    .await
    .expect("combined production pipeline evaluates");

    let case = &report.cases[0];
    assert_eq!(
        case.levers
            .iter()
            .map(|lever| lever.lever.as_str())
            .collect::<Vec<_>>(),
        vec![
            "rag_select",
            "compact_serialization",
            "position_reorder",
            "window_fit"
        ]
    );
    assert_eq!(case.levers[0].outcome, "skipped");
    assert_eq!(case.levers[3].outcome, "applied");
    assert_eq!(case.outcome, "applied");
    assert_eq!(case.reason, None);
    assert_eq!(report.pipeline, all_stateless_configs());
    assert!(case
        .levers
        .windows(2)
        .all(|pair| pair[0].after_tokens == pair[1].before_tokens));
    assert_eq!(
        case.levers
            .iter()
            .map(|lever| lever.tokens_saved)
            .sum::<u64>(),
        case.tokens_saved
    );
}

#[tokio::test]
async fn structured_json_and_public_table_v1_decode_score_equivalently() {
    let rows = (0..200)
        .map(|index| {
            json!({
                "id": index,
                "region": "north",
                "status": "ready",
                "units": 42
            })
        })
        .collect::<Vec<_>>();
    let body = serde_json::to_string_pretty(&rows).expect("rows serialize");
    let case = EvalCase {
        schema_version: 1,
        id: "compact-200-rows".to_string(),
        corpus: "compact_serialization_smoke".to_string(),
        target_model: "gpt-4".to_string(),
        messages: vec![marked_message(
            "Return the ready inventory rows.",
            &[("inventory", 1.0, "json", &body)],
        )],
        quality: QualitySpec::StructuredEquivalence {
            chunk_id: "inventory".to_string(),
        },
        acceptance: AcceptanceSpec {
            min_savings_ratio: Some(0.30),
            min_on_quality_score: Some(1.0),
            min_quality_delta: None,
            require_non_expanding: false,
        },
    };

    let report = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "compact-serialization-smoke-v1".to_string(),
            levers: vec![CompressionLeverConfig::CompactSerialization(
                CompactSerializationConfig {
                    min_tokens: 1,
                    tabular: TabularSerializationConfig {
                        enabled: true,
                        min_rows: 200,
                    },
                },
            )],
            measure_latency: false,
        },
    )
    .await
    .expect("structured compaction evaluates");

    let case = &report.cases[0];
    assert_eq!(case.quality_metric, "structured_equivalence");
    assert_eq!(case.off.quality_score, Some(1.0));
    assert_eq!(case.on.quality_score, Some(1.0));
    assert_eq!(case.quality_delta, Some(0.0));
    assert!(case.savings_ratio >= 0.30, "{case:#?}");
    assert!(case.acceptance_passed);
    assert!(report.overall.acceptance_passed);
    assert_eq!(report.overall.recommendation, Recommendation::Build);
}

#[tokio::test]
async fn structural_scorers_score_a_removed_selected_chunk_zero() {
    let chunks = [
        ("selected", 0.1, "json", r#"{"value":"violet"}"#),
        ("retained", 0.9, "text", "higher ranked synthetic evidence"),
    ];
    let cases = [
        EvalCase {
            schema_version: 1,
            id: "removed-structured-value".to_string(),
            corpus: "structural_removal".to_string(),
            target_model: "gpt-4".to_string(),
            messages: vec![marked_message("query", &chunks)],
            quality: QualitySpec::StructuredEquivalence {
                chunk_id: "selected".to_string(),
            },
            acceptance: AcceptanceSpec {
                min_on_quality_score: Some(1.0),
                ..AcceptanceSpec::default()
            },
        },
        EvalCase {
            schema_version: 1,
            id: "removed-edge-value".to_string(),
            corpus: "structural_removal".to_string(),
            target_model: "gpt-4".to_string(),
            messages: vec![marked_message("query", &chunks)],
            quality: QualitySpec::EdgePlacement {
                chunk_id: "selected".to_string(),
            },
            acceptance: AcceptanceSpec {
                min_on_quality_score: Some(1.0),
                ..AcceptanceSpec::default()
            },
        },
    ];
    let report = evaluate_cases(
        &cases,
        &EvalConfig {
            profile: "structural-removal".to_string(),
            levers: vec![CompressionLeverConfig::RagSelect(RagSelectConfig {
                min_tokens: 1,
                ranking: RetrievalRanking::Supplied,
                max_chunks: 1,
                min_relevance_percent: 0,
                drop_empty: false,
            })],
            measure_latency: false,
        },
    )
    .await
    .expect("removed structural evidence remains a scored result");

    assert!(report.cases.iter().all(|case| {
        case.off.quality_score == Some(1.0)
            && case.on.quality_score == Some(0.0)
            && !case.acceptance_passed
    }));
    assert_eq!(report.overall.recommendation, Recommendation::Defer);
}

#[tokio::test]
async fn edge_placement_improves_and_zero_savings_can_build() {
    let chunks = [
        ("low-a", 0.1, "text", "low evidence a"),
        ("low-b", 0.2, "text", "low evidence b"),
        ("required", 0.9, "text", "EVIDENCE::answer=violet"),
        ("medium-a", 0.3, "text", "medium evidence a"),
        ("medium-b", 0.4, "text", "medium evidence b"),
    ];
    let case = EvalCase {
        schema_version: 1,
        id: "position-required-to-edge".to_string(),
        corpus: "position_reorder_smoke".to_string(),
        target_model: "gpt-4".to_string(),
        messages: vec![marked_message("What is the answer?", &chunks)],
        quality: QualitySpec::EdgePlacement {
            chunk_id: "required".to_string(),
        },
        acceptance: AcceptanceSpec {
            min_savings_ratio: None,
            min_on_quality_score: None,
            min_quality_delta: Some(1.0),
            require_non_expanding: true,
        },
    };

    let report = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "position-reorder-smoke-v1".to_string(),
            levers: vec![CompressionLeverConfig::PositionReorder(
                PositionReorderConfig {
                    ranking: RetrievalRanking::Supplied,
                },
            )],
            measure_latency: false,
        },
    )
    .await
    .expect("position evaluation succeeds");

    let case = &report.cases[0];
    assert_eq!(case.quality_metric, "edge_placement");
    assert_eq!(case.off.quality_score, Some(0.0));
    assert_eq!(case.on.quality_score, Some(1.0));
    assert_eq!(case.quality_delta, Some(1.0));
    assert_eq!(case.tokens_saved, 0);
    assert_eq!(case.off.output_tokens, case.on.output_tokens);
    assert!(case.acceptance_passed);
    assert_eq!(report.overall.recommendation, Recommendation::Build);
}

#[tokio::test]
async fn edge_placement_treats_one_and_two_chunk_blocks_as_edges() {
    for (index, chunks) in [
        vec![("required", 1.0, "text", "one")],
        vec![
            ("required", 1.0, "text", "first"),
            ("other", 0.5, "text", "second"),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let case = EvalCase {
            schema_version: 1,
            id: format!("edge-count-{index}"),
            corpus: "edge_contract".to_string(),
            target_model: "gpt-4".to_string(),
            messages: vec![marked_message("query", &chunks)],
            quality: QualitySpec::EdgePlacement {
                chunk_id: "required".to_string(),
            },
            acceptance: AcceptanceSpec::default(),
        };
        let report = evaluate_cases(
            &[case],
            &EvalConfig {
                profile: "edge-contract".to_string(),
                levers: vec![CompressionLeverConfig::PositionReorder(
                    PositionReorderConfig {
                        ranking: RetrievalRanking::Supplied,
                    },
                )],
                measure_latency: false,
            },
        )
        .await
        .expect("edge contract evaluates");
        assert_eq!(report.cases[0].off.quality_score, Some(1.0));
        assert_eq!(report.cases[0].on.quality_score, Some(1.0));
    }
}

#[test]
fn acceptance_rejects_a_growing_treatment() {
    let acceptance = AcceptanceSpec {
        min_savings_ratio: None,
        min_on_quality_score: Some(1.0),
        min_quality_delta: None,
        require_non_expanding: true,
    };

    assert!(!acceptance.passes(100, 101, Some(1.0), Some(0.0)));
}

#[tokio::test]
async fn rejects_non_finite_and_out_of_range_acceptance_thresholds() {
    let invalid = [
        (
            AcceptanceSpec {
                min_savings_ratio: Some(f64::NAN),
                ..AcceptanceSpec::default()
            },
            "min_savings_ratio must be finite and between 0 and 1",
        ),
        (
            AcceptanceSpec {
                min_on_quality_score: Some(1.01),
                ..AcceptanceSpec::default()
            },
            "min_on_quality_score must be finite and between 0 and 1",
        ),
        (
            AcceptanceSpec {
                min_quality_delta: Some(-1.01),
                ..AcceptanceSpec::default()
            },
            "min_quality_delta must be finite and between -1 and 1",
        ),
    ];

    for (acceptance, expected) in invalid {
        let mut case = long_case();
        case.acceptance = acceptance;
        let error = evaluate_cases(
            &[case],
            &EvalConfig {
                profile: "invalid-acceptance".to_string(),
                levers: window_fit_pipeline(192),
                measure_latency: false,
            },
        )
        .await
        .expect_err("invalid acceptance must fail closed");
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}
