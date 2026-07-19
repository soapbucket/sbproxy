use context_compression_eval::{evaluate_cases, EvalCase, EvalConfig, QualitySpec, Recommendation};
use serde_json::json;

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
    }
}

#[tokio::test]
async fn evaluates_identical_arms_through_real_window_fit() {
    let report = evaluate_cases(
        &[long_case()],
        &EvalConfig {
            profile: "window_fit-smoke-v1".to_string(),
            completion_reserve_tokens: 8_000,
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
    assert_eq!(case.added_compression_latency_micros, None);
    assert_eq!(report.overall.applied_count, 1);
    assert_eq!(report.overall.skipped_count, 0);
    assert_eq!(report.overall.fallback_count, 0);
    assert_eq!(report.overall.skip_rate, 0.0);
    assert_eq!(report.overall.recommendation, Recommendation::Build);
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
            completion_reserve_tokens: 8_000,
            measure_latency: false,
        },
    )
    .await
    .expect_err("savings without a quality result must be invalid");

    assert!(error
        .to_string()
        .contains("claims token savings without an off/on quality score"));
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
            completion_reserve_tokens: 8_000,
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
            completion_reserve_tokens: 8_000,
            measure_latency: true,
        },
    )
    .await
    .expect("observed evaluation succeeds");

    assert_eq!(report.latency_mode, "observed_wall_clock");
    assert!(report.cases[0].added_compression_latency_micros.is_some());
    assert!(report.overall.added_compression_latency_micros.is_some());
}
