use context_compression_eval::{
    evaluate_cases, render_json, render_markdown, EvalCase, EvalConfig, EvalReport, QualitySpec,
};
use serde_json::json;

async fn report() -> EvalReport {
    let case = EvalCase {
        schema_version: 1,
        id: "coding-agent-logs-1".to_string(),
        corpus: "coding_agent_smoke".to_string(),
        target_model: "gpt-4".to_string(),
        messages: vec![
            json!({"role": "system", "content": "Use only supplied command output."}),
            json!({"role": "tool", "content": "old build log ".repeat(300)}),
            json!({"role": "user", "content": "EVIDENCE::failure=timeout. State the failure."}),
        ],
        quality: QualitySpec::EvidenceRetention {
            required_evidence: vec!["EVIDENCE::failure=timeout".to_string()],
        },
    };
    evaluate_cases(
        &[case],
        &EvalConfig {
            profile: "window_fit-smoke-v1".to_string(),
            completion_reserve_tokens: 8_000,
            measure_latency: false,
        },
    )
    .await
    .expect("report")
}

#[tokio::test]
async fn json_and_markdown_are_byte_stable() {
    let report = report().await;

    let first_json = render_json(&report).expect("json renders");
    let second_json = render_json(&report).expect("json rerenders");
    assert_eq!(first_json, second_json);
    assert!(first_json.ends_with('\n'));
    let decoded: EvalReport = serde_json::from_str(&first_json).expect("report JSON round trips");
    assert_eq!(decoded, report);

    let first_markdown = render_markdown(&report);
    let second_markdown = render_markdown(&report);
    assert_eq!(first_markdown, second_markdown);
    assert!(first_markdown.ends_with('\n'));
    assert!(first_markdown.contains("# Context Compression Evaluation"));
    assert!(first_markdown.contains("window_fit-smoke-v1"));
    assert!(first_markdown.contains("coding_agent_smoke"));
    assert!(first_markdown.contains("omitted_for_deterministic_gate"));
    assert!(first_markdown.contains("build"));
}
