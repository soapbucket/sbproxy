//! Runnable demonstration of `sbproxy_ai::evaluation` (WOR-2672): an
//! offline evaluation run over a small dataset using datasets, custom
//! metrics, LLM-as-judge prompting/parsing, prompt scoring, and
//! experiment tracking together.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p sbproxy-ai --example ai_evaluation_harness
//! ```
//!
//! This does not call a real model: `parse_judge_response` is fed a
//! hardcoded stand-in for what a judge model would return, so the
//! example runs offline with no API key.

use sbproxy_ai::evaluation::{
    build_judge_prompt, parse_judge_response, pass_rate, Dataset, DatasetEntry, DatasetStore,
    Experiment, ExperimentStore, JudgeResult, MetricType, PromptScore, PromptScorer,
};
use serde_json::json;
use std::collections::HashMap;

/// Two candidate system-prompt phrasings for the same support task,
/// each answering the same dataset question. `PromptScorer` compares
/// PROMPT VARIANTS this way, not models directly: pick the
/// better-performing template, independent of which model runs it.
const PROMPT_VARIANTS: &[(&str, &str)] = &[
    (
        "terse-system-prompt",
        "Go to Settings > Security > Reset password to change it.",
    ),
    (
        "detailed-system-prompt",
        "You can reset your password there.",
    ),
];

fn main() {
    // --- Dataset: what we're evaluating against ---
    let datasets = DatasetStore::new();
    datasets.save(Dataset::new(
        "support-qa",
        vec![
            DatasetEntry::with_expected(
                "How do I reset my password?",
                "Go to Settings, then Security, then Reset password.",
            ),
            DatasetEntry::with_expected(
                "What is your refund policy?",
                "Full refund within 30 days of purchase.",
            ),
        ],
    ));
    let ds = datasets.get("support-qa").expect("dataset was just saved");
    println!("Evaluating {} entries from '{}'", ds.entries.len(), ds.name);

    // --- Custom pass/fail metrics: cheap, deterministic, no model call ---
    let metrics = vec![
        MetricType::LengthRange(20, 200),
        MetricType::ContainsKeywords(vec!["password".to_string()]),
    ];
    let judge_criteria = vec!["accuracy".to_string(), "helpfulness".to_string()];

    let experiments = ExperimentStore::new();
    let scorer = PromptScorer::new();
    let judge_model = "gpt-4o";

    for (variant_name, response) in PROMPT_VARIANTS {
        let rate = pass_rate(response, &metrics);
        println!("\n[{variant_name}] response: {response:?}");
        println!("  custom-metric pass rate: {rate:.2}");

        // Build the judge prompt an operator would submit to a real judge
        // model, then parse a stand-in response (in production this
        // string comes back from the configured judge model).
        let _prompt = build_judge_prompt(response, &judge_criteria);
        let stub_judge_output = format!(
            r#"{{"scores": {{"accuracy": {}, "helpfulness": 8}}, "reasoning": "clear and on-topic"}}"#,
            if response.len() > 40 { 9 } else { 6 }
        );
        let judged = parse_judge_response(&stub_judge_output).expect("stub judge JSON parses");
        println!("  judge composite score (0-10): {:.1}", judged.score);

        scorer.record(PromptScore::new(
            *variant_name,
            judge_model,
            judged.score / 10.0,
            rate,
        ));

        experiments.record(Experiment::new(
            format!("run-{variant_name}"),
            "support-prompt-variant-comparison",
            judge_model,
            *variant_name,
            json!({"temperature": 0.3}),
            "2026-08-22T00:00:00Z",
        ));
    }

    println!("\nPrompt variants ranked by average judge score (highest first):");
    for (variant, avg) in scorer.rank_prompts() {
        println!("  {avg:.3}  {variant}");
    }
    println!(
        "Average score for 'terse-system-prompt' alone: {:.3}",
        scorer
            .average_score("terse-system-prompt")
            .expect("recorded above")
    );
    println!(
        "Total scoring observations recorded: {}",
        scorer.observation_count()
    );

    println!(
        "\nRecorded {} experiment runs for 'support-prompt-variant-comparison'",
        experiments
            .list_by_name("support-prompt-variant-comparison")
            .len()
    );
    println!(
        "All experiments ever recorded: {}",
        experiments.list_all().len()
    );
    if let Some(run) = experiments.get_by_id("run-terse-system-prompt") {
        println!(
            "Looked up by id: model={}, prompt_version={}",
            run.model, run.prompt_version
        );
    }

    // `JudgeResult::compute_composite` is what `parse_judge_response`
    // calls internally; demonstrated directly here for a caller building
    // its own judge-result aggregation from criteria scores it already
    // has in hand.
    let mut manual_scores = HashMap::new();
    manual_scores.insert("clarity".to_string(), 9.0);
    manual_scores.insert("tone".to_string(), 7.0);
    let composite =
        JudgeResult::compute_composite(manual_scores, "hand-scored example".to_string());
    println!(
        "\nManually composed judge result: score={:.1}, reasoning={:?}",
        composite.score, composite.reasoning
    );
}
