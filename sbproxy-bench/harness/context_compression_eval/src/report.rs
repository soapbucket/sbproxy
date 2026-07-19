use anyhow::Result;

use crate::{AggregateReport, EvalReport, Recommendation};

/// Render stable pretty JSON with one trailing newline.
pub fn render_json(report: &EvalReport) -> Result<String> {
    let mut rendered = serde_json::to_string_pretty(report)?;
    rendered.push('\n');
    Ok(rendered)
}

/// Render a stable human-readable Pareto report.
pub fn render_markdown(report: &EvalReport) -> String {
    let mut output = String::new();
    output.push_str("# Context Compression Evaluation\n\n");
    output.push_str(
        "This is a first-party smoke evaluation, not an official third-party benchmark score.\n\n",
    );
    output.push_str(&format!(
        "- Profile: `{}`\n",
        escape_inline(&report.profile)
    ));
    output.push_str(&format!(
        "- Token counter: `{}`\n",
        escape_inline(&report.token_counter)
    ));
    output.push_str(&format!(
        "- Latency mode: `{}`\n\n",
        escape_inline(&report.latency_mode)
    ));
    output.push_str("## Tokens versus quality and accuracy\n\n");
    output.push_str("| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Added latency (us) | Recommendation |\n");
    output.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
    push_aggregate_row(&mut output, "overall", &report.overall);
    for (corpus, aggregate) in &report.corpora {
        push_aggregate_row(&mut output, corpus, aggregate);
    }

    output.push_str("\n## Outcomes\n\n");
    output.push_str("| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |\n");
    output.push_str("|---|---:|---:|---:|---:|---|\n");
    push_outcome_row(&mut output, "overall", &report.overall);
    for (corpus, aggregate) in &report.corpora {
        push_outcome_row(&mut output, corpus, aggregate);
    }

    output.push_str("\n## Case results\n\n");
    output.push_str("| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Outcome | Reason |\n");
    output.push_str("|---|---|---|---|---:|---:|---:|---:|---:|---|---|\n");
    for case in &report.cases {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            escape_cell(&case.id),
            escape_cell(&case.corpus),
            escape_cell(&case.target_model),
            escape_cell(&case.quality_metric),
            case.tokens_saved,
            percent(case.savings_ratio),
            score(case.off.quality_score),
            score(case.on.quality_score),
            signed_score(case.quality_delta),
            escape_cell(&case.outcome),
            case.reason
                .as_deref()
                .map(escape_cell)
                .unwrap_or_else(|| "-".to_string()),
        ));
    }
    output
}

fn push_outcome_row(output: &mut String, name: &str, report: &AggregateReport) {
    let reasons = if report.reasons.is_empty() {
        "none".to_string()
    } else {
        report
            .reasons
            .iter()
            .map(|(reason, count)| format!("{}={count}", escape_cell(reason)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    output.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} |\n",
        escape_cell(name),
        report.applied_count,
        report.skipped_count,
        report.fallback_count,
        percent(report.skip_rate),
        reasons,
    ));
}

fn push_aggregate_row(output: &mut String, name: &str, report: &AggregateReport) {
    output.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        escape_cell(name),
        report.case_count,
        report.input_tokens,
        report.output_tokens,
        report.tokens_saved,
        percent(report.savings_ratio),
        score(report.off_quality_score),
        score(report.on_quality_score),
        signed_score(report.quality_delta),
        report
            .added_compression_latency_micros
            .map(|value| value.to_string())
            .unwrap_or_else(|| "not measured".to_string()),
        recommendation(report.recommendation),
    ));
}

fn recommendation(value: Recommendation) -> &'static str {
    match value {
        Recommendation::Build => "build",
        Recommendation::Borrow => "borrow",
        Recommendation::Defer => "defer",
    }
}

fn percent(value: f64) -> String {
    format!("{:.2}%", value * 100.0)
}

fn score(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.3}"))
        .unwrap_or_else(|| "not scored".to_string())
}

fn signed_score(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:+.3}"))
        .unwrap_or_else(|| "not scored".to_string())
}

fn escape_inline(value: &str) -> String {
    value.replace('`', "\\`").replace(['\n', '\r'], " ")
}

fn escape_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
        .trim()
        .to_string()
}
