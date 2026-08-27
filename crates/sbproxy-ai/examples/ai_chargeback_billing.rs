//! Runnable demonstration of `sbproxy_ai::billing` (WOR-2672): feed a
//! `ChargebackTracker` a batch of synthetic completed-call events across
//! two tenants and three provider/model pairs (the same `UsageSink`
//! surface every real AI gateway call already flows through), then print
//! team totals, a unified bill, and a 30-day spend forecast.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p sbproxy-ai --example ai_chargeback_billing
//! ```

use sbproxy_ai::billing::{
    forecast_spend, generate_bill_from_snapshot, remaining_budget, ChargebackTracker,
    UsageDataPoint,
};
use sbproxy_ai::usage_sink::{LlmUsageEvent, UsageSink};

/// Build a synthetic completed-call event. In production this comes from
/// the AI dispatch path, not hand-assembled like this; the shape matches
/// exactly what every registered `UsageSink` (this one included) receives.
fn event(
    tenant_id: &str,
    team: &str,
    provider: &str,
    model: &str,
    tokens: u64,
    cost_usd: f64,
) -> LlmUsageEvent {
    LlmUsageEvent {
        provider: provider.to_string(),
        model: model.to_string(),
        prompt_tokens: tokens * 2 / 3,
        completion_tokens: tokens / 3,
        total_tokens: tokens,
        cost_usd,
        latency_ms: 400,
        status: 200,
        key_id: None,
        tenant_id: Some(tenant_id.to_string()),
        project: Some("customer-support-bot".to_string()),
        user: None,
        team: Some(team.to_string()),
        tags: Vec::new(),
        metadata: Default::default(),
        request_id: None,
        session_id: None,
        tag: None,
        priority: None,
        engine_version: None,
        agent_id: None,
        a2a_context_id: None,
        a2a_identity_verified: None,
        workflow_id: None,
        logical_model: None,
        served_model: None,
        finish_reason: None,
        shadow_of: None,
        credential_source: None,
    }
}

fn main() {
    let tracker = ChargebackTracker::new();

    // Two tenants ("acme" and "globex"), three provider/model pairs, a
    // handful of calls each, standing in for a day of real traffic.
    let calls = [
        ("ws-acme", "support-eng", "openai", "gpt-4o", 1200, 0.42),
        ("ws-acme", "support-eng", "openai", "gpt-4o", 900, 0.31),
        (
            "ws-acme",
            "platform-eng",
            "anthropic",
            "claude-3-5-sonnet",
            2000,
            0.90,
        ),
        (
            "ws-globex",
            "data-eng",
            "anthropic",
            "claude-3-haiku",
            1500,
            0.12,
        ),
        (
            "ws-globex",
            "data-eng",
            "openai",
            "gpt-3.5-turbo",
            800,
            0.05,
        ),
    ];
    for (tenant, team, provider, model, tokens, cost) in calls {
        UsageSink::record(
            &tracker,
            &event(tenant, team, provider, model, tokens, cost),
        );
    }

    println!("Recorded {} event-log entries", tracker.entries_count());

    println!("Cost by team:");
    let mut team_totals: Vec<(String, f64)> = tracker.total_by_team().into_iter().collect();
    team_totals.sort_by(|a, b| a.0.cmp(&b.0));
    for (team, cost) in &team_totals {
        println!("  {team:<14} ${cost:.2}");
    }

    println!("\nCost by workspace (tenant):");
    let mut ws_totals: Vec<_> = tracker.workspace_totals_snapshot().into_iter().collect();
    ws_totals.sort_by(|a, b| a.0.cmp(&b.0));
    for (workspace, totals) in &ws_totals {
        println!(
            "  {workspace:<10} {} requests, {} tokens, ${:.2}",
            totals.request_count, totals.tokens, totals.cost_usd
        );
    }

    println!("\nUnified bill for the period:");
    let snapshot = tracker.snapshot();
    let (period_start, period_end) =
        billing_period_from_snapshot(&snapshot).expect("example recorded rows");
    let bill = generate_bill_from_snapshot(&snapshot, &period_start, &period_end)
        .expect("example-derived billing period is valid for the retained snapshot");
    for item in &bill.line_items {
        println!(
            "  {:<10} {:<20} {:>3} req  {:>6} tok  ${:.2}",
            item.provider, item.model, item.requests, item.tokens, item.cost
        );
    }
    println!("  {:->50}", "");
    println!("  total: ${:.2}", bill.total);

    // Project the next 30 days from a week of daily totals shaped like
    // this tracker's current run rate, and check it against a monthly cap.
    let daily_history: Vec<UsageDataPoint> = (0..7)
        .map(|day| UsageDataPoint::new(day, bill.total))
        .collect();
    let monthly_budget = 300.0;
    // Both refuse rather than answer when the series cannot be summed
    // exactly, so a poisoned cost cannot read as "you are under budget".
    match (
        forecast_spend(&daily_history, 30),
        remaining_budget(&daily_history, monthly_budget),
    ) {
        (Some(projected), Some(remaining)) => {
            println!("\nAt today's run rate, projected 30-day spend: ${projected:.2}");
            println!("Remaining budget under a ${monthly_budget:.2} monthly cap: ${remaining:.2}");
        }
        _ => println!("\nSpend history could not be summed exactly; no forecast is reported."),
    }
}

fn billing_period_from_snapshot(
    snapshot: &sbproxy_ai::billing::ChargebackSnapshot,
) -> Option<(String, String)> {
    let period_start = snapshot.earliest_retained_timestamp.clone()?;
    let latest =
        chrono::DateTime::parse_from_rfc3339(snapshot.latest_retained_timestamp.as_deref()?)
            .ok()?
            .with_timezone(&chrono::Utc);
    let period_end = latest.checked_add_signed(chrono::TimeDelta::seconds(1))?;
    Some((period_start, period_end.to_rfc3339()))
}
