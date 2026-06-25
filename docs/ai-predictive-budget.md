# Predictive budgets with soft-landing
*Last modified: 2026-06-24*

A fixed-window budget enforces a hard cliff: requests pass until the cap,
then block at 100%. Soft-landing degrades gracefully as a scope approaches
its limit, so spend tapers instead of stopping dead. It is an opt-in
addition to the existing `budget` block; without it the hard-block behavior
is unchanged.

## Configuration

```yaml
budget:
  limits:
    - scope: workspace
      max_cost_usd: 10.0
      period: daily
  on_exceed: block
  soft_landing:
    warn_at: 0.8         # past 80% of the tightest window, warn
    downgrade_at: 0.95   # past 95%, downgrade to a cheaper model
    downgrade_to: gpt-4o-mini  # optional; else per-limit or cheapest
```

## Behavior

The soft-landing check runs after the hard pre-flight clears, on the
tightest active window across the configured limits (the larger of the
token and cost fractions). Below `warn_at` nothing changes. Between
`warn_at` and `downgrade_at` the request is allowed and a warning is
logged. Between `downgrade_at` and the cap the request's model is rewritten
to the soft-landing target, chosen as `downgrade_to`, else the limit's own
`downgrade_to`, else the cheapest model across the configured providers. At
or above the cap the hard `on_exceed` action owns the decision (block,
downgrade, or log), so the two never fight.

A soft-landing downgrade is recorded on the usage record (and the
verifiable ledger, when configured) with a `budget_soft_landing` tag, so
the degradation is queryable in the spend history.

## Integration with the policy plane

The live window fraction is published to the AI policy plane as
`ai.budget.fraction` and `ai.budget.exceeded` (see
[ai-policy-cel.md](ai-policy-cel.md)), so a CEL rule can compose budget
pressure with guardrail verdicts and principal context, for example to
route free-tier traffic to a cheaper model earlier than paid traffic.

## Try it

The runnable example is in
[`examples/ai-predictive-budget/`](../examples/ai-predictive-budget/).
