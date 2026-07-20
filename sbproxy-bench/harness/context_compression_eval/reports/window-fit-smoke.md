# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `window-fit-smoke-v1`
- Report schema: `3`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Ordered pipeline

1. `{"type":"window_fit","completion_reserve_tokens":8000,"input_budget_tokens":192}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 6 | 1929 | 486 | 1443 | 74.81% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| coding_agent_smoke | 4 | 1325 | 369 | 956 | 72.15% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| ruler_smoke | 2 | 604 | 117 | 487 | 80.63% | 1.000 | 1.000 | +0.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 6 | 0 | 0 | 0.00% | none |
| coding_agent_smoke | 4 | 0 | 0 | 0.00% | none |
| ruler_smoke | 2 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| coding_agent_diff | coding_agent_smoke | gpt-4 | evidence_retention | 230 | 70.12% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| coding_agent_logs | coding_agent_smoke | gpt-4 | evidence_retention | 232 | 72.27% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| coding_agent_rg_output | coding_agent_smoke | gpt-4 | evidence_retention | 311 | 75.12% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| coding_agent_tool_output | coding_agent_smoke | gpt-4 | evidence_retention | 183 | 69.85% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| ruler_multi_hop_launch | ruler_smoke | gpt-4 | evidence_retention | 235 | 79.66% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| ruler_retrieval_orbit | ruler_smoke | gpt-4 | evidence_retention | 252 | 81.55% | 1.000 | 1.000 | +0.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| coding_agent_diff | 1 | window_fit | 328 | 98 | 230 | applied | - |
| coding_agent_logs | 1 | window_fit | 321 | 89 | 232 | applied | - |
| coding_agent_rg_output | 1 | window_fit | 414 | 103 | 311 | applied | - |
| coding_agent_tool_output | 1 | window_fit | 262 | 79 | 183 | applied | - |
| ruler_multi_hop_launch | 1 | window_fit | 295 | 60 | 235 | applied | - |
| ruler_retrieval_orbit | 1 | window_fit | 309 | 57 | 252 | applied | - |
