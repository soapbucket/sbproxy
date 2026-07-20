# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `phase1-pipeline-smoke-v1`
- Report schema: `3`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Ordered pipeline

1. `{"type":"rag_select","min_tokens":1,"ranking":"supplied","max_chunks":3,"min_relevance_percent":20,"drop_empty":false}`
2. `{"type":"compact_serialization","min_tokens":1,"tabular":{"enabled":true,"min_rows":20}}`
3. `{"type":"position_reorder","ranking":"supplied"}`
4. `{"type":"window_fit","completion_reserve_tokens":8000,"input_budget_tokens":512}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 1 | 1873 | 487 | 1386 | 74.00% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| phase1_pipeline_smoke | 1 | 1873 | 487 | 1386 | 74.00% | 1.000 | 1.000 | +0.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 1 | 0 | 0 | 0.00% | none |
| phase1_pipeline_smoke | 1 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| phase1_combined_launch_key | phase1_pipeline_smoke | gpt-4 | evidence_retention | 1386 | 74.00% | 1.000 | 1.000 | +0.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| phase1_combined_launch_key | 1 | rag_select | 1873 | 876 | 997 | applied | - |
| phase1_combined_launch_key | 2 | compact_serialization | 876 | 487 | 389 | applied | - |
| phase1_combined_launch_key | 3 | position_reorder | 487 | 487 | 0 | applied | - |
| phase1_combined_launch_key | 4 | window_fit | 487 | 487 | 0 | skipped | not_eligible |
