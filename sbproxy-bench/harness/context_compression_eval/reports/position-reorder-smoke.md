# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `position-reorder-smoke-v1`
- Report schema: `3`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Ordered pipeline

1. `{"type":"position_reorder","ranking":"supplied"}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 1 | 278 | 278 | 0 | 0.00% | 0.000 | 1.000 | +1.000 | pass | not measured | build |
| position_reorder_smoke | 1 | 278 | 278 | 0 | 0.00% | 0.000 | 1.000 | +1.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 1 | 0 | 0 | 0.00% | none |
| position_reorder_smoke | 1 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| position_required_center_to_edge | position_reorder_smoke | gpt-4 | edge_placement | 0 | 0.00% | 0.000 | 1.000 | +1.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| position_required_center_to_edge | 1 | position_reorder | 278 | 278 | 0 | applied | - |
