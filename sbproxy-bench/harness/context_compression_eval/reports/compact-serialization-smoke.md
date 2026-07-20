# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `compact-serialization-smoke-v1`
- Report schema: `3`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Ordered pipeline

1. `{"type":"compact_serialization","min_tokens":1,"tabular":{"enabled":true,"min_rows":200}}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 1 | 7065 | 3476 | 3589 | 50.80% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| compact_serialization_smoke | 1 | 7065 | 3476 | 3589 | 50.80% | 1.000 | 1.000 | +0.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 1 | 0 | 0 | 0.00% | none |
| compact_serialization_smoke | 1 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| compact_uniform_inventory_200 | compact_serialization_smoke | gpt-4 | structured_equivalence | 3589 | 50.80% | 1.000 | 1.000 | +0.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| compact_uniform_inventory_200 | 1 | compact_serialization | 7065 | 3476 | 3589 | applied | - |
