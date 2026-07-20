# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `compact-serialization-smoke-v1`
- Report schema: `4`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Verified provenance

- Manifest SHA-256: `f96e77cd1248de3c5d0dc9d528e0a21e768a4d335a599caa5d2084f94afbb5b3`
- Evidence boundary: only the selected, manifest-covered inputs listed below.
- No customer data; no official benchmark scores.

| Path | Corpus | Provenance | License | Customer data | Official score | SHA-256 |
|---|---|---|---|---|---|---|
| fixtures/compact-serialization-smoke.jsonl | compact_serialization_smoke | independently_authored_sanitized_shape | Apache-2.0 | no | no | 6486ae7ff0df33d1bd5152037b0bfbc5251f5b05858ba1167254490e49b18737 |

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
