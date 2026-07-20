# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `rag-select-smoke-v1`
- Report schema: `4`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Verified provenance

- Manifest SHA-256: `f96e77cd1248de3c5d0dc9d528e0a21e768a4d335a599caa5d2084f94afbb5b3`
- Evidence boundary: only the selected, manifest-covered inputs listed below.
- No customer data; no official benchmark scores.

| Path | Corpus | Provenance | License | Customer data | Official score | SHA-256 |
|---|---|---|---|---|---|---|
| fixtures/rag-select-smoke.jsonl | rag_select_smoke | independently_authored_sanitized_shape | Apache-2.0 | no | no | 2f6dabbc2d7b8c91c4b9f957beafc2c86ae3cf04cd0b035f802b6dc57c032e80 |

## Ordered pipeline

1. `{"type":"rag_select","min_tokens":1,"ranking":"supplied","max_chunks":2,"min_relevance_percent":50,"drop_empty":false}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 1 | 1398 | 126 | 1272 | 90.99% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| rag_select_smoke | 1 | 1398 | 126 | 1272 | 90.99% | 1.000 | 1.000 | +0.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 1 | 0 | 0 | 0.00% | none |
| rag_select_smoke | 1 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| rag_select_ranked_signal | rag_select_smoke | gpt-4 | evidence_retention | 1272 | 90.99% | 1.000 | 1.000 | +0.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| rag_select_ranked_signal | 1 | rag_select | 1398 | 126 | 1272 | applied | - |
