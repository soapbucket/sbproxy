# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `query-select-smoke-v1`
- Report schema: `4`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Verified provenance

- Manifest SHA-256: `a9a08b96937b1f7b022d69806bf9b5a0ccbc18a036c7c3ffe225f8db30702542`
- Evidence boundary: only the selected, manifest-covered inputs listed below.
- No customer data; no official benchmark scores.

| Path | Corpus | Provenance | License | Customer data | Official score | SHA-256 |
|---|---|---|---|---|---|---|
| fixtures/query-select-smoke.jsonl | query_select_smoke | independently_authored_sanitized_shape | Apache-2.0 | no | no | 13807fd82f05ee93912eaadb12e53540666dc0f39071bee296bc70c2237877a6 |

## Ordered pipeline

1. `{"type":"query_select","max_sentences":4}`
2. `{"type":"window_fit","completion_reserve_tokens":8000,"input_budget_tokens":192}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 2 | 848 | 253 | 595 | 70.17% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| query_select_smoke | 2 | 848 | 253 | 595 | 70.17% | 1.000 | 1.000 | +0.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 2 | 0 | 0 | 0.00% | none |
| query_select_smoke | 2 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| query_select_missing_query_fallback | query_select_smoke | gpt-4 | evidence_retention | 325 | 89.29% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| query_select_multi_document_qa | query_select_smoke | gpt-4 | evidence_retention | 270 | 55.79% | 1.000 | 1.000 | +0.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| query_select_missing_query_fallback | 1 | query_select | 364 | 364 | 0 | skipped | missing_query |
| query_select_missing_query_fallback | 2 | window_fit | 364 | 39 | 325 | applied | - |
| query_select_multi_document_qa | 1 | query_select | 484 | 214 | 270 | applied | - |
| query_select_multi_document_qa | 2 | window_fit | 214 | 214 | 0 | skipped | not_eligible |
