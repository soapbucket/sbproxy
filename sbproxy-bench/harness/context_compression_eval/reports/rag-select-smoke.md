# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `rag-select-smoke-v1`
- Report schema: `3`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

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
