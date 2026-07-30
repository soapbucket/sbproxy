# Context Compression Evaluation

This is a first-party smoke evaluation, not an official third-party benchmark score.

- Profile: `token-prune-target-recorded-smoke-v1`
- Report schema: `4`
- Token counter: `sbproxy_target_model`
- Latency mode: `omitted_for_deterministic_gate`

## Token-prune certification boundary

The checked report uses a deterministic recorded backend with network access disabled. It certifies gateway targeting, accounting, and evidence retention. In production, the gateway uses the configured LLMLingua-2 sidecar.

- Evaluation backend: `deterministic_recorded_v1`
- Production backend: `llmlingua_2_sidecar`
- Network access: `no`

## Verified provenance

- Manifest SHA-256: `a9a08b96937b1f7b022d69806bf9b5a0ccbc18a036c7c3ffe225f8db30702542`
- Evidence boundary: only the selected, manifest-covered inputs listed below.
- No customer data; no official benchmark scores.

| Path | Corpus | Provenance | License | Customer data | Official score | SHA-256 |
|---|---|---|---|---|---|---|
| fixtures/token-prune-smoke.jsonl | token_prune_smoke | independently_authored_recorded_token_prune_smoke | Apache-2.0 | no | no | ad5adc58804edc19b0c14f681a2594f8e6ce764c598109d4203c77bacea917f9 |

## Ordered pipeline

1. `{"type":"token_prune","min_tokens":32,"endpoint":"recorded://token-prune-v1","model":"llmlingua-2-recorded-smoke-v1","timeout_ms":25,"max_chunks":8,"target":{"mode":"target_tokens","target_tokens":48}}`

## Tokens versus quality and accuracy

| Corpus | Cases | Input tokens | Output tokens | Saved | Savings | Off quality | On quality | Delta | Acceptance | Added latency (us) | Recommendation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| overall | 2 | 646 | 306 | 340 | 52.63% | 1.000 | 1.000 | +0.000 | pass | not measured | build |
| token_prune_smoke | 2 | 646 | 306 | 340 | 52.63% | 1.000 | 1.000 | +0.000 | pass | not measured | build |

## Outcomes

| Corpus | Applied | Skipped | Fallback | Skip rate | Reasons |
|---|---:|---:|---:|---:|---|
| overall | 2 | 0 | 0 | 0.00% | none |
| token_prune_smoke | 2 | 0 | 0 | 0.00% | none |

## Case results

| Case | Corpus | Target model | Score | Saved | Savings | Off quality | On quality | Delta | Acceptance | Outcome | Reason |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| token_prune_depot_lookup | token_prune_smoke | gpt-4 | evidence_retention | 170 | 51.99% | 1.000 | 1.000 | +0.000 | pass | applied | - |
| token_prune_route_lookup | token_prune_smoke | gpt-4 | evidence_retention | 170 | 53.29% | 1.000 | 1.000 | +0.000 | pass | applied | - |

## Ordered lever results

| Case | Order | Lever | Before | After | Saved | Outcome | Reason |
|---|---:|---|---:|---:|---:|---|---|
| token_prune_depot_lookup | 1 | token_prune | 327 | 157 | 170 | applied | - |
| token_prune_route_lookup | 1 | token_prune | 319 | 149 | 170 | applied | - |
