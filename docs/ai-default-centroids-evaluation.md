# Default safety centroid evaluation

*Last modified: 2026-07-26*

This report is generated from repo-authored, held-out fixtures. The training and evaluation prompts are disjoint. No external attack corpus is vendored or redistributed.

## Method

The regeneration tool embeds each training prompt with the pinned `all-MiniLM-L6-v2` ONNX model, averages each class into a unit centroid, rounds vector components to six decimal places for cross-CPU reproducibility, then classifies held-out prompts by cosine similarity. A verdict requires a score of at least 0.30 and a 0.10 lead over the runner-up for the binary taxonomies, or a 0.08 lead for the six-class content-safety taxonomy. The false-positive budget is zero unsafe verdicts on the 10 held-out safe prompts in each taxonomy. This conservative budget takes priority over recall because these guardrails block requests before provider egress. Threshold abstentions are allowed.

- Artifact version: `safety-centroids-1.0.0`
- Artifact SHA-256: `69bc52ca6f6c4e0695529dcc8c8f430255e2574a780af3521fff12a4227cbc66`
- Model: `sentence-transformers/all-MiniLM-L6-v2` at revision `5641a7880f40ebf4035d05e60c5f9b7a9c272c84`
- Model SHA-256: `6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452`
- Tokenizer SHA-256: `be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037`

## `content_safety`

Safe-prompt false positives: 0/10. Abstentions: 10/60.

| Class | Support | Precision | Recall |
|---|---:|---:|---:|
| `hate_speech` | 10 | 1.000 | 1.000 |
| `illegal` | 10 | 1.000 | 1.000 |
| `safe` | 10 | 1.000 | 0.100 |
| `self_harm` | 10 | 0.909 | 1.000 |
| `sexual` | 10 | 1.000 | 1.000 |
| `violence` | 10 | 1.000 | 0.800 |

## `jailbreak`

Safe-prompt false positives: 0/10. Abstentions: 7/20.

| Class | Support | Precision | Recall |
|---|---:|---:|---:|
| `jailbreak` | 10 | 1.000 | 1.000 |
| `safe` | 10 | 1.000 | 0.300 |

## `toxicity`

Safe-prompt false positives: 0/10. Abstentions: 7/20.

| Class | Support | Precision | Recall |
|---|---:|---:|---:|
| `safe` | 10 | 1.000 | 0.300 |
| `toxic` | 10 | 1.000 | 1.000 |
