# prompt_injection_v2 eval corpus
*Last modified: 2026-04-27*

Golden corpora used by `crates/sbproxy-modules/tests/prompt_injection_eval.rs`
to gate detector regressions.

## Files

- `golden_injection.txt`: 33 known-injection prompts. One per line. Lines
  starting with `#` are treated as comments by the harness.
- `golden_clean.txt`: 35 known-clean prompts (typical user queries: code
  questions, recipes, travel, language translation, science Q and A).

## Sources

The injection corpus is paraphrased from public material. The originals
do not survive verbatim because the heuristic detector is just a
substring matcher; we keep the spirit of each pattern but vary the
surface form so the corpus exercises both exact pattern hits and
near-miss phrasings the heuristic should still catch.

- OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection):
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
- PROMPTBENCH (Microsoft Research): https://github.com/microsoft/promptbench
- Prompt Injection corpus by Lakera:
  https://github.com/lakeraai/pint-benchmark
- Anthropic prompt injection guidelines:
  https://docs.anthropic.com/en/docs/test-and-evaluate/strengthen-guardrails

The clean corpus is hand-written; it covers code questions, factual Q
and A, language translation, recipes, light creative writing, and DevOps
topics. None of the entries reference any of the high-confidence
patterns in the heuristic detector.

## Thresholds

The harness asserts that the heuristic detector achieves precision and
recall >= 0.7 on this corpus. These thresholds are intentionally lower
than the eventual ONNX target (>0.9) so we are gating against
regressions, not measuring final quality. Bump the thresholds when the
ONNX classifier lands.

## Running

```bash
cargo test -p sbproxy-modules --test prompt_injection_eval -- --ignored
```

The eval is `#[ignore]` by default so the regular `cargo test` run does
not depend on filesystem layout for the corpus.
