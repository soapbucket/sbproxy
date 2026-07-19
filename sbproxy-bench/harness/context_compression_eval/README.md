# Context compression evaluation harness

*Last modified: 2026-07-19*

This standalone Rust harness compares context compression off and on with the
same target model and original message array. The off arm uses an empty public
`CompressionRunner`. The on arm uses the real public `CompressionRunner` and
`WindowFitLever`. Both arms use sbproxy's target-model token counter.

The committed gate is intentionally small and deterministic. It is a
first-party smoke evaluation, not an official benchmark score for RULER,
HELMET, LongBench-v2, or NoLiMa.

## What the report measures

Each case and corpus reports:

- target-model input, output, and saved tokens;
- saved-token ratio;
- off and on quality plus quality delta;
- applied, skipped, or failed outcome and its closed reason;
- optional added compression latency; and
- a deterministic `build`, `borrow`, or `defer` recommendation.

The target-model counter is the production counter used by the compression
runner. Precision depends on the target model's registered tokenizer support,
so the harness does not claim universal exact BPE counts.

The deterministic gate omits wall-clock latency because scheduler timing would
make a committed report flap. Use `--measure-latency` to produce a separate,
non-gated report with observed microseconds:

```bash
cd sbproxy-bench/harness/context_compression_eval
cargo run --locked -- generate \
  --input fixtures/ruler-smoke.jsonl \
  --input fixtures/coding-agent-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --input-budget-tokens 192 \
  --json-report /tmp/context-compression-observed.json \
  --markdown-report /tmp/context-compression-observed.md \
  --measure-latency
```

## Reproduce the committed gate

The harness is outside the root workspace and owns its lockfile. Always use
`--locked`.

```bash
cd sbproxy-bench/harness/context_compression_eval

cargo test --locked
cargo run --locked -- check \
  --input fixtures/ruler-smoke.jsonl \
  --input fixtures/coding-agent-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --input-budget-tokens 192 \
  --json-report reports/window-fit-smoke.json \
  --markdown-report reports/window-fit-smoke.md
```

To intentionally update the committed reports, replace `check` with
`generate`, review both files, then run `check` again. The smoke profile passes
the production `input_budget_tokens` setting explicitly. For `gpt-4`, the
effective budget is the smaller of `--input-budget-tokens 192` and the known
model window minus the 8,000-token completion reserve. The profile does not
represent a production recommendation by itself.

The recommendation thresholds are deliberately simple:

- `build`: at least 20% aggregate savings, treatment quality at least 0.98,
  quality delta no worse than -0.02, and no compression failures;
- `borrow`: positive savings with quality at least 0.95 and no disqualifying
  delta or failure; and
- `defer`: all other results, including missing quality.

A case that saves tokens without both off and on quality results is invalid.

## Committed smoke fixtures

`fixtures/ruler-smoke.jsonl` contains independently authored synthetic
retrieval and multi-hop cases inspired by the problem shape RULER exercises.
It contains no RULER source or data. `fixtures/coding-agent-smoke.jsonl`
contains independently authored and sanitized shapes for tool output, git
diffs, `rg` output, and logs. It contains no credentials, customer prompts,
absolute user paths, or raw session identifiers.

`fixtures/provenance.json` pins each fixture's origin, Apache-2.0 license,
privacy declarations, official-score declaration, corpus identity, and exact
SHA-256 checksum. Generation fails if an input is not covered by the manifest.

The smoke quality scorer measures whether declared evidence markers survive
the off and on message arrays. This deterministic scorer needs no provider
credential, GPU, or network access.

## External benchmark adapter

The adapter path is import-and-report-only. It does not run a target model and
does not generate off/on predictions. Operators generate both predictions with
their chosen benchmark runner and model, then supply them through the
interchange below. The harness reports exact match for those imported
predictions and separately measures production window-fit token changes. It
does not claim that an imported prediction was generated from the harness's
compressed message array.

External data stays outside this repository. The operator exports a row from
the benchmark into this generic JSONL interchange:

```json
{"id":"case-1","context":"...","question":"...","reference_answers":["answer"],"off_prediction":"answer","on_prediction":"answer"}
```

Then normalize it with the suite label and target model:

```bash
cargo run --locked -- adapt \
  --suite ruler \
  --input /path/to/operator-interchange.jsonl \
  --output /tmp/ruler.normalized.jsonl \
  --target-model gpt-4
```

Accepted suite labels are `ruler`, `helmet`, `longbench-v2`, and `no-li-ma`.
The normalized case uses exact match against `reference_answers` for the
operator-supplied off and on predictions. Run each project's official scorer
separately when publishing official accuracy; this harness does not substitute
its exact-match score for a project's scorer.

### RULER

Obtain RULER from the [official NVIDIA repository](https://github.com/NVIDIA/RULER),
generate cases with its documented scripts, run its official scorer, and
export only the fields in the interchange above. Do not copy its code or data
into this harness.

### HELMET and LongBench-v2

Obtain HELMET from the [official Princeton repository](https://github.com/princeton-nlp/HELMET)
and LongBench-v2 from the [official project](https://longbench2.github.io/).
Keep downloaded datasets in operator-managed storage. Export context,
question, accepted answers, and predictions into the interchange format, then
use `--suite helmet` or `--suite longbench-v2`.

### NoLiMa

NoLiMa is available from the [Adobe Research repository](https://github.com/adobe-research/NoLiMa)
under a non-commercial license. This repository does not vendor its code,
needles, or data. Use NoLiMa only when your use complies with its license, keep
it operator-supplied, and pass an operator-created interchange file with
`--suite no-li-ma`.

For any external normalized input, create a separate provenance manifest with
the same schema as `fixtures/provenance.json`, use the closed provenance value
`operator_supplied_external`, declare the data's actual license, and keep
restricted data out of commits. The verifier checks its checksum, corpus,
privacy declarations, and license declaration without treating it as
first-party Apache-2.0 material. External evaluation artifacts should remain in
operator-controlled storage unless a separate review approves redistribution.
