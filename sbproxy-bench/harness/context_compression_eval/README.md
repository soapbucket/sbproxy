# Context compression evaluation harness

*Last modified: 2026-07-19*

This standalone Rust harness compares context compression off and on with the
same target model and original message array. The off arm uses an empty public
`CompressionRunner`. The on arm uses the real public `CompressionRunner` and
an ordered typed pipeline of production stateless levers. Both arms start from
identical messages and use sbproxy's target-model token counter.

The committed gate is intentionally small and deterministic. It is a
first-party smoke evaluation, not an official benchmark score for RULER,
HELMET, LongBench-v2, or NoLiMa.

This is the credential-free harness scoped by WOR-1922. Official suite runs
and target-model prediction generation remain outside this deterministic
gate. Synthetic coding-agent shapes in this repository are independently
authored and are not described as captured production traffic.

## Marked context contract

Retrieval-aware levers act only on explicit markers inside a string-valued
message `content` field. A block has this exact nesting:

```text
<sbproxy-retrieval>
<sbproxy-query>
opaque query text
</sbproxy-query>
<sbproxy-chunk id="stable-id" score="0.9" format="text">
opaque chunk body
</sbproxy-chunk>
</sbproxy-retrieval>
```

`<sbproxy-query>` appears once before the block's `<sbproxy-chunk` entries.
Chunk IDs select structural quality evidence. `score` is a finite supplied
ranking value when a pipeline uses supplied ranking. Supported format labels
are `text`, `json`, and `sbproxy_table_v1`. Text outside
`<sbproxy-retrieval>` blocks remains literal and is never inferred to be
retrieval context. On malformed or oversized marked context, the affected
retrieval-aware lever leaves its input message list unchanged and exposes only
a sanitized closed skip reason. Evaluation then continues through the ordered
pipeline, so a later lever such as WindowFit may still trim the request.

## Typed stateless pipelines

Each checked pipeline file has `schema_version: 1`, a report profile, and an
ordered `levers` array that deserializes directly to production
`CompressionLeverConfig`. The harness builds the actual `RagSelectLever`,
`CompactSerializationLever`, `PositionReorderLever`, and `WindowFitLever`
objects in declaration order. Summary buffering requires external state and
is rejected with `stateful levers are not supported by the deterministic
harness`.

The report CLI requires `--pipeline-config`. Profile and lever-specific
budgets come only from that checked file, so command-line defaults cannot
silently change committed evidence.

## What the report measures

Each case and corpus reports:

- target-model input, output, and saved tokens;
- saved-token ratio;
- off and on quality plus quality delta;
- every ordered lever's applied, skipped, or failed outcome and token
  accounting;
- case and aggregate acceptance status;
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
  --pipeline-config pipelines/window-fit-smoke.json \
  --input fixtures/ruler-smoke.jsonl \
  --input fixtures/coding-agent-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report /tmp/context-compression-observed.json \
  --markdown-report /tmp/context-compression-observed.md \
  --measure-latency
```

## Reproduce the committed gate

The harness is outside the root workspace and owns its lockfile. Always use
`--locked`.

```bash
cd sbproxy-bench/harness/context_compression_eval

cargo nextest run --all-targets --locked
cargo run --locked -- check \
  --pipeline-config pipelines/window-fit-smoke.json \
  --input fixtures/ruler-smoke.jsonl \
  --input fixtures/coding-agent-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/window-fit-smoke.json \
  --markdown-report reports/window-fit-smoke.md
```

To intentionally update the committed reports, replace `check` with
`generate`, review both files, then run `check` again. The window-fit pipeline
passes the production `input_budget_tokens` setting explicitly in
`pipelines/window-fit-smoke.json`. For `gpt-4`, the effective budget is the
smaller of 192 tokens and the known model window minus the 8,000-token
completion reserve.

CI runs the matching `check` command for all five deterministic report pairs:

- `reports/rag-select-smoke.json` and `reports/rag-select-smoke.md`;
- `reports/compact-serialization-smoke.json` and
  `reports/compact-serialization-smoke.md`;
- `reports/position-reorder-smoke.json` and
  `reports/position-reorder-smoke.md`;
- `reports/phase1-pipeline-smoke.json` and
  `reports/phase1-pipeline-smoke.md`; and
- `reports/window-fit-smoke.json` and `reports/window-fit-smoke.md`.

`check` rejects byte drift and also rejects a regenerated overall
recommendation other than `build`.

Cases may declare explicit acceptance gates. `min_savings_ratio` and
`min_on_quality_score` must be finite values from 0 through 1.
`min_quality_delta` must be finite from -1 through 1. `require_non_expanding`
requires treatment tokens to be no greater than control tokens. When every
case declares acceptance, `build` requires every gate to pass and no lever to
fail.

Cases without explicit acceptance preserve the earlier smoke fallback:

- `build`: at least 20% aggregate savings, treatment quality at least 0.98,
  quality delta no worse than -0.02, and no compression failures;
- `borrow`: positive savings with quality at least 0.95 and no disqualifying
  delta or failure; and
- `defer`: all other results, including missing quality.

A case that saves tokens without both off and on quality results is invalid.

## Structural quality scorers

`structured_equivalence` selects one marked chunk by ID. Ordinary `json` is
parsed to `serde_json::Value`; public `sbproxy_table_v1` is decoded through
`decode_sbproxy_table_v1` to the same type. The arm scores 1 only when its
exact normalized value equals the control value.

`edge_placement` finds the selected chunk in its own containing block. For
chunk ordinal `i` among `n` chunks, it uses nearest-edge distance
`d = min(i, n - 1 - i)` and maximum distance `m = floor((n - 1) / 2)`. The
score is `1 - d / m`; when `m` is zero, a one-chunk block scores 1 and both
chunks in a two-chunk block score 1. Edges score 1 and the center scores 0.

## Committed smoke fixtures

`fixtures/ruler-smoke.jsonl` contains independently authored synthetic
retrieval and multi-hop cases inspired by the problem shape RULER exercises.
It contains no RULER source or data. `fixtures/coding-agent-smoke.jsonl`
contains independently authored and sanitized shapes for tool output, git
diffs, `rg` output, and logs. It contains no credentials, customer prompts,
absolute user paths, or raw session identifiers.

Four lever-specific fixtures use independently authored sanitized shapes:

- `rag-select-smoke.jsonl` has useful ranked evidence and long ranked
  distractors;
- `compact-serialization-smoke.jsonl` has exactly 200 uniform rows in one
  marked JSON chunk and requires at least 30% whole-request savings with
  treatment quality 1.0;
- `position-reorder-smoke.jsonl` starts required evidence at the center and
  requires non-expansion plus a positive quality delta; and
- `phase1-pipeline-smoke.jsonl` requires marked query and evidence retention
  plus positive savings through the recommended four-lever order.

`fixtures/provenance.json` pins each fixture's origin, Apache-2.0 license,
privacy declarations, official-score declaration, corpus identity, and exact
SHA-256 checksum. Generation fails if an input is not covered by the manifest.
The committed fixture set contains no customer data. It does not claim official benchmark scores.

Evidence-retention and structural scores are deterministic. They need no
provider credential, GPU, or network access. They are acceptance evidence for
these bounded shapes, not an official benchmark score and not evidence of
target-model answer quality on external suites.

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
