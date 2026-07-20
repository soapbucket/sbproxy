# WOR-1918 Phase 1 Closeout Design

*Last modified: 2026-07-19*

## Status

Approved for implementation planning on 2026-07-19.

## Objective

Close WOR-1918 with one implementation pull request that ships the remaining
safe proxy-side Phase 1 levers:

- WOR-1924: RAG selection, top-N filtering, and drop-empty behavior.
- WOR-1925: compact serialization of embedded structured data.
- WOR-1926: lost-in-the-middle position reordering.
- WOR-1795: tool-result compaction acceptance coverage, consolidated into
  WOR-1925.

The pull request extends the compression foundation already delivered by
WOR-1919 through WOR-1923. It preserves the existing ordered policy,
request-selection, token-accounting, telemetry, and value-ledger surfaces.

## Scope boundary

This closeout includes:

- One strict representation for explicitly marked retrieval context.
- Three independently configurable compression levers.
- Deterministic local ranking with no provider or sidecar call.
- Reversible structured-data compaction.
- A non-expanding runner contract for the quality-only reorder lever.
- Safe semantic-cache bypass for selected pipelines containing a new lever.
- Unit, integration, end-to-end, schema, telemetry, and value tests.
- Reproducible sanitized evaluation fixtures and committed reports.
- Operator documentation, examples, generated schemas, and release notes.
- Linear reconciliation after the pull request merges.

This closeout excludes:

- LLMLingua, CPC, or another learned compressor.
- External reranker or embedding calls.
- Official RULER, HELMET, LongBench-v2, or NoLiMa execution.
- Claims about captured production traffic.
- Model-host KV, soft-token, or optical work.
- Stateful context offloading or a new state backend.
- Mesh integration for summary-buffer state.
- Provisioned-key work owned by WOR-1938 and WOR-1942.
- Unrelated refactoring.

The excluded Linear children move to successor roadmap epics. L7 is recorded
as deferred rather than silently treated as delivered.

## Design principles

1. Explicit marking is required. The proxy never guesses which prose is
   retrieved context.
2. Unmarked and protected content is immutable.
3. Every token-saving lever must strictly reduce the target-model estimate.
4. A quality-only lever may preserve, but never increase, the estimate.
5. A malformed or unsafe input fails open to the original request.
6. Each lever remains independently selectable and independently observable.
7. CI evidence is reproducible and labeled honestly as sanitized structural
   smoke evidence.

## Marked retrieval context

### Message eligibility

The parser examines only string `content` in messages whose role is `user` or
`tool`. It never examines or rewrites:

- `system`, `developer`, or `assistant` messages;
- tool-call arguments or function-call arguments;
- `tools`, `functions`, `response_format`, or schema declarations;
- multimodal content arrays;
- provider-controlled structured fields; or
- unmarked text surrounding a retrieval block.

### Grammar

A block uses exact line-delimited tags:

```text
<sbproxy-retrieval>
<sbproxy-query>
Why did the deployment fail?
</sbproxy-query>
<sbproxy-chunk id="logs" score="0.82" format="text">
retrieved log content
</sbproxy-chunk>
<sbproxy-chunk id="events" format="json">
[
  {"time": "12:01", "reason": "ImagePullBackOff"}
]
</sbproxy-chunk>
</sbproxy-retrieval>
```

The opening and closing block, query, and chunk tags occupy complete lines.
The parser accepts LF and CRLF line endings and preserves the source message's
line-ending convention when it renders a changed block. Tag names are
lowercase and exact. Retrieval blocks cannot nest.

Every block has exactly one non-empty query followed by zero or more chunks.
Producer input normally contains at least one chunk; the zero-chunk form is a
valid result of `rag_select` with drop-empty enabled and remains parseable by
later levers.
Each chunk has:

- a required identifier containing 1 to 64 ASCII letters, digits, `.`, `_`,
  or `-`;
- an optional finite score from 0 through 1; and
- a required format of `text`, `json`, or the internal rendered
  `sbproxy_table_v1` format.

The chunk attribute order is canonical: `id`, optional `score`, then `format`.
Query and chunk bodies are opaque. A body cannot contain its exact closing tag
as a complete line. A producer must escape or encode that line before marking
the block.

Multiple blocks may appear in one eligible message. If any apparent block in
the message is malformed, the current lever skips the entire request without
changing any message. There is no partial rewriting.

The parser accepts at most 32 retrieval blocks per request, 1,024 chunks per
block, and 4,096 chunks across the request. Exceeding any limit produces one
closed safe skip and preserves the original messages. The existing request
body limit remains the byte-size bound.

### Shared representation

The `marked_context` module parses a block into:

- query text;
- stable chunk identifier;
- optional supplied score;
- declared content format;
- original chunk body;
- original ordinal; and
- source message and byte-range information needed for exact reconstruction.

The module owns parsing, validation, canonical rendering, deterministic
ranking primitives, and reversible table decoding. Individual levers do not
implement their own marker grammar.

## Public configuration

The three new variants extend `CompressionLeverConfig`:

```yaml
compression:
  levers:
    - type: rag_select
      min_tokens: 512
      ranking: auto
      max_chunks: 8
      min_relevance_percent: 15
      drop_empty: true

    - type: compact_serialization
      min_tokens: 128
      tabular:
        enabled: true
        min_rows: 8

    - type: position_reorder
      ranking: auto

    - type: window_fit
      input_budget_tokens: 8192
```

Validation rules are:

- `min_tokens` is greater than zero.
- `max_chunks` is greater than zero.
- `min_relevance_percent` is from 0 through 100.
- `ranking` is `auto`, `supplied`, or `lexical`.
- `tabular.min_rows` is at least two when tabular mode is enabled.
- Unknown fields remain rejected.

`auto` uses supplied scores only when every chunk in the block has a valid
score. Otherwise it uses lexical ranking. `supplied` skips a block when any
score is absent. `lexical` ignores supplied scores.

The recommended order is `rag_select`, `compact_serialization`,
`position_reorder`, then `window_fit`.

## RAG selection

`rag_select` operates independently on each valid retrieval block whose
target-model estimate reaches `min_tokens`.

Lexical ranking uses a deterministic normalized TF-IDF vector and cosine
similarity between the marked query and each chunk. Tokenization lowercases
Unicode text, splits on non-alphanumeric boundaries, and uses stable original
ordinals to break equal scores. It does not use network access, model weights,
process-random hashing, or wall-clock state.

For each block, the lever:

1. derives one score per chunk;
2. sorts by descending score and then original ordinal;
3. removes chunks below `min_relevance_percent`;
4. retains at most `max_chunks`; and
5. renders the retained chunks in ranked order.

When no chunk survives and `drop_empty` is true, the retrieval wrapper and
query remain while all chunks are removed. The question is never discarded.
When `drop_empty` is false, the block remains unchanged.

The lever returns a candidate only if at least one block changes. The runner
commits it only when the complete message list strictly reduces the shared
target-model token estimate.

## Compact serialization

`compact_serialization` examines only marked chunks with `format="json"` whose
individual target-model estimate reaches `min_tokens`.

The first candidate is canonical whitespace-free JSON. JSON containing
duplicate object member names at any nesting depth is unsafe and remains
byte-for-byte unchanged, because value parsing would otherwise discard one
member. When tabular mode is
enabled, the lever may instead encode a top-level JSON array as
`sbproxy_table_v1` if all of these conditions hold:

- the array contains at least `min_rows` elements;
- every element is an object;
- every object has the identical key set;
- every value is a JSON string, number, boolean, or null; and
- there are no arrays or objects in a cell.

The table representation contains one canonical JSON array of sorted column
names followed by tab-separated rows. Every cell is rendered as a canonical
JSON scalar. Tabs, newlines, quotes, and backslashes inside strings therefore
remain escaped and cannot be confused with separators.

For example, a chunk changed to `format="sbproxy_table_v1"` has this body:

```text
["reason","time"]
"ImagePullBackOff"\t"12:01"
"BackOff"\t"12:02"
```

The first line is the sorted column array. Every later line is one row with
exactly the same number of literal-tab-separated canonical JSON scalars. The
`\t` notation in the example denotes one literal U+0009 tab, not two output
characters.

The format can be decoded exactly into the same JSON value. Unit and
evaluation tests compare canonical decoded JSON to the original value. The
lever does not claim preservation of insignificant whitespace or object-key
order.

Invalid, nested, heterogeneous, or undersized values remain unchanged. The
lever chooses the smallest valid representation, but the runner commits the
complete candidate only when it strictly reduces the target-model estimate.

## Position reordering

`position_reorder` derives scores using the configured ranking mode. It sorts
chunks by descending relevance and stable original ordinal, then alternates
them across the block edges:

- rank 1 at the beginning;
- rank 2 at the end;
- rank 3 after rank 1;
- rank 4 before rank 2; and
- subsequent ranks following the same pattern.

The lever changes only chunk order. Query text, chunk tags, attributes, and
bodies remain byte-for-byte identical. It returns a candidate only when the
new identifier order differs from the existing order.

## Runner commit contract

The `CompressionLever` trait gains a closed commit rule with a safe default:

- `StrictReduction`: candidate token count must be less than the working
  count. This is the default and applies to `summary_buffer`, `window_fit`,
  `rag_select`, and `compact_serialization`.
- `NonExpanding`: candidate messages must differ and their token count must be
  less than or equal to the working count. Only `position_reorder` uses this
  rule.

Every expansion is rejected as `no_savings`. An unchanged non-expanding
candidate is `not_needed`. An applied non-expanding candidate records zero
savings when its token estimate is equal.

The existing invariant that request savings equal the sum of committed
per-lever savings remains valid. A zero-saving applied lever contributes zero.

## Request data flow

The production path is:

```text
raw chat messages
  -> resolve route/key/CEL/header compression selection
  -> validate marked retrieval blocks
  -> select useful chunks
  -> compact marked structured bodies
  -> reorder chunks toward the edges
  -> apply final window budget
  -> record telemetry and value
  -> provider dispatch
```

Each lever receives the output committed by the previous lever and reparses it
through the shared representation. This keeps every lever independently
usable while maintaining one parser and renderer.

## Error handling

Expected ineligibility is represented by closed skip reasons. The new closed
reasons include malformed marked context, missing supplied score, below
threshold, no selected chunks, unsafe structured shape, and already ordered.
Exact names are stable lowercase metric labels.

The following conditions preserve the original working messages:

- no marked context;
- an unsupported message role or content shape;
- malformed, nested, or incomplete tags;
- duplicate chunk identifiers within one block;
- invalid or missing required scores;
- invalid JSON or duplicate JSON object members;
- unsafe tabular shape;
- no material change;
- no token reduction for a strict lever; or
- any candidate expansion.

Parser and transformation code returns sanitized classifications. Logs and
metrics never contain queries, chunk bodies, identifiers, scores, source
positions, JSON values, or free-form parse errors.

## Semantic-cache behavior

Both semantic-cache implementations currently perform lookup before the
compression runner executes. A response produced from one selected or compacted
context must not be replayed for another behavior.

Any selected default or named pipeline containing `rag_select`,
`compact_serialization`, or `position_reorder` therefore bypasses semantic
cache reads and writes for that request. Existing behavior remains unchanged
for summary-buffer and compatibility-only window-fit pipelines.

Moving deterministic compression ahead of cache-key construction is a future
optimization and is not part of this closeout.

## Telemetry and value accounting

`LeverKind` gains the stable labels:

- `rag_select`;
- `compact_serialization`; and
- `position_reorder`.

The new levers use the existing bounded compression metrics and redacted
summary event for invocation, outcome, reason, latency, before/after estimates,
per-lever savings, and request-total savings.

The primary monitoring metrics remain:

- `sbproxy_ai_compression_lever_total` for per-lever outcomes and closed
  reasons;
- `sbproxy_ai_compression_tokens_total`,
  `sbproxy_ai_compression_tokens_saved_total`, and
  `sbproxy_ai_compression_ratio` for estimated token movement;
- `sbproxy_ai_compression_duration_seconds` for per-lever latency;
- `sbproxy_ai_compression_requests_total`,
  `sbproxy_ai_compression_request_tokens_saved`, and
  `sbproxy_ai_compression_request_levers_run` for the complete pipeline; and
- `sbproxy_ai_compression_value_tokens_saved_total` and
  `sbproxy_ai_compression_value_cost_saved_micros_total` for success-only
  target-model value attribution.

Existing Grafana queries group by the closed `lever` label, so the three new
lever values appear without creating parallel metric families. Existing
recording rules and alerts continue to cover request failure ratio, p95 lever
latency, savings rate, and value-accounting gaps. The pull request updates the
application-rate panel description from "strictly reducing transformation" to
"committed transformation" because `position_reorder` can apply with zero
savings. It does not create noisy per-lever alert copies.

`rag_select` and `compact_serialization` feed the value ledger only when an
applied result saves at least one token. `position_reorder` can record
`applied` with zero savings and never creates an avoided-token or avoided-cost
claim. No metric label contains marker-controlled text.

Every executed non-empty pipeline also emits exactly one structured
`ai_compression_summary` log. A fully skipped pipeline logs at `DEBUG`, an
applied pipeline without failure logs at `INFO`, and any failed lever logs the
request summary at `WARN`. The event contains only identities, closed outcomes,
token estimates, savings, latency, cache-bypass state, and content-free lever
configuration. It never contains query text, chunks, scores, marker IDs,
request bodies, or credentials.

The serialized policy behavior fingerprint includes every new config field.

## Evaluation design

The existing deterministic harness is generalized from a hard-coded
window-fit treatment to a registry that constructs any supported stateless
production lever or ordered stateless pipeline from real configuration.

The quality model adds structural scorers where needed:

- evidence retention for RAG selection and the combined pipeline;
- canonical structured equivalence for compact serialization; and
- normalized edge placement for position reordering.

Committed fixtures and JSON/Markdown reports cover:

1. `rag_select`: distractors are removed while every required evidence marker
   and expected answer remains available.
2. `compact_serialization`: a 200-row uniform tool result saves at least 30
   percent of estimated tokens and decodes to the original JSON value.
3. `position_reorder`: required evidence moves toward an edge, structural
   quality improves, and the token estimate never increases.
4. The combined Phase 1 pipeline: query and required evidence survive while
   total estimated input tokens decrease.

Reports identify the data as independently authored sanitized structural smoke
fixtures. Official-suite adapters stay import-only. No official score, model
prediction, or captured-production-traffic claim is made.

The existing CI drift gate regenerates and compares every committed report.

## Verification

Implementation follows red-green-refactor for each behavior slice. Required
coverage includes:

- parser unit tests for multiple blocks, CRLF, delimiter collisions, nesting,
  duplicate identifiers, malformed attributes, protected roles, and exact
  fail-open output;
- ranking tests for every mode, deterministic scores, stable ties, floors,
  caps, and drop-empty behavior;
- serialization tests for minification, scalar escaping, unsafe-shape skips,
  representation choice, and exact canonical round trips;
- reorder tests for edge placement, stable ties, idempotence, zero-saving
  application, and expansion rejection;
- runner tests for both commit rules and savings invariants;
- config, JSON schema, behavior-fingerprint, semantic-cache bypass, telemetry,
  and value-ledger tests;
- end-to-end tests for route, header, governed-key, and CEL profile selection;
- end-to-end preservation tests for malformed, unmarked, structured, and
  protected content; and
- deterministic report regeneration.

Before completion, the branch runs every gate required by `AGENTS.md`:

```text
cargo fmt --all -- --check
cargo build --workspace
cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci
cargo test --workspace --exclude sbproxy-e2e --locked --doc
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

Focused compression end-to-end tests, schema regeneration, metrics stability,
documentation checks, and report drift checks also pass.

## One-pull-request delivery

All implementation lands on one branch and one pull request. Reviewability
comes from ordered commits rather than multiple pull requests:

1. design and implementation plan;
2. shared marked-context parser and runner commit rule;
3. `rag_select`;
4. `compact_serialization` plus WOR-1795 acceptance coverage;
5. `position_reorder`;
6. generalized evaluation harness and committed reports; and
7. end-to-end coverage, telemetry, schemas, examples, docs, and release notes.

The pull request references WOR-1918, WOR-1924, WOR-1925, WOR-1926, and
WOR-1795.

## Linear closeout

After the pull request is green and merged:

1. Mark WOR-1924, WOR-1925, and WOR-1926 Done.
2. Mark WOR-1795 Duplicate of WOR-1925 after retaining its 200-row and 30
   percent acceptance coverage in WOR-1925.
3. Reparent Phase 2 and Phase 3 proxy work to an existing suitable successor
   epic, or create one proxy-optimization roadmap epic if none exists.
4. Reparent model-host work to an existing suitable model-host context
   efficiency epic, or create one if none exists.
5. Move context-offloading research to an existing stateful-agent-memory
   initiative, or create a dedicated successor if none exists.
6. Record L7 as deferred.
7. Add one final WOR-1918 comment linking the pull request, merge commit,
   reports, verification evidence, and scope boundary.
8. Mark WOR-1918 Done.

WOR-1942 is not a blocker unless the provisioned-key Claude Code flow is later
added to the Phase 1 acceptance boundary.

## Acceptance criteria

WOR-1918 is ready to close when all of the following are true:

1. The three new levers are independently configurable in one ordered policy.
2. Only valid explicitly marked retrieval context can change.
3. RAG selection retains required evidence and reduces distractor-heavy input.
4. Uniform structured tool results meet the 30 percent savings fixture and
   decode exactly.
5. Position reordering improves the edge-placement fixture without increasing
   tokens or claiming savings.
6. The combined pipeline reduces tokens while retaining query and evidence.
7. Malformed, unsafe, unmarked, and protected input is unchanged.
8. Selected new-lever pipelines bypass semantic caches safely.
9. Telemetry and value accounting remain bounded, redacted, and honest.
10. Config schemas, examples, docs, release notes, and reports are current.
11. Every focused and repository-wide verification gate passes.
12. One pull request is merged and Linear scope is reconciled as described.
