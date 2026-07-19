# WOR-1918 Phase 1 Closeout Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task by task, or superpowers:executing-plans for inline execution.

**Goal:** Ship the three remaining proxy-side Phase 1 context-compression levers, their production wiring, deterministic evidence, and closeout material in one pull request.

**Architecture:** Extend the existing ordered CompressionRunner with a shared marked-context parser and a closed commit rule. Build rag_select, compact_serialization, and position_reorder as independent stateless levers over that representation. Reuse the current selection, semantic-cache bypass, telemetry, and value-ledger paths, then generalize the standalone evaluation harness to instantiate the production levers from typed config.

**Tech stack:** Rust 2021, Tokio, serde/serde_json, schemars, tiktoken-rs, Prometheus, Grafana JSON, GitHub Actions, and the standalone context_compression_eval crate.

**Approved design:** docs/superpowers/specs/2026-07-19-wor-1918-phase1-closeout-design.md

**Delivery rule:** Keep every implementation commit on branch rickcrawford/wor-1918-phase1-closeout and publish exactly one pull request covering WOR-1918, WOR-1924, WOR-1925, WOR-1926, and WOR-1795.

---

## Task 1: Add the closed config, outcome, token, and commit-rule contracts

**Files:**

- Modify: crates/sbproxy-ai/src/compression/config.rs
- Modify: crates/sbproxy-ai/src/compression/outcome.rs
- Modify: crates/sbproxy-ai/src/compression/runner.rs
- Modify: crates/sbproxy-ai/src/compression/mod.rs
- Modify: crates/sbproxy-ai/src/token_estimate.rs

### Step 1: Write failing configuration tests

In the config.rs test module, add strict deserialization and validation tests for all new variants. Pin defaults and unknown-field rejection with this public shape:

~~~rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalRanking {
    #[default]
    Auto,
    Supplied,
    Lexical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RagSelectConfig {
    pub min_tokens: u64,
    #[serde(default)]
    pub ranking: RetrievalRanking,
    pub max_chunks: usize,
    #[serde(default)]
    pub min_relevance_percent: u8,
    #[serde(default)]
    pub drop_empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompactSerializationConfig {
    pub min_tokens: u64,
    #[serde(default)]
    pub tabular: TabularSerializationConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TabularSerializationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tabular_min_rows")]
    pub min_rows: usize,
}

impl Default for TabularSerializationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_rows: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionReorderConfig {
    #[serde(default)]
    pub ranking: RetrievalRanking,
}
~~~

The tests must assert:

- min_tokens and max_chunks reject zero.
- min_relevance_percent accepts 0 and 100 and rejects 101.
- tabular.min_rows defaults to 8.
- tabular.min_rows rejects values below 2 only when tabular.enabled is true.
- ranking defaults to auto and accepts only auto, supplied, and lexical.
- every unknown field is rejected.

Run:

    cargo nextest run -p sbproxy-ai compression::config::tests --locked

Expected: FAIL because the variants and types do not exist.

### Step 2: Implement and export the typed configuration

Add RagSelect, CompactSerialization, and PositionReorder to CompressionLeverConfig. Add RetrievalRanking::as_str(). Extend validate_pipeline with the exact approved bounds. Re-export every new public config type from compression/mod.rs.

Run the config tests again. Expected: PASS.

### Step 3: Write failing closed-outcome tests

Extend outcome.rs tests to pin these stable labels:

~~~rust
LeverKind::RagSelect => "rag_select"
LeverKind::CompactSerialization => "compact_serialization"
LeverKind::PositionReorder => "position_reorder"

SkipReason::NoMarkedContext => "no_marked_context"
SkipReason::MalformedMarkedContext => "malformed_marked_context"
SkipReason::MarkedContextTooLarge => "marked_context_too_large"
SkipReason::MissingRelevanceScore => "missing_relevance_score"
SkipReason::NoSelectedChunks => "no_selected_chunks"
SkipReason::UnsafeStructuredShape => "unsafe_structured_shape"
SkipReason::AlreadyOrdered => "already_ordered"
~~~

Update the LeverOutcome::Applied documentation so it says committed transformation, not strictly reducing transformation.

Run:

    cargo nextest run -p sbproxy-ai compression::outcome --locked

Expected: FAIL until the variants and as_str arms exist.

### Step 4: Write failing runner commit-rule tests

Add this closed rule beside CompressionLever:

~~~rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CompressionCommitRule {
    #[default]
    StrictReduction,
    NonExpanding,
}
~~~

Add fn commit_rule(&self) -> CompressionCommitRule with a StrictReduction default to CompressionLever. Extend ScriptedLever so tests can select a rule. Add tests proving:

- strict candidates with equal or greater counts skip as no_savings;
- a changed equal-count NonExpanding candidate applies with zero savings;
- an unchanged equal-count NonExpanding candidate skips as not_needed;
- an expanding NonExpanding candidate skips as no_savings; and
- request savings still equal applied_tokens_saved when a zero-saving lever applies before a reducing lever.

Run:

    cargo nextest run -p sbproxy-ai compression::runner::tests --locked

Expected: FAIL because commit_rule is not implemented.

### Step 5: Implement the commit rule

Read lever.commit_rule() once per candidate. Commit according to:

~~~rust
let changed = candidate != working;
let applies = match lever.commit_rule() {
    CompressionCommitRule::StrictReduction => candidate_tokens < working_tokens,
    CompressionCommitRule::NonExpanding => changed && candidate_tokens <= working_tokens,
};
~~~

For a NonExpanding candidate that is byte-for-byte unchanged and equal in tokens, emit SkipReason::NotNeeded. For every expansion and for every equal StrictReduction candidate, emit SkipReason::NoSavings. Use saturating_sub for the applied saving and preserve the existing debug assertion.

Re-export CompressionCommitRule from compression/mod.rs.

Run the runner tests again. Expected: PASS.

### Step 6: Add a target-model text counter used by eligibility checks

Add a crate-visible helper to token_estimate.rs:

~~~rust
pub(crate) fn estimate_text_tokens(model: &str, text: &str) -> u64
~~~

Use the same recognized-model BPE and unknown-model bytes-divided-by-four rules as the complete-message counter, without message framing. Add tests for a known model, an unknown model, empty text, and consistency with the content contribution used by estimate_json_message_tokens.

Run:

    cargo nextest run -p sbproxy-ai token_estimate::tests --locked

Expected: PASS.

### Step 7: Commit the foundational contract

    git add crates/sbproxy-ai/src/compression/config.rs crates/sbproxy-ai/src/compression/outcome.rs crates/sbproxy-ai/src/compression/runner.rs crates/sbproxy-ai/src/compression/mod.rs crates/sbproxy-ai/src/token_estimate.rs
    git commit -m "feat(ai): define Phase 1 compression contracts"

---

## Task 2: Build the shared marked-context parser and renderer

**Files:**

- Create: crates/sbproxy-ai/src/compression/marked_context/mod.rs
- Create: crates/sbproxy-ai/src/compression/marked_context/parser.rs
- Create: crates/sbproxy-ai/src/compression/marked_context/ranking.rs
- Create: crates/sbproxy-ai/src/compression/marked_context/table.rs
- Modify: crates/sbproxy-ai/src/compression/mod.rs

### Step 1: Write parser tests before implementation

In parser.rs, add unit tests that construct raw serde_json::Value messages and pin:

- one and multiple blocks in one eligible message;
- blocks spread across user and tool messages;
- no parsing in system, developer, assistant, multimodal, tool-call, or function-call fields;
- LF and CRLF acceptance with the original convention retained after a rewrite;
- exact preservation of all unmarked prefix and suffix text;
- rejection of an empty or whitespace-only query;
- query-only blocks after all chunks are removed;
- IDs at lengths 1 and 64 and rejection at 65;
- score boundaries 0 and 1, plus rejection of NaN-like text, infinity, and out-of-range values;
- duplicate IDs, nesting, closing-tag delimiter collisions, noncanonical attributes, missing tags, and incomplete blocks;
- 32 blocks, 1,024 chunks per block, and 4,096 chunks per request at the boundary;
- MarkedContextError::TooLarge immediately above each boundary; and
- an exact clone of the input after every malformed or oversized result.

Run:

    cargo nextest run -p sbproxy-ai marked_context::parser --locked

Expected: FAIL because the module does not exist.

### Step 2: Implement the internal representation

Use these core interfaces in marked_context/mod.rs:

~~~rust
pub(crate) const MAX_RETRIEVAL_BLOCKS: usize = 32;
pub(crate) const MAX_CHUNKS_PER_BLOCK: usize = 1_024;
pub(crate) const MAX_RETRIEVAL_CHUNKS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkFormat {
    Text,
    Json,
    SbproxyTableV1,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RetrievalChunk {
    id: String,
    supplied_score: Option<f64>,
    supplied_score_rendering: Option<String>,
    format: ChunkFormat,
    body: String,
    original_ordinal: usize,
    original_rendering: String,
    changed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RetrievalBlock {
    query: String,
    chunks: Vec<RetrievalChunk>,
    line_ending: LineEnding,
    changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkedContextError {
    Malformed,
    TooLarge,
}

pub(crate) fn parse_marked_messages(
    messages: &[serde_json::Value],
) -> Result<Option<MarkedMessages>, MarkedContextError>;
~~~

MarkedMessages owns a clone of the original messages plus parsed message documents. Each document is a sequence of Literal and Retrieval segments. Provide blocks_mut() for lever transformations and into_messages() for exact reconstruction.

RetrievalBlock must expose query(), chunks(), replace_chunks(), and render(). RetrievalChunk must expose id(), supplied_score(), format(), body(), original_ordinal(), render(), and with_body_and_format(). Reordered unchanged chunks render their original bytes. A changed chunk uses canonical id, optional score, format attribute order and the source line ending while preserving the validated source spelling of the optional score.

Do not add an XML dependency. Parse complete lines with a bounded state machine and exact tag comparisons.

### Step 3: Add a read-only inspection API for the eval harness

Expose owned, read-only snapshots without exposing parser internals:

~~~rust
#[derive(Debug, Clone, PartialEq)]
pub struct MarkedContextSnapshot {
    pub blocks: Vec<RetrievalBlockSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalBlockSnapshot {
    pub query: String,
    pub chunks: Vec<RetrievalChunkSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalChunkSnapshot {
    pub id: String,
    pub score: Option<f64>,
    pub format: String,
    pub body: String,
}

pub fn inspect_marked_context(
    messages: &[serde_json::Value],
) -> Result<Option<MarkedContextSnapshot>, MarkedContextError>;
~~~

Keep MarkedContextError content-free and implement Display with only the closed labels malformed_marked_context and marked_context_too_large. Re-export only the snapshot types, error, inspector, and table decoder from compression/mod.rs.

### Step 4: Run parser and documentation tests

    cargo nextest run -p sbproxy-ai marked_context --locked
    cargo test -p sbproxy-ai --locked --doc

Expected: PASS with no content-bearing Debug or Display output from parser errors.

### Step 5: Commit the shared parser

    git add crates/sbproxy-ai/src/compression/marked_context crates/sbproxy-ai/src/compression/mod.rs
    git commit -m "feat(ai): parse explicit marked retrieval context"

---

## Task 3: Add deterministic ranking and rag_select

**Files:**

- Modify: crates/sbproxy-ai/src/compression/marked_context/ranking.rs
- Create: crates/sbproxy-ai/src/compression/rag_select.rs
- Modify: crates/sbproxy-ai/src/compression/mod.rs

### Step 1: Write ranking tests

Pin the ranking interface:

~~~rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RankedChunk {
    pub index: usize,
    pub score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RankError {
    MissingSuppliedScore,
}

pub(crate) fn rank_chunks(
    block: &RetrievalBlock,
    mode: RetrievalRanking,
) -> Result<Vec<RankedChunk>, RankError>;
~~~

Tests must prove:

- supplied mode sorts descending and breaks ties by original ordinal;
- supplied mode returns MissingSuppliedScore if any chunk is unscored;
- auto uses supplied only when every chunk is scored;
- auto falls back to lexical for a partially scored block;
- lexical ignores supplied scores;
- tokenization lowercases Unicode alphanumeric terms and splits on other characters;
- smoothed IDF is ln((N + 1) / (df + 1)) + 1;
- cosine results are finite and deterministic;
- a zero-vector query produces stable ordinal order; and
- repeated runs return bitwise-identical scores and order.

Run:

    cargo nextest run -p sbproxy-ai marked_context::ranking --locked

Expected: FAIL until rank_chunks exists.

### Step 2: Implement deterministic TF-IDF ranking

Use BTreeMap and BTreeSet for vocabulary and document-frequency accumulation. Never use RandomState-dependent iteration in score construction. Sort with descending f64::total_cmp followed by original_ordinal.

Run the ranking tests again. Expected: PASS.

### Step 3: Write rag_select lever tests

Construct RagSelectLever from RagSelectConfig and add tests for:

- LeverKind::RagSelect, no backend, and the default StrictReduction rule;
- only marked user/tool string content changing;
- min_tokens being measured over each complete rendered block;
- max_chunks and min_relevance_percent filtering;
- ranked-order rendering;
- drop_empty retaining the wrapper and query;
- drop_empty false leaving an empty selection unchanged;
- a missing supplied score leaving that block unchanged while another valid block may change;
- MissingRelevanceScore when no block can change;
- NoMarkedContext, MalformedMarkedContext, MarkedContextTooLarge, BelowThreshold, and NoSelectedChunks;
- multiple blocks transforming independently;
- stable idempotence; and
- input messages remaining immutable.

Run:

    cargo nextest run -p sbproxy-ai rag_select --locked

Expected: FAIL because RagSelectLever does not exist.

### Step 4: Implement rag_select

For each eligible block:

1. Skip it when estimate_text_tokens(model, block.render()) is below min_tokens.
2. Rank it with the configured mode.
3. Keep scores at or above min_relevance_percent divided by 100.
4. Take at most max_chunks.
5. Render retained chunks in rank order.
6. With no survivor, remove chunks only when drop_empty is true.

Return a candidate if at least one block changes. If none changes, choose the most specific content-free reason in this order: MissingRelevanceScore, NoSelectedChunks, BelowThreshold, or NotNeeded. Parser errors always take precedence.

Export RagSelectLever.

### Step 5: Verify runner-level strict reduction

Add an integration-style test in rag_select.rs that passes a candidate through CompressionRunner and proves a logically changed but token-equal candidate is rejected as no_savings.

Run:

    cargo nextest run -p sbproxy-ai rag_select compression::runner --locked

Expected: PASS.

### Step 6: Commit RAG selection

    git add crates/sbproxy-ai/src/compression/marked_context/ranking.rs crates/sbproxy-ai/src/compression/rag_select.rs crates/sbproxy-ai/src/compression/mod.rs
    git commit -m "feat(ai): add deterministic RAG selection"

---

## Task 4: Add reversible compact serialization and WOR-1795 coverage

**Files:**

- Modify: crates/sbproxy-ai/src/compression/marked_context/table.rs
- Create: crates/sbproxy-ai/src/compression/compact_serialization.rs
- Modify: crates/sbproxy-ai/src/compression/mod.rs

### Step 1: Write table codec tests

Pin these interfaces:

~~~rust
pub(crate) fn encode_table(value: &serde_json::Value, min_rows: usize) -> Option<String>;
pub fn decode_sbproxy_table_v1(body: &str) -> Result<serde_json::Value, TableDecodeError>;
~~~

Tests must cover:

- sorted column names;
- identical key sets despite input object-key order;
- strings containing literal tabs, newlines, quotes, and backslashes;
- numbers, booleans, and null;
- exact canonical JSON round trip;
- 199 and 200 row inputs;
- too few rows;
- empty arrays;
- non-array roots;
- non-object rows;
- heterogeneous keys;
- nested arrays or objects in cells;
- wrong column counts;
- malformed scalar cells; and
- trailing or missing lines.

TableDecodeError must be public, must expose only a closed invalid_table label, and must be re-exported with decode_sbproxy_table_v1.

Run:

    cargo nextest run -p sbproxy-ai marked_context::table --locked

Expected: FAIL until the codec exists.

### Step 2: Implement the reversible codec

The first line is serde_json serialization of the sorted column vector. Every later line contains the same number of canonical JSON scalar cells separated by one literal tab. Decode every cell with serde_json, rebuild objects in the column order, and return a top-level array.

Run the table tests again. Expected: PASS.

### Step 3: Write compact_serialization lever tests

Add tests for:

- marked format=json chunks only;
- per-chunk min_tokens;
- whitespace-free JSON minification;
- optional table encoding only for the safe shape;
- choosing the lowest target-model token count across original, minified JSON, and table;
- preferring minified JSON on a token-count tie;
- changing format to sbproxy_table_v1 only when table wins;
- falling back to minified JSON for valid nested or heterogeneous JSON;
- UnsafeStructuredShape for invalid JSON when no other chunk changes;
- malformed marked context failing open;
- unmarked, protected-role, and non-string content remaining exact;
- multiple eligible chunks;
- idempotence on already minified and already tabular chunks; and
- a generated 200-row tool-result case decoding exactly and saving at least 30 percent through CompressionRunner.

Run:

    cargo nextest run -p sbproxy-ai compact_serialization --locked

Expected: FAIL because the lever does not exist.

### Step 4: Implement compact_serialization

For each marked JSON chunk at or above min_tokens:

1. Parse the body as serde_json::Value.
2. Build the canonical minified JSON option.
3. If enabled, build the table option with tabular.min_rows.
4. Count the complete rendered chunk for each option with estimate_text_tokens.
5. Choose a strict improvement over the original, preferring JSON on ties.
6. Replace the body and format through RetrievalChunk::with_body_and_format.

Already formatted sbproxy_table_v1 chunks remain unchanged. Return Candidate only when at least one chunk changes, otherwise return the most specific closed skip.

Export CompactSerializationLever.

### Step 5: Verify WOR-1795 acceptance locally

Run:

    cargo nextest run -p sbproxy-ai compact_serialization::tests::uniform_200_row_tool_result_round_trips_and_saves_thirty_percent --locked

Expected: PASS with decoded JSON equal to the source and savings_ratio at least 0.30.

### Step 6: Commit compact serialization

    git add crates/sbproxy-ai/src/compression/marked_context/table.rs crates/sbproxy-ai/src/compression/compact_serialization.rs crates/sbproxy-ai/src/compression/mod.rs
    git commit -m "feat(ai): add reversible compact serialization"

---

## Task 5: Add lost-in-the-middle position reordering

**Files:**

- Create: crates/sbproxy-ai/src/compression/position_reorder.rs
- Modify: crates/sbproxy-ai/src/compression/mod.rs
- Modify: crates/sbproxy-ai/src/compression/runner.rs

### Step 1: Write position_reorder tests

Add tests proving:

- LeverKind::PositionReorder and CompressionCommitRule::NonExpanding;
- a ranked sequence 1,2,3,4,5,6 renders as 1,3,5,6,4,2;
- odd-sized sequences render as odd ranks ascending followed by even ranks descending;
- chunk tags, attributes, and bodies remain byte-for-byte unchanged;
- multiple blocks reorder independently;
- missing supplied scores leave that block unchanged;
- stable ties use original ordinals;
- an already edge-ordered block skips as already_ordered;
- a second run is idempotent;
- parser failures preserve the full request; and
- an equal-token reordered candidate applies with zero savings while an artificial expansion is rejected by the runner.

Run:

    cargo nextest run -p sbproxy-ai position_reorder --locked

Expected: FAIL because the lever does not exist.

### Step 2: Implement edge placement

Rank through the shared rank_chunks function. Construct the rendered order as all odd one-based ranks in ascending rank order followed by all even one-based ranks in descending rank order. Compare chunk IDs to the current order before marking a block changed.

Return MissingRelevanceScore only when no block changes and at least one block cannot rank in supplied mode. Return AlreadyOrdered when every rankable block already has the target order.

Export PositionReorderLever and override commit_rule to NonExpanding.

### Step 3: Run focused runner and lever tests

    cargo nextest run -p sbproxy-ai position_reorder compression::runner --locked

Expected: PASS, including the zero-saving applied accounting invariant.

### Step 4: Commit position reordering

    git add crates/sbproxy-ai/src/compression/position_reorder.rs crates/sbproxy-ai/src/compression/mod.rs crates/sbproxy-ai/src/compression/runner.rs
    git commit -m "feat(ai): add relevance position reordering"

---

## Task 6: Wire production runtime, cache safety, telemetry, and value

**Files:**

- Modify: crates/sbproxy-core/src/compression_runtime.rs
- Modify: crates/sbproxy-core/src/compression_metrics.rs
- Modify: crates/sbproxy-core/src/server/ai_dispatch.rs
- Modify: crates/sbproxy-ai/src/value_ledger.rs
- Modify: crates/sbproxy-core/src/compression_value.rs
- Modify: crates/sbproxy-observe/src/metrics.rs
- Modify: crates/sbproxy-observe/tests/compression_observability.rs
- Modify: dashboards/grafana/sbproxy-ai-gateway.json

### Step 1: Write failing runtime construction tests

In compression_runtime.rs, add tests that deserialize and execute each stateless lever and the recommended four-lever order. Assert no Redis dependency for any of the three new variants. Assert summary discovery still finds only SummaryBuffer.

Add a behavior-fingerprint test that changes each new field one at a time and proves every fingerprint changes.

Run:

    cargo nextest run -p sbproxy-core compression_runtime --locked

Expected: FAIL because runtime matches are non-exhaustive or do not construct the new levers.

### Step 2: Wire the levers into CompressionRuntime

Import and instantiate:

~~~rust
CompressionLeverConfig::RagSelect(config) =>
    Arc::new(RagSelectLever::new(config.clone()))
CompressionLeverConfig::CompactSerialization(config) =>
    Arc::new(CompactSerializationLever::new(config.clone()))
CompressionLeverConfig::PositionReorder(config) =>
    Arc::new(PositionReorderLever::new(config.clone()))
~~~

Keep SummaryBuffer as the only stateful branch and WindowFit unchanged.

Run the runtime tests again. Expected: PASS.

### Step 3: Add semantic-cache bypass tests

Rename CompiledCompressionPipeline.uses_explicit_input_budget to requires_semantic_cache_bypass. Compute it when the default pipeline contains:

- explicit-budget WindowFit;
- RagSelect;
- CompactSerialization; or
- PositionReorder.

Keep the existing conservative profile rule: any named profiles force origin-level bypass because selectors are request-specific and lookup happens before transformation.

Add tests for each new default pipeline, a legacy WindowFit-only default, an explicit-budget WindowFit default, named profiles, and off selection. Extend ai_dispatch unit tests to prove cache reads and writes are bypassed for a route-default new-lever pipeline even without a captured session.

Run:

    cargo nextest run -p sbproxy-core compression_runtime ai_dispatch::tests::compression --locked

Expected: PASS.

### Step 4: Write telemetry target tests

In compression_metrics.rs, extend target_log and tests with content-free shapes:

~~~json
{"lever":"rag_select","min_tokens":512,"ranking":"auto","max_chunks":8,"min_relevance_percent":15,"drop_empty":true}
{"lever":"compact_serialization","min_tokens":128,"tabular_enabled":true,"tabular_min_rows":8}
{"lever":"position_reorder","ranking":"auto"}
~~~

Add a run containing all three levers and assert:

- exactly one ai_compression_summary event;
- INFO for applied without failures;
- DEBUG when all skip;
- WARN when any fails;
- lever_outcomes contains only closed labels and numeric accounting;
- targets contains no query, chunk ID, body, score, source position, parse error, or credential; and
- a zero-saving applied position_reorder still increments levers_applied.

Run:

    cargo nextest run -p sbproxy-core compression_metrics --locked

Expected: FAIL until target_log handles the new variants.

### Step 5: Extend closed value labels and zero-savings coverage

PendingCompressionValue::from_run already excludes zero savings. Extend it to exclude PositionReorder regardless of its estimator delta, then add tests with RagSelect, CompactSerialization, and PositionReorder to pin that:

- positive RagSelect and CompactSerialization savings reach the ledger;
- every PositionReorder result is omitted, including an accidental positive estimator delta;
- no cost or token metric is emitted for it; and
- an unknown free-form lever label is still rejected.

Extend the closed value-label match in sbproxy-observe/src/metrics.rs to accept rag_select and compact_serialization. Keep position_reorder rejected on this value-only surface; it remains accepted by the ordinary per-lever compression metrics.

Run:

    cargo nextest run -p sbproxy-ai value_ledger --locked
    cargo nextest run -p sbproxy-core compression_value --locked
    cargo nextest run -p sbproxy-observe compression_value --locked

Expected: PASS.

### Step 6: Correct the Grafana application-rate description

Change the Compression Application Rate panel description to:

    Fraction of compression lever invocations that committed a transformation over the last five minutes.

Extend compression_observability.rs to reject the old strictly reducing wording and require committed transformation. Do not add new metric families, recording rules, or per-lever alerts.

Run:

    cargo nextest run -p sbproxy-observe --test compression_observability --locked

Expected: PASS.

### Step 7: Commit production wiring and observability

    git add crates/sbproxy-core/src/compression_runtime.rs crates/sbproxy-core/src/compression_metrics.rs crates/sbproxy-core/src/server/ai_dispatch.rs crates/sbproxy-ai/src/value_ledger.rs crates/sbproxy-core/src/compression_value.rs crates/sbproxy-observe/src/metrics.rs crates/sbproxy-observe/tests/compression_observability.rs dashboards/grafana/sbproxy-ai-gateway.json
    git commit -m "feat(core): wire Phase 1 compression telemetry"

---

## Task 7: Generalize the deterministic evaluation harness

**Files:**

- Modify: sbproxy-bench/harness/context_compression_eval/src/model.rs
- Modify: sbproxy-bench/harness/context_compression_eval/src/evaluator.rs
- Modify: sbproxy-bench/harness/context_compression_eval/src/main.rs
- Modify: sbproxy-bench/harness/context_compression_eval/src/report.rs
- Modify: sbproxy-bench/harness/context_compression_eval/src/lib.rs
- Modify: sbproxy-bench/harness/context_compression_eval/tests/evaluation.rs
- Modify: sbproxy-bench/harness/context_compression_eval/tests/cli.rs
- Modify: sbproxy-bench/harness/context_compression_eval/tests/fixtures.rs
- Modify: sbproxy-bench/harness/context_compression_eval/tests/report_rendering.rs
- Modify: sbproxy-bench/harness/context_compression_eval/tests/documentation.rs
- Create: sbproxy-bench/harness/context_compression_eval/pipelines/window-fit-smoke.json
- Create: sbproxy-bench/harness/context_compression_eval/pipelines/rag-select-smoke.json
- Create: sbproxy-bench/harness/context_compression_eval/pipelines/compact-serialization-smoke.json
- Create: sbproxy-bench/harness/context_compression_eval/pipelines/position-reorder-smoke.json
- Create: sbproxy-bench/harness/context_compression_eval/pipelines/phase1-pipeline-smoke.json
- Create: sbproxy-bench/harness/context_compression_eval/fixtures/rag-select-smoke.jsonl
- Create: sbproxy-bench/harness/context_compression_eval/fixtures/compact-serialization-smoke.jsonl
- Create: sbproxy-bench/harness/context_compression_eval/fixtures/position-reorder-smoke.jsonl
- Create: sbproxy-bench/harness/context_compression_eval/fixtures/phase1-pipeline-smoke.jsonl
- Modify: sbproxy-bench/harness/context_compression_eval/fixtures/provenance.json
- Create: four JSON and four Markdown reports under sbproxy-bench/harness/context_compression_eval/reports
- Modify: sbproxy-bench/harness/context_compression_eval/reports/window-fit-smoke.json
- Modify: sbproxy-bench/harness/context_compression_eval/reports/window-fit-smoke.md
- Modify: sbproxy-bench/harness/context_compression_eval/README.md
- Modify: .github/workflows/context-compression-eval.yml

### Step 1: Write failing typed-pipeline tests

Replace the hard-coded window fields in EvalConfig with:

~~~rust
pub struct EvalConfig {
    pub profile: String,
    pub levers: Vec<CompressionLeverConfig>,
    pub measure_latency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalPipelineFile {
    pub schema_version: u32,
    pub profile: String,
    pub levers: Vec<CompressionLeverConfig>,
}
~~~

Add build_stateless_levers(), returning real production lever objects for RagSelect, CompactSerialization, PositionReorder, and WindowFit. Reject SummaryBuffer with a clear stateful levers are not supported by the deterministic harness error.

Run:

    cargo nextest run --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml --locked evaluation

Expected: FAIL because EvalConfig still hard-codes WindowFit.

### Step 2: Generalize per-case reporting

Change CaseReport to include every ordered lever result:

~~~rust
pub struct CaseLeverReport {
    pub lever: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub before_tokens: u64,
    pub after_tokens: u64,
    pub tokens_saved: u64,
}
~~~

Set the case outcome from CompressionRun::outcome rather than from the first lever. Replace the report's fixed budget fields with the serialized ordered pipeline. Bump report schema_version to 3.

Keep off and on inputs identical. Continue omitting wall-clock latency from committed reports.

### Step 3: Add structural quality contracts

Extend QualitySpec with:

~~~rust
StructuredEquivalence { chunk_id: String }
EdgePlacement { chunk_id: String }
~~~

StructuredEquivalence uses inspect_marked_context plus decode_sbproxy_table_v1. It parses the selected chunk in each arm, normalizes JSON through serde_json::Value, and scores 1 only when the arm is semantically equal to the control value.

EdgePlacement finds the selected chunk ordinal among all chunks in its block and scores normalized distance to the nearest edge. An edge scores 1, the center scores 0, and a one-chunk block scores 1.

Add this optional per-case gate:

~~~rust
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceSpec {
    pub min_savings_ratio: Option<f64>,
    pub min_on_quality_score: Option<f64>,
    pub min_quality_delta: Option<f64>,
    #[serde(default)]
    pub require_non_expanding: bool,
}
~~~

Add #[serde(default)] pub acceptance: AcceptanceSpec to EvalCase. Reject non-finite thresholds and values outside their valid ranges. Add acceptance_passed to CaseReport and AggregateReport. Build requires every case to pass its declared acceptance and no failed lever. Preserve the existing Borrow and Defer fallback for cases without explicit acceptance.

### Step 4: Write focused evaluation tests

Add tests that prove:

- a configured WindowFit pipeline preserves the old report behavior;
- each new lever is built from production CompressionLeverConfig;
- ordered combined results include all four levers;
- structured JSON and sbproxy_table_v1 score equivalently;
- edge placement improves after reordering;
- PositionReorder can pass with zero savings when require_non_expanding is true;
- a growing treatment fails acceptance;
- the 200-row compact case requires at least 0.30 savings and quality 1.0; and
- a stateful pipeline is rejected.

Run:

    cargo nextest run --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml --all-targets --locked

Expected: PASS after implementation.

### Step 5: Replace CLI budget flags with a pipeline file

ReportArgs gains required --pipeline-config and drops --completion-reserve-tokens and --input-budget-tokens. Load and validate EvalPipelineFile before evaluation. Keep --profile only out of the CLI so the committed profile name comes from the checked file.

Update generate and check tests. Check must fail both on report drift and when the regenerated overall recommendation is not Build.

The window-fit pipeline file contains:

~~~json
{
  "schema_version": 1,
  "profile": "window-fit-smoke-v1",
  "levers": [
    {
      "type": "window_fit",
      "completion_reserve_tokens": 8000,
      "input_budget_tokens": 192
    }
  ]
}
~~~

Add analogous files for each new lever and the recommended combined order.

### Step 6: Add independently authored fixtures and provenance

Create:

- rag-select-smoke.jsonl with relevant evidence plus ranked distractors;
- compact-serialization-smoke.jsonl with a marked 200-row uniform tool result;
- position-reorder-smoke.jsonl with the required chunk initially near the center; and
- phase1-pipeline-smoke.jsonl with a marked query, useful evidence, distractors, and uniform JSON.

Declare exact acceptance in each row. The compact case sets min_savings_ratio to 0.30 and min_on_quality_score to 1.0. The position case sets require_non_expanding true and a positive min_quality_delta. The combined case requires query/evidence retention and positive savings.

Run:

    cd sbproxy-bench/harness/context_compression_eval
    shasum -a 256 fixtures/rag-select-smoke.jsonl fixtures/compact-serialization-smoke.jsonl fixtures/position-reorder-smoke.jsonl fixtures/phase1-pipeline-smoke.jsonl

Copy the exact digests into provenance.json with independently_authored_sanitized_shape, Apache-2.0, contains_customer_data false, and official_benchmark_score false.

Run:

    cargo nextest run --manifest-path Cargo.toml --locked fixtures

Expected: PASS.

### Step 7: Generate and check all reports

From the harness directory, run generate once per pipeline and matching input:

    cargo run --locked -- generate --pipeline-config pipelines/rag-select-smoke.json --input fixtures/rag-select-smoke.jsonl --provenance fixtures/provenance.json --json-report reports/rag-select-smoke.json --markdown-report reports/rag-select-smoke.md
    cargo run --locked -- generate --pipeline-config pipelines/compact-serialization-smoke.json --input fixtures/compact-serialization-smoke.jsonl --provenance fixtures/provenance.json --json-report reports/compact-serialization-smoke.json --markdown-report reports/compact-serialization-smoke.md
    cargo run --locked -- generate --pipeline-config pipelines/position-reorder-smoke.json --input fixtures/position-reorder-smoke.jsonl --provenance fixtures/provenance.json --json-report reports/position-reorder-smoke.json --markdown-report reports/position-reorder-smoke.md
    cargo run --locked -- generate --pipeline-config pipelines/phase1-pipeline-smoke.json --input fixtures/phase1-pipeline-smoke.jsonl --provenance fixtures/provenance.json --json-report reports/phase1-pipeline-smoke.json --markdown-report reports/phase1-pipeline-smoke.md
    cargo run --locked -- generate --pipeline-config pipelines/window-fit-smoke.json --input fixtures/ruler-smoke.jsonl --input fixtures/coding-agent-smoke.jsonl --provenance fixtures/provenance.json --json-report reports/window-fit-smoke.json --markdown-report reports/window-fit-smoke.md

Inspect the generated reports for Build, exact quality, thresholds, and the no-official-score disclaimer. Replace generate with check and run all five commands again. Expected: PASS and no report drift.

### Step 8: Update CI and harness documentation

Update the workflow to run all five check commands. Update documentation tests to require --pipeline-config and all four Phase 1 report names. Update the README to explain the marker contract, typed stateless pipeline files, structural scorers, 200-row threshold, and honest evidence boundaries. Remove the obsolete claim that follow-up validation remains under canceled WOR-1879.

Run:

    cargo fmt --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml -- --check
    cargo nextest run --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml --all-targets --locked
    cargo clippy --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml --all-targets --locked -- -D warnings

Expected: PASS.

### Step 9: Commit deterministic Phase 1 evidence

    git add sbproxy-bench/harness/context_compression_eval .github/workflows/context-compression-eval.yml
    git commit -m "test(eval): cover the Phase 1 compression pipeline"

---

## Task 8: Add request-path acceptance, schemas, example, and docs

**Files:**

- Create: e2e/tests/context_compression_phase1.rs
- Modify: e2e/tests/governed_key_policy.rs
- Modify: .github/workflows/context-compression-eval.yml
- Modify: crates/sbproxy-config/tests/compression_examples.rs
- Modify: examples/ai-context-compression-redis/sb.yml
- Modify: examples/ai-context-compression-redis/README.md
- Modify: docs/ai-context-compression.md
- Modify: docs/llms-full.txt
- Modify: schemas/ai-compression.schema.json
- Modify: CHANGELOG.md

### Step 1: Write a failing live request-path test

Create context_compression_phase1.rs with one proxy and mock upstream. Configure the recommended default pipeline. Send marked retrieval input containing:

- a query;
- required text evidence;
- distractors;
- a 200-row uniform JSON tool chunk;
- unmarked user text;
- system, developer, and assistant text containing marker-like strings; and
- a separate malformed marked block.

Use separate requests so one malformed block can prove whole-request fail-open. Assert:

- the valid request reaches the upstream with only marked content transformed;
- query and required evidence survive;
- JSON decodes exactly after table compaction;
- required evidence is at an edge;
- unmarked and protected messages are byte-for-byte unchanged;
- malformed input is forwarded byte-for-byte unchanged;
- x-compression: off preserves the full valid request; and
- the internal header never reaches the provider.

Run:

    cargo nextest run -p sbproxy-e2e --locked --test context_compression_phase1 --test-threads=1

Expected: FAIL before runtime/config support is complete, then PASS.

### Step 2: Exercise governed-key and CEL selection

Add a phase1 named profile to the existing governed-key policy test world and point the compression CEL host at the same profile. Extend dynamic_compression_profile_changes_context_and_header_overrides_it or add one adjacent test that:

- mints a governed key selecting phase1;
- proves the marked upstream body changes;
- proves x-compression: off overrides the governed selection; and
- proves CEL selects phase1 from the pre-compression estimate.

Do not add another proxy process. Reuse the current TestWorld.

Run:

    cargo nextest run -p sbproxy-e2e --locked --test governed_key_policy dynamic_compression_profile_changes_context_and_header_overrides_it --test-threads=1

Expected: PASS.

### Step 3: Add focused E2E commands to CI

In the production request-path smoke job, add context_compression_phase1 and retain the governed-selector and Anthropic-native tests. Install cargo-nextest in the standalone harness job with taiki-e/install-action@nextest, and run its test lane with cargo nextest. Keep the workflow timeout at 35 minutes unless measured CI evidence requires a bounded increase.

### Step 4: Regenerate and verify the compression schema

Run:

    cargo run -p sbproxy-ai --bin generate-ai-compression-schema > schemas/ai-compression.schema.json
    ./scripts/check-config-schema.sh

Expected: the dedicated schema contains all new variants, bounds, defaults, and deny-unknown-fields behavior; the check passes.

### Step 5: Update the runnable example

Extend the existing compact profile in examples/ai-context-compression-redis/sb.yml to the recommended Phase 1 order before WindowFit. Keep the stateful route default unchanged. Add one marked retrieval curl to its README and document:

- the exact marker grammar;
- explicit marking only;
- safe fail-open behavior;
- ranking modes;
- reversible sbproxy_table_v1;
- semantic-cache bypass;
- bounded metrics and ai_compression_summary;
- zero-saving position_reorder value behavior; and
- recommended monitoring queries by lever.

Update compression_examples.rs to compile the profile and assert the four ordered types.

Run:

    cargo nextest run -p sbproxy-config --test compression_examples --locked

Expected: PASS.

### Step 6: Update operator docs and release notes

In docs/ai-context-compression.md:

- add the public YAML contract and validation table;
- add the complete marker grammar and limits;
- document ranking, table encoding, edge order, skip reasons, and cache bypass;
- update the safe log target fields for all new configs;
- update evaluation commands to --pipeline-config and list all reports;
- state that evidence is independently authored structural smoke evidence;
- remove the stale WOR-1879 follow-up language; and
- update rollout guidance to start each new lever independently before using the combined order.

Update the existing Unreleased context-compression changelog bullet rather than adding a competing bullet.

Regenerate the flattened docs:

    ./scripts/regen-llms-full.sh
    ./scripts/regen-llms-full.sh --check

Expected: PASS.

### Step 7: Run focused docs, schema, and E2E checks

    ./scripts/check-config-schema.sh
    cargo nextest run -p sbproxy-config --test compression_examples --locked
    cargo nextest run -p sbproxy-observe --test compression_observability --locked
    cargo nextest run -p sbproxy-e2e --locked --test context_compression_phase1 --test-threads=1
    cargo nextest run -p sbproxy-e2e --locked --test governed_key_policy dynamic_compression_profile_changes_context_and_header_overrides_it --test-threads=1
    cargo nextest run -p sbproxy-e2e --locked --test ai_native_inbound anthropic_native_upstream_receives_the_compressed_message_list --test-threads=1

Expected: PASS.

### Step 8: Commit public acceptance material

    git add e2e/tests/context_compression_phase1.rs e2e/tests/governed_key_policy.rs .github/workflows/context-compression-eval.yml crates/sbproxy-config/tests/compression_examples.rs examples/ai-context-compression-redis docs/ai-context-compression.md docs/llms-full.txt schemas/ai-compression.schema.json CHANGELOG.md
    git commit -m "docs: ship Phase 1 compression acceptance"

---

## Task 9: Verify, review, publish one PR, and close Linear after merge

**Files:**

- Review every changed file
- No new implementation files unless verification exposes a defect

### Step 1: Inspect scope before claiming completion

    git status --short
    git diff --stat origin/main...HEAD
    git diff --check origin/main...HEAD
    git log --oneline --decorate origin/main..HEAD

Expected: only WOR-1918 closeout files are changed, there is no whitespace damage, and all commits are on the one feature branch.

### Step 2: Run focused deterministic gates

    ./scripts/check-config-schema.sh
    ./scripts/regen-llms-full.sh --check
    cargo fmt --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml -- --check
    cargo nextest run --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml --all-targets --locked
    cargo clippy --manifest-path sbproxy-bench/harness/context_compression_eval/Cargo.toml --all-targets --locked -- -D warnings

Then run all five harness check commands from Task 7. Expected: PASS with byte-for-byte committed report parity.

### Step 3: Run all repository gates required by AGENTS.md

    cargo fmt --all -- --check
    cargo build --workspace
    cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci
    cargo test --workspace --exclude sbproxy-e2e --locked --doc
    cargo clippy --workspace --all-targets -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

Expected: every command exits 0. Record exact command results and elapsed time for the pull request.

### Step 4: Run focused live request-path gates

    cargo nextest run -p sbproxy-e2e --locked --test context_compression_phase1 --test-threads=1
    cargo nextest run -p sbproxy-e2e --locked --test governed_key_policy dynamic_compression_profile_changes_context_and_header_overrides_it --test-threads=1
    cargo nextest run -p sbproxy-e2e --locked --test ai_native_inbound anthropic_native_upstream_receives_the_compressed_message_list --test-threads=1

Expected: PASS.

### Step 5: Perform the required verification and code-review workflows

Invoke superpowers:verification-before-completion and attach fresh command evidence. Then invoke superpowers:requesting-code-review and resolve every substantive finding on this same branch. Re-run the narrowest affected test after each fix and the full gates after the final fix.

Do not create a second branch or pull request.

### Step 6: Publish exactly one pull request

Invoke github:yeet for the current branch. The pull request title should be:

    feat(ai): close WOR-1918 Phase 1 context compression

The body must:

- link WOR-1918, WOR-1924, WOR-1925, WOR-1926, and WOR-1795;
- summarize the explicit marker contract and three levers;
- state semantic-cache, logging, metric, and value behavior;
- link the four Phase 1 reports;
- state that the evidence is synthetic structural smoke evidence, not an official benchmark or captured production claim;
- list exact verification commands and results;
- identify deferred Phase 2, Phase 3, model-host, and context-offloading work; and
- state that this is the only implementation PR for the epic closeout.

### Step 7: Keep fixes in the same PR until green

Monitor GitHub checks. If a check fails, invoke github:gh-fix-ci, make the smallest correction on this branch, run local focused verification, commit, and push to the same PR. Address review threads with github:gh-address-comments. Do not split follow-up PRs for in-scope defects.

### Step 8: Merge and reconcile Linear

After required checks and approvals are green, merge the one PR according to repository policy. Then use the linear skill to:

1. Mark WOR-1924, WOR-1925, and WOR-1926 Done.
2. Mark WOR-1795 Duplicate of WOR-1925, citing the 200-row and 30 percent acceptance report.
3. Move WOR-1927, WOR-1928, WOR-1930, and WOR-1931 to the successor proxy-optimization epic.
4. Move WOR-1932 through WOR-1935 to the successor model-host context-efficiency epic.
5. Move WOR-1936 and WOR-1937 to the stateful-agent-memory or context-offloading successor.
6. Record design lever L7 as deferred.
7. Add one final WOR-1918 comment with the PR, merge commit, reports, verification evidence, logging and metric contract, and scope boundary.
8. Mark WOR-1918 Done.

Leave WOR-1942 separate unless the provisioned-key Claude Code flow is explicitly added to this acceptance boundary.

### Step 9: Final completion check

Confirm:

- one merged PR;
- all five issue references present;
- all Phase 1 reports reproducible;
- no open required review or CI failure;
- Linear children and successors reconciled; and
- WOR-1918 in Done.

Only then report WOR-1918 closed.
