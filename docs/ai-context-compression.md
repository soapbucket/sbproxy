# AI context compression

*Last modified: 2026-07-20*

SBproxy can transform an AI chat request through an ordered, route-local
compression pipeline before provider selection and dispatch. A route can keep
one default pipeline and declare named profiles for different callers. Use
the retrieval-aware stateless levers for explicitly marked context, then use
`window_fit` for a final deterministic input bound. Add `summary_buffer` when
conversations need a compact running summary stored in a shared state backend
(Redis by default, or the replicated mesh substrate) so gateway workers can
restart and successive turns can land on different replicas.

This page is the canonical operator guide for compression configuration,
runtime behavior, state, degradation, and telemetry.

## Runtime contract

Each `ai_proxy` action can declare one `compression.levers` array. SBproxy runs
the entries in declaration order against one working message list:

1. A lever sees the output committed by earlier levers.
2. `summary_buffer`, `window_fit`, `rag_select`, and
   `compact_serialization` replace the working list only when the candidate
   strictly reduces SBproxy's token estimate for the effective model.
   `position_reorder` may commit a changed, non-expanding candidate.
3. A skipped or failed lever leaves the working list unchanged.
4. Later levers still run after a skip or failure.
5. Provider routing and failover see only the final committed list.

For explicitly marked retrieval input, the recommended order is `rag_select`,
`compact_serialization`, `position_reorder`, then `window_fit`. Stateful chat
history commonly uses `summary_buffer` followed by `window_fit`. These can be
separate named profiles on one route.

| Lever | State | Purpose | Typical position |
|---|---|---|---|
| `summary_buffer` | Configured Redis L2 service | Replace eligible older text history with a bounded, incremental summary | First |
| `rag_select` | None | Retain the most relevant chunks in explicitly marked retrieval blocks | Before serialization |
| `compact_serialization` | None | Compact safe marked JSON and uniform scalar object rows | After selection |
| `position_reorder` | None | Move highly ranked chunks toward block edges | Before the final bound |
| `window_fit` | None | Apply the legacy newest-to-oldest message-selection heuristic within the known model window | Last |

Request workers do not retain canonical summaries in process. Canonical
session summary state lives only in the configured Redis L2 service. A worker
can restart or a later request can land on another replica without relying on
worker-local conversation memory.

The compression record key is an opaque digest over the tenant, normalized AI
origin, captured session ID, and a stable summary-policy fingerprint. The
fingerprint covers provider, model, threshold, retained-tail size, summary
target, state lifetime, fixed prompt text, record schema, and summary behavior
version. A policy or incompatible behavior change starts a separate lineage,
so mixed replicas cannot reuse each other's summaries. Raw session IDs and
original messages are not stored in the record.

## Marked retrieval context

`rag_select`, `compact_serialization`, and `position_reorder` inspect only
string-valued `content` on `user` and `tool` messages. Callers must mark the
retrieval context explicitly. SBproxy does not infer it from ordinary text,
and it ignores marker-like strings in `system`, `developer`, or `assistant`
messages.

One block has this exact line-delimited shape:

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
Tag names are lowercase and exact. Blocks cannot nest. Every block has exactly
one non-empty query followed by zero or more chunks. Zero chunks is valid
output after `rag_select` removes every chunk with `drop_empty: true`.

Each chunk opening tag uses this attribute order:

```text
<sbproxy-chunk id="ID" score="SCORE" format="FORMAT">
```

`id` is required and contains from 1 to 64 ASCII letters, digits, `.`, `_`, or
`-`. `score` is optional, finite, and falls from 0 through 1. `format` is
required and is `text`, `json`, or `sbproxy_table_v1`. Query and chunk bodies
are opaque. A body cannot contain its exact closing tag as a complete line.
The producer must encode or escape that line before marking the block. LF and
CRLF are accepted, and each block must use one consistent line ending.

An apparent block with missing, reordered, extra, nested, or incomplete tags
is malformed. Duplicate chunk IDs within one block are also malformed. An
orphan block, query, or chunk sentinel on a complete line makes the eligible
message malformed. Text outside a valid block remains literal and is copied
exactly when that message is rendered after a marked transformation.

The parser accepts at most 32 retrieval blocks per request, 1,024 chunks per
block, and 4,096 chunks across the request. Each retrieval-aware lever parses
the entire current message list before changing it. A malformed or oversized
block makes that lever skip the complete working list without a partial
rewrite. The next ordered lever still runs. If `window_fit` follows the
retrieval levers, it may trim the request even though each retrieval lever
skipped.

## Stateless retrieval levers

The public recommended contract is:

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
      completion_reserve_tokens: 1024
      input_budget_tokens: 8192
```

Ranking accepts `auto`, `supplied`, or `lexical`. `auto` uses supplied scores
only when every chunk in the block has one; otherwise it uses lexical ranking.
`supplied` skips a block when any score is absent. `lexical` ignores supplied
scores. Lexical ranking is deterministic normalized TF-IDF cosine similarity
between the marked query and each chunk. It lowercases Unicode text, splits on
non-alphanumeric boundaries, and uses original chunk order to break ties. It
does not call a model or network service.

### RAG selection

`rag_select` evaluates each block independently after its marked token estimate
reaches `min_tokens`. It ranks chunks, removes scores below
`min_relevance_percent`, retains at most `max_chunks`, and renders retained
chunks in ranked order. The marked query is never removed. If no chunk
survives, `drop_empty: true` keeps the wrapper and query with zero chunks;
`drop_empty: false` leaves that block unchanged. The complete candidate must
reduce the working message-list estimate before the runner commits it.

### Compact serialization

`compact_serialization` considers only marked `format="json"` chunks whose
estimate reaches `min_tokens`. Canonical whitespace-free JSON is one candidate.
When tabular mode is enabled, a top-level array may instead become
`sbproxy_table_v1` when it has at least `min_rows` objects, every object has the
same key set, and every cell is a string, number, boolean, or null. Nested
arrays and objects are ineligible.

Table v1 contains a canonical JSON array of sorted column names followed by
literal-tab-separated rows of canonical JSON scalars:

```text
["reason","time"]
"ImagePullBackOff"	"12:01"
"BackOff"	"12:02"
```

JSON escaping protects tabs, newlines, quotes, and backslashes inside string
cells. The public `decode_sbproxy_table_v1` decoder reconstructs the exact
`serde_json::Value`. Insignificant source whitespace and object-key order are
not preserved. SBproxy chooses the smallest safe representation and commits it
only when the complete message list strictly shrinks by the shared estimate.

### Position reordering

`position_reorder` derives the same closed ranking, then places rank 1 at the
start, rank 2 at the end, rank 3 after rank 1, rank 4 before rank 2, and
continues that alternating edge pattern. Query text, chunk tags, attributes,
and bodies remain byte-for-byte identical; only chunk order can change.

This lever uses a non-expanding commit rule. A changed order may apply with the
same token estimate and zero saved tokens. That application remains visible in
ordinary per-lever metrics, but it does not create a token-saving value row.

## Stateless window fitting

`window_fit` needs no session ID and no external state. The hosted request must
carry a non-empty effective `model`; otherwise the compression pipeline is not
invoked. It has two modes.

- Compatibility mode omits `input_budget_tokens`. It looks up the model's
  known context window, subtracts `completion_reserve_tokens`, preserves a
  leading system message, and applies the legacy newest-to-oldest selection
  heuristic.
- Explicit-budget mode sets `input_budget_tokens` to a positive integer. It
  uses the same target-model counter as compression accounting, works for an
  unknown model, and enforces the smaller of that configured budget and the
  known model window minus `completion_reserve_tokens`.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
      compression:
        levers:
          - type: window_fit
            completion_reserve_tokens: 1024
            input_budget_tokens: 8192
```

The completion reserve defaults to `1024`. In explicit-budget mode, SBproxy
counts the complete JSON message shape, including provider-specific fields.
It preserves the contiguous leading `system` and `developer` instruction
prefix, requires the complete newest protocol unit to fit, and retains a
contiguous newest suffix. OpenAI assistant tool calls stay grouped with their
`tool` or `function` results. Anthropic assistant `tool_use` blocks stay grouped
with the following user `tool_result` blocks. SBproxy never retains half of a
tool exchange or drops the current turn while keeping stale history.

If the protected prefix plus newest unit cannot fit, the lever skips as
`not_eligible` and leaves the request unchanged. If the original request
already fits, it skips as `not_needed`. An explicit budget therefore provides
a safe trimming target, but it does not authorize dropping protected
instructions or breaking the provider protocol.

Without `input_budget_tokens`, an unknown model window skips as
`unknown_model_window`. Compatibility mode keeps its older estimator and
selection behavior so existing `context_compress` deployments do not change.

The older `resilience.llm_aware.context_compress: true` switch remains a
compatibility shorthand for a one-lever `window_fit` policy when no explicit
`compression` block is present. An explicit `compression` block is
authoritative, including `levers: []`.

## Profiles and request selection

Named profiles live under the route's `compression.profiles` map. Each profile
has its own `levers` and optional Redis `state`. Profile names contain from 1
to 64 bytes, start with a lowercase ASCII letter or digit, and then use only
lowercase ASCII letters, digits, `_`, or `-`. The reserved values `on` and
`off` cannot be profile names.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
      compression:
        levers:
          - type: window_fit
            input_budget_tokens: 16384
        profiles:
          compact:
            levers:
              - type: window_fit
                input_budget_tokens: 4096
```

Selectors use one closed grammar:

| Selector | Pipeline |
|---|---|
| `on` | Route default `compression.levers` |
| `off` | No compression |
| A declared profile name | That profile's pipeline |

One request resolves exactly one selector in this precedence order:

1. `X-Compression` request header.
2. Governed key `compression_profile`.
3. CEL action `compression:<selector>`.
4. Route default, equivalent to `on`.

The request header is the caller override. SBproxy accepts exactly one header
value, strips it before upstream dispatch, and returns `400` for malformed
syntax or an undeclared header profile. The governed-key Admin API and static
configuration reject malformed selector syntax when it is written. If a
legacy or externally modified governed record contains a malformed or
undeclared selector, SBproxy disables compression for that request and records
`invalid_operator`. CEL uses the same safe operator behavior: a malformed or
undeclared compression action resolves to `off`, while unrelated CEL errors
still follow `ai_policy.on_error`.

```bash
# Select the route default.
curl -H 'X-Compression: on' ...

# Disable compression for this request, even when the key or CEL selects it.
curl -H 'X-Compression: off' ...

# Select one named route-local profile.
curl -H 'X-Compression: compact' ...
```

## Stateful summary buffering

`summary_buffer` is eligible only for a supported `/v1/chat/completions`
message array with a non-empty effective model, captured session ID, tenant,
and origin. It runs when SBproxy's model-aware estimate reaches `min_tokens`
and enough eligible history remains after the protected prefix and recent tail
are excluded.

### Captured session identity

The compression layer never creates a session ID. It consumes the session ULID
already captured by the request envelope. A caller should send a stable,
valid `X-Sb-Session-Id` on every turn in one conversation:

```yaml
origins:
  "ai.example.com":
    sessions:
      capture: true
      auto_generate: never
```

With `auto_generate: never`, a missing or invalid header leaves no captured
session and `summary_buffer` skips with `missing_session`. The rest of the
pipeline and the upstream request continue.

The general session-capture layer can be configured to generate and echo a
ULID for anonymous traffic, but that is outside compression. If an SDK uses
that behavior, it must read the echoed `X-Sb-Session-Id` and send the same ID
on later turns. A newly generated ID on every request does not join those
requests into one summary history.

### Material that can be summarized

The lever partitions the message list into three regions:

- Every contiguous leading `system` or `developer` message is protected and
  copied byte-for-byte.
- The last `retain_recent_messages` entries are protected and copied
  byte-for-byte.
- Only the middle region is eligible for summarization. Every entry there must
  contain exactly `role` and string `content`, with role `user` or
  `assistant`.

Top-level `tools`, `functions`, `response_format`, `schema`, `json_schema`, or
`output_schema` fields make the summary lever skip with
`structured_request`. A tool call, tool result, name field, multimodal content
array, schema material, or any other structured entry in the middle region
also causes that safe skip. Structured material in the protected recent tail
is preserved exactly and does not prevent older simple text from being
summarized.

The generated summary is inserted immediately after the protected prefix as a
synthetic `role: user` message. It is untrusted historical context, inside
explicit wrapper tags and with an instruction that it must never be treated as
instructions. The dedicated summarizer receives the source as untrusted JSON
under its own fixed system instruction.

### Incremental state and branch mismatch

The stored record includes digests of the protected prefix and all original
history covered by the summary. On a later request with the same tenant,
origin, and captured session:

- An exact history match reuses the stored summary without a summarizer call or
  state write. Because there is no write, exact reuse does not refresh the
  record TTL.
- Appended history sends only newly covered messages plus the prior summary to
  the summarizer, then advances the logical version.
- A record at or past its logical expiration skips with `state_expired`, even
  during the short interval before Redis physically removes it.
- A changed protected prefix, edited covered message, shortened history, or
  different history fork skips with `branch_mismatch`. SBproxy does not reuse
  or overwrite the record for the mismatched branch.

Treat a deliberate conversation fork as a new session. If a caller reused a
session ID after resetting or editing history, assign a new ID or remove the
old opaque record through the authenticated Admin API.

### Dedicated summarizer policy

Every `summary_buffer` selects one exact provider and model from the same AI
handler. Startup validation requires the provider to exist and be enabled, the
model to be declared by that provider or accepted by its wildcard model
configuration, and the model to pass the handler's model policy.

The internal request does not enter ordinary routing, semantic caching,
shadowing, or compression, so it cannot recurse. It is a non-streaming chat
completion sent only to the configured provider and model with
`max_tokens: target_summary_tokens`.

Request-scoped credential governance and the effective AI budget still apply:

- A credential that disallows the summarizer provider or model produces the
  safe skip `policy_denied`.
- A budget preflight that would block or downgrade the internal call produces
  the safe skip `budget_denied`.
- A successful internal call is charged to the same tenant and sanitized
  credential identifier with surface `compression_summary`. That usage remains
  charged even if a later state commit fails.
- Prior summary plus new source must fit the summarizer model's input window.
  Oversized input skips as `summarizer_input_too_large` before dispatch.
- `summarizer.timeout` is a hard wall-clock deadline. A timeout fails open as
  `summarizer_timeout`.

Empty, malformed, or oversized summary output fails validation. The provider's
reported output count and a conservative local estimate must both fit
`target_summary_tokens`.

## Redis state

`backend: redis` reuses the process-wide Redis L2 configuration and Redis
service. It inherits all four connection fields: `dsn`, `ca_file`, `cert_file`,
and `key_file`. The compression runtime clones the same validated Redis client
and opens its own lazy multiplexed connection. The compression block does not
accept a separate DSN, CA, or client identity, so it cannot silently lose the
L2 trust or mTLS configuration.

Redis serializes updates with a bounded lease, a monotonic fence, and a
logical-version compare-and-set. The lease is the configured summarizer timeout
plus a fixed 5-second margin for the bounded state load, validation, and commit;
it is not renewed indefinitely.

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://cache-user:${REDIS_PASSWORD_URLENCODED}@redis.internal:6380/7
      ca_file: /etc/sbproxy/redis/ca.pem
      cert_file: /etc/sbproxy/redis/client.pem
      key_file: /etc/sbproxy/redis/client-key.pem

origins:
  "ai.example.com":
    sessions:
      capture: true
      auto_generate: never
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini]
      compression:
        state:
          backend: redis
          ttl: 24h
        levers:
          - type: summary_buffer
            min_tokens: 12000
            retain_recent_messages: 8
            target_summary_tokens: 2048
            summarizer:
              provider: openai
              model: gpt-4o-mini
              timeout: 5s
          - type: window_fit
            completion_reserve_tokens: 1024
```

Selecting Redis without `proxy.l2_cache_settings.driver: redis` is a startup
configuration error. Invalid DSN semantics, invalid TLS field combinations,
and bad local PEM material are also rejected before serving. Each configuration
compile reads and validates the Redis PEM files once. The general L2 store and
compression state adapter then clone the same immutable validated connection
snapshot; constructing compression or admin adapters later does not reopen
those files. A configuration reload compiles a new snapshot and therefore
reads the files for that reload. Configuration validation does not open a
network connection. TLS verification, authentication, and database selection
happen when the lazy compression connection is first used.

Once the runtime is active, a Redis connection, TLS, authentication, database,
or command failure makes the stateful lever fail open for that request. The
current internal bounds are 500 milliseconds for connection setup, 1 second
for a command response, and 2 seconds for a complete state operation. A failed
cached connection is replaced, and a later request can recover without
restarting SBproxy. There is no worker-local summary fallback.

The general synchronous L2 metrics named `sbproxy_redis_kv_*` cover
`RedisKVStore` consumers such as shared response cache and rate limiting. The
compression runtime remains covered by
`sbproxy_ai_compression_state_operations_total`,
`sbproxy_ai_compression_state_operation_duration_seconds`, and
`sbproxy_ai_compression_redis_coordination_total`; it does not double-count its
async operations in the synchronous families.

## Choosing a state backend: Redis or mesh

`compression.state.backend` accepts `redis` and `mesh`. Redis is the default
recommendation. It serializes every update with a distributed lease, a
monotonic fence, and an atomic compare-and-set, so a cross-node update race is
prevented before any write happens. Choose `mesh` for a Redis-free fleet that
already runs `proxy.cluster.replication` and can accept eventually consistent
session summaries.

The two contracts are different; do not treat them as interchangeable:

| Property | `redis` | `mesh` |
|---|---|---|
| External dependency | Redis service via `proxy.l2_cache_settings` | None beyond `proxy.cluster.replication` |
| Update serialization | Distributed lease and fence across all workers | Worker-local lease only; cross-node writers race |
| Compare-and-set | Atomic inside one Lua script | Conditional put with read-back verification |
| Concurrent equal-version writers | Blocked by the lease or rejected before writing | Deterministic last-writer-wins merge; the loser fails with a stale-version error, the survivor is flagged `conflict_detected` |
| Reported consistency | `serialized` | `eventual_lww` |
| Durability | Redis persistence configuration | `factor` replicated copies, quorum acknowledgements, redb shards under `state_dir` |
| Partition behavior | The unreachable side fails open per request | Divergence converges through the causal merge after the heal; deletes cannot resurrect |

Enabling cluster replication by itself changes nothing here: compression stays
on whatever backend the configuration selects, and a route without a `state`
block keeps none. The backend switch is always the explicit
`compression.state.backend` value.

### Mesh state

`backend: mesh` requires `proxy.cluster.replication` on every node. Selecting
mesh without cluster replication fails at startup with a message naming the
missing block; it never falls back to a weaker store. See
[mesh-replication.md](mesh-replication.md) for the substrate's configuration
and its consistency contract.

Session records are replicated keys with the `compression:v1:` prefix on the
cluster substrate. The write path behaves as follows:

- `acquire_update` grants a worker-local permit. It short-circuits duplicate
  summarizer work inside one process; it does not block writers on other
  nodes. Serialization across nodes comes from the version check below, not
  from the permit.
- A commit reads the current replicated version at the configured read
  consistency, rejects a stale expectation, writes the record at exactly the
  next logical version, then reads the key back and requires that write to be
  the reconciled winner. Two nodes that race the same parent version produce
  exactly one surviving record cluster-wide: the loser's request degrades
  safely with a stale-version failure (the request proceeds uncompressed for
  that lever), and the surviving record carries `conflict_detected: true`.
- A delete replicates a tombstone through the same quorum write path.
  Tombstones fence stale live copies on every replica and are collected only
  by acknowledgement-aware garbage collection, so a deleted summary does not
  resurrect after a partition, restart, or rebalance. A writer that has read
  the tombstone re-creates the session at the next version.

With the default `quorum` read and write consistency, read and write replica
sets overlap, so the commit verification observes any competing committed
write. At `consistency: one`, a partition can accept equal-version updates on
both sides; after the heal the causal merge settles one deterministic winner
on every replica and flags the conflict. Summaries are derived state: the
losing side's content is regenerated from the conversation on a later turn.

The configured `state.ttl` bounds each live record's replicated lifetime.
Tombstones ignore TTL and remain until every replica of the key acknowledges
the deletion.

Admin listing and purge enumerate mesh session state through the substrate's
topology-safe fleet pagination: pages are bounded, a cursor keeps working
while nodes join or leave mid-walk, and a record held by any current member is
listed. A record replicated on several nodes can appear in more than one page,
so collapse results by `id`. If a current member cannot be queried, the
listing fails rather than returning a silently partial page.

Mesh-backed state shares `sbproxy_ai_compression_state_operations_total` and
`sbproxy_ai_compression_state_operation_duration_seconds` with
`backend="mesh"`, and reports coordination pressure in
`mesh_compression_coordination_total`. Replication health itself is covered by
the substrate's `mesh_replication_*`, `mesh_anti_entropy_*`, `mesh_handoff_*`,
and `mesh_tombstone_gc_*` families.

## Configuration reference

| Field | Required | Constraint |
|---|---|---|
| `compression.state.backend` | For `summary_buffer` | `redis` (default recommendation) or `mesh` (requires `proxy.cluster.replication`) |
| `compression.state.ttl` | For `summary_buffer` | Positive seconds or human duration |
| `compression.allow_admin_content_inspection` | No | Default `false`; enables audited Admin-only content inspection for configured origins |
| `compression.levers` | No | Ordered list; an explicit empty list disables compression |
| `compression.profiles` | No | Route-local map of named pipelines selectable by a request, governed key, or CEL |
| `compression.profiles.<name>.state` | For a profile with `summary_buffer` | `redis` or `mesh`; independent of the route default state |
| `compression.profiles.<name>.levers` | No | Ordered levers for this named profile; an empty list selects no runtime |
| `summary_buffer.min_tokens` | Yes | Greater than zero |
| `summary_buffer.retain_recent_messages` | Yes | Greater than zero |
| `summary_buffer.target_summary_tokens` | Yes | Greater than zero and smaller than `min_tokens` |
| `summary_buffer.summarizer.provider` | Yes | Enabled provider on the same handler |
| `summary_buffer.summarizer.model` | Yes | Non-empty model allowed by the handler and configured provider |
| `summary_buffer.summarizer.timeout` | Yes | Positive seconds or human duration |
| `rag_select.min_tokens` | Yes | Greater than zero; minimum marked-block estimate before selection |
| `rag_select.ranking` | No | `auto`, `supplied`, or `lexical`; defaults to `auto` |
| `rag_select.max_chunks` | Yes | Greater than zero |
| `rag_select.min_relevance_percent` | No | From `0` through `100`; defaults to `0` |
| `rag_select.drop_empty` | No | Defaults to `false` |
| `compact_serialization.min_tokens` | Yes | Greater than zero; minimum marked JSON chunk estimate |
| `compact_serialization.tabular.enabled` | No | Defaults to `false` |
| `compact_serialization.tabular.min_rows` | No | Defaults to `8`; at least `2` when tabular mode is enabled |
| `position_reorder.ranking` | No | `auto`, `supplied`, or `lexical`; defaults to `auto` |
| `window_fit.completion_reserve_tokens` | No | Defaults to `1024` |
| `window_fit.input_budget_tokens` | No | Positive explicit input-message budget, capped by known model capacity |

Unknown fields in the compression policy, profile, state, lever, tabular, or
summarizer blocks are rejected. Numeric validation runs at configuration load;
invalid values do not weaken a pipeline into a different default.

Summary content is sensitive. Metadata listing, optional audited inspection,
single-record deletion, and bounded purge are documented in the
[Admin API reference](admin-api-reference.md#ai-compression-session-state). Keep
`allow_admin_content_inspection: false` unless an audited operational workflow
requires content access. Do not operate on backend keys directly.

Metadata listing and purge use bounded pages and opaque cursors on both
backends: a Redis-backed store scans its shared Redis namespace, and a
mesh-backed store walks the replicated substrate's topology-safe fleet
pagination.

## Semantic cache interaction

Semantic-cache keys do not currently partition entries by compression
behavior. SBproxy therefore bypasses both semantic-cache implementations before
lookup whenever request-time selection could change the prompt. The same
decision prevents write-back after an upstream response.

| Policy and request | Semantic cache |
|---|---|
| Any explicit header, governed-key, or CEL selector | Bypassed for read and write |
| Route declares one or more named profiles | Bypassed for every request on that route |
| Route default contains `rag_select`, `compact_serialization`, or `position_reorder` | Bypassed for every request on that route |
| Route default uses `input_budget_tokens` | Bypassed for every request on that route |
| `summary_buffer` and captured session | Bypassed for read and write |
| Legacy default-only compatibility `window_fit` | Existing cache scope is unchanged |
| No compression policy | Existing cache scope is unchanged |

The conservative route-wide bypass for named profiles also applies when a
particular request selects `off` or the default. It closes cross-profile reuse
without adding a behavior partition to external semantic-cache interfaces.
An explicit selector bypasses even on a route that only has the default
pipeline. A retrieval-aware default bypasses because cache lookup currently
happens before compression. The legacy default-only path stays compatible
unless its stateful session rule requires a bypass.

This rule applies to the semantic cache. It does not disable the separate
idempotency middleware.

## Failure and degradation behavior

Compression runtime failures fail open at the lever boundary. They do not reject
the caller's AI request or roll back changes committed by earlier levers. A
failed lever preserves the message list it received, records a closed failure
reason, and lets later levers run. If no lever has applied, the original list
remains available to a later fallback such as `window_fit` or to upstream
dispatch.

Block- and chunk-local conditions become aggregate skip reasons only when no
other block or chunk changes. If any block or chunk changes, the lever returns
the complete candidate with all unchanged local data copied byte-for-byte. The
runner records `applied` when that candidate satisfies the lever's commit rule;
otherwise it records `skipped`, `no_savings`.

| Condition | Lever outcome | Request and state behavior |
|---|---|---|
| Missing captured session | `skipped`, `missing_session` | No state access; later levers run |
| No explicit retrieval block | `skipped`, `no_marked_context` | Current working messages continue; later levers run |
| Malformed or oversized marked context | `skipped`, `malformed_marked_context` or `marked_context_too_large` | The current retrieval lever makes no partial rewrite; later levers may still act |
| Supplied ranking lacks a score | `skipped`, `missing_relevance_score` when no other block changes | The affected retrieval block is unchanged; a change in another block yields a complete candidate |
| Selection retains no chunks with `drop_empty: false` | `skipped`, `no_selected_chunks` when no other block changes | The affected retrieval block is unchanged; a change in another block yields a complete candidate |
| Invalid JSON in a marked JSON chunk | `skipped`, `unsafe_structured_shape` only when no other chunk changes | The invalid chunk remains unchanged; a change in another chunk yields a candidate instead of the aggregate skip |
| Valid nested, heterogeneous, or otherwise table-ineligible JSON | `applied`; `skipped`, `not_needed`; or runner `skipped`, `no_savings` | Still eligible for deterministic JSON minification; shape alone is not unsafe |
| Chunks already have the edge order | `skipped`, `already_ordered` when no other block changes | Chunk bytes and order remain unchanged; a change in another block yields a complete candidate |
| Below threshold, insufficient history, unknown window, or no need | `skipped` when the lever produces no candidate | Working messages and state remain unchanged |
| Structured or multimodal material would be summarized | `skipped`, `structured_request` | Protected material is never sent to the summarizer |
| Stored digest does not match the incoming branch | `skipped`, `branch_mismatch` | Existing record is not reused or overwritten |
| Stored record reached its logical expiry | `skipped`, `state_expired` | Expired summary is not reused; Redis removes the record at its TTL |
| Update permit is contended | `skipped`, `lock_contended` | No unbounded wait; later levers run |
| Credential or budget denies internal summarization | `skipped`, `policy_denied` or `budget_denied` | No summarizer call and no state write |
| Summarizer input is too large | `skipped`, `summarizer_input_too_large` | No summarizer call and no state write |
| State load or commit is unavailable | `failed`, `state_unavailable` | Last committed messages continue; no local state fallback |
| Lease, fence, or logical version changed | `failed`, `lease_lost` or `stale_version` | Candidate is not committed to the request |
| Summarizer times out or provider fails | `failed`, `summarizer_timeout` or `summarizer_provider` | Last committed messages continue |
| Summary output is empty, malformed, or too large | `failed`, `invalid_summary` | No state write and no message replacement |
| Candidate violates its commit rule | `skipped`, `no_savings` | A strict lever must reduce the estimate; every lever rejects expansion |
| Protected prefix or newest protocol unit exceeds an explicit budget | `skipped`, `not_eligible` | The messages received by `window_fit` continue unchanged; earlier levers may already have committed changes |

Configuration errors are different from runtime degradation. A
`summary_buffer` without `compression.state`, an unavailable selected runtime
wiring, an invalid summarizer reference, or an invalid numeric constraint is
rejected at load or startup rather than silently weakened.

### Closed outcomes and reasons

Lever outcomes are `applied`, `skipped`, and `failed`. Applied outcomes use an
empty `reason` label. Skip reasons are:

`no_savings`, `not_eligible`, `not_needed`, `unknown_model_window`,
`missing_session`, `unsupported_request`, `below_threshold`,
`insufficient_history`, `structured_request`, `branch_mismatch`,
`state_expired`, `no_new_history`, `summarizer_input_too_large`, `budget_denied`,
`policy_denied`, `lock_contended`, `no_marked_context`,
`malformed_marked_context`, `marked_context_too_large`,
`missing_relevance_score`, `no_selected_chunks`, `unsafe_structured_shape`, and
`already_ordered`.

Failure reasons are:

`state_unavailable`, `lease_lost`, `stale_version`, `summarizer_timeout`,
`summarizer_provider`, `invalid_summary`, `serialization`, and `internal`.

The request outcome is failure-first:

- `failed` when any lever failed, even if a later lever applied.
- `applied` when at least one lever applied and none failed.
- `skipped` when every lever skipped.

## Metrics

All token measurements use the same target-model SBproxy counter at the runner
boundary. The strict levers apply only when `after_tokens < before_tokens`.
`position_reorder` can apply when the messages changed and
`after_tokens == before_tokens`; it reports zero saved tokens. Skipped and
failed levers also report zero. Known OpenAI model families use their
registered tokenizer. Other model names use the documented UTF-8 byte-length
fallback. Value reports expose this as
`token_count_precision: model_tokenizer` or `heuristic`; both values remain
estimates of the provider's eventual billed usage.

The arithmetic is exact relative to that shared estimate. For model families
without a dedicated tokenizer, the estimator uses its documented conservative
UTF-8 byte-length heuristic, not a Unicode character count. These metrics are
not reconciled to provider-reported usage after dispatch.

Per-lever savings can be summed safely because every applied lever starts from
the preceding committed output. At request scope,
`initial_tokens - final_tokens` is observed exactly once in
`sbproxy_ai_compression_request_tokens_saved`, so a two-lever request is not
double-counted in the request distribution.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sbproxy_ai_compression_lever_total` | Counter | `tenant_id`, `api_key_id`, `lever`, `outcome`, `reason`, `backend` | One row per lever invocation |
| `sbproxy_ai_compression_tokens_total` | Counter | `tenant_id`, `api_key_id`, `lever`, `direction` | Applied-lever tokens with `direction="input"` or `"output"` |
| `sbproxy_ai_compression_tokens_saved_total` | Counter | `tenant_id`, `api_key_id`, `lever` | Applied reduction in SBproxy's model-aware token estimate per lever |
| `sbproxy_ai_compression_ratio` | Histogram | `tenant_id`, `api_key_id`, `lever` | Applied `after_tokens / before_tokens` |
| `sbproxy_ai_compression_duration_seconds` | Histogram | `tenant_id`, `api_key_id`, `lever`, `outcome`, `backend` | Wall-clock duration of every lever invocation |
| `sbproxy_ai_compression_requests_total` | Counter | `tenant_id`, `api_key_id`, `outcome`, `backend`, `cache_bypass` | One row per executed non-empty compression pipeline |
| `sbproxy_ai_compression_selection_total` | Counter | `tenant_id`, `source`, `outcome` | Request policy resolutions with closed selection labels |
| `sbproxy_ai_compression_request_tokens_saved` | Histogram | `tenant_id`, `api_key_id`, `outcome`, `backend` | One initial-minus-final observation per request |
| `sbproxy_ai_compression_request_levers_run` | Histogram | `tenant_id`, `api_key_id`, `outcome`, `backend` | Number of configured levers executed per request |
| `sbproxy_ai_compression_state_operations_total` | Counter | `backend`, `operation`, `outcome` | External state operations |
| `sbproxy_ai_compression_state_operation_duration_seconds` | Histogram | `backend`, `operation`, `outcome` | External state operation latency |
| `sbproxy_ai_compression_redis_coordination_total` | Counter | `event` | Redis contention and rejected update events |
| `mesh_compression_coordination_total` | Counter | `event` | Mesh contention and rejected update events |
| `sbproxy_ai_compression_value_tokens_saved_total` | Counter | `tenant_id`, `origin`, `model`, `lever`, `token_count_precision` | Per-lever target-model input tokens avoided on terminal provider success |
| `sbproxy_ai_compression_value_cost_saved_micros_total` | Counter | `tenant_id`, `origin`, `model`, `lever`, `token_count_precision` | Gross target-model input cost avoided on terminal provider success, in micro-USD |

`lever` is `summary_buffer`, `window_fit`, `rag_select`,
`compact_serialization`, or `position_reorder`. `backend` is `redis`, `mesh`,
or `none`. Request `cache_bypass` is `true` or `false`. State `operation` is
`get`, `commit`, `delete`, `list`, or `purge`; its `outcome` is `ok`,
`missing`, or `error`.

Coordination `event` values are `contention`, `lease_expiry`,
`stale_version`, and `fence_rejection` on both coordination counters. On the
mesh counter, `contention` and the lease events describe worker-local permits,
and `stale_version` includes a deterministic loss to a concurrent
equal-version writer.

Value `token_count_precision` is `model_tokenizer` or `heuristic`. Selection
`source` is `header`, `governed_key`, `cel_policy`, or
`route_default`. Its outcome is `selected`, `disabled`, `default`,
`invalid_operator`, or `rejected`. The route-default selection is emitted when
the route has request-selectable or explicitly budgeted behavior; legacy
default-only routes do not gain a new hot-path metric solely from this change.

The `tenant_id` and public `api_key_id` label values pass through the shared
cardinality budget. Bearer credentials are never used as metric labels.

### PromQL examples

```promql
# Model-aware estimated tokens removed per second, split by lever
sum by (lever) (
  rate(sbproxy_ai_compression_tokens_saved_total[5m])
)

# P95 initial-to-final tokens saved per request, counted once
histogram_quantile(
  0.95,
  sum by (le, backend) (
    rate(sbproxy_ai_compression_request_tokens_saved_bucket[5m])
  )
)

# Failure-first request ratio
sum(rate(sbproxy_ai_compression_requests_total{outcome="failed"}[5m]))
/
clamp_min(sum(rate(sbproxy_ai_compression_requests_total[5m])), 0.000001)

# Lever skip and failure reasons
sum by (lever, outcome, reason, backend) (
  rate(sbproxy_ai_compression_lever_total{outcome=~"skipped|failed"}[5m])
)

# External state errors by backend and operation
sum by (backend, operation) (
  rate(sbproxy_ai_compression_state_operations_total{outcome="error"}[5m])
)

# Redis coordination pressure
sum by (event) (
  rate(sbproxy_ai_compression_redis_coordination_total[5m])
)

# Requests that conservatively bypassed the semantic cache
sum by (cache_bypass) (
  rate(sbproxy_ai_compression_requests_total[5m])
)

# Gross compression value delivered by successful provider requests
sum by (model, lever, token_count_precision) (
  rate(sbproxy_ai_compression_value_cost_saved_micros_total[5m])
) / 1000000
```

The bundled Prometheus recording rules and alerts include application rate,
failure ratio, P95 lever latency, saved-token rate, sustained compression
failures, and state rejections.

## Value accounting and Admin report

Compression savings become delivered value only after the terminal provider
attempt succeeds with a billable `2xx` response. A failed attempt, cache hit,
skipped lever, failed lever, or zero-token reduction does not add value. Each
applied reducing lever is recorded separately against the target model.
`position_reorder` is omitted from this value-only surface, including when its
non-expanding change applied successfully. Gross avoided cost prices the saved
input tokens at the target model's known input rate. An unknown rate keeps the
token saving and records zero cost instead of inventing a price. Internal
summarizer usage remains in the normal usage stream and is not subtracted from
this gross figure.

The authenticated endpoint `GET /admin/model-host/value` includes stable
`compression` rows by model and lever, aggregate `compression_totals`,
`total_compression_tokens_saved`, and
`total_compression_gross_cost_saved_micros`. Each compression row and each
per-lever `compression_totals` entry includes `token_count_precision`. The two
top-level totals can combine both precision classes. The local-serving
completion totals remain separate, so compression does not fabricate a local
or cloud completion.

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/model-host/value" \
  | jq '{compression,compression_totals,total_compression_tokens_saved,total_compression_gross_cost_saved_micros}'
```

The current durable path is the provider-level `serve:` compatibility form. A
`providers[].serve` block activates it when that same block contains at least
one `models[].reference` and sets `cache_dir`; the process-wide ledger then uses
`<cache_dir>/value-ledger.redb`. If compression already initialized the shared
ledger in memory, activation promotes that ledger object in place and atomically
merges its totals with existing redb rows, so existing value sinks and Admin
readers remain valid. The first successfully activated durable path is
canonical; a conflicting later path emits a bounded warning and continues on
the canonical ledger. `proxy.model_host.cache.directory` does not currently
activate value-ledger persistence. Without a qualifying block, compression
uses a bounded in-memory ledger.

The ledger keeps at most 1,000 model lanes total, including the deterministic
`__other__` overflow lane. Once 999 non-overflow model names have been admitted,
additional names aggregate into `__other__`; metric labels pass through the
normal cardinality budget. Neither surface contains prompt or summary content.

## Safe summary log event

Every executed non-empty pipeline emits one structured event with
`event="ai_compression_summary"` on the `ai_compression` tracing target.

An explicit header, governed-key, or CEL selection emits a separate
content-free event with `event="ai_compression_selection"`, `tenant_id`,
`source`, and `outcome`. Routes with named profiles or an explicit input budget
also emit that event for their route-default resolution because those routes
require semantic-cache separation. Legacy default-only routes without either
feature omit the selection event; an executed non-empty pipeline still emits
the summary event above. Rejected headers and invalid operator selectors add a
closed `reason`. The event never logs the selector text, bearer value, profile
contents, prompt, or summary.

| Request result | Level |
|---|---|
| Every lever skipped | `DEBUG` |
| At least one applied and none failed | `INFO` |
| Any lever failed | `WARN` |

The top-level fields are `event`, `tenant_id`, `api_key_id`, `outcome`,
`initial_tokens`, `final_tokens`, `tokens_saved`, `levers_run`,
`levers_applied`, `latency_ms`, `backend`, `consistency`, `cache_bypass`,
`selection_source`, `selection_outcome`, `lever_outcomes`, and `targets`.

`backend` is `redis` or `none`. The corresponding `consistency` value is
`serialized` or `none`.

`lever_outcomes` is a JSON-encoded list containing only `lever`, `outcome`,
`reason`, `backend`, `before_tokens`, `after_tokens`, `tokens_saved`, and
`duration_ms`. `targets` is a JSON-encoded list. A summary target contains
`lever`, `min_tokens`, `retain_recent_messages`, `target_summary_tokens`, and
`timeout_ms`; a window-fit target contains `lever` and
`completion_reserve_tokens`, plus `input_budget_tokens` when configured.
A RAG-selection target contains `lever`, `min_tokens`, `ranking`,
`max_chunks`, `min_relevance_percent`, and `drop_empty`. A compact-serialization
target contains `lever`, `min_tokens`, `tabular_enabled`, and
`tabular_min_rows`. A position-reorder target contains only `lever` and
`ranking`.

The event never contains message text, generated or prior summary content, raw
session IDs, record IDs, request bodies, provider credentials, bearer values,
queries, chunk identifiers, chunk bodies, supplied scores, source positions,
parse details, or other credential material. `api_key_id` is the sanitized
public credential identifier used for attribution, not a secret.

## Evaluation gate

The standalone harness at
`sbproxy-bench/harness/context_compression_eval` compares the real off and on
runner paths with the same target model and original message array. Its
committed fixtures are independently authored structural smoke evidence. They
report input, output, and saved tokens; deterministic structural quality;
closed outcomes; optional added latency; and a `build`, `borrow`, or `defer`
recommendation. They are not captured customer traffic, target-model
predictions, or evidence of answer quality on an external benchmark.

```bash
cd sbproxy-bench/harness/context_compression_eval
cargo nextest run --all-targets --locked

cargo run --locked -- check \
  --pipeline-config pipelines/rag-select-smoke.json \
  --input fixtures/rag-select-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/rag-select-smoke.json \
  --markdown-report reports/rag-select-smoke.md

cargo run --locked -- check \
  --pipeline-config pipelines/compact-serialization-smoke.json \
  --input fixtures/compact-serialization-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/compact-serialization-smoke.json \
  --markdown-report reports/compact-serialization-smoke.md

cargo run --locked -- check \
  --pipeline-config pipelines/position-reorder-smoke.json \
  --input fixtures/position-reorder-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/position-reorder-smoke.json \
  --markdown-report reports/position-reorder-smoke.md

cargo run --locked -- check \
  --pipeline-config pipelines/phase1-pipeline-smoke.json \
  --input fixtures/phase1-pipeline-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/phase1-pipeline-smoke.json \
  --markdown-report reports/phase1-pipeline-smoke.md

cargo run --locked -- check \
  --pipeline-config pipelines/window-fit-smoke.json \
  --input fixtures/ruler-smoke.jsonl \
  --input fixtures/coding-agent-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/window-fit-smoke.json \
  --markdown-report reports/window-fit-smoke.md
```

Those commands check all five committed JSON and Markdown report pairs. Each
pipeline file deserializes through the production typed lever configuration.
The structural scorers verify marked evidence retention, exact decoded JSON
values, and edge placement for named chunks. They do not run a provider, score
a generated answer, or infer semantic correctness beyond the authored fixture
assertions.

Adapters for RULER, HELMET, LongBench-v2, and NoLiMa are import-and-report-only.
They normalize operator-supplied contexts, references, and already generated
off/on predictions. The harness does not download those suites, run their
models, or claim an official benchmark score. Keep their data and licenses in
operator-managed storage, then use each project's official scorer for
published results. The harness README documents the interchange and provenance
manifest. The committed coding-agent shapes are independently authored and
sanitized; the repository does not describe them as production captures.

## Operational rollout

1. Start with `window_fit` and confirm model-window coverage and saved-token
   telemetry.
2. Add a named profile containing only `rag_select`. Send marked canary traffic
   and check required-evidence retention, selection rates, and closed skip
   reasons.
3. Test `compact_serialization` in its own profile. Decode sampled Table v1
   output in a controlled test and compare the exact JSON value.
4. Test `position_reorder` independently. Watch applied operations as well as
   token savings because a useful reorder can save zero tokens.
5. Combine `rag_select`, `compact_serialization`, `position_reorder`, and
   `window_fit` in the recommended order only after each lever's structural
   evidence and telemetry are understood. Widen the named profile gradually.
6. For stateful history, make callers send and reuse a stable captured session
   ULID, then validate the shared Redis L2 service on every replica.
7. Put `summary_buffer` before `window_fit` with conservative thresholds,
   recent-tail size, summary target, and timeout. Watch state errors, Redis
   coordination, request savings, and summarizer spend before widening it.
8. Use the authenticated Admin API for metadata, deletion, and purge. Leave
   content inspection disabled unless an audited incident workflow requires it.

To disable the new pipeline explicitly, set `compression.levers: []`. Existing
Redis records remain until their TTL expires; re-enabling the same policy before
expiry can reuse them. Metadata, delete, and purge remain available through the
Admin API as long as the global Redis L2 configuration remains present, even
when no active handler uses `summary_buffer`; content inspection stays disabled
without an active origin opt-in. To keep only stateless protection, remove
`summary_buffer`, its `state` block, and leave `window_fit` configured. A newly
committed summary refreshes its TTL, while an exact-summary reuse does not.

SBproxy has no OmniRoute runtime dependency, compatibility layer, state import,
or migration path for context compression. Configure SBproxy policies directly
and begin with fresh external summary state.

## See also

- [`examples/ai-context-compression-redis/`](../examples/ai-context-compression-redis/)
  for a runnable copy of this pipeline: start Redis, then `curl` the chat
  endpoint with a captured session ID to see the summary state persist across
  turns.
- [AI gateway guide](ai-gateway.md) for provider, policy, budget, cache, and
  routing behavior around the compression stage.
- [LLM-aware resilience](ai-llm-aware-resilience.md) for typed upstream
  failures and the legacy window-fit shorthand.
- [Dependency degradation matrix](degradation.md) for fleet-wide outage
  behavior.
- [Admin API reference](admin-api-reference.md#ai-compression-session-state) for
  summary-state operations.
- [Metric stability](metrics-stability.md) for the public Prometheus contract.
