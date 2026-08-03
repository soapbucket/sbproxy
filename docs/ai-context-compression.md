# AI context compression

*Last modified: 2026-08-02*

SBproxy can transform an AI chat request through an ordered, route-local
compression pipeline before provider selection and dispatch. A route can keep
one default pipeline and declare named profiles for different callers. Use
the retrieval-aware stateless levers for explicitly marked context. The
`query_select` lever keeps sentences related to the marked question.
`token_prune` can then use an operator-supplied LLMLingua-2-compatible ONNX
model to remove lower-value tokens. Finish with `window_fit` for a deterministic
input bound. Add `summary_buffer` when conversations need a compact running
summary. With no `state` block, `summary_buffer` uses a process-owned Local redb
database with a 24-hour TTL. Select Redis or mesh explicitly when summaries
must move between replicas.

This page is the canonical operator guide for compression configuration,
runtime behavior, state, degradation, and telemetry.

## Runtime contract

Each `ai_proxy` action can declare one `compression.levers` array. SBproxy runs
the entries in declaration order against one working message list:

1. A lever sees the output committed by earlier levers.
2. `summary_buffer`, `window_fit`, `token_prune`, `query_select`, `rag_select`,
   and `compact_serialization` replace the working list only when the candidate
   strictly reduces SBproxy's token estimate for the effective model.
   `position_reorder` may commit a changed, non-expanding candidate.
3. A skipped or failed lever leaves the working list unchanged.
4. Later levers still run after a skip or failure.
5. Provider routing and failover see only the final committed list.

For explicitly marked retrieval input, a useful quality-first order is
`query_select`, `token_prune`, then `window_fit`. Put `rag_select` before
`query_select` when the retriever returns many independent chunks. Run
`compact_serialization` only on structured chunks, which `token_prune` and
`query_select` deliberately skip. `query_select` already places the strongest
retained chunks at the block edges, so a following `position_reorder` is
usually redundant. Stateful chat history commonly uses `summary_buffer`
followed by `window_fit`. These can be separate named profiles on one route.

| Lever | State | Purpose | Typical position |
|---|---|---|---|
| `summary_buffer` | Local by default; explicit Redis or mesh | Replace eligible older text history with a bounded, incremental summary | First |
| `rag_select` | None | Retain the most relevant chunks in explicitly marked retrieval blocks | Before serialization |
| `query_select` | None | Retain query-related sentences and place the strongest retained chunks at block edges | Before token pruning |
| `token_prune` | None in SBproxy; ONNX model in the classifier sidecar | Remove lower-value source tokens from marked text chunks | After sentence selection |
| `compact_serialization` | None | Compact safe marked JSON and uniform scalar object rows | After selection |
| `position_reorder` | None | Move highly ranked chunks toward block edges | Before the final bound |
| `window_fit` | None | Apply the legacy newest-to-oldest message-selection heuristic within the known model window | Last |

Canonical session summaries are never held only in worker memory. Local state
survives a restart of the same process deployment through its redb file, but it
is not shared between replicas. Explicit Redis or mesh state allows a later
request to land on another replica.

The compression record key is an opaque digest over the tenant, normalized AI
origin, captured session ID, and a stable summary-policy fingerprint. The
fingerprint covers provider, model, threshold, retained-tail size, summary
target, state lifetime, fixed prompt text, record schema, and summary behavior
version. A policy or incompatible behavior change starts a separate lineage,
so mixed replicas cannot reuse each other's summaries. Raw session IDs and
original messages are not stored in the record.

## Marked retrieval context

`token_prune`, `query_select`, `rag_select`, `compact_serialization`, and
`position_reorder` inspect only string-valued `content` on `user` and `tool`
messages. Callers must mark the retrieval context explicitly. SBproxy does not
infer it from ordinary text, and it ignores marker-like strings in `system`,
`developer`, or `assistant` messages.

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

    - type: query_select
      max_sentences: 12

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

### Query-aware sentence selection

`query_select` uses the query already present in each marked retrieval block.
It segments every `format="text"` chunk into sentences, ranks the sentences
against that query with deterministic normalized TF-IDF, and keeps only
positive-scoring sentences. It makes no network call.

Choose exactly one bound:

```yaml
# Keep at most 12 sentences in each retrieval block.
- type: query_select
  max_sentences: 12

# Or bound selected sentence bodies by the target model's token estimate.
- type: query_select
  target_tokens: 2048
```

`max_sentences` accepts from 1 through 4,096. `target_tokens` accepts from 1
through 1,000,000. Each configured bound applies independently to each marked
block. In either mode, SBproxy processes at most 4,096 source sentences in one
block. A larger block skips the whole lever as `marked_context_too_large`
before ranking and leaves its input unchanged. The token form counts selected
sentence bodies, including one separator between sentences retained from the
same chunk. Retrieval tags and surrounding message text are outside that
target, and the runner still requires the complete message candidate to be
smaller.

Within a retained chunk, sentences return to their original source order.
Chunks are ranked by their strongest retained sentence and placed from the
outside inward, alternating between the beginning and end of the block. This
reduces lost-in-the-middle exposure without changing sentence wording.
Original chunk IDs remain attached to the selected text.

The lever skips ordinary unmarked input, malformed or oversized marked input,
blank queries, and non-text chunks. It also skips when no sentence has positive
lexical overlap with the query. A later `token_prune` or `window_fit` lever
still runs against the unchanged input.

### Sidecar token pruning

`token_prune` sends marked `format="text"` chunk bodies to the classifier
sidecar's `Compress` RPC. The sidecar runs an operator-supplied
LLMLingua-2-compatible token classifier and returns text assembled from source
spans. SBproxy validates the returned counts, checks that the text is
extractive, and remeasures the complete candidate before it can commit.

```yaml
- type: token_prune
  min_tokens: 512
  endpoint: http://127.0.0.1:9440
  model: llmlingua-2
  timeout_ms: 250
  max_chunks: 32
  target:
    mode: retain_ratio
    retain_percent: 60
```

`min_tokens` is the target model's estimate across all marked chunk bodies in
the request. Below it, the sidecar is not called. `max_chunks` limits sidecar
calls per request. It defaults to 64 and accepts values from 1 through 256.
`timeout_ms` applies to each call, accepts from 1 through 60,000, and defaults
to 250.
Connections are lazy and shared by the compiled route. A Unix socket is also
accepted, for example `unix:///run/sbproxy/classifier.sock`; the socket path
must be absolute.

The target has two exclusive forms:

```yaml
# Retain 60 percent of each chunk according to the pruning tokenizer.
target:
  mode: retain_ratio
  retain_percent: 60

# Fit all marked bodies within 2,048 target-model tokens.
target:
  mode: target_tokens
  target_tokens: 2048
```

`retain_percent` accepts from 1 through 99. In ratio mode, the sidecar applies
the percentage to each chunk using its pruning tokenizer. SBproxy then counts
each returned chunk with the request's target model and rejects any chunk over
the same percentage of its original target-model estimate. In `target_tokens`
mode, SBproxy divides the aggregate budget across chunks in proportion to their
target-model estimates, sends those allocations to the sidecar, then counts
all returned bodies again with the request's target model. The lever fails
open when either target check fails. Each chunk needs an allocation of at
least one token. If `target_tokens` is smaller than the marked chunk count, the
lever skips as `not_eligible` without calling the sidecar.

All marked chunks in the current request must use `format="text"`. The lever
does not send JSON or `sbproxy_table_v1` to the model. It also skips when the
marked fanout exceeds `max_chunks`. A timeout, unavailable sidecar, unknown
sidecar model, or invalid response records a closed lever failure and preserves
the messages received by the lever. Later levers continue, so `window_fit`
remains a dependency-free final bound.

The runtime submits batch size 1. A compatible ONNX model may declare that
batch axis as fixed `1`, symbolic, or unspecified, and must emit `f32` logits
whose final dimension is `2`. Class index 1 is the probability that a source
token should be retained. The tokenizer must provide source offsets and word
IDs. The sidecar averages subtoken scores into whole-word decisions and
divides longer input at punctuation-aware boundaries. Model IDs are limited
to 256 UTF-8 bytes. The matching tokenizer must use the official mBERT
WordPiece or XLM-R Unigram LLMLingua-2 layout, add exactly two model special
tokens, and contain no non-special added tokens. See
[Local inference](local-inference.md#run-token-pruning) for the model command
and isolation guidance.

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
JSON containing duplicate object member names at any nesting depth is unsafe:
the lever leaves that chunk byte-for-byte unchanged instead of parsing it into
a value that would silently discard one member.
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
has its own `levers` and optional `state` backend; stateful profiles default to
the process-local durable backend when `state` is omitted. Profile names
contain from 1 to 64 bytes, start with a lowercase ASCII letter or digit, and
then use only lowercase ASCII letters, digits, `_`, or `-`. The reserved values
`on` and `off` cannot be profile names.

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
  during the short interval before the selected backend physically removes it.
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

## Local state (default)

A default or named pipeline that contains `summary_buffer` and omits `state`
is normalized independently to:

```yaml
state:
  backend: local
  ttl: 24h
```

An explicit `backend: local` uses the same adapter and requires an explicit
positive `ttl`. Explicit Redis and mesh choices stay on the selected backend;
an unavailable dependency is a startup error and never falls back to Local.
Pipelines containing only stateless levers such as `rag_select` do not open or
create a Local database.

`proxy.compression_state.local_path` may pin the process database:

```yaml
proxy:
  compression_state:
    local_path: /var/lib/sbproxy/compression-state.redb
```

The explicit path must be absolute, nonempty, no longer than 4096 bytes, and
contain no control characters. Configuration validation checks this string
contract without touching the filesystem. Runtime startup then selects the
path in this exact order:

1. `proxy.compression_state.local_path`, when configured.
2. `/var/lib/sbproxy/compression-state.redb` when `/var/lib/sbproxy` is
   writable.
3. `$XDG_STATE_HOME/sbproxy/compression-state.redb`.
4. On macOS,
   `$HOME/Library/Application Support/sbproxy/compression-state.redb`.
5. On other Unix systems,
   `$HOME/.local/state/sbproxy/compression-state.redb`.

Only absolute XDG and home paths participate. Windows requires an explicit
path. Startup fails when a required Local database cannot be selected or
opened, and the error names the selected path.
An existing Local database may still be opened for Admin lifecycle operations
after every Local `summary_buffer` policy is removed; a missing dormant path is
never created just for Admin.

Local is a one-process durability boundary. Do not place its file on a shared
network mount or point several SBproxy processes at it; use Redis or mesh for a
fleet. Within one process, redb transactions, persisted leases, monotonic
fences, and logical-version compare-and-set serialize updates. A
crash-held lease expires after its bounded lease time (the summarizer timeout
plus the fixed state-operation margin), and the next process can continue.
Every redb operation runs on Tokio's blocking pool rather than an async request
worker. Local reports `consistency="serialized"`.

The redb file stores generated summary text in plaintext. Protect the file,
parent directory, snapshots, and backups with OS permissions and storage
encryption appropriate for prompt data. Admin list responses remain
content-free, and the content endpoint still requires Admin authorization,
handler opt-in, and a successful audit write. TTL expiry, delete, and purge
make records unavailable, but redb may retain freed pages for reuse instead of
shrinking the file immediately; capacity should be planned around the file's
high-water allocation.

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

## Choosing a state backend

`compression.state.backend` accepts `local`, `redis`, and `mesh`. Omitted state
on a `summary_buffer` pipeline means Local with a 24-hour TTL. Choose Redis for
serialized cross-process updates, or mesh for a Redis-free fleet that already
runs `proxy.cluster.replication` and can accept eventual consistency.

The contracts are different; do not treat them as interchangeable:

| Property | `local` | `redis` | `mesh` |
|---|---|---|---|
| External dependency | One process-owned redb file | Redis service via `proxy.l2_cache_settings` | None beyond `proxy.cluster.replication` |
| Update serialization | Persisted lease and fence for one process database | Distributed lease and fence across all workers | Worker-local lease only; cross-node writers race |
| Compare-and-set | Atomic redb write transaction | Atomic inside one Lua script | Conditional put with read-back verification |
| Concurrent equal-version writers | Serialized or rejected before commit | Blocked by the lease or rejected before writing | Deterministic last-writer-wins merge; the loser fails with a stale-version error, the survivor is flagged `conflict_detected` |
| Reported consistency | `serialized` | `serialized` | `eventual_lww` |
| Durability | Same-node process restarts at the selected path | Redis persistence configuration | `factor` replicated copies, quorum acknowledgements, redb shards under `state_dir` |
| Fleet behavior | Not shared; use one file from one process | Shared across Redis clients | Replicated and convergent across mesh nodes |

Enabling Redis or cluster replication by itself changes nothing here. An
explicit backend always remains on that backend, while omitted state on a
stateful summary pipeline always selects Local. A policy containing no
`summary_buffer` remains stateless and creates no Local database.

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
  by acknowledgment-aware garbage collection, so a deleted summary does not
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
| `compression.state` | No | A pipeline with `summary_buffer` defaults independently to Local state with a 24-hour TTL; stateless pipelines keep no state |
| `compression.state.backend` | In an explicit `state` block | `local`, `redis`, or `mesh`; explicit choices never fall back |
| `compression.state.ttl` | In an explicit `state` block | Positive seconds or human duration |
| `compression.allow_admin_content_inspection` | No | Default `false`; enables audited Admin-only content inspection for configured origins |
| `compression.levers` | No | Ordered list; an explicit empty list disables compression |
| `compression.profiles` | No | Route-local map of named pipelines selectable by a request, governed key, or CEL |
| `compression.profiles.<name>.state` | No | Defaults independently to Local/24h when that profile contains `summary_buffer`; never inherits route state |
| `compression.profiles.<name>.levers` | No | Ordered levers for this named profile; an empty list selects no runtime |
| `summary_buffer.min_tokens` | Yes | Greater than zero |
| `summary_buffer.retain_recent_messages` | Yes | Greater than zero |
| `summary_buffer.target_summary_tokens` | Yes | Greater than zero and smaller than `min_tokens` |
| `summary_buffer.summarizer.provider` | Yes | Enabled provider on the same handler |
| `summary_buffer.summarizer.model` | Yes | Non-empty model allowed by the handler and configured provider |
| `summary_buffer.summarizer.timeout` | Yes | Positive seconds or human duration |
| `token_prune.min_tokens` | Yes | Greater than zero; minimum target-model estimate across marked bodies before a sidecar call |
| `token_prune.endpoint` | Yes | Classifier gRPC URI or `unix://` plus an absolute socket path |
| `token_prune.model` | Yes | Non-empty token model ID loaded by the sidecar; at most 256 UTF-8 bytes |
| `token_prune.timeout_ms` | No | Defaults to `250`; from `1` through `60000`, applied per chunk |
| `token_prune.max_chunks` | No | Defaults to `64`; from `1` through `256` |
| `token_prune.target` | Yes | Exactly one tagged target: `mode: retain_ratio` with `retain_percent`, or `mode: target_tokens` with `target_tokens` |
| `token_prune.target.retain_percent` | For ratio mode | From `1` through `99` |
| `token_prune.target.target_tokens` | For token mode | From `1` through `1000000`; aggregate marked-body target measured again with the request model |
| `query_select.max_sentences` | One query bound is required | From `1` through `4096`; mutually exclusive with `target_tokens` |
| `query_select.target_tokens` | One query bound is required | From `1` through `1000000`; mutually exclusive with `max_sentences` |
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

Metadata listing and purge use bounded pages and opaque cursors on all
backends. Local performs a bounded metadata-only redb scan, Redis scans its
shared namespace, and mesh walks the replicated substrate's topology-safe
fleet pagination.

## Semantic cache interaction

Semantic-cache keys do not currently partition entries by compression
behavior. SBproxy therefore bypasses both semantic-cache implementations before
lookup whenever request-time selection could change the prompt. The same
decision prevents write-back after an upstream response.

| Policy and request | Semantic cache |
|---|---|
| Any explicit header, governed-key, or CEL selector | Bypassed for read and write |
| Route declares one or more named profiles | Bypassed for every request on that route |
| Route default contains `token_prune`, `query_select`, `rag_select`, `compact_serialization`, or `position_reorder` | Bypassed for every request on that route |
| Route default uses `input_budget_tokens` | Bypassed for every request on that route |
| `summary_buffer` and captured session | Bypassed for read and write |
| Supported chat surface with a non-`off` reasoning policy | Bypassed for read and write |
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
| No explicit retrieval block | `query_select`: `skipped`, `missing_query`; other marked-context levers: `skipped`, `no_marked_context` | Current working messages continue; later levers run |
| Malformed marked context, parser limits, or more than 4,096 source sentences in one `query_select` block | `skipped`, `malformed_marked_context` or `marked_context_too_large` | The current retrieval lever makes no partial rewrite; later levers may still act |
| Query is blank or no sentence has positive lexical overlap | A blank query is `skipped`, `malformed_marked_context`; no positive overlap is `skipped`, `no_selected_chunks` when no other block changes | The affected block stays unchanged; later levers run |
| Token-prune marked-body estimate is below `min_tokens` | `skipped`, `below_threshold` | No sidecar call; later levers run |
| Token-prune chunk count exceeds `max_chunks` | `skipped`, `marked_context_too_large` | No sidecar call or partial rewrite; later levers run |
| Token-prune `target_tokens` is smaller than the marked chunk count | `skipped`, `not_eligible` | No sidecar call; later levers run |
| Token-prune sidecar is unavailable or times out | `failed`, `token_prune_unavailable` | Current messages continue unchanged; later levers run |
| Token-prune response is empty, non-extractive, over target, or has invalid counts | `failed`, `invalid_token_prune_output` | Candidate is discarded; later levers run |
| Supplied ranking lacks a score | `skipped`, `missing_relevance_score` when no other block changes | The affected retrieval block is unchanged; a change in another block yields a complete candidate |
| Selection retains no chunks with `drop_empty: false` | `skipped`, `no_selected_chunks` when no other block changes | The affected retrieval block is unchanged; a change in another block yields a complete candidate |
| Invalid JSON in a marked JSON chunk | `skipped`, `unsafe_structured_shape` only when no other chunk changes | The invalid chunk remains byte-for-byte unchanged; a change in another chunk yields a candidate instead of the aggregate skip |
| Duplicate object members in a marked JSON chunk | `skipped`, `unsafe_structured_shape` only when no other chunk changes | The duplicate-bearing chunk remains byte-for-byte unchanged at every nesting depth; a change in another chunk yields a candidate instead of the aggregate skip |
| Valid nested, heterogeneous, or otherwise table-ineligible JSON | `applied`; `skipped`, `not_needed`; or runner `skipped`, `no_savings` | Still eligible for deterministic JSON minification; shape alone is not unsafe |
| Chunks already have the edge order | `skipped`, `already_ordered` when no other block changes | Chunk bytes and order remain unchanged; a change in another block yields a complete candidate |
| Below threshold, insufficient history, unknown window, or no need | `skipped` when the lever produces no candidate | Working messages and state remain unchanged |
| Structured or multimodal material would be summarized | `skipped`, `structured_request` | Protected material is never sent to the summarizer |
| Stored digest does not match the incoming branch | `skipped`, `branch_mismatch` | Existing record is not reused or overwritten |
| Stored record reached its logical expiry | `skipped`, `state_expired` | Expired summary is not reused; the selected backend removes or hides it at its TTL |
| Update permit is contended | `skipped`, `lock_contended` | No unbounded wait; later levers run |
| Credential or budget denies internal summarization | `skipped`, `policy_denied` or `budget_denied` | No summarizer call and no state write |
| Summarizer input is too large | `skipped`, `summarizer_input_too_large` | No summarizer call and no state write |
| State load or commit is unavailable | `failed`, `state_unavailable` | Last committed messages continue; no backend substitution occurs |
| Lease, fence, or logical version changed | `failed`, `lease_lost` or `stale_version` | Candidate is not committed to the request |
| Summarizer times out or provider fails | `failed`, `summarizer_timeout` or `summarizer_provider` | Last committed messages continue |
| Summary output is empty, malformed, or too large | `failed`, `invalid_summary` | No state write and no message replacement |
| Candidate violates its commit rule | `skipped`, `no_savings` | A strict lever must reduce the estimate; every lever rejects expansion |
| Protected prefix or newest protocol unit exceeds an explicit budget | `skipped`, `not_eligible` | The messages received by `window_fit` continue unchanged; earlier levers may already have committed changes |

Configuration errors are different from runtime degradation. An unavailable
explicit Redis or mesh dependency, an unopenable required Local path, an
invalid summarizer reference, or an invalid numeric constraint is rejected at
load or startup rather than silently weakened. Omitting state for
`summary_buffer` is valid and selects Local/24h.

### Closed outcomes and reasons

Lever outcomes are `applied`, `skipped`, and `failed`. Applied outcomes use an
empty `reason` label. Skip reasons are:

`no_savings`, `not_eligible`, `not_needed`, `unknown_model_window`,
`missing_session`, `unsupported_request`, `below_threshold`,
`insufficient_history`, `structured_request`, `branch_mismatch`,
`state_expired`, `no_new_history`, `summarizer_input_too_large`, `budget_denied`,
`policy_denied`, `lock_contended`, `no_marked_context`,
`malformed_marked_context`, `marked_context_too_large`,
`missing_query`, `missing_relevance_score`, `no_selected_chunks`,
`unsafe_structured_shape`, and `already_ordered`.

Failure reasons are:

`state_unavailable`, `lease_lost`, `stale_version`, `summarizer_timeout`,
`summarizer_provider`, `invalid_summary`, `token_prune_unavailable`,
`invalid_token_prune_output`, `serialization`, and `internal`.

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

`lever` is `summary_buffer`, `window_fit`, `token_prune`, `query_select`,
`rag_select`, `compact_serialization`, or `position_reorder`. `backend` is
`local`, `redis`, `mesh`, or `none`. Request `cache_bypass` is `true` or
`false`. State `operation` is `get`, `commit`, `delete`, `list`, or `purge`;
its `outcome` is `ok`, `missing`, or `error`.

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

`backend` is `local`, `redis`, `mesh`, or `none`. The corresponding
`consistency` value is `serialized`, `eventual_lww`, or `none`.

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
`ranking`. A query-selection target contains `lever` and exactly one of
`max_sentences` or `target_tokens`. A token-pruning target contains `lever`,
`min_tokens`, `model`, `timeout_ms`, `max_chunks`, and its tagged target. The
sidecar endpoint is deliberately absent from this event.

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
  --pipeline-config pipelines/query-select-smoke.json \
  --input fixtures/query-select-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/query-select-smoke.json \
  --markdown-report reports/query-select-smoke.md

cargo run --locked -- check \
  --pipeline-config pipelines/token-prune-retain-smoke.json \
  --input fixtures/token-prune-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/token-prune-retain-smoke.json \
  --markdown-report reports/token-prune-retain-smoke.md

cargo run --locked -- check \
  --pipeline-config pipelines/token-prune-target-smoke.json \
  --input fixtures/token-prune-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/token-prune-target-smoke.json \
  --markdown-report reports/token-prune-target-smoke.md

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

Those commands check all eight committed JSON and Markdown report pairs. Each
pipeline file deserializes through the production typed lever configuration.
Report schema 4 embeds the exact verified provenance-manifest SHA-256 and the
metadata for only the selected fixture inputs, including their fixture
digests, origin, license, customer-data declaration, and official-score
declaration. That keeps the evidence boundary attached when a report is copied
away from the repository.
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
3. Test `query_select` against a labeled multi-document question set. Check
   answer evidence as well as token savings, then tune one sentence or token
   bound.
4. Run `token_prune` in a separate profile. Start the classifier sidecar with
   an operator-reviewed model, choose a conservative retain ratio, and watch
   both `token_prune_unavailable` and `invalid_token_prune_output`.
5. Test `compact_serialization` in its own profile. Decode sampled Table v1
   output in a controlled test and compare the exact JSON value.
6. Test `position_reorder` independently. Watch applied operations as well as
   token savings because a useful reorder can save zero tokens.
7. Combine the levers only after each one has passed its own quality check.
   Keep `window_fit` last so an unavailable sidecar cannot remove the final
   deterministic bound.
8. For stateful history, make callers send and reuse a stable captured session
   ULID. Start with the Local default on one process; configure Redis or mesh
   explicitly before distributing sessions across replicas.
9. Put `summary_buffer` before `window_fit` with conservative thresholds,
   recent-tail size, summary target, and timeout. Watch state errors,
   coordination when applicable, request savings, and summarizer spend before
   widening it.
10. Use the authenticated Admin API for metadata, deletion, and purge. Leave
   content inspection disabled unless an audited incident workflow requires it.

To disable the new pipeline explicitly, set `compression.levers: []`. Existing
records remain until their TTL expires; re-enabling the same policy before
expiry can reuse them. Metadata, delete, and purge remain available while the
selected external backend is configured. An existing Local database is retained
for Admin discovery without creating a missing file, even when no active
handler uses `summary_buffer`; content inspection stays disabled without an
active origin opt-in. To keep only stateless protection, remove
`summary_buffer` and its `state` block, then leave `query_select`,
`token_prune`, `rag_select`, `window_fit`, or the other stateless levers
configured. A stateless-only process does not create a Local database. A newly
committed summary refreshes its TTL, while an exact-summary reuse does not.

SBproxy has no OmniRoute runtime dependency, compatibility layer, state import,
or migration path for context compression. Configure SBproxy policies directly
and begin with fresh external summary state.

## See also

- [`examples/ai-context-optimization/`](../examples/ai-context-optimization/)
  for a stateless `query_select`, `token_prune`, and `window_fit` pipeline with
  a marked multi-document request.
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
