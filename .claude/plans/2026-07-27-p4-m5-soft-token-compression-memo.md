# P4 M5 spike: soft-token compression on owned weights

Ticket: WOR-1934 (Backlog, Priority 4). AC: a feasibility memo with a
recommended candidate and an effort estimate.

## Why this only matters when we host the model

Soft-token compression replaces a long text span with a small number of
learned embedding vectors that are not decodable back to text, produced by
an adapter trained against the base model's own weights. That adapter has
to be trained per base model (or per model family) and loaded into the
same forward pass as the model doing generation. Both requirements only
resolve when sbproxy owns the model process, which for this codebase means
the managed vLLM/llama.cpp local-serving path, not the proxy path in front
of a closed API. This is the one compression lever in the whole P4 menu
that is a genuine product differentiator rather than a client-side
prompt-engineering trick, because a closed-API vendor is never going to
expose "accept a batch of opaque embedding vectors instead of tokens" on
their public API.

## Candidates

- **ICAE** (2307.06945, In-Context Autoencoder): trains a LoRA-style
  encoder adapter that compresses a context window into a small set of
  "memory slots," decoded by the same frozen base LLM. ~4x compression
  reported at near-lossless downstream task performance. Training cost is
  modest (LoRA-scale, not full fine-tune) because the decoder is frozen.
- **500xCompressor** (2408.03094): pushes compression far higher (down to
  a handful of tokens for a full document) at the cost of a heavier
  encoder and a training recipe. The name is the pitch and also the risk:
  compression that extreme trades away recall on parts of the context.
- **Gisting** (2304.08467): compresses fixed instruction/system prompts
  into "gist tokens" learned once per prompt, cached and reused across
  requests. Narrower scope than ICAE (works well for a static system
  prompt, not an arbitrary long user context) but correspondingly cheaper
  to train and simpler to cache.
- **Cartridges** (2506.06266) and **KV-Distill** (2503.10337): both target
  compressing a document into a reusable artifact closer to the KV cache
  itself than to input tokens (a "trained KV cache" rather than trained
  embeddings), meant to be computed once per corpus and reused across many
  queries against it.
- **Concise & Precise** (2407.02043): the tool-schema-specific case of the
  same idea, compressing a verbose JSON tool schema into soft tokens.
  Narrow but directly relevant if sbproxy's MCP tool-definition payloads
  ever become a measured context-budget cost for self-hosted deployments.

## Reuse and caching story

The methods split into two shapes that need different caching designs:
- **Per-prompt-class** (Gisting, Concise & Precise): the compressed
  representation is a function of the prompt template, not the specific
  request. Compute once per template version, cache keyed on a hash of the
  template, reuse indefinitely. Cheapest to build and closest to sbproxy's
  existing prompt-cache-adjacent work (`enable_prefix_caching`, this
  workstream).
- **Per-corpus** (Cartridges, KV-Distill, and ICAE/500xCompressor at the
  long-document end): the compressed representation is a function of the
  specific document or corpus. Needs a cache keyed on document content
  hash, an eviction policy, and a decision about whether compression runs
  eagerly (on ingest) or lazily (on first request referencing that
  document) -- structurally the same shape as the existing artifact cache
  in `artifact/cache.rs`, just caching a derived tensor artifact instead
  of a downloaded one.

## Recommendation

**Candidate: Gisting**, for a first prototype. It has the narrowest scope
(compressing a fixed, operator-configured system/tool prompt rather than
arbitrary user context), the cheapest training recipe, and the caching
story is per-template rather than per-corpus, which reuses the same
content-addressed-cache pattern already proven in this crate rather than
requiring a new per-document cache subsystem. It is also the shape of
compression sbproxy's own MCP tool-definition payloads would benefit from
most directly, since those are exactly "large, mostly-static, prepended to
every request" context.

ICAE is the better long-term target once Gisting is proven, since it
generalizes to arbitrary user-supplied context rather than only
operator-configured static prompts, but it needs a heavier training and
per-corpus caching investment that is not justified until Gisting has
validated the training-adapter-per-model operational model end to end.

## Effort estimate

Rough order of magnitude, not a committed plan:
- Training a Gisting-style adapter for one base model family (e.g. one
  Qwen3 size): 1-2 weeks, most of it data/eval harness work rather than
  the adapter training itself, which is cheap (LoRA-scale).
- Serving integration (loading the adapter alongside the base model in
  vLLM, wiring gist-token caching by prompt-template hash): 1 week, mostly
  in `sbproxy-model-host`'s launch/config path, following the
  `lora_adapters` precedent already shipped for regular LoRA.
- Total for a first working prototype against one model family: roughly
  3-4 weeks. Extending to additional model families is mostly the training
  step repeated, not new serving-integration work.

This is a real investment, not a spike; recommend re-scoping as its own
epic if greenlit rather than absorbing it into this Phase 4 spike ticket.
