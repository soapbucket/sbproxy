# ADR: AI gateway hub format and the `ChatFormat` trait
*Last modified: 2026-05-12*

Status: proposed. Drives WOR-224 (hub `ChatFormat` trait + `/v1/messages` + `/v1/responses` inbound).

## Context

SBproxy's AI gateway today accepts the OpenAI `POST /v1/chat/completions` shape from clients and either passes it through (OpenAI-compatible upstreams: Groq, Together, DeepSeek, Mistral, Perplexity, OpenRouter, vLLM, Ollama) or hands it to a per-provider translator that rewrites request and response bytes (Anthropic Messages today; Gemini and Bedrock left as TODO in `crates/sbproxy-ai/src/translators/mod.rs:36`). The translator API is two free functions, `translate_request` and `translate_response`, branching on a small `ProviderFormat` enum.

That worked while the only inbound shape was OpenAI chat-completions and the only translated upstream was Anthropic. It does not generalize.

Operators are already asking for two more inbound shapes:

1. `POST /v1/messages` (the Anthropic Messages shape, so the Anthropic SDK and Claude Code can point at SBproxy directly).
2. `POST /v1/responses` (the OpenAI Responses API, which the OpenAI Python and TypeScript SDKs are migrating to).

And five outbound shapes are in scope:

1. OpenAI (and every OpenAI-compatible upstream).
2. Anthropic Messages.
3. Google Gemini and Vertex AI (same wire, two transports).
4. AWS Bedrock InvokeModel / Converse.
5. Custom (per-provider plugin, owned by the operator).

Three inbound shapes times five outbound shapes is fifteen translation pairs. Building each pair by hand would mean fifteen code paths, fifteen test matrices, and fifteen places where a new tool-call field has to be threaded. We have already seen the cost in miniature: the existing Anthropic translator strips seven OpenAI-only fields, hoists `system` messages, defaults `max_tokens`, and rewrites a path; adding a Gemini translator in the same style would duplicate ninety percent of that code.

The cost shows up most clearly in three places.

First, streaming. SSE event shapes differ for every provider. OpenAI emits `delta.content` chunks; Anthropic emits `event: content_block_delta` with a JSON-Patch-like body; Bedrock wraps everything in an AWS event-stream envelope with `:event-type` headers; Gemini emits its own `streamGenerateContent` shape. A per-pair translator means writing the same stream demuxer N times.

Second, observability. We want to emit OpenInference / OTel GenAI spans that name the model, tokens, tools, and finish reason regardless of inbound or outbound format. With per-pair translators we either repeat the extraction logic per translator or add a parallel "extract telemetry from raw bytes" code path.

Third, guardrails. The prompt-injection classifier, PII redactor, response-cache key, semantic cache, cost router, and budget gate all need a stable view of "what the user said" and "what the model said." Today those features only see the inbound OpenAI shape; they will go blind the moment the inbound is Anthropic Messages.

The hub format solves all three by collapsing N times M into N plus M. Every inbound parser writes into one canonical Rust value; every outbound emitter reads from the same canonical Rust value; everything in between (telemetry, guardrails, caching, routing) speaks one shape.

## Decision

We will introduce a `ChatFormat` trait under `crates/sbproxy-ai/src/format/` that owns translation in both directions, and a canonical `ChatRequest` / `ChatResponse` pair that every translator round-trips through. Each format implements the same trait twice over: once as an inbound parser (bytes from the client become a `ChatRequest`) and once as an outbound emitter (a `ChatRequest` becomes bytes for the upstream). Streaming follows the same pattern with `ChatEvent` chunks.

The pseudo-Rust surface is short on purpose. The trait is the contract the whole pipeline depends on, so the smaller it is the fewer places have to change when we add a sixth provider.

```rust,ignore
// crates/sbproxy-ai/src/format/mod.rs

/// A bidirectional translator between a wire format and the hub.
///
/// Implementors are stateless and cheap to construct; the gateway
/// holds one instance per registered format inside a registry.
pub trait ChatFormat: Send + Sync + 'static {
    /// Stable identifier used in config and logs (`openai`,
    /// `anthropic`, `gemini`, `bedrock`, `responses`).
    fn id(&self) -> &'static str;

    /// Inbound path this format claims (`/v1/chat/completions`,
    /// `/v1/messages`, `/v1/responses`). Returned as a slice because a
    /// format may claim several paths (Bedrock has both
    /// `InvokeModel` and `Converse`).
    fn inbound_paths(&self) -> &'static [&'static str];

    // --- Request direction ---

    /// Parse client bytes on an inbound path into the hub request.
    /// Errors here are HTTP 400 to the client: malformed JSON, missing
    /// required fields, an unsupported feature the format cannot
    /// represent in the hub at all.
    fn parse_request(&self, bytes: &[u8]) -> Result<ChatRequest, ChatError>;

    /// Emit upstream bytes for the hub request, plus the upstream
    /// path. Returned path is the path the AI client should hit on the
    /// upstream (Anthropic rewrites to `/v1/messages`; OpenAI keeps
    /// `/v1/chat/completions`).
    fn emit_request(&self, req: &ChatRequest) -> Result<EmittedRequest, ChatError>;

    // --- Response direction ---

    /// Parse a non-streaming upstream response body into the hub
    /// response.
    fn parse_response(&self, bytes: &[u8]) -> Result<ChatResponse, ChatError>;

    /// Emit the hub response back to the client in this format's
    /// wire shape.
    fn emit_response(&self, resp: &ChatResponse) -> Result<Vec<u8>, ChatError>;

    // --- Streaming ---

    /// Parse a single SSE frame (the bytes between two blank lines)
    /// into zero or more hub events. A single upstream frame can
    /// expand to several hub events (Anthropic's `message_start`
    /// frame emits both `MessageStart` and a first `Usage` event).
    fn parse_event(&self, frame: &SseFrame) -> Result<Vec<ChatEvent>, ChatError>;

    /// Emit hub events back to the client as SSE frames. The
    /// translator owns terminator framing (`data: [DONE]` for OpenAI,
    /// `event: message_stop` for Anthropic).
    fn emit_event(&self, ev: &ChatEvent) -> Result<Vec<SseFrame>, ChatError>;
}

pub struct EmittedRequest {
    pub path: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>, // `anthropic-version`, etc.
}
```

The trait makes four deliberate choices.

First, parse-and-emit are separate methods, not a single round-trip. The pipeline often parses on one format and emits on another; baking that asymmetry into the trait means there is no temptation to write a "translator" that only works for one direction.

Second, the trait is bytes-in / bytes-out at the edges and a typed `ChatRequest` / `ChatResponse` in the middle. That keeps wire formats out of the rest of the codebase: telemetry, guardrails, and cache code never look at raw JSON.

Third, streaming is opaque-frame in, hub-event out, not "parse the whole stream." A frame is the unit Pingora's response body filter sees, and the SSE framing layer (`event:` / `data:` / blank line) is identical across providers. Only the payload differs.

Fourth, `ChatError` is the formats' error type, with HTTP status carried inline. Format errors map directly to client errors; transport errors are caught upstream and never reach the format layer.

## Hub format shape

The hub `ChatRequest` and `ChatResponse` shape are deliberately close to the OpenAI chat-completions JSON shape. OpenAI's chat-completions is the closest existing shape to a lowest common denominator: it has roles, message-level content arrays, tool calls, tool results, finish reasons, usage tokens, and streaming deltas, and every other provider's shape can be projected into it without losing the load-bearing fields.

```rust,ignore
// crates/sbproxy-ai/src/format/types.rs

pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolDefinition>,
    pub tool_choice: ToolChoice,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,        // hub keeps it even though OpenAI lacks it
    pub stop: Vec<String>,
    pub stream: bool,
    pub system: Option<String>,    // hoisted out of messages on parse
    pub metadata: ChatMetadata,    // request id, user id, workspace id
    pub extensions: BTreeMap<String, Value>, // see below
}

pub struct ChatMessage {
    pub role: Role,                // System | User | Assistant | Tool
    pub content: Vec<ContentPart>,
    pub name: Option<String>,
    pub tool_call_id: Option<String>, // set when role == Tool
}

pub enum ContentPart {
    Text { text: String },
    Image { source: ImageSource, media_type: String },
    ToolUse { id: String, name: String, input: Value },
    ToolResult { tool_call_id: String, content: String, is_error: bool },
}

pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value, // typed JSON, not the OpenAI string-of-JSON
}

pub struct ChatResponse {
    pub id: String,
    pub model: String,
    pub content: Vec<ContentPart>,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: FinishReason,
    pub usage: Usage,
    pub extensions: BTreeMap<String, Value>,
}

pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Other(String), // a provider can survive a finish_reason we have not seen
}
```

Three places the hub deliberately diverges from OpenAI's shape:

1. **Tool-call `arguments` are typed JSON, not a string.** OpenAI ships `function.arguments` as a string containing JSON, because the OpenAI streaming protocol assembles that string token by token. Anthropic ships it as a real JSON object. Storing the typed value in the hub means the OpenAI emitter is responsible for stringification (a one-line `serde_json::to_string`) and every other consumer (Anthropic, Gemini, Bedrock, telemetry, guardrails) gets the structured form for free.

2. **`top_k` is in the hub even though OpenAI lacks it.** Anthropic, Gemini, and Bedrock all accept `top_k`, and dropping it on the OpenAI inbound would silently degrade sampling control for users routing OpenAI-shape requests at an Anthropic upstream. The OpenAI emitter drops it on the way out.

3. **`system` is a single optional string, not interleaved.** OpenAI permits `system` messages anywhere in the array; Anthropic requires a single top-level `system` field. The hub stores `system` as a single string (concatenated with `\n\n` on parse if the inbound had several system turns) and every emitter that wants per-turn system has to re-derive it. In practice no upstream wants per-turn system; the round-trip is lossy at the wire level (you cannot tell after the fact whether the original had one system message or three concatenated ones), but lossless at the semantic level (the model sees the same prompt).

The `extensions` map is the escape valve for provider-specific knobs the hub does not model. Anthropic `cache_control` blocks land in `extensions["anthropic.cache_control"]`; OpenAI `response_format: json_object` lands in `extensions["openai.response_format"]`. Each emitter looks for the extensions namespaced to its own format and applies them; everyone else ignores them. The namespacing rule is enforced at parse time so a misnamed key is a 400 to the client, not a silent drop on the upstream.

`ChatEvent` is the streaming counterpart and has a deliberately small vocabulary, covered in its own section below.

## Inbound endpoints

WOR-224 ships three inbound parsers, registered into a parser registry keyed by inbound path:

- `/v1/chat/completions` (OpenAI): the existing route, refactored to call `OpenAiFormat::parse_request`. This is the pass-through path; the registry can short-circuit it when both inbound and outbound are OpenAI, skipping the hub entirely so the no-translation hot path is byte-for-byte identical.
- `/v1/messages` (Anthropic): new route. Backed by `AnthropicFormat::parse_request`. Existing Anthropic clients (the Anthropic SDK, Claude Code, Cursor) point at this path and Just Work, including when the configured upstream is OpenAI or Gemini.
- `/v1/responses` (OpenAI Responses): new route. Backed by `OpenAiResponsesFormat::parse_request`. The Responses shape is OpenAI's stateful-conversation API; the hub parser flattens it into a stateless `ChatRequest` and the response emitter re-wraps the result.

The registry is a small struct in `crates/sbproxy-ai/src/format/registry.rs` that holds a map from inbound path to `Arc<dyn ChatFormat>`. Outbound is selected from the provider config (each provider declares its format in `ai_providers.yml`), so the runtime never has to guess which emitter to use.

Configuration touches one new field on the AI gateway block, and inbound-path support is opt-in:

```yaml
ai:
  inbound_formats:
    - openai           # /v1/chat/completions, always on for back-compat
    - anthropic        # /v1/messages, opt-in
    - openai_responses # /v1/responses, opt-in
  providers:
    - id: claude-sonnet
      format: anthropic
      url: https://api.anthropic.com
      models: [claude-3-5-sonnet]
```

Opt-in inbound formats is the conservative default. If we turn on `/v1/messages` for every operator who upgrades, we hijack any operator who happens to already route `/v1/messages` to a real Anthropic upstream through SBproxy as a transparent proxy.

## Streaming translation

Streaming is the highest-leverage and the highest-risk part of this design, so the hub event vocabulary is deliberately tiny.

```rust,ignore
pub enum ChatEvent {
    MessageStart { id: String, model: String },
    ContentDelta { index: usize, part: ContentPartDelta },
    ToolCallDelta { index: usize, delta: ToolCallDelta },
    Usage(Usage),
    MessageStop { finish_reason: FinishReason },
}

pub enum ContentPartDelta {
    Text(String),
    // Image / ToolResult are non-streaming today; they appear in full
    // inside MessageStart-adjacent metadata, not as deltas.
}

pub struct ToolCallDelta {
    pub id: Option<String>,        // present in the first delta
    pub name: Option<String>,      // present in the first delta
    pub arguments_chunk: Option<String>, // raw JSON chunk for OpenAI;
                                         // Anthropic emits whole objects
}
```

Five events cover every provider we have looked at. The mapping table:

| Hub event | OpenAI SSE | Anthropic SSE | Gemini SSE | Bedrock event-stream |
|---|---|---|---|---|
| `MessageStart` | first `data:` with `id` | `event: message_start` | first chunk with `responseId` | `:event-type: messageStart` |
| `ContentDelta` | `delta.content` | `event: content_block_delta` (text) | `candidates[0].content.parts[].text` | `:event-type: contentBlockDelta` (text) |
| `ToolCallDelta` | `delta.tool_calls[]` | `event: content_block_delta` (input_json_delta) | `functionCall.args` partials | `:event-type: contentBlockDelta` (toolUse) |
| `Usage` | last chunk (`usage` block when `stream_options.include_usage`) | `event: message_delta` (`usage`) | `usageMetadata` on final chunk | `:event-type: metadata` |
| `MessageStop` | `data: [DONE]` after `finish_reason` chunk | `event: message_stop` | `finishReason` field | `:event-type: messageStop` |

Three rules keep the streaming path honest.

First, **frames are the unit, not bytes.** Every translator gets a complete SSE frame (parsed by the same SSE framer in `sbproxy-transport`, which already exists for HTTP/2 push and gRPC). A translator never sees a partial frame, so it never has to buffer.

Second, **a single upstream frame may produce zero or many hub events.** Anthropic's `message_start` frame carries enough state to emit both `MessageStart` and a "seed" usage record; OpenAI's first chunk emits only `MessageStart`. Returning `Vec<ChatEvent>` makes that explicit.

Third, **emitters own terminator framing.** OpenAI requires a trailing `data: [DONE]`; Anthropic does not. Bedrock has a binary event-stream framing layer that wraps the SSE payload. Each emitter is responsible for getting the goodbye right.

The pass-through hot path is unchanged: when inbound and outbound are both OpenAI, the registry detects the match and the streaming bytes are forwarded with zero parsing. This matters because OpenAI-compatible upstreams are still the common case and any streaming overhead is paid per token.

## Cross-format lossiness

Three classes of feature do not survive every cross-format hop, and the hub will say so out loud rather than dropping silently.

**Anthropic `cache_control` blocks** mark message content for Anthropic's prompt caching. There is no OpenAI analog. When the inbound is Anthropic and the outbound is OpenAI:

1. The parser stashes the blocks in `extensions["anthropic.cache_control"]` so they round-trip if the outbound is also Anthropic.
2. The OpenAI emitter drops the extension and adds one entry to the request's `lossiness` log (a `Vec<LossinessNote>` on `ChatRequest` that telemetry exports as a span attribute).
3. The classifier logs a `sbproxy_ai_format_lossy_field_total{field="anthropic.cache_control",direction="downgrade"}` counter so operators can see it on a dashboard.

This is "warn and best-effort." The request still goes through; the model still answers; the operator can see in metrics and traces that the cache hint was dropped.

**Anthropic thinking blocks** (`type: thinking` content blocks) come back from extended-thinking models. OpenAI o1 and o3 emit a similar concept (`reasoning_content`) but with different framing and no streamable shape. The hub keeps thinking as a first-class `ContentPart::Thinking { signature, text }` variant so any inbound parser that sees it preserves it on the way to any outbound emitter that knows what to do with it; emitters that do not (OpenAI Chat Completions today) drop it with a `lossiness` note.

**OpenAI `response_format: json_schema`** is a structured-output mode OpenAI implements at decoding time. Anthropic and Gemini have similar features with different schemas and different field names. The hub does not model structured output as a first-class field today; it lives in `extensions["openai.response_format"]` and only the OpenAI emitter applies it. Cross-emitting from OpenAI to Anthropic with a `response_format` request adds a lossiness note and the operator's tests are likely to fail. This is the loudest of the three: we will document it in `ai-gateway.md` as a known limitation and revisit when WOR-... follow-ups land.

Lossiness notes carry three fields: the field name, the direction (`downgrade` or `unsupported`), and a short string explaining the effect. They surface in OpenInference spans (as a `lossiness` attribute on the parent span) and in structured logs at WARN level once per request. They do not block the request.

## Migration path

The existing Anthropic translator at `crates/sbproxy-ai/src/translators/anthropic.rs` becomes two halves of one `AnthropicFormat` implementor. `request_to_native` is the bones of `emit_request`; `response_to_openai` is the bones of `parse_response` plus a no-op `emit_response`. The free-function API in `translators/mod.rs` stays as a deprecated shim for one release so any out-of-tree callers do not break.

Implementation breaks into roughly six to eight chunks. Each one is small enough to land on its own and CI gate, in line with the workspace's tracer-bullet preference.

1. **Hub types and registry.** Land `ChatRequest`, `ChatResponse`, `ChatMessage`, `ContentPart`, `ToolCall`, `ChatEvent`, the `ChatFormat` trait, and an empty `FormatRegistry`. No wire integration yet; the crate compiles and has unit tests for the types.

2. **OpenAI format as the identity.** Implement `OpenAiFormat: ChatFormat` so the existing `/v1/chat/completions` path can go through the hub on a feature flag. Round-trip every existing AI e2e test through the hub under the flag; flip the flag once green.

3. **Anthropic format migration.** Port the current translator into `AnthropicFormat`. Add an outbound test matrix (OpenAI inbound, Anthropic outbound) that proves byte-equivalent behavior with the legacy free-function path. Delete the free functions once the matrix is green for two releases.

4. **`/v1/messages` inbound.** Register `AnthropicFormat` as an inbound parser, gated by `inbound_formats: [..., anthropic]`. Add a route handler that picks the format from path. New e2e: Anthropic SDK against SBproxy against an OpenAI upstream.

5. **`/v1/responses` inbound.** Add `OpenAiResponsesFormat`. The Responses shape has stateful conversation handling that the hub will flatten; add a stateless emitter back to Responses for the round-trip.

6. **Streaming.** Implement `parse_event` / `emit_event` for OpenAI, Anthropic, and OpenAI Responses. Add a streaming conformance test (one fixture per provider, replayed deterministically).

7. **Gemini format.** Add `GeminiFormat` (request + response + streaming). Lights up Gemini and Vertex upstreams without a Google-side translator code path elsewhere.

8. **Bedrock format.** Add `BedrockFormat`. Bedrock's binary event-stream wrapping is the tricky part; SigV4 stays in the existing auth layer.

Six chunks ship a working hub with three inbound shapes and three outbound shapes. Chunks seven and eight are independent and can ship in either order.

## Alternatives considered

**Per-pair translators (the status quo).** Keep adding `translate_request_anthropic_to_openai`, `translate_request_gemini_to_openai`, and so on, fanning out to one function per pair. The translator file already has Gemini and Bedrock as TODO comments. Cost: N times M code paths, duplicated streaming logic, observability hooks duplicated per pair. Wins: zero new types, no abstraction, easy to grep. We rejected this because the duplication compounds with every provider and the streaming demuxer in particular is too large to write five times.

**Upstream-only routing through OpenRouter or LiteLLM.** Send every non-OpenAI provider through OpenRouter or a sidecar LiteLLM. Wins: zero in-process translation; OpenRouter's pricing is already integrated. Cost: an extra network hop, opaque routing decisions, no control over guardrails or PII redaction (they fire after the hop), no streaming visibility, vendor lock to OpenRouter's evolution. We rejected this because the whole pitch of "the AI gateway built like a real proxy" is that everything happens in process; an external hop defeats that.

**Fork OpenAI's Python SDK shapes and use them verbatim as the hub.** Mirror OpenAI's Python `Pydantic` types in Rust and treat the OpenAI shape (with `.arguments` as a string, no `top_k`) as the canonical form. Wins: zero invention; copy from a working spec. Cost: locks the hub to OpenAI's evolution (Responses already obsoletes parts of it), forces every Anthropic-only field through a string-of-JSON keyhole, and makes structured tool arguments awkward to inspect. We rejected this because the OpenAI shape is the closest existing shape, not a correct hub. The hub diverges in three places (typed `arguments`, hub-only `top_k`, single `system`) on purpose.

**One trait, but bytes-in / bytes-out at the trait surface (no hub types).** Make `ChatFormat` a `(format_a, format_b, bytes_in) -> bytes_out` API and skip the canonical types. Wins: minimum allocations on the no-translation path. Cost: telemetry, guardrails, caching, and cost routing all have to re-parse the bytes; we are back to N times M for those features. We rejected this because the bytes-in / bytes-out surface only solves the translation problem and leaves four other features uncovered.

## Open questions

These are genuinely undecided and need an answer before WOR-224 closes; do not treat the absence of an answer as a sign the design will not change.

1. **Cost routing and inbound model names.** Today the cost router keys on the OpenAI model name. When the inbound is Anthropic Messages with `model: claude-3-5-sonnet`, does the router look up Anthropic pricing, or does it expect the operator's `ai_providers.yml` to declare an alias? Probably the latter, but the alias-resolution path needs a design.

2. **Guardrail input scope on multi-turn conversations.** The prompt-injection classifier inspects the latest user message today. With Anthropic-style messages where a `tool_result` block can carry attacker-controlled text from a previous tool call, the "latest user message" is the wrong scope. Hub-level: scan every `Tool` role message too? Open.

3. **Streaming back-pressure.** The hub emits `Vec<ChatEvent>` per upstream frame. If a slow client cannot keep up with the upstream's frame rate, we either buffer (memory pressure) or drop (correctness loss). Pingora already has body-write back-pressure; need to confirm that the trait surface composes with it cleanly when the emitter produces several SSE frames per hub event.

4. **`extensions` versioning.** Provider wire formats evolve. If Anthropic adds a new `cache_control` mode, every old parser will silently drop it. Do we pin a wire-version per format, fail closed on unknown extensions, or warn? Probably "warn and pass through under a versioned key," but the policy is not written yet.

5. **`/v1/responses` stateful mode.** The Responses API has a `previous_response_id` field that points at a prior conversation. The hub flattens to stateless requests; the operator-facing question is whether SBproxy stores those conversations itself or refuses the field. Refusing is the conservative answer for v1, but it breaks `client.responses.create(previous_response_id=...)` calls.

6. **Schema discipline for `extensions`.** Today the rule is "namespace by format id" but it is not enforced beyond a runtime check. A JSON Schema fragment per format would let the config compiler validate at load time. Worth doing in chunk one or worth deferring? Open.

7. **Where does the AWS event-stream wrapper live?** Bedrock's streaming layer is non-trivial. Inside `BedrockFormat::parse_event`, or in a `sbproxy-transport` helper that other AWS services could share? Leaning toward the helper, but not certain until the second AWS-shape provider lands.
