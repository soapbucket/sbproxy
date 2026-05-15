//! Native upstream SSE parsers for non-OpenAI providers.
//!
//! When an OpenAI client sets `stream: true` and the configured
//! upstream is Anthropic, Gemini, or Bedrock, the upstream emits SSE
//! frames in its own wire shape. This module owns the parse step that
//! turns those frames into the small `HubChunk` vocabulary defined in
//! the ADR. From there, every outbound emitter (`OpenAiChatFormat`,
//! `AnthropicMessagesFormat`, `OpenAiResponsesFormat`) can re-emit a
//! single hub stream in its own wire shape via `from_hub_stream`.
//!
//! The parsers are deliberately tolerant: malformed frames are
//! discarded rather than failing the relay. The hub stream is a
//! best-effort projection: every observable text token, tool-call
//! fragment, finish reason, and usage record makes it through.
//! Fields the hub does not model (Anthropic `cache_control`, Gemini
//! safety ratings) drop with no fanfare; lossiness counters surface
//! the gap in metrics rather than failing the request.
//!
//! ## Anthropic
//!
//! Anthropic frames look like:
//!
//! ```text
//! event: message_start
//! data: {"type":"message_start","message":{"id":"msg_1","model":"claude-...","usage":{...}}}
//!
//! event: content_block_start
//! data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
//!
//! event: content_block_delta
//! data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}
//!
//! event: content_block_stop
//! data: {"type":"content_block_stop","index":0}
//!
//! event: message_delta
//! data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}
//!
//! event: message_stop
//! data: {"type":"message_stop"}
//! ```
//!
//! Each frame maps cleanly onto one `HubChunk`. Tool-call streaming
//! arrives as `content_block_start` with `content_block.type ==
//! "tool_use"` followed by `content_block_delta` frames whose
//! `delta.type == "input_json_delta"` and `delta.partial_json`
//! carries argument fragments.
//!
//! ## Gemini
//!
//! Gemini's streaming endpoint is
//! `:streamGenerateContent?alt=sse`. Frames are `data: { ... }` JSON
//! objects (no `event:` lines). Each object is a partial
//! `GenerateContentResponse` with one or more `candidates[].content.parts[]`
//! entries and an optional `usageMetadata` block on the terminal frame.
//!
//! ## Bedrock
//!
//! Bedrock Converse-stream frames the body in the binary `event-stream`
//! envelope with `:event-type` headers. The shapes we care about
//! (`messageStart`, `contentBlockStart`, `contentBlockDelta`,
//! `contentBlockStop`, `messageStop`, `metadata`) carry a JSON payload
//! whose internal field map mirrors Converse's non-streaming response.
//! This module parses the JSON payloads directly; the binary envelope
//! decode lives in the relay's transport layer.

use serde_json::{Map, Value};

use super::{ContentPartDelta, FinishReason, HubChunk, HubToolCallDelta, HubUsage};

/// Stateful parser for Anthropic Messages SSE streams.
///
/// Holds three pieces of state across frames so the hub-chunk
/// vocabulary stays accurate:
///
///   * `tool_call_indices` maps Anthropic content-block index ->
///     hub tool-call index. The first time we see a `tool_use`
///     content-block-start frame we allocate the next tool-call
///     index; subsequent `input_json_delta` frames at the same
///     content-block index map to the same tool-call index.
///   * `usage` accumulates `output_tokens` across `message_start`
///     and `message_delta` frames. Anthropic emits the prompt-token
///     count once on `message_start` and updates the output-token
///     count on `message_delta`; the terminal `message_stop` does
///     not repeat usage.
///   * `finish_reason` is captured on `message_delta` (the carrier
///     for `stop_reason`) so the terminal `message_stop` frame can
///     emit a final `HubChunk::MessageStop` with the right reason.
#[derive(Debug, Default)]
pub struct AnthropicStreamState {
    /// Map from Anthropic content-block index to hub tool-call index.
    tool_call_indices: std::collections::HashMap<usize, usize>,
    /// Next hub tool-call index to allocate.
    next_tool_call_index: usize,
    /// Latest usage snapshot observed on the wire.
    usage: HubUsage,
    /// Finish reason captured from `message_delta`.
    finish_reason: FinishReason,
    /// Whether we have emitted `MessageStop` already.
    emitted_stop: bool,
}

impl AnthropicStreamState {
    /// Construct an empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one parsed Anthropic SSE event JSON payload (the body
    /// after `data: `) and return zero or more hub chunks. Unknown
    /// event types are ignored.
    pub fn ingest(&mut self, payload: &Value) -> Vec<HubChunk> {
        let obj = match payload.as_object() {
            Some(o) => o,
            None => return Vec::new(),
        };
        let ty = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match ty {
            "message_start" => self.handle_message_start(obj),
            "content_block_start" => self.handle_content_block_start(obj),
            "content_block_delta" => self.handle_content_block_delta(obj),
            "content_block_stop" => Vec::new(),
            "message_delta" => self.handle_message_delta(obj),
            "message_stop" => self.handle_message_stop(),
            "ping" | "error" => Vec::new(),
            _ => Vec::new(),
        }
    }

    fn handle_message_start(&mut self, obj: &Map<String, Value>) -> Vec<HubChunk> {
        let msg = obj.get("message").and_then(|m| m.as_object());
        let id = msg
            .and_then(|m| m.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let model = msg
            .and_then(|m| m.get("model"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Seed usage with the prompt-token count.
        if let Some(u) = msg.and_then(|m| m.get("usage")).and_then(|u| u.as_object()) {
            self.usage.prompt_tokens = u
                .get("input_tokens")
                .and_then(|n| n.as_u64())
                .unwrap_or(self.usage.prompt_tokens);
            self.usage.completion_tokens = u
                .get("output_tokens")
                .and_then(|n| n.as_u64())
                .unwrap_or(self.usage.completion_tokens);
            self.refresh_total();
        }
        vec![HubChunk::MessageStart { id, model }]
    }

    fn handle_content_block_start(&mut self, obj: &Map<String, Value>) -> Vec<HubChunk> {
        let index = obj.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
        let block = obj.get("content_block").and_then(|b| b.as_object());
        let block_ty = block
            .and_then(|b| b.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if block_ty == "tool_use" {
            // Allocate a fresh tool-call slot and emit the first
            // delta carrying id and name.
            let tool_idx = self.next_tool_call_index;
            self.next_tool_call_index += 1;
            self.tool_call_indices.insert(index, tool_idx);
            let id = block
                .and_then(|b| b.get("id"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let name = block
                .and_then(|b| b.get("name"))
                .and_then(|v| v.as_str())
                .map(String::from);
            return vec![HubChunk::ToolCallDelta {
                index: tool_idx,
                delta: HubToolCallDelta {
                    id,
                    name,
                    arguments_chunk: None,
                },
            }];
        }
        Vec::new()
    }

    fn handle_content_block_delta(&mut self, obj: &Map<String, Value>) -> Vec<HubChunk> {
        let index = obj.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
        let delta = match obj.get("delta").and_then(|d| d.as_object()) {
            Some(d) => d,
            None => return Vec::new(),
        };
        let delta_ty = delta.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match delta_ty {
            "text_delta" => {
                let text = delta
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if text.is_empty() {
                    return Vec::new();
                }
                vec![HubChunk::ContentDelta {
                    index,
                    delta: ContentPartDelta::Text(text),
                }]
            }
            "input_json_delta" => {
                let partial = delta
                    .get("partial_json")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tool_idx = self.tool_call_indices.get(&index).copied().unwrap_or(index);
                vec![HubChunk::ToolCallDelta {
                    index: tool_idx,
                    delta: HubToolCallDelta {
                        id: None,
                        name: None,
                        arguments_chunk: if partial.is_empty() {
                            None
                        } else {
                            Some(partial)
                        },
                    },
                }]
            }
            _ => Vec::new(),
        }
    }

    fn handle_message_delta(&mut self, obj: &Map<String, Value>) -> Vec<HubChunk> {
        let mut chunks: Vec<HubChunk> = Vec::new();
        if let Some(delta) = obj.get("delta").and_then(|d| d.as_object()) {
            if let Some(stop) = delta.get("stop_reason").and_then(|s| s.as_str()) {
                self.finish_reason = anthropic_stop_reason_to_hub(stop);
            }
        }
        if let Some(u) = obj.get("usage").and_then(|u| u.as_object()) {
            if let Some(input) = u.get("input_tokens").and_then(|n| n.as_u64()) {
                self.usage.prompt_tokens = input;
            }
            if let Some(output) = u.get("output_tokens").and_then(|n| n.as_u64()) {
                self.usage.completion_tokens = output;
            }
            self.refresh_total();
            chunks.push(HubChunk::Usage(self.usage.clone()));
        }
        chunks
    }

    fn handle_message_stop(&mut self) -> Vec<HubChunk> {
        if self.emitted_stop {
            return Vec::new();
        }
        self.emitted_stop = true;
        vec![HubChunk::MessageStop {
            finish_reason: self.finish_reason.clone(),
        }]
    }

    fn refresh_total(&mut self) {
        self.usage.total_tokens = self.usage.prompt_tokens + self.usage.completion_tokens;
    }
}

fn anthropic_stop_reason_to_hub(reason: &str) -> FinishReason {
    match reason {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        other => FinishReason::Other(other.to_string()),
    }
}

/// Stateful parser for Google Gemini `streamGenerateContent?alt=sse`
/// streams.
///
/// Gemini emits a sequence of `data: { ... }` frames, each carrying a
/// partial `GenerateContentResponse`. The parser:
///
///   * Emits a single `MessageStart` on the first frame with a
///     non-empty `responseId` (or a synthetic one derived from the
///     model when the upstream omits it).
///   * Folds every `candidates[0].content.parts[].text` into a hub
///     `ContentDelta` text chunk.
///   * Folds `candidates[0].content.parts[].functionCall` into
///     `ToolCallDelta` events.
///   * Captures `usageMetadata.promptTokenCount` /
///     `candidatesTokenCount` on every frame; the latest snapshot is
///     emitted as a `HubChunk::Usage` before `MessageStop`.
///   * Emits `MessageStop` when a frame carries a non-`null`
///     `candidates[0].finishReason`.
#[derive(Debug, Default)]
pub struct GeminiStreamState {
    /// Whether `MessageStart` has been emitted yet.
    started: bool,
    /// Latest usage snapshot.
    usage: HubUsage,
    /// Whether we have emitted MessageStop.
    emitted_stop: bool,
    /// Next hub tool-call index.
    next_tool_call_index: usize,
}

impl GeminiStreamState {
    /// Construct an empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one Gemini SSE payload.
    pub fn ingest(&mut self, payload: &Value) -> Vec<HubChunk> {
        let obj = match payload.as_object() {
            Some(o) => o,
            None => return Vec::new(),
        };

        let mut chunks: Vec<HubChunk> = Vec::new();

        // Emit MessageStart the first time we see anything.
        if !self.started {
            self.started = true;
            let id = obj
                .get("responseId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let model = obj
                .get("modelVersion")
                .or_else(|| obj.get("model"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            chunks.push(HubChunk::MessageStart { id, model });
        }

        // Walk candidates -> content -> parts.
        let mut finish_reason: Option<FinishReason> = None;
        if let Some(cands) = obj.get("candidates").and_then(|c| c.as_array()) {
            if let Some(first) = cands.first() {
                if let Some(parts) = first
                    .get("content")
                    .and_then(|c| c.get("parts"))
                    .and_then(|p| p.as_array())
                {
                    for (idx, part) in parts.iter().enumerate() {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            if !text.is_empty() {
                                chunks.push(HubChunk::ContentDelta {
                                    index: idx,
                                    delta: ContentPartDelta::Text(text.to_string()),
                                });
                            }
                        }
                        if let Some(fc) = part.get("functionCall").and_then(|f| f.as_object()) {
                            let tool_idx = self.next_tool_call_index;
                            self.next_tool_call_index += 1;
                            let name = fc.get("name").and_then(|n| n.as_str()).map(String::from);
                            let args = fc.get("args").cloned().unwrap_or(Value::Null);
                            let args_str = if args.is_null() {
                                None
                            } else {
                                Some(args.to_string())
                            };
                            chunks.push(HubChunk::ToolCallDelta {
                                index: tool_idx,
                                delta: HubToolCallDelta {
                                    id: Some(format!("call_{}", tool_idx)),
                                    name,
                                    arguments_chunk: args_str,
                                },
                            });
                        }
                    }
                }
                if let Some(fr) = first
                    .get("finishReason")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    finish_reason = Some(gemini_finish_reason_to_hub(fr));
                }
            }
        }

        // Usage snapshot.
        if let Some(u) = obj.get("usageMetadata").and_then(|u| u.as_object()) {
            if let Some(p) = u.get("promptTokenCount").and_then(|n| n.as_u64()) {
                self.usage.prompt_tokens = p;
            }
            if let Some(c) = u.get("candidatesTokenCount").and_then(|n| n.as_u64()) {
                self.usage.completion_tokens = c;
            }
            if let Some(t) = u.get("totalTokenCount").and_then(|n| n.as_u64()) {
                self.usage.total_tokens = t;
            } else {
                self.usage.total_tokens = self.usage.prompt_tokens + self.usage.completion_tokens;
            }
        }

        // Terminal frame: emit usage then stop.
        if let Some(fr) = finish_reason {
            if !self.emitted_stop {
                if self.usage.total_tokens > 0
                    || self.usage.prompt_tokens > 0
                    || self.usage.completion_tokens > 0
                {
                    chunks.push(HubChunk::Usage(self.usage.clone()));
                }
                chunks.push(HubChunk::MessageStop { finish_reason: fr });
                self.emitted_stop = true;
            }
        }

        chunks
    }
}

fn gemini_finish_reason_to_hub(reason: &str) -> FinishReason {
    match reason {
        "STOP" => FinishReason::Stop,
        "MAX_TOKENS" => FinishReason::Length,
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => FinishReason::ContentFilter,
        "TOOL_CALLS" => FinishReason::ToolCalls,
        other => FinishReason::Other(other.to_string()),
    }
}

/// Stateful parser for AWS Bedrock Converse-stream JSON payloads.
///
/// The Bedrock Converse-stream wire format wraps each event in a
/// binary `event-stream` envelope with a `:event-type` header
/// indicating the shape (`messageStart`, `contentBlockStart`,
/// `contentBlockDelta`, `contentBlockStop`, `messageStop`, `metadata`).
/// The binary envelope decode is the relay's job; this parser sees
/// already-decoded JSON payloads paired with the event-type string.
#[derive(Debug, Default)]
pub struct BedrockStreamState {
    started: bool,
    finish_reason: FinishReason,
    usage: HubUsage,
    emitted_stop: bool,
    /// Map from content-block index to hub tool-call index.
    tool_call_indices: std::collections::HashMap<usize, usize>,
    next_tool_call_index: usize,
}

impl BedrockStreamState {
    /// Construct an empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one Bedrock event. `event_type` is the `:event-type`
    /// header from the envelope; `payload` is the JSON body.
    pub fn ingest(&mut self, event_type: &str, payload: &Value) -> Vec<HubChunk> {
        let obj = payload.as_object();
        match event_type {
            "messageStart" => {
                if self.started {
                    return Vec::new();
                }
                self.started = true;
                vec![HubChunk::MessageStart {
                    id: String::new(),
                    model: String::new(),
                }]
            }
            "contentBlockStart" => {
                let index = obj
                    .and_then(|o| o.get("contentBlockIndex"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                if let Some(start) = obj.and_then(|o| o.get("start")).and_then(|s| s.as_object()) {
                    if let Some(tu) = start.get("toolUse").and_then(|t| t.as_object()) {
                        let tool_idx = self.next_tool_call_index;
                        self.next_tool_call_index += 1;
                        self.tool_call_indices.insert(index, tool_idx);
                        return vec![HubChunk::ToolCallDelta {
                            index: tool_idx,
                            delta: HubToolCallDelta {
                                id: tu
                                    .get("toolUseId")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                name: tu.get("name").and_then(|v| v.as_str()).map(String::from),
                                arguments_chunk: None,
                            },
                        }];
                    }
                }
                Vec::new()
            }
            "contentBlockDelta" => {
                let index = obj
                    .and_then(|o| o.get("contentBlockIndex"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                let delta = match obj.and_then(|o| o.get("delta")).and_then(|d| d.as_object()) {
                    Some(d) => d,
                    None => return Vec::new(),
                };
                if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                    if !text.is_empty() {
                        return vec![HubChunk::ContentDelta {
                            index,
                            delta: ContentPartDelta::Text(text.to_string()),
                        }];
                    }
                }
                if let Some(tu) = delta.get("toolUse").and_then(|t| t.as_object()) {
                    let input = tu.get("input").and_then(|v| v.as_str()).map(String::from);
                    let tool_idx = self.tool_call_indices.get(&index).copied().unwrap_or(index);
                    return vec![HubChunk::ToolCallDelta {
                        index: tool_idx,
                        delta: HubToolCallDelta {
                            id: None,
                            name: None,
                            arguments_chunk: input,
                        },
                    }];
                }
                Vec::new()
            }
            "contentBlockStop" => Vec::new(),
            "messageStop" => {
                if let Some(reason) = obj
                    .and_then(|o| o.get("stopReason"))
                    .and_then(|v| v.as_str())
                {
                    self.finish_reason = bedrock_stop_reason_to_hub(reason);
                }
                Vec::new()
            }
            "metadata" => {
                let mut chunks = Vec::new();
                if let Some(u) = obj.and_then(|o| o.get("usage")).and_then(|u| u.as_object()) {
                    if let Some(p) = u.get("inputTokens").and_then(|n| n.as_u64()) {
                        self.usage.prompt_tokens = p;
                    }
                    if let Some(c) = u.get("outputTokens").and_then(|n| n.as_u64()) {
                        self.usage.completion_tokens = c;
                    }
                    if let Some(t) = u.get("totalTokens").and_then(|n| n.as_u64()) {
                        self.usage.total_tokens = t;
                    } else {
                        self.usage.total_tokens =
                            self.usage.prompt_tokens + self.usage.completion_tokens;
                    }
                    chunks.push(HubChunk::Usage(self.usage.clone()));
                }
                if !self.emitted_stop {
                    self.emitted_stop = true;
                    chunks.push(HubChunk::MessageStop {
                        finish_reason: self.finish_reason.clone(),
                    });
                }
                chunks
            }
            _ => Vec::new(),
        }
    }
}

fn bedrock_stop_reason_to_hub(reason: &str) -> FinishReason {
    match reason {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        "content_filtered" | "guardrail_intervened" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_string()),
    }
}

/// Incremental SSE framer.
///
/// Provider streams arrive as a byte stream where each frame is
/// terminated by a blank line (`\n\n` or `\r\n\r\n`). The framer
/// buffers partial bytes across chunks and yields complete frames
/// to the caller. It does not interpret payload contents; that is
/// the per-provider parser's job.
///
/// Returned frames keep their `event:` and `data:` line prefixes so
/// the caller can route on `event:` (Anthropic, Bedrock) or treat
/// every frame as `data:` (Gemini, OpenAI).
#[derive(Debug, Default)]
pub struct SseFramer {
    buf: String,
}

impl SseFramer {
    /// Construct an empty framer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes and pull any complete frames the buffer now holds.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<String> {
        // Append decoded text; non-UTF8 bytes are replaced.
        self.buf.push_str(&String::from_utf8_lossy(bytes));
        let mut frames = Vec::new();
        loop {
            let lf2 = self.buf.find("\n\n");
            let crlf2 = self.buf.find("\r\n\r\n");
            let (idx, sep_len) = match (lf2, crlf2) {
                (Some(a), Some(b)) if a < b => (a, 2),
                (Some(_), Some(b)) => (b, 4),
                (Some(a), None) => (a, 2),
                (None, Some(b)) => (b, 4),
                (None, None) => break,
            };
            let frame: String = self.buf.drain(..idx).collect();
            self.buf.drain(..sep_len);
            if !frame.is_empty() {
                frames.push(frame);
            }
        }
        frames
    }

    /// Flush any trailing partial frame at end-of-stream.
    pub fn flush(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.buf))
        }
    }
}

/// One of the three native upstream SSE wire shapes the relay parses
/// into hub chunks.
///
/// The enum is kept narrow on purpose. OpenAI Chat Completions
/// streams pass through unchanged today; the bypass-only ticket
/// (WOR-229) covers an even shorter no-translation path for that
/// case. Custom providers that need a fourth shape register a
/// plugin translator and run outside this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStreamFormat {
    /// Anthropic Messages SSE (`event: message_start` / etc.).
    Anthropic,
    /// Google Gemini `streamGenerateContent?alt=sse`.
    Gemini,
    /// AWS Bedrock Converse-stream JSON payloads.
    Bedrock,
}

/// Stateful translator that ingests bytes from a native upstream
/// SSE stream and yields a sequence of `HubChunk`s.
///
/// Holds the per-format parser state plus an `SseFramer` that
/// reassembles frames across byte-boundary splits. The relay feeds
/// every upstream byte chunk into `feed`; the returned hub chunks
/// are then fed to the inbound format's `from_hub_stream` emitter.
#[derive(Debug)]
pub struct NativeStreamTranslator {
    format: NativeStreamFormat,
    framer: SseFramer,
    anthropic: AnthropicStreamState,
    gemini: GeminiStreamState,
    bedrock: BedrockStreamState,
}

impl NativeStreamTranslator {
    /// Construct a translator for the named native format.
    pub fn new(format: NativeStreamFormat) -> Self {
        Self {
            format,
            framer: SseFramer::new(),
            anthropic: AnthropicStreamState::new(),
            gemini: GeminiStreamState::new(),
            bedrock: BedrockStreamState::new(),
        }
    }

    /// Feed a chunk of upstream bytes and return every hub chunk
    /// that can be produced from the bytes seen so far.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<HubChunk> {
        let frames = self.framer.feed(bytes);
        let mut chunks: Vec<HubChunk> = Vec::new();
        for frame in frames {
            chunks.extend(self.ingest_frame(&frame));
        }
        chunks
    }

    /// Flush any trailing partial frame at end-of-stream.
    pub fn flush(&mut self) -> Vec<HubChunk> {
        let mut chunks: Vec<HubChunk> = Vec::new();
        if let Some(frame) = self.framer.flush() {
            chunks.extend(self.ingest_frame(&frame));
        }
        chunks
    }

    fn ingest_frame(&mut self, frame: &str) -> Vec<HubChunk> {
        let (event, data) = split_sse_frame(frame);
        if data.trim() == "[DONE]" || data.is_empty() {
            return Vec::new();
        }
        let payload: Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        match self.format {
            NativeStreamFormat::Anthropic => self.anthropic.ingest(&payload),
            NativeStreamFormat::Gemini => self.gemini.ingest(&payload),
            NativeStreamFormat::Bedrock => {
                let ev = event.unwrap_or_default();
                self.bedrock.ingest(&ev, &payload)
            }
        }
    }
}

/// Parse a single complete SSE frame into its `event:` type (if any)
/// and concatenated `data:` payload. Lines that are neither `event:`
/// nor `data:` (`id:`, `retry:`, comments) are ignored.
pub fn split_sse_frame(frame: &str) -> (Option<String>, String) {
    let mut event: Option<String> = None;
    let mut data = String::new();
    for line in frame.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(ev) = line.strip_prefix("event: ") {
            event = Some(ev.to_string());
        } else if let Some(ev) = line.strip_prefix("event:") {
            event = Some(ev.trim().to_string());
        } else if let Some(d) = line.strip_prefix("data: ") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(d);
        } else if let Some(d) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(d.trim_start());
        }
    }
    (event, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn anthropic_parser_handles_basic_text_stream() {
        let mut s = AnthropicStreamState::new();
        let start = json!({
            "type": "message_start",
            "message": {
                "id": "msg_01",
                "model": "claude-3-5-sonnet",
                "usage": {"input_tokens": 9, "output_tokens": 0}
            }
        });
        let chunks = s.ingest(&start);
        assert!(matches!(chunks[0], HubChunk::MessageStart { .. }));

        let delta = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "Hello"}
        });
        let chunks = s.ingest(&delta);
        assert!(matches!(chunks[0], HubChunk::ContentDelta { index: 0, .. }));

        let mdelta = json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 4}
        });
        let chunks = s.ingest(&mdelta);
        assert!(matches!(chunks[0], HubChunk::Usage(_)));

        let stop = json!({"type": "message_stop"});
        let chunks = s.ingest(&stop);
        assert!(matches!(
            chunks[0],
            HubChunk::MessageStop {
                finish_reason: FinishReason::Stop
            }
        ));
    }

    #[test]
    fn anthropic_parser_streams_tool_call_arguments() {
        let mut s = AnthropicStreamState::new();
        s.ingest(&json!({
            "type": "message_start",
            "message": {"id": "msg_1", "model": "claude", "usage": {"input_tokens": 1, "output_tokens": 0}}
        }));
        let start = json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "get_weather"}
        });
        let chunks = s.ingest(&start);
        match &chunks[0] {
            HubChunk::ToolCallDelta { index, delta } => {
                assert_eq!(*index, 0);
                assert_eq!(delta.id.as_deref(), Some("toolu_1"));
                assert_eq!(delta.name.as_deref(), Some("get_weather"));
                assert!(delta.arguments_chunk.is_none());
            }
            other => panic!("expected tool_call_delta, got {other:?}"),
        }
        let d1 = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": "{\"ci"}
        });
        let chunks = s.ingest(&d1);
        match &chunks[0] {
            HubChunk::ToolCallDelta { index, delta } => {
                assert_eq!(*index, 0);
                assert_eq!(delta.arguments_chunk.as_deref(), Some("{\"ci"));
            }
            other => panic!("expected tool_call_delta, got {other:?}"),
        }
        let d2 = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": "ty\":\"SF\"}"}
        });
        let chunks = s.ingest(&d2);
        match &chunks[0] {
            HubChunk::ToolCallDelta { delta, .. } => {
                assert_eq!(delta.arguments_chunk.as_deref(), Some("ty\":\"SF\"}"));
            }
            other => panic!("expected tool_call_delta, got {other:?}"),
        }
    }

    #[test]
    fn anthropic_parser_emits_tool_use_finish_reason() {
        let mut s = AnthropicStreamState::new();
        s.ingest(&json!({"type": "message_start", "message": {"id": "x", "model": "y", "usage": {"input_tokens": 1, "output_tokens": 0}}}));
        s.ingest(&json!({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
            "usage": {"output_tokens": 5}
        }));
        let chunks = s.ingest(&json!({"type": "message_stop"}));
        match &chunks[0] {
            HubChunk::MessageStop { finish_reason } => {
                assert_eq!(*finish_reason, FinishReason::ToolCalls);
            }
            other => panic!("expected MessageStop, got {other:?}"),
        }
    }

    #[test]
    fn gemini_parser_emits_message_start_then_text_then_stop() {
        let mut s = GeminiStreamState::new();
        let f1 = json!({
            "responseId": "gen_1",
            "modelVersion": "gemini-1.5-pro",
            "candidates": [{
                "content": {"parts": [{"text": "Hello"}]},
            }]
        });
        let chunks = s.ingest(&f1);
        assert!(matches!(chunks[0], HubChunk::MessageStart { .. }));
        assert!(matches!(chunks[1], HubChunk::ContentDelta { .. }));

        let f2 = json!({
            "candidates": [{
                "content": {"parts": [{"text": " world"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2, "totalTokenCount": 5}
        });
        let chunks = s.ingest(&f2);
        // ContentDelta, Usage, MessageStop.
        assert!(matches!(chunks[0], HubChunk::ContentDelta { .. }));
        assert!(matches!(chunks[1], HubChunk::Usage(_)));
        assert!(matches!(
            chunks[2],
            HubChunk::MessageStop {
                finish_reason: FinishReason::Stop
            }
        ));
    }

    #[test]
    fn gemini_parser_emits_function_call() {
        let mut s = GeminiStreamState::new();
        let f = json!({
            "responseId": "g",
            "candidates": [{
                "content": {"parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]},
                "finishReason": "STOP"
            }]
        });
        let chunks = s.ingest(&f);
        let has_tool = chunks
            .iter()
            .any(|c| matches!(c, HubChunk::ToolCallDelta { .. }));
        assert!(has_tool, "expected a tool-call delta among {chunks:?}");
    }

    #[test]
    fn bedrock_parser_walks_full_lifecycle() {
        let mut s = BedrockStreamState::new();
        let chunks = s.ingest("messageStart", &json!({"role": "assistant"}));
        assert!(matches!(chunks[0], HubChunk::MessageStart { .. }));

        let chunks = s.ingest(
            "contentBlockDelta",
            &json!({"contentBlockIndex": 0, "delta": {"text": "Hello"}}),
        );
        assert!(matches!(chunks[0], HubChunk::ContentDelta { .. }));

        // messageStop captures reason but does not emit yet.
        let chunks = s.ingest("messageStop", &json!({"stopReason": "end_turn"}));
        assert!(chunks.is_empty());

        let chunks = s.ingest(
            "metadata",
            &json!({"usage": {"inputTokens": 2, "outputTokens": 3, "totalTokens": 5}}),
        );
        assert_eq!(chunks.len(), 2);
        assert!(matches!(chunks[0], HubChunk::Usage(_)));
        assert!(matches!(
            chunks[1],
            HubChunk::MessageStop {
                finish_reason: FinishReason::Stop
            }
        ));
    }

    #[test]
    fn bedrock_parser_handles_tool_use_block() {
        let mut s = BedrockStreamState::new();
        s.ingest("messageStart", &json!({}));
        let chunks = s.ingest(
            "contentBlockStart",
            &json!({
                "contentBlockIndex": 1,
                "start": {"toolUse": {"toolUseId": "t1", "name": "lookup"}}
            }),
        );
        match &chunks[0] {
            HubChunk::ToolCallDelta { delta, .. } => {
                assert_eq!(delta.id.as_deref(), Some("t1"));
                assert_eq!(delta.name.as_deref(), Some("lookup"));
            }
            other => panic!("expected tool delta, got {other:?}"),
        }
        let chunks = s.ingest(
            "contentBlockDelta",
            &json!({"contentBlockIndex": 1, "delta": {"toolUse": {"input": "{\"q"}}}),
        );
        match &chunks[0] {
            HubChunk::ToolCallDelta { delta, .. } => {
                assert_eq!(delta.arguments_chunk.as_deref(), Some("{\"q"));
            }
            other => panic!("expected tool delta, got {other:?}"),
        }
    }

    #[test]
    fn sse_framer_splits_on_blank_lines() {
        let mut f = SseFramer::new();
        let frames = f.feed(b"event: message_start\ndata: {\"id\":1}\n\nevent: ping\ndata: {}\n\n");
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains("message_start"));
        assert!(frames[1].contains("ping"));
    }

    #[test]
    fn sse_framer_buffers_partial_chunks() {
        let mut f = SseFramer::new();
        let frames = f.feed(b"event: foo\ndata: {\"a\":");
        assert!(frames.is_empty());
        let frames = f.feed(b"1}\n\n");
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("\"a\":1"));
    }

    #[test]
    fn sse_framer_handles_crlf_separator() {
        let mut f = SseFramer::new();
        let frames = f.feed(b"event: x\r\ndata: {}\r\n\r\n");
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn split_sse_frame_extracts_event_and_data() {
        let (ev, data) = split_sse_frame("event: message_delta\ndata: {\"a\":1}");
        assert_eq!(ev.as_deref(), Some("message_delta"));
        assert_eq!(data, "{\"a\":1}");
    }

    #[test]
    fn split_sse_frame_concatenates_multi_data_lines() {
        let (_, data) = split_sse_frame("data: hello\ndata: world");
        assert_eq!(data, "hello\nworld");
    }

    #[test]
    fn translator_anthropic_chains_bytes_to_hub_chunks() {
        let mut t = NativeStreamTranslator::new(NativeStreamFormat::Anthropic);
        let bytes = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"c\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let chunks = t.feed(bytes);
        assert!(matches!(chunks[0], HubChunk::MessageStart { .. }));
        assert!(chunks
            .iter()
            .any(|c| matches!(c, HubChunk::ContentDelta { .. })));
        assert!(chunks.iter().any(|c| matches!(c, HubChunk::Usage(_))));
        assert!(chunks
            .iter()
            .any(|c| matches!(c, HubChunk::MessageStop { .. })));
    }

    #[test]
    fn translator_gemini_chains_bytes_to_hub_chunks() {
        let mut t = NativeStreamTranslator::new(NativeStreamFormat::Gemini);
        let bytes = b"data: {\"responseId\":\"g\",\"modelVersion\":\"gem\",\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2}}\n\n";
        let chunks = t.feed(bytes);
        assert!(matches!(chunks[0], HubChunk::MessageStart { .. }));
        assert!(chunks
            .iter()
            .any(|c| matches!(c, HubChunk::MessageStop { .. })));
    }

    #[test]
    fn translator_skips_done_sentinels() {
        let mut t = NativeStreamTranslator::new(NativeStreamFormat::Gemini);
        let bytes = b"data: [DONE]\n\n";
        let chunks = t.feed(bytes);
        assert!(chunks.is_empty());
    }

    #[test]
    fn round_trip_anthropic_native_to_openai_chat_sse() {
        // Simulate the full pipeline: Anthropic native upstream SSE
        // bytes -> hub chunks -> OpenAI Chat SSE frames. The test
        // asserts that a downstream OpenAI client receives a valid
        // OpenAI Chat Completions SSE stream.
        use crate::format::{ChatFormat, OpenAiChatFormat};
        let mut translator = NativeStreamTranslator::new(NativeStreamFormat::Anthropic);
        let emitter = OpenAiChatFormat;
        let ctx = crate::format::BridgeContext::default();

        // Feed a complete Anthropic stream in one go.
        let bytes = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"model\":\"claude-3-5\",\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let hub_chunks = translator.feed(bytes);

        let mut openai_sse = String::new();
        for chunk in &hub_chunks {
            for frame in emitter.from_hub_stream(chunk, &ctx).unwrap() {
                openai_sse.push_str(&frame);
            }
        }
        // The OpenAI client expects a leading role chunk, two content
        // deltas, and a `data: [DONE]` terminator.
        assert!(openai_sse.contains("\"role\":\"assistant\""));
        assert!(openai_sse.contains("\"content\":\"Hello\""));
        assert!(openai_sse.contains("\"content\":\" world\""));
        assert!(openai_sse.contains("\"finish_reason\":\"stop\""));
        assert!(openai_sse.contains("data: [DONE]"));
    }

    #[test]
    fn round_trip_anthropic_tool_call_argument_chunks_reassemble() {
        // Anthropic streams `input_json_delta` chunks; an OpenAI
        // client should see those as a sequence of `tool_calls`
        // deltas with `arguments` string fragments that concatenate
        // back to valid JSON.
        use crate::format::{ChatFormat, OpenAiChatFormat};
        let mut t = NativeStreamTranslator::new(NativeStreamFormat::Anthropic);
        let bytes = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"c\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ci\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"ty\\\":\\\"SF\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let chunks = t.feed(bytes);
        let emitter = OpenAiChatFormat;
        let mut sse = String::new();
        let ctx = crate::format::BridgeContext::default();
        for c in &chunks {
            for f in emitter.from_hub_stream(c, &ctx).unwrap() {
                sse.push_str(&f);
            }
        }
        assert!(sse.contains("toolu_1"));
        assert!(sse.contains("get_weather"));
        // Pull both argument fragments out and concatenate; the
        // result must parse as JSON.
        let mut concatenated = String::new();
        for chunk in &chunks {
            if let HubChunk::ToolCallDelta { delta, .. } = chunk {
                if let Some(a) = &delta.arguments_chunk {
                    concatenated.push_str(a);
                }
            }
        }
        assert_eq!(concatenated, "{\"city\":\"SF\"}");
        let parsed: serde_json::Value = serde_json::from_str(&concatenated).unwrap();
        assert_eq!(parsed["city"], "SF");
        assert!(sse.contains("\"finish_reason\":\"tool_calls\""));
    }
}
