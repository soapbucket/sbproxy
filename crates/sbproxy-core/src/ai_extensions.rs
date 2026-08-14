//! Request-local adaptation between the AI hub and extension events.

use sbproxy_ai::format::{ContentPartDelta, FinishReason, HubChunk};
use sbproxy_ai::guardrails::stream::CompletedToolCall;
use sbproxy_extension::bundle::{AiChainVerdict, AiExtensionChain, AiExtensionSession};
use sbproxy_plugin::{
    AiExtensionEvent, AiExtensionEventPayload, AiExtensionMessage, AiExtensionRole,
    AiExtensionStreamChunk, AiExtensionToolCall, ExtensionHookKind,
    AI_EXTENSION_EVENT_SCHEMA_VERSION,
};

const MAX_EVENT_TEXT_BYTES: usize = 1024 * 1024;
const MAX_EVENT_MESSAGES: usize = 256;
const MAX_EVENT_ID_BYTES: usize = 512;

/// Client-safe refusal returned by an enforcing AI extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AiExtensionBlock {
    pub(crate) status: u16,
    pub(crate) code: String,
    pub(crate) message: String,
}

impl AiExtensionBlock {
    fn runtime_failure() -> Self {
        Self {
            status: 503,
            code: "ai_extension_failed".to_owned(),
            message: "An AI extension could not evaluate this event".to_owned(),
        }
    }

    fn event_too_large() -> Self {
        Self {
            status: 413,
            code: "ai_extension_event_too_large".to_owned(),
            message: "The normalized AI event exceeded its safety limit".to_owned(),
        }
    }

    /// A hook rewrote content the host cannot faithfully write back
    /// into the provider-shaped body (for example, a single
    /// replacement text against a multi-choice completion). Shipping
    /// the original behind a hook that believes it rewrote it is the
    /// one outcome this refusal exists to prevent.
    pub(crate) fn mutation_unrepresentable() -> Self {
        Self {
            status: 502,
            code: "ai_extension_mutation_unrepresentable".to_owned(),
            message: "An AI extension rewrote content this response shape cannot carry".to_owned(),
        }
    }
}

/// AI hook state pinned to one request and one pipeline generation.
pub(crate) struct AiRequestExtensions {
    session: AiExtensionSession,
    sequence: u64,
    request_id: Option<String>,
    model: Option<String>,
    kinds: AiHookKinds,
    stats: AiStreamStats,
    closed: bool,
}

#[derive(Clone, Copy)]
struct AiHookKinds {
    input: bool,
    output: bool,
    tool: bool,
    stream: bool,
    close: bool,
    failure: bool,
    enforcing_input: bool,
    enforcing_output: bool,
    enforcing_tool: bool,
    enforcing_stream: bool,
}

#[derive(Default)]
struct AiStreamStats {
    finish_reason: Option<String>,
    content_bytes: u64,
    content_delta_count: u64,
    tool_call_count: u64,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

impl AiRequestExtensions {
    /// Start request-local state when this generation has AI hooks.
    pub(crate) fn start(chain: &AiExtensionChain, request_id: &str, model: &str) -> Option<Self> {
        if chain.is_empty() {
            return None;
        }
        let kind = |kind| chain.has_kind(kind);
        let enforcing = |kind| chain.has_enforcing(kind);
        Some(Self {
            session: chain.start_session(),
            sequence: 0,
            request_id: Some(bounded_id(request_id)),
            model: Some(bounded_id(model)),
            kinds: AiHookKinds {
                input: kind(ExtensionHookKind::AiGuardrailInput),
                output: kind(ExtensionHookKind::AiGuardrailOutput),
                tool: kind(ExtensionHookKind::AiToolCall),
                stream: kind(ExtensionHookKind::AiStreamEvent),
                close: kind(ExtensionHookKind::AiClose),
                failure: kind(ExtensionHookKind::AiFailure),
                enforcing_input: enforcing(ExtensionHookKind::AiGuardrailInput),
                enforcing_output: enforcing(ExtensionHookKind::AiGuardrailOutput),
                enforcing_tool: enforcing(ExtensionHookKind::AiToolCall),
                enforcing_stream: enforcing(ExtensionHookKind::AiStreamEvent),
            },
            stats: AiStreamStats::default(),
            closed: false,
        })
    }

    pub(crate) const fn needs_stream_decode(&self) -> bool {
        self.kinds.stream || self.kinds.tool || self.kinds.close
    }

    pub(crate) const fn needs_tool_assembly(&self) -> bool {
        self.kinds.tool
    }

    pub(crate) const fn enforces_stream_events(&self) -> bool {
        self.kinds.enforcing_stream
    }

    pub(crate) const fn delays_first_downstream_byte(&self) -> bool {
        self.kinds.enforcing_stream || self.kinds.enforcing_tool
    }

    pub(crate) const fn holds_tool_frames(&self) -> bool {
        self.kinds.enforcing_tool
    }

    /// Returns the canonical message list a hook rewrote, or `None`
    /// when the input passed through unmodified. The caller owns
    /// writing a mutated list back into the provider-shaped body.
    pub(crate) async fn guard_input(
        &mut self,
        stage: &str,
        body: &serde_json::Value,
    ) -> Result<Option<Vec<AiExtensionMessage>>, AiExtensionBlock> {
        if !self.kinds.input {
            return Ok(None);
        }
        let messages = match canonical_input_messages(body) {
            Ok(messages) => messages,
            Err(()) if self.kinds.enforcing_input => {
                return Err(AiExtensionBlock::event_too_large());
            }
            Err(()) => {
                tracing::warn!("AI observation event exceeded its normalized input limit");
                return Ok(None);
            }
        };
        match self
            .dispatch(AiExtensionEventPayload::GuardrailInput {
                stage: bounded_id(stage),
                messages,
            })
            .await?
        {
            Some(AiExtensionEventPayload::GuardrailInput { messages, .. }) => Ok(Some(messages)),
            // Mutation preserves the payload kind by construction
            // (`apply_mutation` replaces content within its own
            // variant), so this arm is unreachable; failing closed
            // beats shipping input a hook believes it rewrote.
            Some(_) => Err(AiExtensionBlock::runtime_failure()),
            None => Ok(None),
        }
    }

    /// Returns the canonical output text a hook rewrote, or `None`
    /// when the output passed through unmodified. The caller owns
    /// splicing a mutated text back into the provider-shaped body and
    /// refusing when that splice is not representable.
    pub(crate) async fn guard_output(
        &mut self,
        body: &[u8],
    ) -> Result<Option<String>, AiExtensionBlock> {
        if !self.kinds.output {
            return Ok(None);
        }
        let Some(content) = canonical_output_text(body) else {
            return Ok(None);
        };
        if content.len() > MAX_EVENT_TEXT_BYTES {
            if self.kinds.enforcing_output {
                return Err(AiExtensionBlock::event_too_large());
            }
            tracing::warn!("AI output observation exceeded its normalized event limit");
            return Ok(None);
        }
        match self
            .dispatch(AiExtensionEventPayload::GuardrailOutput { content })
            .await?
        {
            Some(AiExtensionEventPayload::GuardrailOutput { content }) => Ok(Some(content)),
            // See `guard_input`: kind-preserving by construction.
            Some(_) => Err(AiExtensionBlock::runtime_failure()),
            None => Ok(None),
        }
    }

    /// Record and enforce normalized hub chunks before their wire frames ship.
    pub(crate) async fn stream_chunks(
        &mut self,
        chunks: &[HubChunk],
    ) -> Result<(), AiExtensionBlock> {
        for chunk in chunks {
            let event = match chunk {
                HubChunk::MessageStart { model, .. } => {
                    self.model = Some(bounded_id(model));
                    Some(AiExtensionStreamChunk::MessageStart)
                }
                HubChunk::ContentDelta {
                    index,
                    delta: ContentPartDelta::Text(text),
                } => {
                    if text.len() > MAX_EVENT_TEXT_BYTES {
                        if self.kinds.enforcing_stream {
                            return Err(AiExtensionBlock::event_too_large());
                        }
                        tracing::warn!("AI stream observation delta exceeded its event limit");
                        None
                    } else {
                        self.stats.content_bytes = self
                            .stats
                            .content_bytes
                            .saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
                        self.stats.content_delta_count =
                            self.stats.content_delta_count.saturating_add(1);
                        Some(AiExtensionStreamChunk::ContentDelta {
                            index: *index,
                            text: text.clone(),
                        })
                    }
                }
                HubChunk::Usage(usage) => {
                    self.stats.prompt_tokens = Some(usage.prompt_tokens);
                    self.stats.completion_tokens = Some(usage.completion_tokens);
                    Some(AiExtensionStreamChunk::Usage {
                        prompt_tokens: usage.prompt_tokens,
                        completion_tokens: usage.completion_tokens,
                        total_tokens: usage.total_tokens,
                    })
                }
                HubChunk::MessageStop { finish_reason } => {
                    let reason = finish_reason_label(finish_reason);
                    self.stats.finish_reason = Some(reason.clone());
                    Some(AiExtensionStreamChunk::MessageStop {
                        finish_reason: reason,
                    })
                }
                HubChunk::ToolCallDelta { .. } => None,
            };
            if self.kinds.stream {
                if let Some(chunk) = event {
                    let mutated = self
                        .dispatch(AiExtensionEventPayload::Stream { chunk })
                        .await?;
                    self.expect_unmutated(mutated)?;
                }
            }
        }
        Ok(())
    }

    /// Enforce complete tool calls before held frames are released.
    pub(crate) async fn tool_calls(
        &mut self,
        calls: &[CompletedToolCall],
    ) -> Result<(), AiExtensionBlock> {
        self.stats.tool_call_count = self
            .stats
            .tool_call_count
            .saturating_add(u64::try_from(calls.len()).unwrap_or(u64::MAX));
        if !self.kinds.tool {
            return Ok(());
        }
        for call in calls {
            if call.args_json.len() > MAX_EVENT_TEXT_BYTES {
                if self.kinds.enforcing_tool {
                    return Err(AiExtensionBlock::event_too_large());
                }
                tracing::warn!("AI tool-call observation exceeded its event limit");
                continue;
            }
            let mutated = self
                .dispatch(AiExtensionEventPayload::ToolCall {
                    call: AiExtensionToolCall {
                        index: call.index,
                        id: call.id.as_deref().map(bounded_id),
                        name: bounded_id(&call.name),
                        arguments_json: call.args_json.clone(),
                    },
                })
                .await?;
            self.expect_unmutated(mutated)?;
        }
        Ok(())
    }

    /// Report a failed upstream call to any `ai.failure` hooks.
    ///
    /// The one point on the AI chain that had no hook at all, so a
    /// provider error was observed by nothing: an operator could not
    /// rewrite it into a house-standard shape, attribute it to a
    /// tenant, or drive a fallback from a policy.
    ///
    /// A verdict here cannot change the outcome. The call already
    /// failed, and a hook that blocks a failure is asking to turn one
    /// error into a different one, so the dispatch result is recorded
    /// and discarded rather than propagated. That keeps this event
    /// purely additive, which is what lets it ship ahead of hook
    /// mutation.
    pub(crate) async fn failure(
        &mut self,
        cause: sbproxy_plugin::AiFailureCause,
        status: Option<u16>,
        provider: Option<&str>,
        message: &str,
    ) {
        if !self.kinds.failure {
            return;
        }
        let _ = self
            .dispatch(AiExtensionEventPayload::Failure {
                cause,
                status,
                provider: provider.map(bounded_id),
                message: bounded_id(message),
            })
            .await;
    }

    /// Emit close metadata once and finish runtime contexts.
    pub(crate) async fn close(&mut self) -> Result<(), AiExtensionBlock> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let decision = if self.kinds.close {
            self.dispatch(AiExtensionEventPayload::Close {
                finish_reason: self.stats.finish_reason.clone(),
                content_bytes: self.stats.content_bytes,
                content_delta_count: self.stats.content_delta_count,
                tool_call_count: self.stats.tool_call_count,
                prompt_tokens: self.stats.prompt_tokens,
                completion_tokens: self.stats.completion_tokens,
            })
            .await
            .map(|_| ())
        } else {
            Ok(())
        };
        let finish = self
            .session
            .finish()
            .map_err(|_| AiExtensionBlock::runtime_failure());
        decision.and(finish)
    }

    /// Dispatch one event; `Ok(Some(payload))` is the payload after a
    /// hook rewrote it, `Ok(None)` an unmodified release.
    ///
    /// Identity stays immune to mutation by construction: the host
    /// builds the event here, hooks can only rewrite its payload
    /// content, and the returned value is the payload alone, so a
    /// guest that echoes back `sequence` or `request_id` changes
    /// nothing.
    async fn dispatch(
        &mut self,
        payload: AiExtensionEventPayload,
    ) -> Result<Option<AiExtensionEventPayload>, AiExtensionBlock> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(AiExtensionBlock::runtime_failure)?;
        let mut event = AiExtensionEvent {
            schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
            sequence: self.sequence,
            request_id: self.request_id.clone(),
            model: self.model.clone(),
            payload,
        };
        match self.session.dispatch(&mut event).await {
            Ok(AiChainVerdict::Release) => Ok(None),
            Ok(AiChainVerdict::Mutated) => Ok(Some(event.payload)),
            Ok(AiChainVerdict::Block {
                status,
                code,
                message,
            }) => Err(AiExtensionBlock {
                status,
                code,
                message,
            }),
            Err(error) => {
                tracing::warn!(error = %error, "enforcing AI extension hook failed");
                Err(AiExtensionBlock::runtime_failure())
            }
        }
    }

    /// Refuse a mutation on a seam with no write-back.
    ///
    /// Config validation refuses `mutates: true` on stream and
    /// tool-call hooks precisely because their wire frames have no
    /// write-back yet, so this cannot fire today. If that invariant
    /// ever breaks, the failure mode to prevent is shipping original
    /// bytes behind a hook that believes it rewrote them, so the seam
    /// fails closed rather than logging and continuing.
    #[allow(clippy::unused_self)] // reads as a seam method at call sites
    fn expect_unmutated(
        &self,
        mutated: Option<AiExtensionEventPayload>,
    ) -> Result<(), AiExtensionBlock> {
        if mutated.is_some() {
            tracing::error!(
                "AI extension mutation reached a host seam with no write-back; refusing"
            );
            return Err(AiExtensionBlock::runtime_failure());
        }
        Ok(())
    }
}

fn bounded_id(value: &str) -> String {
    if value.len() <= MAX_EVENT_ID_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_EVENT_ID_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn canonical_output_text(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    if serde_json::from_str::<serde_json::Value>(text).is_ok() {
        sbproxy_ai::guardrails::assistant_response_text(text)
    } else {
        Some(text.to_owned())
    }
}

fn finish_reason_label(reason: &FinishReason) -> String {
    match reason {
        FinishReason::Stop => "stop".to_owned(),
        FinishReason::Length => "length".to_owned(),
        FinishReason::ToolCalls => "tool_calls".to_owned(),
        FinishReason::ContentFilter => "content_filter".to_owned(),
        FinishReason::Other(reason) => bounded_id(reason),
    }
}

fn canonical_input_messages(body: &serde_json::Value) -> Result<Vec<AiExtensionMessage>, ()> {
    if let Some(messages) = body.get("messages").and_then(serde_json::Value::as_array) {
        return messages
            .iter()
            .map(canonical_message)
            .take(MAX_EVENT_MESSAGES + 1)
            .collect::<Result<Vec<_>, _>>()
            .and_then(limit_messages);
    }
    if let Some(input) = body.get("input") {
        if let Some(text) = input.as_str() {
            return Ok(vec![user_message(text)?]);
        }
        if let Some(messages) = input.as_array() {
            return messages
                .iter()
                .map(canonical_message)
                .take(MAX_EVENT_MESSAGES + 1)
                .collect::<Result<Vec<_>, _>>()
                .and_then(limit_messages);
        }
    }
    for field in ["prompt", "query"] {
        if let Some(text) = body.get(field).and_then(serde_json::Value::as_str) {
            return Ok(vec![user_message(text)?]);
        }
    }
    Ok(Vec::new())
}

fn limit_messages(messages: Vec<AiExtensionMessage>) -> Result<Vec<AiExtensionMessage>, ()> {
    (messages.len() <= MAX_EVENT_MESSAGES)
        .then_some(messages)
        .ok_or(())
}

fn user_message(content: &str) -> Result<AiExtensionMessage, ()> {
    Ok(AiExtensionMessage {
        role: AiExtensionRole::User,
        content: bounded_text(content)?,
        name: None,
        tool_call_id: None,
    })
}

fn canonical_message(value: &serde_json::Value) -> Result<AiExtensionMessage, ()> {
    let role = match value
        .get("role")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("user")
    {
        "system" | "developer" => AiExtensionRole::System,
        "assistant" => AiExtensionRole::Assistant,
        "tool" | "function" => AiExtensionRole::Tool,
        _ => AiExtensionRole::User,
    };
    let content = value
        .get("content")
        .and_then(content_text)
        .or_else(|| {
            value
                .get("text")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    Ok(AiExtensionMessage {
        role,
        content: bounded_text(&content)?,
        name: value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(bounded_id),
        tool_call_id: value
            .get("tool_call_id")
            .and_then(serde_json::Value::as_str)
            .map(bounded_id),
    })
}

/// Splice a hook-rewritten canonical message list back into the
/// provider-shaped request body.
///
/// The canonical view is lossy: [`AiExtensionMessage`] carries no
/// `tool_calls`, drops non-text content parts, and folds provider role
/// spellings (`developer`, `function`) into their canonical roles.
/// Reconstructing the body from it would therefore destroy fields the
/// hook never touched. The original body stays authoritative instead,
/// and only the content of messages the hook actually changed is
/// spliced in, by position:
///
/// - message identity must be unchanged: same count, same roles, same
///   `name` and `tool_call_id` per position; a rewrite that adds,
///   removes, reorders, or relabels messages refuses;
/// - a message whose content is unchanged is left byte-for-byte alone,
///   `tool_calls`, image parts, and provider role spellings included;
/// - a changed message's text lands in the one slot its canonical
///   content came from (a string `content`, the single text part of a
///   parts array, or a bare `text` field); a changed message with
///   several text parts has no single slot for the joined replacement
///   and refuses.
///
/// `Some(block)` is the refusal; shipping the original behind a hook
/// that believes it rewrote the input is the outcome it prevents.
pub(crate) fn write_mutated_input_messages(
    body: &mut serde_json::Value,
    mutated: &[AiExtensionMessage],
) -> Option<AiExtensionBlock> {
    let refuse = || Some(AiExtensionBlock::mutation_unrepresentable());
    let Ok(original) = canonical_input_messages(body) else {
        return refuse();
    };
    if original.len() != mutated.len() {
        return refuse();
    }
    if original
        .iter()
        .zip(mutated)
        .any(|(o, m)| o.role != m.role || o.name != m.name || o.tool_call_id != m.tool_call_id)
    {
        return refuse();
    }
    let changed: Vec<(usize, &str)> = original
        .iter()
        .zip(mutated)
        .enumerate()
        .filter(|(_, (o, m))| o.content != m.content)
        .map(|(index, (_, m))| (index, m.content.as_str()))
        .collect();
    if changed.is_empty() {
        return None;
    }
    // Locate the array or single-string field the canonical view was
    // built from, in exactly `canonical_input_messages`' shape order.
    if let Some(messages) = body
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
    {
        return splice_changed_entries(messages, &changed);
    }
    if let Some(input) = body.get_mut("input") {
        if let Some(entries) = input.as_array_mut() {
            return splice_changed_entries(entries, &changed);
        }
        if input.is_string() {
            // A single user message by construction (identity matched
            // above against the canonical single-message view).
            *input = serde_json::Value::String(changed[0].1.to_owned());
            return None;
        }
    }
    for field in ["prompt", "query"] {
        if body.get(field).is_some_and(serde_json::Value::is_string) {
            body[field] = serde_json::Value::String(changed[0].1.to_owned());
            return None;
        }
    }
    refuse()
}

fn splice_changed_entries(
    entries: &mut [serde_json::Value],
    changed: &[(usize, &str)],
) -> Option<AiExtensionBlock> {
    for (index, content) in changed {
        let representable = entries
            .get_mut(*index)
            .is_some_and(|entry| splice_entry_content(entry, content));
        if !representable {
            return Some(AiExtensionBlock::mutation_unrepresentable());
        }
    }
    None
}

/// Write replacement text into the one slot this entry's canonical
/// content was read from, mirroring `canonical_message`: `content` as
/// a string, `content` as a parts array (text parts joined), then a
/// bare `text` field. Only entries the hook changed reach here, so a
/// multi-text-part refusal never blocks a message that was left alone.
fn splice_entry_content(entry: &mut serde_json::Value, content: &str) -> bool {
    if let Some(slot) = entry.get_mut("content") {
        match slot {
            serde_json::Value::String(text) => {
                *text = content.to_owned();
                return true;
            }
            serde_json::Value::Array(parts) => {
                let mut text_parts = parts
                    .iter_mut()
                    .filter(|part| part.get("text").is_some_and(serde_json::Value::is_string));
                if let Some(first) = text_parts.next() {
                    if text_parts.next().is_some() {
                        // Several text parts were joined on extraction;
                        // the joined replacement has no single home.
                        return false;
                    }
                    first["text"] = serde_json::Value::String(content.to_owned());
                    return true;
                }
                // No text part: extraction fell through to the bare
                // `text` field below.
            }
            _ => {}
        }
    }
    if entry.get("text").is_some_and(serde_json::Value::is_string) {
        entry["text"] = serde_json::Value::String(content.to_owned());
        return true;
    }
    false
}

fn content_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(parts) => {
            let text = parts
                .iter()
                .filter_map(|part| part.get("text").and_then(serde_json::Value::as_str))
                .collect::<Vec<_>>();
            (!text.is_empty()).then(|| text.join("\n"))
        }
        _ => None,
    }
}

fn bounded_text(value: &str) -> Result<String, ()> {
    (value.len() <= MAX_EVENT_TEXT_BYTES)
        .then(|| value.to_owned())
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sbproxy_ai::format::{ContentPartDelta, FinishReason, HubChunk, HubUsage};
    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_extension::bundle::{AiExtensionChain, DynamicBundleRegistry};
    use sbproxy_plugin::{AiExtensionMessage, AiExtensionRole};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{canonical_input_messages, AiRequestExtensions};

    fn chain(manifest: &str, javascript: &str) -> (TempDir, AiExtensionChain) {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join("bundle.yaml"), manifest).unwrap();
        std::fs::write(bundle.join("entry.js"), javascript).unwrap();
        let registry = DynamicBundleRegistry::load(
            &ExtensionBundlesConfig {
                bundles_dir: Some(directory.path().display().to_string()),
                sources: Vec::new(),
            },
            directory.path(),
            &BTreeSet::new(),
        )
        .unwrap();
        let chain = AiExtensionChain::from_registry(registry.as_ref()).unwrap();
        (directory, chain)
    }

    #[test]
    fn canonical_input_messages_cover_chat_responses_and_prompt_shapes() {
        let chat = canonical_input_messages(&json!({
            "messages": [
                {"role": "system", "content": "rules"},
                {"role": "user", "content": [{"type": "text", "text": "hello"}]},
                {"role": "tool", "content": "result", "name": "lookup", "tool_call_id": "call-1"}
            ]
        }))
        .unwrap();
        assert_eq!(
            chat,
            vec![
                AiExtensionMessage {
                    role: AiExtensionRole::System,
                    content: "rules".to_owned(),
                    name: None,
                    tool_call_id: None,
                },
                AiExtensionMessage {
                    role: AiExtensionRole::User,
                    content: "hello".to_owned(),
                    name: None,
                    tool_call_id: None,
                },
                AiExtensionMessage {
                    role: AiExtensionRole::Tool,
                    content: "result".to_owned(),
                    name: Some("lookup".to_owned()),
                    tool_call_id: Some("call-1".to_owned()),
                },
            ]
        );

        let responses = canonical_input_messages(&json!({
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "question"}]}]
        }))
        .unwrap();
        assert_eq!(responses[0].content, "question");

        let prompt = canonical_input_messages(&json!({"prompt": "complete this"})).unwrap();
        assert_eq!(prompt[0].role, AiExtensionRole::User);
        assert_eq!(prompt[0].content, "complete this");
    }

    #[tokio::test]
    async fn enforcing_input_bundle_blocks_before_dispatch() {
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: input-block\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_guardrail_input\n    type: inspect_input\n    export: inspect\n",
            r#"export function inspect(input) { if (input.event.messages[0].content !== "blocked") throw new Error("wrong input"); return {version:"sbproxy-envelope/v1",decision:"block",status:422,code:"fixture_input",message:"fixture blocked"}; }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();

        let block = request
            .guard_input(
                "original",
                &json!({"messages": [{"role": "user", "content": "blocked"}]}),
            )
            .await
            .unwrap_err();
        assert_eq!(block.status, 422);
        assert_eq!(block.code, "fixture_input");
    }

    #[tokio::test]
    async fn close_bundle_receives_stream_aggregates() {
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: close-block\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_close\n    type: inspect_close\n    export: inspect\n",
            r#"export function inspect(input) { const e=input.event; if (e.content_bytes !== 5 || e.content_delta_count !== 1 || e.prompt_tokens !== 3 || e.completion_tokens !== 2 || e.finish_reason !== "stop") throw new Error("wrong aggregate"); return {version:"sbproxy-envelope/v1",decision:"block",status:409,code:"fixture_close",message:"fixture close"}; }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        request
            .stream_chunks(&[
                HubChunk::MessageStart {
                    id: "response-1".to_owned(),
                    model: "model-1".to_owned(),
                },
                HubChunk::ContentDelta {
                    index: 0,
                    delta: ContentPartDelta::Text("hello".to_owned()),
                },
                HubChunk::Usage(HubUsage {
                    prompt_tokens: 3,
                    completion_tokens: 2,
                    total_tokens: 5,
                }),
                HubChunk::MessageStop {
                    finish_reason: FinishReason::Stop,
                },
            ])
            .await
            .unwrap();

        let block = request.close().await.unwrap_err();
        assert_eq!(block.status, 409);
        assert_eq!(block.code, "fixture_close");
    }
}

#[cfg(test)]
mod input_splice_tests {
    use super::write_mutated_input_messages;
    use sbproxy_plugin::{AiExtensionMessage, AiExtensionRole};

    fn message(role: AiExtensionRole, content: &str) -> AiExtensionMessage {
        AiExtensionMessage {
            role,
            content: content.to_owned(),
            name: None,
            tool_call_id: None,
        }
    }

    /// The reviewer-found blocker case: a multi-turn tool-calling
    /// conversation with a developer-role message and an image part.
    /// Redacting one user message must not disturb any of it.
    #[test]
    fn splice_preserves_fields_the_canonical_view_cannot_carry() {
        let mut body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "developer", "content": "be safe"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call-1", "type": "function",
                     "function": {"name": "search", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call-1", "content": "result"},
                {"role": "user", "content": [
                    {"type": "text", "text": "my card is 4111"},
                    {"type": "image_url", "image_url": {"url": "https://example.test/x.png"}}
                ]}
            ],
            "temperature": 0.2,
        });
        let expected_untouched = body.clone();
        let mutated = [
            message(AiExtensionRole::System, "be safe"),
            message(AiExtensionRole::Assistant, ""),
            AiExtensionMessage {
                role: AiExtensionRole::Tool,
                content: "result".to_owned(),
                name: None,
                tool_call_id: Some("call-1".to_owned()),
            },
            message(AiExtensionRole::User, "my card is [REDACTED]"),
        ];
        assert!(write_mutated_input_messages(&mut body, &mutated).is_none());
        // Only the changed user message's text slot moved.
        assert_eq!(
            body["messages"][3]["content"][0]["text"],
            "my card is [REDACTED]"
        );
        // The image part survived next to it.
        assert_eq!(
            body["messages"][3]["content"][1],
            expected_untouched["messages"][3]["content"][1]
        );
        // Untouched messages are byte-identical: the developer role
        // spelling, the assistant's tool_calls, the tool linkage.
        assert_eq!(body["messages"][0], expected_untouched["messages"][0]);
        assert_eq!(body["messages"][1], expected_untouched["messages"][1]);
        assert_eq!(body["messages"][2], expected_untouched["messages"][2]);
        assert_eq!(body["temperature"], expected_untouched["temperature"]);
    }

    #[test]
    fn identity_changes_refuse() {
        let base = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "raw"}],
        });
        // Added message.
        let mut body = base.clone();
        assert!(write_mutated_input_messages(
            &mut body,
            &[
                message(AiExtensionRole::System, "injected"),
                message(AiExtensionRole::User, "raw"),
            ],
        )
        .is_some());
        // Removed message.
        let mut body = base.clone();
        assert!(write_mutated_input_messages(&mut body, &[]).is_some());
        // Relabeled role.
        let mut body = base.clone();
        assert!(write_mutated_input_messages(
            &mut body,
            &[message(AiExtensionRole::System, "raw")]
        )
        .is_some());
        // Every refusal left the body untouched.
        assert_eq!(body, base);
    }

    #[test]
    fn changed_multi_text_part_message_refuses_but_unchanged_one_passes() {
        // Two text parts joined on extraction have no single slot for
        // the joined replacement.
        let mut body = serde_json::json!({
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "a"},
                {"type": "text", "text": "b"}
            ]}],
        });
        assert!(write_mutated_input_messages(
            &mut body,
            &[message(AiExtensionRole::User, "clean")]
        )
        .is_some());
        // The same shape passes when the hook left it alone and changed
        // a different message (the joined canonical view of the two
        // text parts, with a newline between them).
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "a"},
                    {"type": "text", "text": "b"}
                ]},
                {"role": "user", "content": "raw"}
            ],
        });
        let mutated = [
            message(AiExtensionRole::User, "a\nb"),
            message(AiExtensionRole::User, "clean"),
        ];
        assert!(write_mutated_input_messages(&mut body, &mutated).is_none());
        assert_eq!(body["messages"][1]["content"], "clean");
        assert_eq!(body["messages"][0]["content"][1]["text"], "b");
    }

    #[test]
    fn single_string_shapes_splice_content_and_refuse_more() {
        for field in ["input", "prompt", "query"] {
            let mut body = serde_json::json!({"model": "m", field: "raw"});
            assert!(write_mutated_input_messages(
                &mut body,
                &[message(AiExtensionRole::User, "clean")]
            )
            .is_none());
            assert_eq!(body[field], "clean");

            let mut body = serde_json::json!({"model": "m", field: "raw"});
            let block = write_mutated_input_messages(
                &mut body,
                &[
                    message(AiExtensionRole::User, "clean"),
                    message(AiExtensionRole::User, "second"),
                ],
            )
            .expect("two messages cannot land in one string field");
            assert_eq!(block.code, "ai_extension_mutation_unrepresentable");
            assert_eq!(body[field], "raw");
        }
    }

    #[test]
    fn no_op_and_unknown_shapes() {
        // An identical list is a no-op, whatever the shape.
        let mut body = serde_json::json!({"model": "m", "embedding_input": ["a"]});
        let before = body.clone();
        assert!(write_mutated_input_messages(&mut body, &[]).is_none());
        assert_eq!(body, before);
        // A rewrite against a shape with no message list refuses.
        assert!(write_mutated_input_messages(
            &mut body,
            &[message(AiExtensionRole::User, "clean")]
        )
        .is_some());
    }
}

#[cfg(test)]
mod mutation_seam_tests {
    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_extension::bundle::{AiExtensionChain, DynamicBundleRegistry};
    use sbproxy_plugin::AiExtensionRole;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    use super::AiRequestExtensions;

    fn chain(manifest: &str, javascript: &str) -> (TempDir, AiExtensionChain) {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join("bundle.yaml"), manifest).unwrap();
        std::fs::write(bundle.join("entry.js"), javascript).unwrap();
        let registry = DynamicBundleRegistry::load(
            &ExtensionBundlesConfig {
                bundles_dir: Some(directory.path().display().to_string()),
                sources: Vec::new(),
            },
            directory.path(),
            &BTreeSet::new(),
        )
        .unwrap();
        let chain = AiExtensionChain::from_registry(registry.as_ref()).unwrap();
        (directory, chain)
    }

    #[tokio::test]
    async fn guard_output_returns_the_rewritten_text_to_its_caller() {
        // The seam by name: a mutating hook's text must come back out
        // of `guard_output`, because the pipeline caller is the one
        // that splices it into the provider-shaped body. A mutation
        // that stops inside the chain is indistinguishable from
        // inspect-only.
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: output-redactor
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_output
    type: redact_output
    export: redact
    execution:
      mutates: true
",
            // base64("clean text")
            r#"export function redact(input) { if (input.event.content !== "raw text") throw new Error("saw " + input.event.content); return {version:"sbproxy-envelope/v1",decision:"mutate",code:"redacted",body_base64:"Y2xlYW4gdGV4dA=="}; }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        let body = br#"{"choices":[{"message":{"role":"assistant","content":"raw text"}}]}"#;
        let mutated = request.guard_output(body).await.unwrap();
        assert_eq!(mutated.as_deref(), Some("clean text"));
    }

    #[tokio::test]
    async fn guard_output_without_a_mutation_returns_none() {
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: output-inspector
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_output
    type: inspect_output
    export: inspect
",
            r#"export function inspect() { return {version:"sbproxy-envelope/v1",decision:"release"}; }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        let body = br#"{"choices":[{"message":{"role":"assistant","content":"raw text"}}]}"#;
        assert_eq!(request.guard_output(body).await.unwrap(), None);
    }

    #[tokio::test]
    async fn guard_input_returns_the_rewritten_messages_to_its_caller() {
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: input-redactor
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_input
    type: redact_input
    export: redact
    execution:
      mutates: true
",
            // base64 of [{"role":"user","content":"clean question"}]
            r#"export function redact(input) { if (input.event.messages[0].content !== "raw question") throw new Error("saw " + input.event.messages[0].content); return {version:"sbproxy-envelope/v1",decision:"mutate",code:"redacted",body_base64:"W3sicm9sZSI6InVzZXIiLCJjb250ZW50IjoiY2xlYW4gcXVlc3Rpb24ifV0="}; }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        let body = serde_json::json!({
            "model": "model-1",
            "messages": [{"role": "user", "content": "raw question"}],
        });
        let mutated = request
            .guard_input("original", &body)
            .await
            .unwrap()
            .expect("the hook rewrote the messages");
        assert_eq!(mutated.len(), 1);
        assert_eq!(mutated[0].role, AiExtensionRole::User);
        assert_eq!(mutated[0].content, "clean question");
    }
}

#[cfg(test)]
mod failure_event_tests {
    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_extension::bundle::{AiExtensionChain, DynamicBundleRegistry};
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    use super::AiRequestExtensions;

    fn chain(manifest: &str, javascript: &str) -> (TempDir, AiExtensionChain) {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join("bundle.yaml"), manifest).unwrap();
        std::fs::write(bundle.join("entry.js"), javascript).unwrap();
        let registry = DynamicBundleRegistry::load(
            &ExtensionBundlesConfig {
                bundles_dir: Some(directory.path().display().to_string()),
                sources: Vec::new(),
            },
            directory.path(),
            &BTreeSet::new(),
        )
        .unwrap();
        let chain = AiExtensionChain::from_registry(registry.as_ref()).unwrap();
        (directory, chain)
    }

    #[tokio::test]
    async fn a_failure_hook_receives_the_classified_cause_and_not_provider_prose() {
        // The event carries a closed set so a hook branches on a cause
        // rather than pattern-matching provider text that changes
        // without notice. The hook asserts the shape itself and throws
        // if it is wrong, which surfaces as a block we then ignore.
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: failure-observer\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_failure\n    type: observe_failure\n    export: observe\n",
            r#"export function observe(input) {
                 const e = input.event;
                 if (e.cause !== "rate_limit") throw new Error("wrong cause: " + e.cause);
                 if (e.status !== 429) throw new Error("wrong status");
                 if (e.provider !== "openai") throw new Error("wrong provider");
                 return {version:"sbproxy-envelope/v1",decision:"release"};
               }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        request
            .failure(
                sbproxy_plugin::AiFailureCause::RateLimit,
                Some(429),
                Some("openai"),
                "rate_limit",
            )
            .await;
    }

    #[tokio::test]
    async fn a_blocking_failure_hook_cannot_change_the_outcome() {
        // The call already failed. A hook that blocks a failure is
        // asking to turn one error into a different one, so the verdict
        // is recorded and discarded. This is what keeps the event purely
        // additive and lets it ship ahead of hook mutation.
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: failure-blocker\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_failure\n    type: block_failure\n    export: refuse\n",
            r#"export function refuse() { return {version:"sbproxy-envelope/v1",decision:"block",status:418,code:"nope",message:"nope"}; }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        // Returns unit: there is no verdict for the caller to act on.
        request
            .failure(
                sbproxy_plugin::AiFailureCause::ServerError,
                Some(500),
                Some("anthropic"),
                "server_error",
            )
            .await;
    }

    #[tokio::test]
    async fn a_chain_without_a_failure_hook_does_not_dispatch() {
        // A bundle carrying only a close hook must not see failures.
        let (_directory, chain) = chain(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: close-only\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_close\n    type: inspect_close\n    export: inspect\n",
            r#"export function inspect() { throw new Error("a close hook must never see a failure event"); }"#,
        );
        let mut request = AiRequestExtensions::start(&chain, "request-1", "model-1").unwrap();
        request
            .failure(
                sbproxy_plugin::AiFailureCause::Timeout,
                None,
                None,
                "timeout",
            )
            .await;
    }
}
