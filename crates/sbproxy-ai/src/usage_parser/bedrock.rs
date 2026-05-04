//! AWS Bedrock SSE usage parser.
//!
//! Bedrock fronts a handful of model providers (Anthropic, Cohere,
//! Amazon Titan, Mistral) and wraps every model-native streaming
//! chunk in a JSON envelope of the shape:
//!
//! ```json
//! {"bytes": "<base64-of-inner-json>"}
//! ```
//!
//! The inner JSON is the model's native chunk shape (e.g. an
//! Anthropic `message_delta` event). For the OSS parser we focus on
//! the dominant case (Anthropic via Bedrock). The decoded inner
//! payload is fed line-by-line into an embedded
//! [`super::anthropic::AnthropicUsageParser`] so the same max-of
//! logic applies.
//!
//! Bedrock streams use AWS's vendored SSE shape but operators
//! commonly proxy them as flat `data: {...}` lines. We accept both:
//! `data:`-prefixed lines and bare JSON object lines are both
//! candidates for envelope decode.

use super::{feed_lines, AnthropicUsageParser, SseUsageParser, UsageTokens};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// SSE usage parser for AWS Bedrock streams.
#[derive(Debug, Default)]
pub struct BedrockUsageParser {
    line_buf: Vec<u8>,
    inner: AnthropicUsageParser,
}

impl BedrockUsageParser {
    /// Construct an empty parser.
    pub fn new() -> Self {
        Self {
            line_buf: Vec::with_capacity(1024),
            inner: AnthropicUsageParser::new(),
        }
    }

    /// Decode a single Bedrock envelope line and feed the inner
    /// payload to the Anthropic parser.
    fn process_line(&mut self, line: &[u8]) {
        let line = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => return,
        };
        // Accept `data: {...}` or bare `{...}`. Bedrock framing
        // varies between SDKs.
        let payload = line
            .strip_prefix("data:")
            .map(|s| s.trim_start())
            .unwrap_or(line)
            .trim();
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        let parsed: serde_json::Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => return,
        };
        // The envelope's `bytes` field is the base64-encoded inner
        // chunk. If absent, the line is either a heartbeat or some
        // shape we don't recognise; ignore it.
        let encoded = match parsed.get("bytes").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return,
        };
        let decoded = match STANDARD.decode(encoded) {
            Ok(b) => b,
            Err(_) => return,
        };
        // The decoded payload is the model-native chunk JSON. For
        // Anthropic-on-Bedrock that's a single event object like
        // `{"type":"message_delta","usage":{"output_tokens":42}}`.
        // Wrap it as a synthetic SSE `data:` line so the inner
        // parser's existing line shape is satisfied.
        let mut synthetic = Vec::with_capacity(decoded.len() + 6);
        synthetic.extend_from_slice(b"data: ");
        synthetic.extend_from_slice(&decoded);
        self.inner.process_decoded_line(&synthetic);
    }
}

impl SseUsageParser for BedrockUsageParser {
    fn feed(&mut self, chunk: &[u8]) {
        let mut completed: Vec<Vec<u8>> = Vec::new();
        feed_lines(&mut self.line_buf, chunk, |line| {
            completed.push(line.to_vec());
        });
        for line in &completed {
            self.process_line(line);
        }
    }

    fn snapshot(&self) -> Option<UsageTokens> {
        self.inner.snapshot()
    }

    fn provider(&self) -> &'static str {
        "bedrock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        STANDARD.encode(s.as_bytes())
    }

    #[test]
    fn decodes_anthropic_inner_chunks() {
        let mut p = BedrockUsageParser::new();
        // Simulate two Bedrock envelopes carrying Anthropic events.
        let start =
            b64(r#"{"type":"message_start","usage":{"input_tokens":17,"output_tokens":0}}"#);
        let delta = b64(r#"{"type":"message_delta","usage":{"output_tokens":99}}"#);
        let body = format!(
            "data: {{\"bytes\":\"{}\"}}\n\ndata: {{\"bytes\":\"{}\"}}\n\n",
            start, delta
        );
        p.feed(body.as_bytes());
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 17,
                completion_tokens: 99,
            })
        );
    }

    #[test]
    fn handles_bare_json_lines_without_data_prefix() {
        let mut p = BedrockUsageParser::new();
        let inner =
            b64(r#"{"type":"message_delta","usage":{"input_tokens":4,"output_tokens":12}}"#);
        let body = format!("{{\"bytes\":\"{}\"}}\n", inner);
        p.feed(body.as_bytes());
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 4,
                completion_tokens: 12,
            })
        );
    }

    #[test]
    fn ignores_envelope_without_bytes_field() {
        let mut p = BedrockUsageParser::new();
        p.feed(b"data: {\"hello\":\"world\"}\n\n");
        assert!(p.snapshot().is_none());
    }

    #[test]
    fn ignores_invalid_base64() {
        let mut p = BedrockUsageParser::new();
        p.feed(b"data: {\"bytes\":\"not-base64-!!\"}\n\n");
        assert!(p.snapshot().is_none());
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = BedrockUsageParser::new();
        let inner = b64(r#"{"type":"message_delta","usage":{"input_tokens":2,"output_tokens":3}}"#);
        let line = format!("data: {{\"bytes\":\"{}\"}}\n\n", inner);
        let bytes = line.as_bytes();
        let mid = bytes.len() / 2;
        p.feed(&bytes[..mid]);
        assert!(p.snapshot().is_none());
        p.feed(&bytes[mid..]);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 2,
                completion_tokens: 3,
            })
        );
    }

    #[test]
    fn provider_tag_is_bedrock() {
        assert_eq!(BedrockUsageParser::new().provider(), "bedrock");
    }
}
