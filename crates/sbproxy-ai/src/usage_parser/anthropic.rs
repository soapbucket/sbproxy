//! Anthropic SSE usage parser.
//!
//! Anthropic streams emit usage in two events:
//! * `message_start` carries `usage.input_tokens` (and a placeholder
//!   `output_tokens: 0`).
//! * `message_delta` carries the final `usage.output_tokens`.
//!
//! The parser keeps the largest values it has seen so the post-stream
//! snapshot reflects the final totals from either shape, regardless of
//! which event arrives first.

use super::{feed_lines, SseUsageParser, UsageTokens};

/// SSE usage parser for Anthropic Messages API.
#[derive(Debug, Default)]
pub struct AnthropicUsageParser {
    line_buf: Vec<u8>,
    input_tokens: u32,
    output_tokens: u32,
    saw_usage: bool,
}

impl AnthropicUsageParser {
    /// Construct an empty parser.
    pub fn new() -> Self {
        Self {
            line_buf: Vec::with_capacity(1024),
            input_tokens: 0,
            output_tokens: 0,
            saw_usage: false,
        }
    }

    /// Process one completed SSE line. Anthropic uses a mix of
    /// `event:` markers and `data:` payloads; the usage object lives
    /// at the top level of every event JSON that carries one, so we
    /// only need to parse `data:` lines.
    fn process_line(&mut self, line: &[u8]) {
        let line = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => return,
        };
        let payload = match line.strip_prefix("data:") {
            Some(rest) => rest.trim_start(),
            None => return,
        };
        if payload.is_empty() {
            return;
        }
        let parsed: serde_json::Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => return,
        };
        // Anthropic puts usage on the top-level `usage` field for
        // both `message_start` (input only) and `message_delta`
        // (output_tokens added). Some shapes nest under `message`
        // (e.g. `message_start` carries it under both); accept
        // either path.
        let usage = parsed
            .get("usage")
            .or_else(|| parsed.pointer("/message/usage"));
        let usage = match usage {
            Some(u) => u,
            None => return,
        };
        let input = usage
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let output = usage
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if input == 0 && output == 0 {
            return;
        }
        self.saw_usage = true;
        let input_u32 = u32_saturating(input);
        let output_u32 = u32_saturating(output);
        // Max-of so message_start's input doesn't get clobbered by
        // message_delta (which omits input_tokens).
        if input_u32 > self.input_tokens {
            self.input_tokens = input_u32;
        }
        if output_u32 > self.output_tokens {
            self.output_tokens = output_u32;
        }
    }

    /// Feed a single completed line directly. Used by
    /// [`super::bedrock::BedrockUsageParser`] which decodes envelope
    /// frames upstream and wants to pipe each inner SSE line into the
    /// Anthropic line parser without an extra newline split.
    pub(crate) fn process_decoded_line(&mut self, line: &[u8]) {
        self.process_line(line);
    }
}

fn u32_saturating(v: u64) -> u32 {
    if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    }
}

impl SseUsageParser for AnthropicUsageParser {
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
        if !self.saw_usage {
            return None;
        }
        Some(UsageTokens {
            prompt_tokens: self.input_tokens,
            completion_tokens: self.output_tokens,
        })
    }

    fn provider(&self) -> &'static str {
        "anthropic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_message_start_and_delta() {
        let mut p = AnthropicUsageParser::new();
        let body = b"event: message_start\n\
                     data: {\"type\":\"message_start\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}\n\n\
                     event: content_block_delta\n\
                     data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
                     event: message_delta\n\
                     data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 7,
                completion_tokens: 42,
            })
        );
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = AnthropicUsageParser::new();
        p.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":3,");
        assert!(p.snapshot().is_none());
        p.feed(b"\"output_tokens\":11}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 3,
                completion_tokens: 11,
            })
        );
    }

    #[test]
    fn nested_message_usage_is_picked_up() {
        // Some Anthropic shapes nest the usage object under
        // `message.usage` on `message_start`. The parser must walk
        // that path too.
        let mut p = AnthropicUsageParser::new();
        let body = b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":9,\"output_tokens\":0}}}\n\n";
        p.feed(body);
        // No top-level usage but nested path exists; parser should
        // still record input.
        assert_eq!(p.snapshot().map(|u| u.prompt_tokens), Some(9));
    }

    #[test]
    fn provider_tag_is_anthropic() {
        assert_eq!(AnthropicUsageParser::new().provider(), "anthropic");
    }

    #[test]
    fn snapshot_none_on_empty_stream() {
        assert!(AnthropicUsageParser::new().snapshot().is_none());
    }
}
