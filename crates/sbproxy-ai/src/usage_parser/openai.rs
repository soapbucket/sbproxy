//! OpenAI SSE usage parser.
//!
//! OpenAI's chat-completions stream emits content deltas as
//! `data: {<json>}\n\n` frames followed by a terminal frame with a
//! top-level `usage` object reporting `prompt_tokens` and
//! `completion_tokens`, then `data: [DONE]`. This parser scans every
//! `data:` line and records the largest `(prompt, completion)` pair
//! it sees.
//!
//! Real-world streams may interleave keep-alive comments (`: ping`)
//! and frames without `usage`; both are silently ignored. JSON parse
//! failures are also ignored: a malformed upstream chunk must never
//! abort the relay.

use super::{feed_lines, SseUsageParser, UsageTokens};

/// SSE usage parser for OpenAI / Azure OpenAI chat completions.
#[derive(Debug, Default)]
pub struct OpenAiUsageParser {
    /// Bytes seen since the last newline. Carries trailing partial
    /// lines across chunk boundaries.
    line_buf: Vec<u8>,
    /// Largest `prompt_tokens` observed so far.
    prompt_tokens: u32,
    /// Largest `completion_tokens` observed so far.
    completion_tokens: u32,
    /// True once at least one usage block has been parsed. Used so
    /// `snapshot()` returns `None` when no usage was ever seen.
    saw_usage: bool,
}

impl OpenAiUsageParser {
    /// Construct an empty parser.
    pub fn new() -> Self {
        Self {
            line_buf: Vec::with_capacity(1024),
            prompt_tokens: 0,
            completion_tokens: 0,
            saw_usage: false,
        }
    }

    /// Parse a single completed SSE line.
    fn process_line(&mut self, line: &[u8]) {
        let line = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => return,
        };
        let payload = match line.strip_prefix("data:") {
            Some(rest) => rest.trim_start(),
            None => return,
        };
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        let parsed: serde_json::Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => return,
        };
        let usage = match parsed.get("usage") {
            Some(u) => u,
            None => return,
        };
        // OpenAI shape uses `prompt_tokens` / `completion_tokens`.
        // We accept the Anthropic spelling too so this parser is
        // resilient to shape drift on relay-style upstreams.
        let prompt = usage
            .get("prompt_tokens")
            .or_else(|| usage.get("input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completion = usage
            .get("completion_tokens")
            .or_else(|| usage.get("output_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if prompt == 0 && completion == 0 {
            return;
        }
        self.saw_usage = true;
        // Use max so a later, smaller `usage` does not overwrite a
        // fuller report.
        let prompt_u32 = u32_saturating(prompt);
        let completion_u32 = u32_saturating(completion);
        if prompt_u32 > self.prompt_tokens {
            self.prompt_tokens = prompt_u32;
        }
        if completion_u32 > self.completion_tokens {
            self.completion_tokens = completion_u32;
        }
    }
}

/// Saturating cast from u64 to u32 so a misbehaving upstream cannot
/// wrap the counter.
fn u32_saturating(v: u64) -> u32 {
    if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    }
}

impl SseUsageParser for OpenAiUsageParser {
    fn feed(&mut self, chunk: &[u8]) {
        // Borrow split: copy completed lines into a scratch buffer,
        // then process them after the loop. This sidesteps the
        // simultaneous &mut borrow of self.line_buf and self.
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
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
        })
    }

    fn provider(&self) -> &'static str {
        "openai"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_terminal_usage() {
        let mut p = OpenAiUsageParser::new();
        let body = b"data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
                     data: {\"id\":\"x\",\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":34,\"total_tokens\":46}}\n\n\
                     data: [DONE]\n\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 12,
                completion_tokens: 34,
            })
        );
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = OpenAiUsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":");
        assert!(p.snapshot().is_none(), "no full line yet");
        p.feed(b"5,\"completion_tokens\":9}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 5,
                completion_tokens: 9,
            })
        );
    }

    #[test]
    fn ignores_done_and_keepalive() {
        let mut p = OpenAiUsageParser::new();
        p.feed(b": ping\n\ndata: [DONE]\n\ndata: not-json\n\n");
        assert!(p.snapshot().is_none());
    }

    #[test]
    fn picks_max_across_multiple_usage_blocks() {
        let mut p = OpenAiUsageParser::new();
        // First usage frame reports lower numbers (e.g. partial), the
        // second reports higher. Max-of must win.
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}\n\n");
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":42}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 3,
                completion_tokens: 42,
            })
        );
    }

    #[test]
    fn provider_tag_is_openai() {
        assert_eq!(OpenAiUsageParser::new().provider(), "openai");
    }

    #[test]
    fn snapshot_none_on_empty_stream() {
        let p = OpenAiUsageParser::new();
        assert!(p.snapshot().is_none());
    }
}
