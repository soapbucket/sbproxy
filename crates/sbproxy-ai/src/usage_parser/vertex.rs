//! Vertex AI / Gemini SSE usage parser.
//!
//! Vertex's `streamGenerateContent` returns SSE frames where each
//! `data:` payload is a `GenerateContentResponse` JSON object. The
//! `usageMetadata` field carries `promptTokenCount` and
//! `candidatesTokenCount` (output) plus `totalTokenCount`. Unlike
//! Anthropic, Vertex repeats `usageMetadata` on every chunk; the
//! values grow monotonically as the response is generated, so
//! max-of yields the final totals.

use super::{feed_lines, SseUsageParser, UsageTokens};

/// SSE usage parser for Vertex AI / Gemini streamGenerateContent.
#[derive(Debug, Default)]
pub struct VertexUsageParser {
    line_buf: Vec<u8>,
    prompt_tokens: u32,
    completion_tokens: u32,
    saw_usage: bool,
}

impl VertexUsageParser {
    /// Construct an empty parser.
    pub fn new() -> Self {
        Self {
            line_buf: Vec::with_capacity(1024),
            prompt_tokens: 0,
            completion_tokens: 0,
            saw_usage: false,
        }
    }

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
        let meta = match parsed.get("usageMetadata") {
            Some(m) => m,
            None => return,
        };
        let prompt = meta
            .get("promptTokenCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Vertex names output `candidatesTokenCount`; some
        // pre-release shapes used `outputTokenCount`. Accept both.
        let completion = meta
            .get("candidatesTokenCount")
            .or_else(|| meta.get("outputTokenCount"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if prompt == 0 && completion == 0 {
            return;
        }
        self.saw_usage = true;
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

fn u32_saturating(v: u64) -> u32 {
    if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    }
}

impl SseUsageParser for VertexUsageParser {
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
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
        })
    }

    fn provider(&self) -> &'static str {
        "vertex"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_terminal_usage_metadata() {
        // Real Vertex shape: chunks each carry `usageMetadata`,
        // values grow until the final chunk.
        let mut p = VertexUsageParser::new();
        let body = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}],\"usageMetadata\":{\"promptTokenCount\":11,\"candidatesTokenCount\":2,\"totalTokenCount\":13}}\n\n\
                     data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}]}}],\"usageMetadata\":{\"promptTokenCount\":11,\"candidatesTokenCount\":4,\"totalTokenCount\":15}}\n\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 11,
                completion_tokens: 4,
            })
        );
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = VertexUsageParser::new();
        p.feed(b"data: {\"usageMetadata\":{\"promptTokenCount\":");
        assert!(p.snapshot().is_none());
        p.feed(b"7,\"candidatesTokenCount\":13}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 7,
                completion_tokens: 13,
            })
        );
    }

    #[test]
    fn accepts_pre_release_output_token_count() {
        let mut p = VertexUsageParser::new();
        let body = b"data: {\"usageMetadata\":{\"promptTokenCount\":3,\"outputTokenCount\":4}}\n\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 3,
                completion_tokens: 4,
            })
        );
    }

    #[test]
    fn provider_tag_is_vertex() {
        assert_eq!(VertexUsageParser::new().provider(), "vertex");
    }

    #[test]
    fn snapshot_none_on_empty_stream() {
        assert!(VertexUsageParser::new().snapshot().is_none());
    }

    #[test]
    fn ignores_chunks_without_usage_metadata() {
        let mut p = VertexUsageParser::new();
        p.feed(b"data: {\"candidates\":[{\"content\":{}}]}\n\n");
        assert!(p.snapshot().is_none());
    }
}
