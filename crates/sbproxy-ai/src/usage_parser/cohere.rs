//! Cohere SSE usage parser.
//!
//! Cohere's `/v1/chat` streaming endpoint emits a sequence of events
//! tagged by an `event_type` discriminator on each JSON payload. The
//! terminal `stream-end` event carries the final token counts under
//! `response.meta.billed_units.input_tokens` and
//! `output_tokens`. Earlier `text-generation` events do not carry
//! usage and are ignored.
//!
//! Some Cohere SDKs use camelCase (`eventType`); we accept both. Some
//! payloads also nest billed units directly under `meta.billed_units`
//! without the `response` wrapper; we walk both paths.

use super::{feed_lines, SseUsageParser, UsageTokens};

/// SSE usage parser for Cohere chat streams.
#[derive(Debug, Default)]
pub struct CohereUsageParser {
    line_buf: Vec<u8>,
    prompt_tokens: u32,
    completion_tokens: u32,
    saw_usage: bool,
}

impl CohereUsageParser {
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
        // Cohere streams use `data: <json>` framing as well as bare
        // JSON object lines (depending on SDK). Accept both.
        let payload = line
            .strip_prefix("data:")
            .map(|s| s.trim_start())
            .unwrap_or(line)
            .trim();
        if payload.is_empty() || !payload.starts_with('{') {
            return;
        }
        let parsed: serde_json::Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => return,
        };
        // Look for `billed_units` in both `response.meta` and `meta`.
        let billed = parsed
            .pointer("/response/meta/billed_units")
            .or_else(|| parsed.pointer("/meta/billed_units"));
        let billed = match billed {
            Some(b) => b,
            None => return,
        };
        let prompt = billed
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completion = billed
            .get("output_tokens")
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

impl SseUsageParser for CohereUsageParser {
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
        "cohere"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_stream_end_billed_units() {
        let mut p = CohereUsageParser::new();
        // text-generation event (no usage), then stream-end with
        // billed_units. The parser must skip the first and pick up
        // the second.
        let body = b"data: {\"event_type\":\"text-generation\",\"text\":\"Hi\"}\n\n\
                     data: {\"event_type\":\"stream-end\",\"finish_reason\":\"COMPLETE\",\"response\":{\"meta\":{\"billed_units\":{\"input_tokens\":15,\"output_tokens\":7}}}}\n\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 15,
                completion_tokens: 7,
            })
        );
    }

    #[test]
    fn accepts_bare_meta_billed_units() {
        let mut p = CohereUsageParser::new();
        let body = b"data: {\"event_type\":\"stream-end\",\"meta\":{\"billed_units\":{\"input_tokens\":3,\"output_tokens\":5}}}\n\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 3,
                completion_tokens: 5,
            })
        );
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = CohereUsageParser::new();
        let body = b"data: {\"event_type\":\"stream-end\",\"meta\":{\"billed_units\":{\"input_tokens\":4,\"output_tokens\":";
        p.feed(body);
        assert!(p.snapshot().is_none());
        p.feed(b"6}}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 4,
                completion_tokens: 6,
            })
        );
    }

    #[test]
    fn ignores_text_generation_only_streams() {
        let mut p = CohereUsageParser::new();
        p.feed(b"data: {\"event_type\":\"text-generation\",\"text\":\"hello\"}\n\n");
        p.feed(b"data: {\"event_type\":\"text-generation\",\"text\":\" world\"}\n\n");
        assert!(p.snapshot().is_none());
    }

    #[test]
    fn provider_tag_is_cohere() {
        assert_eq!(CohereUsageParser::new().provider(), "cohere");
    }
}
