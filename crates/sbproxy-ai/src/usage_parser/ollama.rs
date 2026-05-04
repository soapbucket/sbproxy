//! Ollama line-delimited JSON usage parser.
//!
//! Ollama's `/api/chat` and `/api/generate` endpoints emit
//! line-delimited JSON (NDJSON), not SSE. Each line is a complete
//! JSON object describing one streaming step. The terminal line
//! sets `done: true` and carries `prompt_eval_count` (input tokens)
//! and `eval_count` (output tokens). Earlier lines do not carry
//! eval counts.
//!
//! The parser scans every JSON line and records the largest
//! `(prompt_eval_count, eval_count)` pair it sees. We do not gate on
//! `done: true` so a stream that closes early without the terminal
//! `done` flag still produces a best-effort snapshot.

use super::{feed_lines, SseUsageParser, UsageTokens};

/// Usage parser for Ollama NDJSON streams.
#[derive(Debug, Default)]
pub struct OllamaUsageParser {
    line_buf: Vec<u8>,
    prompt_tokens: u32,
    completion_tokens: u32,
    saw_usage: bool,
}

impl OllamaUsageParser {
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
        // NDJSON lines are bare JSON objects, not `data:` framed.
        let line = match std::str::from_utf8(line) {
            Ok(s) => s.trim(),
            Err(_) => return,
        };
        if line.is_empty() || !line.starts_with('{') {
            return;
        }
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return,
        };
        let prompt = parsed
            .get("prompt_eval_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completion = parsed
            .get("eval_count")
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

impl SseUsageParser for OllamaUsageParser {
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
        "ollama"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_terminal_done_line() {
        let mut p = OllamaUsageParser::new();
        let body = b"{\"model\":\"llama3\",\"message\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"done\":false}\n\
                     {\"model\":\"llama3\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"prompt_eval_count\":21,\"eval_count\":34,\"total_duration\":1234}\n";
        p.feed(body);
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 21,
                completion_tokens: 34,
            })
        );
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = OllamaUsageParser::new();
        p.feed(b"{\"done\":true,\"prompt_eval_count\":");
        assert!(p.snapshot().is_none());
        p.feed(b"7,\"eval_count\":11}\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 7,
                completion_tokens: 11,
            })
        );
    }

    #[test]
    fn ignores_lines_without_eval_counts() {
        let mut p = OllamaUsageParser::new();
        p.feed(b"{\"model\":\"llama3\",\"message\":{\"content\":\"x\"},\"done\":false}\n");
        assert!(p.snapshot().is_none());
    }

    #[test]
    fn provider_tag_is_ollama() {
        assert_eq!(OllamaUsageParser::new().provider(), "ollama");
    }
}
