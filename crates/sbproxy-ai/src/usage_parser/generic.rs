//! Generic SSE usage parser.
//!
//! Best-effort fallback for upstreams whose shape is not pinned at
//! config time. The parser scans each `data:` line for any of the
//! well-known usage object keys (OpenAI's `prompt_tokens` /
//! `completion_tokens`, Anthropic's `input_tokens` /
//! `output_tokens`, Vertex's `usageMetadata`, Cohere's
//! `billed_units`, Ollama's `prompt_eval_count` / `eval_count`) and
//! takes the first match. Failures are silent: a line with no
//! usable fields is dropped on the floor.
//!
//! `auto` resolves to this parser when no host or content-type hint
//! identifies a known upstream. Operators who route through a
//! middlebox or a self-hosted gateway can either rely on `generic`
//! or pin the parser explicitly.

use super::{feed_lines, SseUsageParser, UsageTokens};

/// Multi-shape SSE usage parser.
#[derive(Debug, Default)]
pub struct GenericUsageParser {
    line_buf: Vec<u8>,
    prompt_tokens: u32,
    completion_tokens: u32,
    saw_usage: bool,
}

impl GenericUsageParser {
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
        // Accept `data: {...}` (SSE) or bare `{...}` (NDJSON) lines.
        let payload = line
            .strip_prefix("data:")
            .map(|s| s.trim_start())
            .unwrap_or(line)
            .trim();
        if payload.is_empty() || payload == "[DONE]" || !payload.starts_with('{') {
            return;
        }
        let parsed: serde_json::Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => return,
        };
        let (prompt, completion) = extract_usage(&parsed);
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

/// Pull `(prompt_tokens, completion_tokens)` from any of the
/// well-known shapes. Order matters: we try the most-specific shape
/// first so a payload that happens to also carry an Anthropic-style
/// alias does not double-count.
fn extract_usage(v: &serde_json::Value) -> (u64, u64) {
    // OpenAI shape: top-level `usage.prompt_tokens` /
    // `usage.completion_tokens`.
    if let Some(usage) = v.get("usage") {
        let prompt = usage
            .get("prompt_tokens")
            .or_else(|| usage.get("input_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let completion = usage
            .get("completion_tokens")
            .or_else(|| usage.get("output_tokens"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        if prompt > 0 || completion > 0 {
            return (prompt, completion);
        }
    }
    // Vertex: `usageMetadata`.
    if let Some(meta) = v.get("usageMetadata") {
        let prompt = meta
            .get("promptTokenCount")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let completion = meta
            .get("candidatesTokenCount")
            .or_else(|| meta.get("outputTokenCount"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        if prompt > 0 || completion > 0 {
            return (prompt, completion);
        }
    }
    // Cohere: `response.meta.billed_units` or `meta.billed_units`.
    if let Some(billed) = v
        .pointer("/response/meta/billed_units")
        .or_else(|| v.pointer("/meta/billed_units"))
    {
        let prompt = billed
            .get("input_tokens")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let completion = billed
            .get("output_tokens")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        if prompt > 0 || completion > 0 {
            return (prompt, completion);
        }
    }
    // Ollama: top-level `prompt_eval_count` + `eval_count`.
    let prompt = v
        .get("prompt_eval_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let completion = v.get("eval_count").and_then(|x| x.as_u64()).unwrap_or(0);
    (prompt, completion)
}

fn u32_saturating(v: u64) -> u32 {
    if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    }
}

impl SseUsageParser for GenericUsageParser {
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
        "generic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_openai_shape() {
        let mut p = GenericUsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 10,
                completion_tokens: 20,
            })
        );
    }

    #[test]
    fn picks_vertex_shape() {
        let mut p = GenericUsageParser::new();
        p.feed(
            b"data: {\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":7}}\n\n",
        );
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 5,
                completion_tokens: 7,
            })
        );
    }

    #[test]
    fn picks_cohere_shape() {
        let mut p = GenericUsageParser::new();
        p.feed(
            b"data: {\"response\":{\"meta\":{\"billed_units\":{\"input_tokens\":3,\"output_tokens\":4}}}}\n\n",
        );
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 3,
                completion_tokens: 4,
            })
        );
    }

    #[test]
    fn picks_ollama_shape() {
        let mut p = GenericUsageParser::new();
        p.feed(b"{\"done\":true,\"prompt_eval_count\":2,\"eval_count\":11}\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 2,
                completion_tokens: 11,
            })
        );
    }

    #[test]
    fn picks_anthropic_shape_via_input_output_aliases() {
        let mut p = GenericUsageParser::new();
        p.feed(b"data: {\"usage\":{\"input_tokens\":4,\"output_tokens\":6}}\n\n");
        assert_eq!(
            p.snapshot(),
            Some(UsageTokens {
                prompt_tokens: 4,
                completion_tokens: 6,
            })
        );
    }

    #[test]
    fn ignores_unknown_shape_silently() {
        let mut p = GenericUsageParser::new();
        p.feed(b"data: {\"weird\":{\"counts\":[1,2,3]}}\n\n");
        assert!(p.snapshot().is_none());
    }

    #[test]
    fn handles_chunks_split_mid_line() {
        let mut p = GenericUsageParser::new();
        p.feed(b"data: {\"usage\":{\"prompt_tokens\":");
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
    fn provider_tag_is_generic() {
        assert_eq!(GenericUsageParser::new().provider(), "generic");
    }
}
