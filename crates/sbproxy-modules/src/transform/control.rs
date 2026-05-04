//! Control transforms: payload limits, body discard, and SSE chunking.

use bytes::BytesMut;
use serde::Deserialize;

// --- PayloadLimitTransform ---

/// Enforces a maximum body size. Can truncate or reject oversized payloads.
#[derive(Debug, Deserialize)]
pub struct PayloadLimitTransform {
    /// Maximum allowed body size in bytes.
    pub max_size: usize,
    /// If true, truncate the body to `max_size`. If false, return an error.
    #[serde(default)]
    pub truncate: bool,
}

impl PayloadLimitTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Enforce the size limit on the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        if body.len() > self.max_size {
            if self.truncate {
                body.truncate(self.max_size);
            } else {
                anyhow::bail!(
                    "payload size {} exceeds limit of {} bytes",
                    body.len(),
                    self.max_size
                );
            }
        }
        Ok(())
    }
}

// --- DiscardTransform ---

/// Discards the entire response body, returning an empty body.
#[derive(Debug, Deserialize, Default)]
pub struct DiscardTransform {}

impl DiscardTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Clear the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        body.clear();
        Ok(())
    }
}

// --- SseChunkingTransform ---

/// Ensures SSE-format responses are properly chunked with a line prefix
/// and double-newline delimiters between events.
#[derive(Debug, Deserialize, Default)]
pub struct SseChunkingTransform {
    /// Prefix for each line. Defaults to "data: " if not set.
    #[serde(default)]
    pub line_prefix: Option<String>,
}

impl SseChunkingTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Format the body as SSE events. Each non-empty line gets the prefix,
    /// and events are separated by double newlines.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let prefix = self.line_prefix.as_deref().unwrap_or("data: ");

        let text = std::str::from_utf8(&body[..])
            .map_err(|e| anyhow::anyhow!("body is not valid UTF-8: {}", e))?;

        let mut output = String::with_capacity(text.len() + text.len() / 4);
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            // Skip lines that already have the prefix to avoid double-prefixing.
            if line.starts_with(prefix) {
                output.push_str(line);
            } else {
                output.push_str(prefix);
                output.push_str(line);
            }
            output.push_str("\n\n");
        }

        body.clear();
        body.extend_from_slice(output.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PayloadLimitTransform tests ---

    #[test]
    fn payload_limit_from_config() {
        let config = serde_json::json!({"max_size": 1024, "truncate": true});
        let t = PayloadLimitTransform::from_config(config).unwrap();
        assert_eq!(t.max_size, 1024);
        assert!(t.truncate);
    }

    #[test]
    fn payload_limit_under_limit() {
        let t = PayloadLimitTransform {
            max_size: 100,
            truncate: false,
        };
        let mut body = BytesMut::from(&b"short body"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"short body");
    }

    #[test]
    fn payload_limit_exact_limit() {
        let t = PayloadLimitTransform {
            max_size: 5,
            truncate: false,
        };
        let mut body = BytesMut::from(&b"exact"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"exact");
    }

    #[test]
    fn payload_limit_over_limit_truncate() {
        let t = PayloadLimitTransform {
            max_size: 5,
            truncate: true,
        };
        let mut body = BytesMut::from(&b"this is too long"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"this ");
        assert_eq!(body.len(), 5);
    }

    #[test]
    fn payload_limit_over_limit_reject() {
        let t = PayloadLimitTransform {
            max_size: 5,
            truncate: false,
        };
        let mut body = BytesMut::from(&b"this is too long"[..]);
        let err = t.apply(&mut body).unwrap_err();
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn payload_limit_empty_body() {
        let t = PayloadLimitTransform {
            max_size: 0,
            truncate: false,
        };
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    // --- DiscardTransform tests ---

    #[test]
    fn discard_from_config() {
        let config = serde_json::json!({});
        let t = DiscardTransform::from_config(config).unwrap();
        // Just verify it deserializes without error.
        let _ = format!("{:?}", t);
    }

    #[test]
    fn discard_clears_body() {
        let t = DiscardTransform {};
        let mut body = BytesMut::from(&b"some content here"[..]);
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn discard_empty_body() {
        let t = DiscardTransform {};
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn discard_large_body() {
        let t = DiscardTransform {};
        let data = vec![0u8; 10_000];
        let mut body = BytesMut::from(&data[..]);
        assert_eq!(body.len(), 10_000);
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    // --- SseChunkingTransform tests ---

    #[test]
    fn sse_chunking_from_config() {
        let config = serde_json::json!({"line_prefix": "event: "});
        let t = SseChunkingTransform::from_config(config).unwrap();
        assert_eq!(t.line_prefix.as_deref(), Some("event: "));
    }

    #[test]
    fn sse_chunking_default_prefix() {
        let t = SseChunkingTransform::default();
        let mut body = BytesMut::from(&b"hello\nworld"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert_eq!(result, "data: hello\n\ndata: world\n\n");
    }

    #[test]
    fn sse_chunking_custom_prefix() {
        let t = SseChunkingTransform {
            line_prefix: Some("event: ".into()),
        };
        let mut body = BytesMut::from(&b"line1\nline2"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert_eq!(result, "event: line1\n\nevent: line2\n\n");
    }

    #[test]
    fn sse_chunking_skips_empty_lines() {
        let t = SseChunkingTransform::default();
        let mut body = BytesMut::from(&b"line1\n\nline2\n"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert_eq!(result, "data: line1\n\ndata: line2\n\n");
    }

    #[test]
    fn sse_chunking_already_prefixed() {
        let t = SseChunkingTransform::default();
        let mut body = BytesMut::from(&b"data: already prefixed"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        // Should not double-prefix.
        assert_eq!(result, "data: already prefixed\n\n");
    }

    #[test]
    fn sse_chunking_empty_body() {
        let t = SseChunkingTransform::default();
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn sse_chunking_single_line() {
        let t = SseChunkingTransform::default();
        let mut body = BytesMut::from(&b"single event"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert_eq!(result, "data: single event\n\n");
    }
}
