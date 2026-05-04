//! SSE (Server-Sent Events) parser and writer for AI streaming responses.

use bytes::Bytes;

use crate::types::StreamChunk;

/// A parsed SSE event.
#[derive(Debug)]
pub enum SseEvent {
    /// A parsed streaming chunk.
    Chunk(StreamChunk),
    /// The stream is complete.
    Done,
    /// An event type line (e.g., `event: delta`).
    EventType(String),
    /// Raw data that could not be parsed as a StreamChunk.
    Raw(String),
}

/// Parse an SSE event from a single line.
pub fn parse_sse_line(line: &str) -> Option<SseEvent> {
    if let Some(data) = line.strip_prefix("data: ") {
        if data == "[DONE]" {
            Some(SseEvent::Done)
        } else {
            match serde_json::from_str::<StreamChunk>(data) {
                Ok(chunk) => Some(SseEvent::Chunk(chunk)),
                Err(_) => Some(SseEvent::Raw(data.to_string())),
            }
        }
    } else {
        line.strip_prefix("event: ")
            .map(|event_type| SseEvent::EventType(event_type.to_string()))
    }
}

/// Format a StreamChunk as an SSE data line.
pub fn format_sse_chunk(chunk: &StreamChunk) -> Bytes {
    let json = serde_json::to_string(chunk).unwrap_or_default();
    Bytes::from(format!("data: {}\n\n", json))
}

/// Format the SSE done sentinel.
pub fn format_sse_done() -> Bytes {
    Bytes::from_static(b"data: [DONE]\n\n")
}

/// Accumulates stream chunks into a complete response.
pub struct StreamAccumulator {
    /// All chunks received so far in the order they arrived.
    pub chunks: Vec<StreamChunk>,
    /// Concatenated delta content across all received chunks.
    pub content: String,
    /// Model identifier captured from the first chunk.
    pub model: String,
    /// Response identifier captured from the first chunk.
    pub id: String,
}

impl StreamAccumulator {
    /// Create an empty accumulator with no chunks recorded.
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            content: String::new(),
            model: String::new(),
            id: String::new(),
        }
    }

    /// Add a chunk, accumulating delta content.
    pub fn add_chunk(&mut self, chunk: StreamChunk) {
        if self.id.is_empty() {
            self.id = chunk.id.clone();
            self.model = chunk.model.clone();
        }
        for choice in &chunk.choices {
            if let Some(content) = &choice.delta.content {
                self.content.push_str(content);
            }
        }
        self.chunks.push(chunk);
    }

    /// Total number of chunks received.
    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }
}

impl Default for StreamAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Delta, StreamChoice};

    fn make_chunk(id: &str, model: &str, content: Option<&str>) -> StreamChunk {
        StreamChunk {
            id: id.to_string(),
            object: "chat.completion.chunk".to_string(),
            created: 1700000000,
            model: model.to_string(),
            choices: vec![StreamChoice {
                index: 0,
                delta: Delta {
                    role: None,
                    content: content.map(|s| s.to_string()),
                },
                finish_reason: None,
            }],
            usage: None,
        }
    }

    #[test]
    fn parse_sse_data_chunk() {
        let chunk = make_chunk("id-1", "gpt-4", Some("Hello"));
        let json = serde_json::to_string(&chunk).unwrap();
        let line = format!("data: {}", json);
        match parse_sse_line(&line) {
            Some(SseEvent::Chunk(c)) => {
                assert_eq!(c.id, "id-1");
                assert_eq!(c.choices[0].delta.content.as_deref(), Some("Hello"));
            }
            other => panic!("expected Chunk, got {:?}", other),
        }
    }

    #[test]
    fn parse_sse_done() {
        match parse_sse_line("data: [DONE]") {
            Some(SseEvent::Done) => {}
            other => panic!("expected Done, got {:?}", other),
        }
    }

    #[test]
    fn parse_sse_event_type() {
        match parse_sse_line("event: delta") {
            Some(SseEvent::EventType(t)) => assert_eq!(t, "delta"),
            other => panic!("expected EventType, got {:?}", other),
        }
    }

    #[test]
    fn parse_sse_raw_invalid_json() {
        match parse_sse_line("data: {invalid json}") {
            Some(SseEvent::Raw(s)) => assert_eq!(s, "{invalid json}"),
            other => panic!("expected Raw, got {:?}", other),
        }
    }

    #[test]
    fn parse_sse_empty_line() {
        assert!(parse_sse_line("").is_none());
    }

    #[test]
    fn parse_sse_comment_line() {
        assert!(parse_sse_line(": comment").is_none());
    }

    #[test]
    fn format_sse_chunk_output() {
        let chunk = make_chunk("id-1", "gpt-4", Some("Hi"));
        let bytes = format_sse_chunk(&chunk);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("data: "));
        assert!(text.ends_with("\n\n"));
        assert!(text.contains("\"id\":\"id-1\""));
    }

    #[test]
    fn format_sse_done_output() {
        let bytes = format_sse_done();
        assert_eq!(&bytes[..], b"data: [DONE]\n\n");
    }

    #[test]
    fn stream_accumulator_add_chunks() {
        let mut acc = StreamAccumulator::new();
        assert_eq!(acc.total_chunks(), 0);
        assert!(acc.content.is_empty());

        acc.add_chunk(make_chunk("id-1", "gpt-4", Some("Hello")));
        assert_eq!(acc.total_chunks(), 1);
        assert_eq!(acc.content, "Hello");
        assert_eq!(acc.id, "id-1");
        assert_eq!(acc.model, "gpt-4");

        acc.add_chunk(make_chunk("id-1", "gpt-4", Some(", world!")));
        assert_eq!(acc.total_chunks(), 2);
        assert_eq!(acc.content, "Hello, world!");
    }

    #[test]
    fn stream_accumulator_no_content_delta() {
        let mut acc = StreamAccumulator::new();
        acc.add_chunk(make_chunk("id-1", "gpt-4", None));
        assert_eq!(acc.total_chunks(), 1);
        assert!(acc.content.is_empty());
    }

    #[test]
    fn stream_accumulator_default() {
        let acc = StreamAccumulator::default();
        assert_eq!(acc.total_chunks(), 0);
    }
}
