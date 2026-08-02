//! Shared parsing and rendering for explicitly marked retrieval context.

mod parser;
pub(super) mod ranking;
pub(super) mod table;

use serde_json::Value;
use std::fmt;

pub(crate) use parser::parse_marked_messages;

pub(crate) const MAX_RETRIEVAL_BLOCKS: usize = 32;
pub(crate) const MAX_CHUNKS_PER_BLOCK: usize = 1_024;
pub(crate) const MAX_RETRIEVAL_CHUNKS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineEnding {
    Lf,
    CrLf,
}

impl LineEnding {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::CrLf => "\r\n",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkFormat {
    Text,
    Json,
    SbproxyTableV1,
}

impl ChunkFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::SbproxyTableV1 => "sbproxy_table_v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RetrievalChunk {
    id: String,
    supplied_score: Option<f64>,
    supplied_score_rendering: Option<String>,
    format: ChunkFormat,
    body: String,
    original_ordinal: usize,
    original_rendering: String,
    changed: bool,
}

impl RetrievalChunk {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn supplied_score(&self) -> Option<f64> {
        self.supplied_score
    }

    pub(crate) fn format(&self) -> ChunkFormat {
        self.format
    }

    pub(crate) fn body(&self) -> &str {
        &self.body
    }

    // Task 3 consumes stable source ordinals when deterministic ranking lands.
    #[allow(dead_code)]
    pub(crate) fn original_ordinal(&self) -> usize {
        self.original_ordinal
    }

    // Task 4 renders transformed chunks through this shared canonical path.
    #[allow(dead_code)]
    pub(crate) fn render(&self) -> String {
        if !self.changed {
            return self.original_rendering.clone();
        }

        let bytes = self.original_rendering.as_bytes();
        let line_ending = match bytes.iter().position(|byte| *byte == b'\n') {
            Some(index) if index > 0 && bytes[index - 1] == b'\r' => LineEnding::CrLf,
            _ => LineEnding::Lf,
        };
        let eol = line_ending.as_str();
        let mut rendered = format!("<sbproxy-chunk id=\"{}\"", self.id);
        if let Some(score) = &self.supplied_score_rendering {
            rendered.push_str(" score=\"");
            rendered.push_str(score);
            rendered.push('"');
        }
        rendered.push_str(" format=\"");
        rendered.push_str(self.format.as_str());
        rendered.push_str("\">");
        rendered.push_str(eol);
        rendered.push_str(&self.body);
        if !self.body.is_empty() {
            rendered.push_str(eol);
        }
        rendered.push_str("</sbproxy-chunk>");
        rendered
    }

    // Task 4 consumes this copy-on-change transformation boundary.
    #[allow(dead_code)]
    pub(crate) fn with_body_and_format(&self, body: String, format: ChunkFormat) -> Self {
        if self.body == body && self.format == format {
            return self.clone();
        }

        let mut changed = self.clone();
        changed.body = body;
        changed.format = format;
        changed.changed = true;
        changed
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RetrievalBlock {
    query: String,
    chunks: Vec<RetrievalChunk>,
    line_ending: LineEnding,
    changed: bool,
}

impl RetrievalBlock {
    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    pub(crate) fn chunks(&self) -> &[RetrievalChunk] {
        &self.chunks
    }

    // Tasks 3 and 5 consume this all-at-once chunk replacement boundary.
    #[allow(dead_code)]
    pub(crate) fn replace_chunks(&mut self, chunks: Vec<RetrievalChunk>) {
        if self.chunks != chunks {
            self.chunks = chunks;
            self.changed = true;
        }
    }

    // Tasks 3 through 5 render complete transformed blocks through this path.
    #[allow(dead_code)]
    pub(crate) fn render(&self) -> String {
        let eol = self.line_ending.as_str();
        let mut rendered = String::from("<sbproxy-retrieval>");
        rendered.push_str(eol);
        rendered.push_str("<sbproxy-query>");
        rendered.push_str(eol);
        rendered.push_str(&self.query);
        rendered.push_str(eol);
        rendered.push_str("</sbproxy-query>");
        rendered.push_str(eol);
        for chunk in &self.chunks {
            rendered.push_str(&chunk.render());
            rendered.push_str(eol);
        }
        rendered.push_str("</sbproxy-retrieval>");
        rendered
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Literal(String),
    Retrieval(RetrievalBlock),
}

#[derive(Debug, Clone, PartialEq)]
struct MessageDocument {
    message_index: usize,
    segments: Vec<Segment>,
}

impl MessageDocument {
    // Rendering becomes live when the first marked-context lever lands in Task 3.
    #[allow(dead_code)]
    fn changed(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| matches!(segment, Segment::Retrieval(block) if block.changed))
    }

    // Rendering becomes live when the first marked-context lever lands in Task 3.
    #[allow(dead_code)]
    fn render(&self) -> String {
        let mut rendered = String::new();
        for segment in &self.segments {
            match segment {
                Segment::Literal(literal) => rendered.push_str(literal),
                Segment::Retrieval(block) => rendered.push_str(&block.render()),
            }
        }
        rendered
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MarkedMessages {
    original_messages: Vec<Value>,
    documents: Vec<MessageDocument>,
}

impl MarkedMessages {
    pub(crate) fn blocks_mut(&mut self) -> impl Iterator<Item = &mut RetrievalBlock> {
        self.documents
            .iter_mut()
            .flat_map(|document| document.segments.iter_mut())
            .filter_map(|segment| match segment {
                Segment::Retrieval(block) => Some(block),
                Segment::Literal(_) => None,
            })
    }

    // Task 3 consumes reconstruction after applying the first parser-backed lever.
    #[allow(dead_code)]
    pub(crate) fn into_messages(mut self) -> Vec<Value> {
        for document in &self.documents {
            if !document.changed() {
                continue;
            }
            let Some(content) = self.original_messages[document.message_index]
                .as_object_mut()
                .and_then(|message| message.get_mut("content"))
            else {
                continue;
            };
            *content = Value::String(document.render());
        }
        self.original_messages
    }
}

/// Closed failure categories for marked-context parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkedContextError {
    /// The marker grammar or a marked value is invalid.
    Malformed,
    /// A marked-context block or chunk count exceeds a closed limit.
    TooLarge,
}

impl fmt::Display for MarkedContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed_marked_context",
            Self::TooLarge => "marked_context_too_large",
        })
    }
}

impl std::error::Error for MarkedContextError {}

/// Owned read-only view of all explicit retrieval blocks in a message list.
#[derive(Debug, Clone, PartialEq)]
pub struct MarkedContextSnapshot {
    /// Retrieval blocks in message and source order.
    pub blocks: Vec<RetrievalBlockSnapshot>,
}

/// Owned read-only view of one explicit retrieval block.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalBlockSnapshot {
    /// Opaque retrieval query text.
    pub query: String,
    /// Marked chunks in source order.
    pub chunks: Vec<RetrievalChunkSnapshot>,
}

/// Owned read-only view of one explicit retrieval chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalChunkSnapshot {
    /// Stable producer-supplied chunk identifier.
    pub id: String,
    /// Optional finite producer-supplied relevance score.
    pub score: Option<f64>,
    /// Declared exact chunk format label.
    pub format: String,
    /// Opaque chunk body text.
    pub body: String,
}

/// Inspect explicit retrieval context without exposing mutable parser internals.
pub fn inspect_marked_context(
    messages: &[Value],
) -> Result<Option<MarkedContextSnapshot>, MarkedContextError> {
    let Some(mut marked) = parse_marked_messages(messages)? else {
        return Ok(None);
    };
    let blocks = marked
        .blocks_mut()
        .map(|block| RetrievalBlockSnapshot {
            query: block.query().to_string(),
            chunks: block
                .chunks()
                .iter()
                .map(|chunk| RetrievalChunkSnapshot {
                    id: chunk.id().to_string(),
                    score: chunk.supplied_score(),
                    format: chunk.format().as_str().to_string(),
                    body: chunk.body().to_string(),
                })
                .collect(),
        })
        .collect();
    Ok(Some(MarkedContextSnapshot { blocks }))
}
