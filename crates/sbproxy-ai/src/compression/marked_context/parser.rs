use super::{
    ChunkFormat, LineEnding, MarkedContextError, MarkedMessages, MessageDocument, RetrievalBlock,
    RetrievalChunk, Segment, MAX_CHUNKS_PER_BLOCK, MAX_RETRIEVAL_BLOCKS, MAX_RETRIEVAL_CHUNKS,
};
use serde_json::Value;
use std::collections::BTreeSet;

const RETRIEVAL_OPEN: &str = "<sbproxy-retrieval>";
const RETRIEVAL_CLOSE: &str = "</sbproxy-retrieval>";
const QUERY_OPEN: &str = "<sbproxy-query>";
const QUERY_CLOSE: &str = "</sbproxy-query>";
const CHUNK_CLOSE: &str = "</sbproxy-chunk>";
const CHUNK_OPEN_PREFIX: &str = "<sbproxy-chunk id=\"";

#[derive(Debug, Clone, Copy)]
struct Line<'a> {
    text: &'a str,
    start: usize,
    content_end: usize,
    ending: Option<LineEnding>,
}

struct LineCursor<'a> {
    content: &'a str,
    position: usize,
}

impl<'a> LineCursor<'a> {
    fn new(content: &'a str) -> Self {
        Self {
            content,
            position: 0,
        }
    }
}

impl<'a> Iterator for LineCursor<'a> {
    type Item = Line<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.content.len() {
            return None;
        }

        let start = self.position;
        let bytes = self.content.as_bytes();
        let newline = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset);
        let Some(newline) = newline else {
            self.position = self.content.len();
            return Some(Line {
                text: &self.content[start..],
                start,
                content_end: self.content.len(),
                ending: None,
            });
        };

        let (content_end, ending) = if newline > start && bytes[newline - 1] == b'\r' {
            (newline - 1, LineEnding::CrLf)
        } else {
            (newline, LineEnding::Lf)
        };
        self.position = newline + 1;
        Some(Line {
            text: &self.content[start..content_end],
            start,
            content_end,
            ending: Some(ending),
        })
    }
}

#[derive(Default)]
struct ParseCounts {
    blocks: usize,
    chunks: usize,
}

struct ParsedBlock {
    block: RetrievalBlock,
    end: usize,
}

struct ParsedChunkOpen<'a> {
    id: &'a str,
    supplied_score: Option<f64>,
    supplied_score_rendering: Option<&'a str>,
    format: ChunkFormat,
}

pub(crate) fn parse_marked_messages(
    messages: &[Value],
) -> Result<Option<MarkedMessages>, MarkedContextError> {
    let mut counts = ParseCounts::default();
    let mut documents = Vec::new();

    for (message_index, message) in messages.iter().enumerate() {
        let Some(content) = eligible_content(message) else {
            continue;
        };
        let Some(segments) = parse_document(content, &mut counts)? else {
            continue;
        };
        documents.push(MessageDocument {
            message_index,
            segments,
        });
    }

    if documents.is_empty() {
        return Ok(None);
    }

    Ok(Some(MarkedMessages {
        original_messages: messages.to_vec(),
        documents,
    }))
}

fn eligible_content(message: &Value) -> Option<&str> {
    let message = message.as_object()?;
    match message.get("role")?.as_str()? {
        "user" | "tool" => message.get("content")?.as_str(),
        _ => None,
    }
}

fn parse_document(
    content: &str,
    counts: &mut ParseCounts,
) -> Result<Option<Vec<Segment>>, MarkedContextError> {
    let mut lines = LineCursor::new(content);
    let mut segments = Vec::new();
    let mut literal_start = 0;
    let mut found = false;

    while let Some(line) = lines.next() {
        if is_orphan_sentinel(line.text) {
            return Err(MarkedContextError::Malformed);
        }
        if line.text != RETRIEVAL_OPEN {
            continue;
        }

        if counts.blocks == MAX_RETRIEVAL_BLOCKS {
            return Err(MarkedContextError::TooLarge);
        }
        counts.blocks += 1;

        found = true;
        segments.push(Segment::Literal(
            content[literal_start..line.start].to_string(),
        ));
        let parsed = parse_block(content, &mut lines, line, counts)?;
        segments.push(Segment::Retrieval(parsed.block));
        literal_start = parsed.end;
    }

    if !found {
        return Ok(None);
    }
    segments.push(Segment::Literal(content[literal_start..].to_string()));
    Ok(Some(segments))
}

fn parse_block<'a>(
    content: &'a str,
    lines: &mut LineCursor<'a>,
    open: Line<'a>,
    counts: &mut ParseCounts,
) -> Result<ParsedBlock, MarkedContextError> {
    let line_ending = open.ending.ok_or(MarkedContextError::Malformed)?;
    let query_open = lines.next().ok_or(MarkedContextError::Malformed)?;
    if query_open.text != QUERY_OPEN || query_open.ending != Some(line_ending) {
        return Err(MarkedContextError::Malformed);
    }

    let query_body_start = line_after(&query_open);
    let query_close = find_query_close(lines)?;
    if query_close.ending != Some(line_ending) {
        return Err(MarkedContextError::Malformed);
    }
    let query = body_before_close(content, query_body_start, query_close.start, line_ending)?;
    if query.trim().is_empty() {
        return Err(MarkedContextError::Malformed);
    }

    let mut chunks = Vec::new();
    let mut ids = BTreeSet::new();
    loop {
        let next = lines.next().ok_or(MarkedContextError::Malformed)?;
        if next.text == RETRIEVAL_CLOSE {
            if next.ending.is_some_and(|ending| ending != line_ending) {
                return Err(MarkedContextError::Malformed);
            }
            return Ok(ParsedBlock {
                block: RetrievalBlock {
                    query: query.to_string(),
                    chunks,
                    line_ending,
                    changed: false,
                },
                end: next.content_end,
            });
        }
        if next.text == RETRIEVAL_OPEN {
            return Err(MarkedContextError::Malformed);
        }

        let parsed_open = parse_chunk_open(next.text)?;
        if next.ending != Some(line_ending) {
            return Err(MarkedContextError::Malformed);
        }
        if chunks.len() == MAX_CHUNKS_PER_BLOCK || counts.chunks == MAX_RETRIEVAL_CHUNKS {
            return Err(MarkedContextError::TooLarge);
        }
        if !ids.insert(parsed_open.id.to_string()) {
            return Err(MarkedContextError::Malformed);
        }

        let chunk_body_start = line_after(&next);
        let close = find_chunk_close(lines)?;
        if close.ending != Some(line_ending) {
            return Err(MarkedContextError::Malformed);
        }
        let body = body_before_close(content, chunk_body_start, close.start, line_ending)?;
        counts.chunks += 1;
        chunks.push(RetrievalChunk {
            id: parsed_open.id.to_string(),
            supplied_score: parsed_open.supplied_score,
            supplied_score_rendering: parsed_open.supplied_score_rendering.map(str::to_string),
            format: parsed_open.format,
            body: body.to_string(),
            original_ordinal: chunks.len(),
            original_rendering: content[next.start..close.content_end].to_string(),
            changed: false,
        });
    }
}

fn find_query_close<'a>(lines: &mut LineCursor<'a>) -> Result<Line<'a>, MarkedContextError> {
    for line in lines {
        if line.text == QUERY_CLOSE {
            return Ok(line);
        }
        if line.text == RETRIEVAL_OPEN {
            return Err(MarkedContextError::Malformed);
        }
    }
    Err(MarkedContextError::Malformed)
}

fn find_chunk_close<'a>(lines: &mut LineCursor<'a>) -> Result<Line<'a>, MarkedContextError> {
    for line in lines {
        if line.text == CHUNK_CLOSE {
            return Ok(line);
        }
        if line.text == RETRIEVAL_OPEN {
            return Err(MarkedContextError::Malformed);
        }
    }
    Err(MarkedContextError::Malformed)
}

fn parse_chunk_open(opening: &str) -> Result<ParsedChunkOpen<'_>, MarkedContextError> {
    let rest = opening
        .strip_prefix(CHUNK_OPEN_PREFIX)
        .ok_or(MarkedContextError::Malformed)?;
    let (id, rest) = rest.split_once('"').ok_or(MarkedContextError::Malformed)?;
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(MarkedContextError::Malformed);
    }

    let (score, score_rendering, rest) = if let Some(rest) = rest.strip_prefix(" score=\"") {
        let (rendering, rest) = rest.split_once('"').ok_or(MarkedContextError::Malformed)?;
        let score = rendering
            .parse::<f64>()
            .map_err(|_| MarkedContextError::Malformed)?;
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(MarkedContextError::Malformed);
        }
        (Some(score), Some(rendering), rest)
    } else {
        (None, None, rest)
    };

    let format = rest
        .strip_prefix(" format=\"")
        .and_then(|rest| rest.strip_suffix("\">"))
        .ok_or(MarkedContextError::Malformed)?;
    let format = match format {
        "text" => ChunkFormat::Text,
        "json" => ChunkFormat::Json,
        "sbproxy_table_v1" => ChunkFormat::SbproxyTableV1,
        _ => return Err(MarkedContextError::Malformed),
    };

    Ok(ParsedChunkOpen {
        id,
        supplied_score: score,
        supplied_score_rendering: score_rendering,
        format,
    })
}

fn is_orphan_sentinel(line: &str) -> bool {
    matches!(
        line,
        RETRIEVAL_CLOSE | QUERY_OPEN | QUERY_CLOSE | CHUNK_CLOSE
    ) || line.starts_with(CHUNK_OPEN_PREFIX)
}

fn body_before_close(
    content: &str,
    body_start: usize,
    close_start: usize,
    line_ending: LineEnding,
) -> Result<&str, MarkedContextError> {
    if body_start == close_start {
        return Ok("");
    }
    content[body_start..close_start]
        .strip_suffix(line_ending.as_str())
        .ok_or(MarkedContextError::Malformed)
}

fn line_after(line: &Line<'_>) -> usize {
    line.content_end + line.ending.map_or(0, |ending| ending.as_str().len())
}

#[cfg(test)]
mod tests {
    use super::super::{
        inspect_marked_context, parse_marked_messages, ChunkFormat, MarkedContextError,
        MAX_CHUNKS_PER_BLOCK, MAX_RETRIEVAL_BLOCKS, MAX_RETRIEVAL_CHUNKS,
    };
    use serde_json::{json, Value};

    fn message(role: &str, content: impl Into<String>) -> Value {
        json!({"role": role, "content": content.into()})
    }

    fn chunk(id: &str, score: Option<&str>, format: &str, body: &str, eol: &str) -> String {
        let score = score
            .map(|score| format!(" score=\"{score}\""))
            .unwrap_or_default();
        format!(
            "<sbproxy-chunk id=\"{id}\"{score} format=\"{format}\">{eol}{body}{eol}</sbproxy-chunk>"
        )
    }

    fn block(query: &str, chunks: &[String], eol: &str) -> String {
        let mut rendered = format!(
            "<sbproxy-retrieval>{eol}<sbproxy-query>{eol}{query}{eol}</sbproxy-query>{eol}"
        );
        for chunk in chunks {
            rendered.push_str(chunk);
            rendered.push_str(eol);
        }
        rendered.push_str("</sbproxy-retrieval>");
        rendered
    }

    fn generated_block(chunk_count: usize, id_offset: usize, eol: &str) -> String {
        let chunks = (0..chunk_count)
            .map(|index| {
                chunk(
                    &format!("chunk-{}", id_offset + index),
                    None,
                    "text",
                    "body",
                    eol,
                )
            })
            .collect::<Vec<_>>();
        block("bounded query", &chunks, eol)
    }

    fn assert_error_preserves(messages: Vec<Value>, expected: MarkedContextError) {
        let original = messages.clone();
        assert!(matches!(
            parse_marked_messages(&messages),
            Err(error) if error == expected
        ));
        assert_eq!(messages, original);
        assert!(matches!(
            inspect_marked_context(&messages),
            Err(error) if error == expected
        ));
        assert_eq!(messages, original);
    }

    #[test]
    fn parses_one_and_multiple_blocks_in_one_eligible_message() {
        let first = block(
            "first question",
            &[chunk("a", Some("0.25"), "text", "alpha", "\n")],
            "\n",
        );
        let second = block(
            "second question",
            &[
                chunk("b", None, "json", "{\"b\":2}", "\n"),
                chunk("c", Some("1"), "sbproxy_table_v1", "[\"c\"]\n3", "\n"),
            ],
            "\n",
        );
        let messages = vec![message(
            "user",
            format!("literal prefix\n{first}\nliteral middle\n{second}\nliteral suffix"),
        )];

        let snapshot = inspect_marked_context(&messages)
            .expect("valid marked context")
            .expect("blocks present");

        assert_eq!(snapshot.blocks.len(), 2);
        assert_eq!(snapshot.blocks[0].query, "first question");
        assert_eq!(snapshot.blocks[0].chunks[0].id, "a");
        assert_eq!(snapshot.blocks[0].chunks[0].score, Some(0.25));
        assert_eq!(snapshot.blocks[0].chunks[0].format, "text");
        assert_eq!(snapshot.blocks[0].chunks[0].body, "alpha");
        assert_eq!(snapshot.blocks[1].query, "second question");
        assert_eq!(snapshot.blocks[1].chunks.len(), 2);
        assert_eq!(snapshot.blocks[1].chunks[0].format, "json");
        assert_eq!(snapshot.blocks[1].chunks[1].format, "sbproxy_table_v1");
    }

    #[test]
    fn parses_blocks_across_user_and_tool_messages_in_request_order() {
        let user_block = block(
            "user query",
            &[chunk("user-result", None, "text", "u", "\n")],
            "\n",
        );
        let tool_block = block(
            "tool query",
            &[chunk("tool-result", Some("0.9"), "json", "[]", "\n")],
            "\n",
        );
        let messages = vec![
            message("user", user_block),
            message("assistant", "protected"),
            message("tool", tool_block),
        ];

        let snapshot = inspect_marked_context(&messages)
            .expect("valid marked context")
            .expect("blocks present");

        assert_eq!(snapshot.blocks.len(), 2);
        assert_eq!(snapshot.blocks[0].query, "user query");
        assert_eq!(snapshot.blocks[1].query, "tool query");
    }

    #[test]
    fn ignores_protected_roles_multimodal_and_call_fields() {
        let marked = block(
            "secret query",
            &[chunk("secret", None, "text", "secret body", "\n")],
            "\n",
        );
        let messages = vec![
            message("system", &marked),
            message("developer", &marked),
            message("assistant", &marked),
            json!({
                "role": "user",
                "content": [{"type": "text", "text": marked}],
            }),
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{"function": {"arguments": marked}}],
                "function_call": {"arguments": marked},
            }),
            json!({
                "role": "user",
                "content": "ordinary user text",
                "tool_calls": [{"function": {"arguments": marked}}],
                "function_call": {"arguments": marked},
                "tools": [{"description": marked}],
            }),
        ];
        let original = messages.clone();

        assert!(inspect_marked_context(&messages)
            .expect("protected content is ignored")
            .is_none());
        assert!(parse_marked_messages(&messages)
            .expect("protected content is ignored")
            .is_none());
        assert_eq!(messages, original);
    }

    #[test]
    fn accepts_many_unmarked_lines_without_a_semantic_line_limit() {
        let mut content = String::new();
        for index in 0..100_000 {
            content.push_str("ordinary literal line");
            content.push_str(if index % 2 == 0 { "\n" } else { "\r\n" });
        }
        content.push_str("final literal line without a terminator");
        let messages = vec![message("user", content)];
        let original = messages.clone();

        assert!(parse_marked_messages(&messages)
            .expect("unmarked lines are valid")
            .is_none());
        assert!(inspect_marked_context(&messages)
            .expect("unmarked lines are valid")
            .is_none());
        assert_eq!(messages, original);
    }

    #[test]
    fn rewrites_lf_and_crlf_with_each_source_convention() {
        for eol in ["\n", "\r\n"] {
            let original_block = block(
                "why",
                &[chunk("result", Some("8e-1"), "text", "before", eol)],
                eol,
            );
            let messages = vec![message(
                "user",
                format!("prefix{eol}{original_block}{eol}suffix"),
            )];
            let mut parsed = parse_marked_messages(&messages)
                .expect("valid marked context")
                .expect("block present");
            let parsed_block = parsed.blocks_mut().next().expect("one block");
            let changed = parsed_block.chunks()[0]
                .with_body_and_format("after".to_string(), ChunkFormat::Json);
            parsed_block.replace_chunks(vec![changed]);

            let output = parsed.into_messages();
            let expected_block = block(
                "why",
                &[chunk("result", Some("8e-1"), "json", "after", eol)],
                eol,
            );
            assert_eq!(
                output,
                vec![message(
                    "user",
                    format!("prefix{eol}{expected_block}{eol}suffix")
                )]
            );
        }
    }

    #[test]
    fn preserves_every_unmarked_prefix_suffix_and_message_byte() {
        let marked = block(
            "query",
            &[
                chunk("first", Some("0.20"), "text", "one\n\n", "\n"),
                chunk("second", None, "text", "two", "\n"),
            ],
            "\n",
        );
        let prefix = "\0préface\r\nnot a marker: <sbproxy-query>\n";
        let suffix = "\ntrailing \t bytes 🙂\0";
        let messages = vec![
            json!({"role": "system", "content": "unchanged", "extra": {"n": 1}}),
            message("tool", format!("{prefix}{marked}{suffix}")),
            json!({"role": "assistant", "content": [1, 2, 3]}),
        ];
        let mut parsed = parse_marked_messages(&messages)
            .expect("valid marked context")
            .expect("block present");
        let block = parsed.blocks_mut().next().expect("one block");
        let reordered = vec![block.chunks()[1].clone(), block.chunks()[0].clone()];
        block.replace_chunks(reordered);

        let output = parsed.into_messages();
        let content = output[1]["content"].as_str().expect("string content");

        assert!(content.starts_with(prefix));
        assert!(content.ends_with(suffix));
        assert_eq!(output[0], messages[0]);
        assert_eq!(output[2], messages[2]);
        assert!(content.contains(
            "<sbproxy-chunk id=\"first\" score=\"0.20\" format=\"text\">\none\n\n\n</sbproxy-chunk>"
        ));
    }

    #[test]
    fn rejects_empty_and_whitespace_only_queries_without_mutation() {
        for query in ["", "   ", "\t\t", " \t "] {
            let marked = block(query, &[chunk("result", None, "text", "body", "\n")], "\n");
            assert_error_preserves(
                vec![message("user", format!("before\n{marked}\nafter"))],
                MarkedContextError::Malformed,
            );
        }
    }

    #[test]
    fn query_only_blocks_remain_valid_after_all_chunks_are_removed() {
        let messages = vec![message(
            "user",
            block(
                "keep the question",
                &[chunk("discard", None, "text", "body", "\n")],
                "\n",
            ),
        )];
        let mut parsed = parse_marked_messages(&messages)
            .expect("valid marked context")
            .expect("block present");
        let parsed_block = parsed.blocks_mut().next().expect("one block");
        parsed_block.replace_chunks(Vec::new());

        let output = parsed.into_messages();
        let expected = vec![message("user", block("keep the question", &[], "\n"))];
        assert_eq!(output, expected);

        let snapshot = inspect_marked_context(&output)
            .expect("query-only result is valid")
            .expect("block remains");
        assert_eq!(snapshot.blocks[0].query, "keep the question");
        assert!(snapshot.blocks[0].chunks.is_empty());
    }

    #[test]
    fn accepts_identifier_lengths_one_and_sixty_four() {
        let max_id = "a".repeat(64);
        let messages = vec![message(
            "user",
            block(
                "query",
                &[
                    chunk("x", None, "text", "one", "\n"),
                    chunk(&max_id, None, "text", "two", "\n"),
                ],
                "\n",
            ),
        )];

        let snapshot = inspect_marked_context(&messages)
            .expect("boundary identifiers are valid")
            .expect("block present");

        assert_eq!(snapshot.blocks[0].chunks[0].id, "x");
        assert_eq!(snapshot.blocks[0].chunks[1].id, max_id);
    }

    #[test]
    fn rejects_identifier_length_sixty_five_and_invalid_characters() {
        for id in ["a".repeat(65), "has space".to_string(), "café".to_string()] {
            let messages = vec![message(
                "user",
                block("query", &[chunk(&id, None, "text", "body", "\n")], "\n"),
            )];
            assert_error_preserves(messages, MarkedContextError::Malformed);
        }
    }

    #[test]
    fn accepts_score_boundaries_and_preserves_source_spelling_on_change() {
        let messages = vec![message(
            "user",
            block(
                "query",
                &[
                    chunk("zero", Some("0"), "text", "zero", "\n"),
                    chunk("one", Some("1.000e0"), "text", "one", "\n"),
                ],
                "\n",
            ),
        )];
        let mut parsed = parse_marked_messages(&messages)
            .expect("score boundaries are valid")
            .expect("block present");
        let parsed_block = parsed.blocks_mut().next().expect("one block");
        assert_eq!(parsed_block.chunks()[0].supplied_score(), Some(0.0));
        assert_eq!(parsed_block.chunks()[1].supplied_score(), Some(1.0));
        let changed =
            parsed_block.chunks()[1].with_body_and_format("changed".to_string(), ChunkFormat::Json);
        parsed_block.replace_chunks(vec![changed]);

        assert!(parsed.into_messages()[0]["content"]
            .as_str()
            .expect("string content")
            .contains("id=\"one\" score=\"1.000e0\" format=\"json\""));
    }

    #[test]
    fn rejects_non_finite_nan_like_and_out_of_range_scores() {
        for score in [
            "NaN", "nan", "inf", "-inf", "Infinity", "-0.0001", "1.0001", "2",
        ] {
            let messages = vec![message(
                "tool",
                block(
                    "query",
                    &[chunk("result", Some(score), "text", "body", "\n")],
                    "\n",
                ),
            )];
            assert_error_preserves(messages, MarkedContextError::Malformed);
        }
    }

    #[test]
    fn rejects_duplicate_ids_nesting_and_closing_delimiter_collisions() {
        let duplicate = block(
            "query",
            &[
                chunk("same", None, "text", "one", "\n"),
                chunk("same", Some("0.5"), "json", "two", "\n"),
            ],
            "\n",
        );
        let nested = format!(
            "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\n{}\n</sbproxy-retrieval>",
            block("nested", &[], "\n")
        );
        let query_collision = "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\nmore query\n</sbproxy-query>\n</sbproxy-retrieval>";
        let chunk_collision = "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\n<sbproxy-chunk id=\"x\" format=\"text\">\nbody\n</sbproxy-chunk>\nmore body\n</sbproxy-chunk>\n</sbproxy-retrieval>";

        for malformed in [
            duplicate,
            nested,
            query_collision.to_string(),
            chunk_collision.to_string(),
        ] {
            assert_error_preserves(
                vec![message("user", malformed)],
                MarkedContextError::Malformed,
            );
        }
    }

    #[test]
    fn rejects_noncanonical_chunk_attributes() {
        let openings = [
            "<sbproxy-chunk format=\"text\" id=\"x\">",
            "<sbproxy-chunk id=\"x\"  format=\"text\">",
            "<sbproxy-chunk id=\"x\">",
            "<sbproxy-chunk id=\"x\" extra=\"y\" format=\"text\">",
            "<sbproxy-chunk id='x' format=\"text\">",
            "<sbproxy-chunk id=\"x\" format=\"TEXT\">",
            "<sbproxy-chunk id=\"x\" format=\"text\" >",
            "<sbproxy-chunk id=\"x\" score=\"0.5\" score=\"0.6\" format=\"text\">",
        ];

        for opening in openings {
            let malformed = format!(
                "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\n{opening}\nbody\n</sbproxy-chunk>\n</sbproxy-retrieval>"
            );
            assert_error_preserves(
                vec![message("user", malformed)],
                MarkedContextError::Malformed,
            );
        }
    }

    #[test]
    fn rejects_missing_tags_and_incomplete_blocks() {
        let malformed = [
            "<sbproxy-retrieval>",
            "<sbproxy-retrieval>\ntext\n</sbproxy-retrieval>",
            "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-retrieval>",
            "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\n<sbproxy-chunk id=\"x\" format=\"text\">\nbody\n</sbproxy-retrieval>",
            "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>",
            "<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\n<sbproxy-chunk id=\"x\" format=\"text\"",
        ];

        for input in malformed {
            assert_error_preserves(
                vec![message("user", format!("prefix\n{input}"))],
                MarkedContextError::Malformed,
            );
        }
    }

    #[test]
    fn rejects_exact_orphan_sentinels_without_a_retrieval_opener() {
        let orphan_lines = [
            "</sbproxy-retrieval>",
            "<sbproxy-query>",
            "</sbproxy-query>",
            "<sbproxy-chunk id=\"x\" format=\"text\">",
            "</sbproxy-chunk>",
        ];

        for orphan in orphan_lines {
            assert_error_preserves(
                vec![message(
                    "user",
                    format!("literal prefix\n{orphan}\nliteral suffix"),
                )],
                MarkedContextError::Malformed,
            );
        }
    }

    #[test]
    fn query_and_chunk_bodies_are_opaque_to_other_exact_sentinels() {
        let query =
            "question\n<sbproxy-query>\n</sbproxy-chunk>\n</sbproxy-retrieval>\nstill question";
        let body = "body\n<sbproxy-query>\n</sbproxy-query>\n<sbproxy-chunk id=\"nested-looking\" format=\"text\">\n</sbproxy-retrieval>\nstill body";
        let messages = vec![message(
            "tool",
            block(query, &[chunk("result", None, "text", body, "\n")], "\n"),
        )];

        let snapshot = inspect_marked_context(&messages)
            .expect("non-closing body sentinels are opaque")
            .expect("block present");

        assert_eq!(snapshot.blocks[0].query, query);
        assert_eq!(snapshot.blocks[0].chunks[0].body, body);
    }

    #[test]
    fn accepts_maximum_block_count_and_rejects_the_next_block() {
        let at_limit = (0..MAX_RETRIEVAL_BLOCKS)
            .map(|index| block(&format!("query {index}"), &[], "\n"))
            .collect::<Vec<_>>()
            .join("\n");
        let messages = vec![message("user", &at_limit)];

        let snapshot = inspect_marked_context(&messages)
            .expect("block count boundary is valid")
            .expect("blocks present");
        assert_eq!(snapshot.blocks.len(), MAX_RETRIEVAL_BLOCKS);

        let over_limit = format!("{at_limit}\n{}", block("one too many", &[], "\n"));
        assert_error_preserves(
            vec![message("user", over_limit)],
            MarkedContextError::TooLarge,
        );
    }

    #[test]
    fn accepts_maximum_chunks_per_block_and_rejects_the_next_chunk() {
        let at_limit = vec![message(
            "tool",
            generated_block(MAX_CHUNKS_PER_BLOCK, 0, "\n"),
        )];

        let snapshot = inspect_marked_context(&at_limit)
            .expect("per-block chunk boundary is valid")
            .expect("block present");
        assert_eq!(snapshot.blocks[0].chunks.len(), MAX_CHUNKS_PER_BLOCK);

        assert_error_preserves(
            vec![message(
                "tool",
                generated_block(MAX_CHUNKS_PER_BLOCK + 1, 0, "\n"),
            )],
            MarkedContextError::TooLarge,
        );
    }

    #[test]
    fn accepts_maximum_request_chunks_and_rejects_the_next_chunk() {
        let full_blocks = MAX_RETRIEVAL_CHUNKS / MAX_CHUNKS_PER_BLOCK;
        let at_limit = (0..full_blocks)
            .map(|block_index| {
                message(
                    if block_index % 2 == 0 { "user" } else { "tool" },
                    generated_block(
                        MAX_CHUNKS_PER_BLOCK,
                        block_index * MAX_CHUNKS_PER_BLOCK,
                        "\n",
                    ),
                )
            })
            .collect::<Vec<_>>();

        let snapshot = inspect_marked_context(&at_limit)
            .expect("request chunk boundary is valid")
            .expect("blocks present");
        assert_eq!(
            snapshot
                .blocks
                .iter()
                .map(|block| block.chunks.len())
                .sum::<usize>(),
            MAX_RETRIEVAL_CHUNKS
        );

        let mut over_limit = at_limit;
        over_limit.push(message("user", generated_block(1, 10_000, "\n")));
        assert_error_preserves(over_limit, MarkedContextError::TooLarge);
    }

    #[test]
    fn unchanged_chunks_keep_original_rendering_when_reordered() {
        let first = chunk("first", Some(".50"), "text", "alpha\n\n", "\r\n");
        let second = chunk("second", Some("5e-1"), "json", "{ \"b\": 2 }", "\r\n");
        let messages = vec![message(
            "tool",
            block("query", &[first.clone(), second.clone()], "\r\n"),
        )];
        let mut parsed = parse_marked_messages(&messages)
            .expect("valid marked context")
            .expect("block present");
        let parsed_block = parsed.blocks_mut().next().expect("one block");
        assert_eq!(parsed_block.query(), "query");
        assert_eq!(parsed_block.chunks()[0].id(), "first");
        assert_eq!(parsed_block.chunks()[0].format(), ChunkFormat::Text);
        assert_eq!(parsed_block.chunks()[0].body(), "alpha\n\n");
        assert_eq!(parsed_block.chunks()[0].original_ordinal(), 0);
        assert_eq!(parsed_block.chunks()[1].original_ordinal(), 1);
        let reordered = vec![
            parsed_block.chunks()[1].clone(),
            parsed_block.chunks()[0].clone(),
        ];
        parsed_block.replace_chunks(reordered);
        let rendered_block = parsed_block.render();

        assert_eq!(rendered_block, block("query", &[second, first], "\r\n"));
    }

    #[test]
    fn changed_chunk_render_uses_its_source_line_ending_and_canonical_attributes() {
        let messages = vec![message(
            "tool",
            block(
                "query",
                &[chunk("result", Some("5e-1"), "text", "before", "\r\n")],
                "\r\n",
            ),
        )];
        let mut parsed = parse_marked_messages(&messages)
            .expect("valid marked context")
            .expect("block present");
        let parsed_block = parsed.blocks_mut().next().expect("one block");
        let changed =
            parsed_block.chunks()[0].with_body_and_format("after".to_string(), ChunkFormat::Json);

        assert_eq!(
            changed.render(),
            chunk("result", Some("5e-1"), "json", "after", "\r\n")
        );
    }

    #[test]
    fn parser_errors_use_only_closed_content_free_labels() {
        assert_eq!(
            MarkedContextError::Malformed.to_string(),
            "malformed_marked_context"
        );
        assert_eq!(
            MarkedContextError::TooLarge.to_string(),
            "marked_context_too_large"
        );
        assert_eq!(format!("{:?}", MarkedContextError::Malformed), "Malformed");
        assert_eq!(format!("{:?}", MarkedContextError::TooLarge), "TooLarge");
    }
}
