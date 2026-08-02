//! Strict retrieval-query extraction.
//!
//! Only two sources exist: the text of the final user message, or a
//! bounded string addressed by a JSON pointer. Extraction never falls
//! back to a whole-prompt flatten, because that would leak system
//! messages, conversation history, and tool output into the retrieval
//! query.

use sbproxy_ai::rag_config::RagQueryConfig;

use crate::error::QueryError;

/// Extract the retrieval query from `body` according to `source`.
///
/// The returned string is guaranteed non-empty after trimming and at
/// most `max_bytes` bytes long. Every failure is a typed
/// [`QueryError`]; no fallback source is consulted.
pub fn extract_query(
    source: &RagQueryConfig,
    body: &serde_json::Value,
    max_bytes: usize,
) -> Result<String, QueryError> {
    let query = match source {
        RagQueryConfig::LastUserMessage => last_user_text(body)?,
        RagQueryConfig::JsonPointer { pointer } => body
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .ok_or(QueryError::MissingString)?
            .to_owned(),
    };
    if query.trim().is_empty() {
        return Err(QueryError::Empty);
    }
    if query.len() > max_bytes {
        return Err(QueryError::TooLarge {
            actual: query.len(),
            maximum: max_bytes,
        });
    }
    Ok(query)
}

/// Return the text of the last `role: user` message in `messages`.
///
/// Walks the `messages` array backward and stops at the first user
/// entry. String content is returned as-is; array content contributes
/// only its `text` and `input_text` blocks, concatenated in order.
/// Images, audio, tool calls, unknown block types, earlier turns,
/// system messages, assistant messages, and tool messages are ignored.
pub fn last_user_text(body: &serde_json::Value) -> Result<String, QueryError> {
    let messages = body
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or(QueryError::MissingUserMessage)?;
    let last_user = messages
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(serde_json::Value::as_str) == Some("user"))
        .ok_or(QueryError::MissingUserMessage)?;
    match last_user.get("content") {
        Some(serde_json::Value::String(text)) => Ok(text.clone()),
        Some(serde_json::Value::Array(blocks)) => {
            let mut text = String::new();
            for block in blocks {
                let block_type = block.get("type").and_then(serde_json::Value::as_str);
                if matches!(block_type, Some("text") | Some("input_text")) {
                    if let Some(part) = block.get("text").and_then(serde_json::Value::as_str) {
                        text.push_str(part);
                    }
                }
            }
            Ok(text)
        }
        _ => Err(QueryError::MissingUserMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn last_user_message_does_not_include_system_history_or_tools() {
        let body = json!({
            "messages": [
                {"role":"system","content":"system secret"},
                {"role":"user","content":"old question"},
                {"role":"tool","content":"tool output"},
                {"role":"assistant","content":"old answer"},
                {"role":"user","content":[
                    {"type":"text","text":"current "},
                    {"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}},
                    {"type":"input_text","text":"question"}
                ]}
            ]
        });
        assert_eq!(
            extract_query(&RagQueryConfig::LastUserMessage, &body, 8_192).unwrap(),
            "current question"
        );
    }

    #[test]
    fn json_pointer_accepts_only_a_bounded_string() {
        let body = json!({"input":{"query":"refund policy"}});
        let source = RagQueryConfig::JsonPointer {
            pointer: "/input/query".into(),
        };
        assert_eq!(extract_query(&source, &body, 64).unwrap(), "refund policy");
        assert!(extract_query(&source, &json!({"input":{"query":{}}}), 64).is_err());
        assert!(extract_query(&source, &json!({"input":{"query":"123456"}}), 5).is_err());
    }

    #[test]
    fn empty_or_whitespace_text_is_a_typed_error() {
        let body = json!({"messages":[{"role":"user","content":"   "}]});
        assert_eq!(
            extract_query(&RagQueryConfig::LastUserMessage, &body, 64),
            Err(QueryError::Empty)
        );
        let body = json!({"messages":[{"role":"user","content":[]}]});
        assert_eq!(
            extract_query(&RagQueryConfig::LastUserMessage, &body, 64),
            Err(QueryError::Empty)
        );
    }

    #[test]
    fn missing_final_user_text_is_a_typed_error() {
        for body in [
            json!({}),
            json!({"messages":[]}),
            json!({"messages":[{"role":"assistant","content":"answer"}]}),
            json!({"messages":[{"role":"user"}]}),
            json!({"messages":[{"role":"user","content":42}]}),
        ] {
            assert_eq!(
                extract_query(&RagQueryConfig::LastUserMessage, &body, 64),
                Err(QueryError::MissingUserMessage),
                "{body}"
            );
        }
    }

    #[test]
    fn oversized_query_reports_both_sizes() {
        let body = json!({"messages":[{"role":"user","content":"1234567890"}]});
        assert_eq!(
            extract_query(&RagQueryConfig::LastUserMessage, &body, 9),
            Err(QueryError::TooLarge {
                actual: 10,
                maximum: 9,
            })
        );
    }
}
