//! Deterministic chunk selection, context rendering, and injection.
//!
//! Selection is a pure function over retrieved chunks with hard byte
//! caps. Rendering compiles the operator template once, with strict
//! undefined behavior, and treats chunk text strictly as data: chunk
//! content is never evaluated as a second template, so template syntax
//! inside retrieved documents stays literal. Injection inserts exactly
//! one `role: system` message immediately before the last user message.

use minijinja::{Environment, UndefinedBehavior};
use sbproxy_ai::rag_config::{MAX_SOURCE_ID_BYTES, MAX_TEMPLATE_BYTES};

use crate::error::{RagBuildError, RagError};
use crate::runtime::RetrievedChunk;

/// Select and bound the chunks that enter the context template.
///
/// Chunks with an empty source ID, a source ID over
/// [`MAX_SOURCE_ID_BYTES`], an empty body, or a non-finite score are
/// rejected. Survivors sort by descending score, then ascending source
/// ID, so equal-score output is deterministic. Scores below `min_score`
/// are dropped, each content value is truncated at a valid UTF-8
/// boundary no later than `max_chunk_bytes`, and selection stops before
/// the selected content sum would exceed `max_context_bytes` or the
/// count would exceed `top_k`.
pub fn select_chunks(
    mut chunks: Vec<RetrievedChunk>,
    min_score: f32,
    top_k: usize,
    max_chunk_bytes: usize,
    max_context_bytes: usize,
) -> Vec<RetrievedChunk> {
    chunks.retain(|chunk| {
        !chunk.source_id.is_empty()
            && chunk.source_id.len() <= MAX_SOURCE_ID_BYTES
            && !chunk.content.is_empty()
            && chunk.score.is_finite()
            && chunk.score >= min_score
    });
    chunks.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    let mut selected = Vec::new();
    let mut total_bytes = 0usize;
    for mut chunk in chunks {
        if selected.len() == top_k {
            break;
        }
        truncate_at_utf8_boundary(&mut chunk.content, max_chunk_bytes);
        if chunk.content.is_empty() {
            // A multi-byte first character can truncate to nothing;
            // an empty chunk adds no context.
            continue;
        }
        if total_bytes + chunk.content.len() > max_context_bytes {
            break;
        }
        total_bytes += chunk.content.len();
        selected.push(chunk);
    }
    selected
}

/// Truncate `text` at the last valid UTF-8 boundary at or before
/// `max_bytes`.
fn truncate_at_utf8_boundary(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

/// A context template compiled once at build time with strict
/// undefined behavior.
///
/// Exactly one template named `context` lives in the environment, and
/// exactly two variables are exposed at render time: `query` and
/// `chunks`. Chunk fields reach the template as serialized data, so
/// template syntax inside chunk content is emitted literally.
pub struct ContextTemplate {
    env: Environment<'static>,
}

impl ContextTemplate {
    /// Compile `source` into a reusable template.
    ///
    /// Fails with [`RagBuildError::Template`] when the source exceeds
    /// [`MAX_TEMPLATE_BYTES`] or does not parse. The error carries the
    /// minijinja error class, not template or data content.
    pub fn compile(source: &str) -> Result<Self, RagBuildError> {
        if source.len() > MAX_TEMPLATE_BYTES {
            return Err(RagBuildError::Template(format!(
                "template is {} bytes; the maximum is {MAX_TEMPLATE_BYTES}",
                source.len()
            )));
        }
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        env.add_template_owned("context", source.to_owned())
            .map_err(|error| RagBuildError::Template(error.kind().to_string()))?;
        Ok(Self { env })
    }
}

/// Render `query` and `chunks` through `template` and enforce
/// `max_context_bytes` on the complete rendered string.
///
/// Render failures and oversized output return [`RagError::Render`]
/// with an error class only; rendered content never enters the error.
pub fn render_context(
    template: &ContextTemplate,
    query: &str,
    chunks: &[RetrievedChunk],
    max_context_bytes: usize,
) -> Result<String, RagError> {
    let compiled = template
        .env
        .get_template("context")
        .map_err(|error| RagError::Render(error.kind().to_string()))?;
    let rendered = compiled
        .render(minijinja::context! { query => query, chunks => chunks })
        .map_err(|error| RagError::Render(error.kind().to_string()))?;
    if rendered.len() > max_context_bytes {
        return Err(RagError::Render(format!(
            "rendered context is {} bytes; the configured maximum is {max_context_bytes}",
            rendered.len()
        )));
    }
    Ok(rendered)
}

/// Insert `context` as one `role: system` message immediately before
/// the last `role: user` message in `body`.
///
/// Fails with [`RagError::Inject`] when the body has no `messages`
/// array or no user message. Injection failures always propagate to
/// the caller; the failure policy never applies to them.
pub fn inject_context(body: &mut serde_json::Value, context: &str) -> Result<(), RagError> {
    let messages = body
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| RagError::Inject("request body has no messages array".to_owned()))?;
    let last_user_index = messages
        .iter()
        .rposition(|message| {
            message.get("role").and_then(serde_json::Value::as_str) == Some("user")
        })
        .ok_or_else(|| RagError::Inject("request body has no user message".to_owned()))?;
    messages.insert(
        last_user_index,
        serde_json::json!({"role": "system", "content": context}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_ai::rag_config::DEFAULT_PROMPT_TEMPLATE;
    use serde_json::json;

    fn chunk(source_id: &str, content: &str, score: f32) -> RetrievedChunk {
        RetrievedChunk {
            source_id: source_id.to_owned(),
            content: content.to_owned(),
            score,
        }
    }

    #[test]
    fn chunks_sort_by_score_then_source_and_obey_both_byte_caps() {
        let chunks = vec![
            chunk("b", "bbbb", 0.90),
            chunk("a", "aaaa", 0.90),
            chunk("c", "cccccccc", 0.60),
        ];
        let selected = select_chunks(chunks, 0.70, 3, 4, 8);
        assert_eq!(
            selected
                .iter()
                .map(|chunk| chunk.source_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(
            selected
                .iter()
                .map(|chunk| chunk.content.len())
                .sum::<usize>(),
            8
        );
    }

    #[test]
    fn injection_adds_one_system_message_before_the_last_user_turn() {
        let mut body = json!({
            "messages": [
                {"role":"system","content":"application rules"},
                {"role":"user","content":"How fast are refunds?"}
            ]
        });
        inject_context(&mut body, "bounded context").unwrap();
        assert_eq!(body["messages"][1]["role"], "system");
        assert_eq!(body["messages"][1]["content"], "bounded context");
        assert_eq!(body["messages"][2]["role"], "user");
    }

    #[test]
    fn non_finite_scores_are_rejected() {
        let chunks = vec![
            chunk("nan", "content", f32::NAN),
            chunk("inf", "content", f32::INFINITY),
            chunk("neg", "content", f32::NEG_INFINITY),
            chunk("ok", "content", 0.9),
        ];
        let selected = select_chunks(chunks, 0.0, 8, 64, 256);
        assert_eq!(
            selected
                .iter()
                .map(|chunk| chunk.source_id.as_str())
                .collect::<Vec<_>>(),
            ["ok"]
        );
    }

    #[test]
    fn invalid_source_ids_and_empty_bodies_are_rejected() {
        let overlong = "s".repeat(MAX_SOURCE_ID_BYTES + 1);
        let chunks = vec![
            chunk(&overlong, "content", 0.9),
            chunk("", "content", 0.9),
            chunk("empty-body", "", 0.9),
            chunk("ok", "content", 0.9),
        ];
        let selected = select_chunks(chunks, 0.0, 8, 64, 256);
        assert_eq!(
            selected
                .iter()
                .map(|chunk| chunk.source_id.as_str())
                .collect::<Vec<_>>(),
            ["ok"]
        );
    }

    #[test]
    fn top_k_caps_the_selection_count() {
        let chunks = vec![
            chunk("a", "aa", 0.9),
            chunk("b", "bb", 0.8),
            chunk("c", "cc", 0.7),
        ];
        let selected = select_chunks(chunks, 0.0, 2, 64, 256);
        assert_eq!(
            selected
                .iter()
                .map(|chunk| chunk.source_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn chunk_truncation_respects_utf8_boundaries() {
        // "a" is one byte; the accented "\u{e9}" is two bytes, so a
        // two-byte cap lands mid-character and must step back to "a".
        let chunks = vec![chunk("a", "a\u{e9}", 0.9)];
        let selected = select_chunks(chunks, 0.0, 1, 2, 256);
        assert_eq!(selected[0].content, "a");
    }

    #[test]
    fn rendered_output_over_max_context_bytes_is_an_error() {
        let template = ContextTemplate::compile(DEFAULT_PROMPT_TEMPLATE).unwrap();
        let chunks = vec![chunk("a", "aaaa", 0.9)];
        let error = render_context(&template, "query", &chunks, 8).unwrap_err();
        assert!(matches!(error, RagError::Render(_)), "{error:?}");
    }

    #[test]
    fn chunk_content_is_data_and_never_a_second_template() {
        let template = ContextTemplate::compile(DEFAULT_PROMPT_TEMPLATE).unwrap();
        let chunks = vec![chunk("doc-1", r#"{% include "secret" %}"#, 0.9)];
        let rendered = render_context(&template, "query", &chunks, 64 * 1024).unwrap();
        assert!(
            rendered.contains(r#"{% include "secret" %}"#),
            "chunk template syntax must stay literal: {rendered}"
        );
    }

    #[test]
    fn strict_undefined_rejects_unknown_template_variables() {
        let template = ContextTemplate::compile("{{ missing }}").unwrap();
        let error = render_context(&template, "query", &[], 64 * 1024).unwrap_err();
        assert!(matches!(error, RagError::Render(_)), "{error:?}");
    }

    #[test]
    fn injection_without_a_messages_array_is_an_error() {
        let mut body = json!({"input": "plain"});
        let error = inject_context(&mut body, "context").unwrap_err();
        assert!(matches!(error, RagError::Inject(_)), "{error:?}");
        assert_eq!(body, json!({"input": "plain"}));
    }

    #[test]
    fn injection_without_a_user_message_is_an_error() {
        let mut body = json!({"messages":[{"role":"system","content":"rules"}]});
        let error = inject_context(&mut body, "context").unwrap_err();
        assert!(matches!(error, RagError::Inject(_)), "{error:?}");
    }
}
