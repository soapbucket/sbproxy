// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Token counting + chat-template rendering (WOR-1671).
//!
//! Budgets, context-fit, and the KV math all need an accurate token
//! count against the model's *own* tokenizer, and a locally-served
//! model needs its own chat template applied when the engine expects a
//! preformatted prompt rather than messages. This module is behind the
//! `tokenizer` feature, which is on by default (it pulls `tokenizers` +
//! `minijinja`, both already default dependencies elsewhere in the
//! workspace, so enabling it adds no new lock entries). The HF
//! `tokenizers` crate loads the model's `tokenizer.json`; `minijinja`
//! is what TGI and mistral.rs use to render the Jinja `chat_template`.
//! With the feature compiled in, callers get this exact count instead
//! of a length-based heuristic.

use serde::Serialize;

/// One chat message for template rendering. Matches the shape HF chat
/// templates expect (`message.role`, `message.content`).
#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    /// `system`, `user`, `assistant`, or `tool`.
    pub role: String,
    /// The message text.
    pub content: String,
}

impl ChatMessage {
    /// Build a message.
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
        }
    }
}

/// Count tokens in `text` against a model's `tokenizer.json` (its raw
/// bytes). This is the exact count the engine will see, so budgets and
/// context-fit decisions match reality rather than a heuristic.
pub fn count_tokens(tokenizer_json: &[u8], text: &str) -> Result<usize, String> {
    let tokenizer = tokenizers::Tokenizer::from_bytes(tokenizer_json)
        .map_err(|e| format!("load tokenizer: {e}"))?;
    let encoding = tokenizer
        .encode(text, false)
        .map_err(|e| format!("encode: {e}"))?;
    Ok(encoding.get_ids().len())
}

/// Render a model's Jinja `chat_template` over a message list, the way
/// the engine's own chat endpoint would, for the case where the engine
/// wants a preformatted prompt. `add_generation_prompt` is exposed to
/// the template as most HF templates branch on it.
pub fn render_chat_template(
    template: &str,
    messages: &[ChatMessage],
    add_generation_prompt: bool,
) -> Result<String, String> {
    let mut env = minijinja::Environment::new();
    env.add_template("chat", template)
        .map_err(|e| format!("parse chat_template: {e}"))?;
    let tmpl = env
        .get_template("chat")
        .map_err(|e| format!("get chat_template: {e}"))?;
    tmpl.render(minijinja::context! {
        messages => messages,
        add_generation_prompt => add_generation_prompt,
    })
    .map_err(|e| format!("render chat_template: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal WordLevel tokenizer.json: whitespace-split, three-word
    /// vocab with an unknown token. Small enough to embed, real enough
    /// to exercise the `tokenizers` load + encode path.
    const TINY_TOKENIZER: &str = r#"{
        "version": "1.0",
        "truncation": null,
        "padding": null,
        "added_tokens": [],
        "normalizer": null,
        "pre_tokenizer": {"type": "Whitespace"},
        "post_processor": null,
        "decoder": null,
        "model": {
            "type": "WordLevel",
            "vocab": {"hello": 0, "world": 1, "[UNK]": 2},
            "unk_token": "[UNK]"
        }
    }"#;

    #[test]
    fn counts_tokens_against_the_tokenizer() {
        // Two known words -> 2 tokens.
        assert_eq!(
            count_tokens(TINY_TOKENIZER.as_bytes(), "hello world").unwrap(),
            2
        );
        // A third, unknown word still counts (maps to [UNK]).
        assert_eq!(
            count_tokens(TINY_TOKENIZER.as_bytes(), "hello world foo").unwrap(),
            3
        );
        // Empty text -> 0 tokens.
        assert_eq!(count_tokens(TINY_TOKENIZER.as_bytes(), "").unwrap(), 0);
    }

    #[test]
    fn bad_tokenizer_json_is_an_error() {
        assert!(count_tokens(b"not json", "hi").is_err());
    }

    #[test]
    fn real_tokenizer_diverges_from_a_length_heuristic() {
        // A 20-character single "word" (no whitespace) that is not an
        // exact vocab entry: the real tokenizer looks it up and falls
        // back to exactly one `[UNK]` token. A naive length-based
        // heuristic (`chars / 4`, the kind of estimate used when there
        // is no local tokenizer.json to load against) would guess 5.
        // The two numbers disagree, which is the point: this asserts
        // the exact vocab-lookup path ran, not an approximation.
        let text = "helloworldhelloworld";
        assert_eq!(text.len(), 20);
        let exact = count_tokens(TINY_TOKENIZER.as_bytes(), text).unwrap();
        let heuristic_guess = text.len() / 4;
        assert_eq!(exact, 1, "expected a single [UNK] token from real lookup");
        assert_ne!(
            exact, heuristic_guess,
            "real tokenizer count should not match a length-based guess"
        );
    }

    #[test]
    fn renders_a_chat_template() {
        // A small template in the HF shape.
        let tmpl = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}\
{% if add_generation_prompt %}assistant: {% endif %}";
        let msgs = vec![
            ChatMessage::new("system", "be terse"),
            ChatMessage::new("user", "hi"),
        ];
        let out = render_chat_template(tmpl, &msgs, true).unwrap();
        assert_eq!(out, "system: be terse\nuser: hi\nassistant: ");
        // Without the generation prompt, the trailing marker is omitted.
        let out2 = render_chat_template(tmpl, &msgs, false).unwrap();
        assert!(!out2.contains("assistant: "));
    }

    #[test]
    fn malformed_template_is_an_error() {
        assert!(render_chat_template("{% for %}", &[], false).is_err());
    }
}
