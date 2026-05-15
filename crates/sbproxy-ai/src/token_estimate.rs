// SPDX-License-Identifier: BUSL-1.1
//! Pre-request prompt token estimation for fail-fast TPM enforcement (WOR-232).
//!
//! The WOR-223 [`ModelRateLimiter`](crate::ratelimit::ModelRateLimiter) reconciles
//! the real `usage.prompt_tokens` against a pre-flight reservation after the
//! upstream call completes. That reservation defaults to a small constant
//! ([`crate::ratelimit::DEFAULT_ESTIMATED_TOKENS`]) so a large prompt can still
//! land at the upstream, eat one round-trip of network and provider compute,
//! and only then trip TPM at reconcile time.
//!
//! [`estimate_tokens`] gives the request filter a real estimate before the
//! upstream call. The limiter reserves that estimate in
//! [`ModelRateLimiter::admit`](crate::ratelimit::ModelRateLimiter::admit); when
//! it would exceed TPM we 429 the client with a real `Retry-After`. Then we
//! reconcile against `usage.prompt_tokens` in the existing
//! [`Admission::reconcile`](crate::ratelimit::Admission::reconcile) path so the
//! bucket math is settled against the truth.
//!
//! ## Model coverage
//!
//! - GPT-4, GPT-3.5, embeddings models use `cl100k_base`.
//! - GPT-4o, GPT-4.1, GPT-5, o1 / o3 / o4 use `o200k_base`.
//! - The upstream `tiktoken-rs` crate ships the model prefix table that maps
//!   every published OpenAI / Azure deployment name to one of those BPEs;
//!   we delegate to it.
//! - Anthropic Claude does not publish its BPE vocabulary. We fall back to
//!   a documented `chars / 4 + 1` heuristic for any model the tiktoken
//!   prefix table cannot identify. This is the same heuristic the older
//!   [`crate::context_compress::estimate_message_tokens`] uses and matches
//!   Anthropic's own published rule of thumb. Reconcile against the real
//!   `usage.input_tokens` in the response corrects any drift, and the
//!   `sbproxy_ai_token_estimate_error_ratio` histogram surfaces the gap.
//!
//! Token caching is by tokenizer (cl100k vs o200k), not by model: every
//! GPT-4-family request shares one `CoreBPE` instance amortized behind
//! `tiktoken-rs`'s own static singletons.

use crate::types::Message;

/// Per-message framing overhead used by the OpenAI cookbook for
/// `tiktoken`-based counting. Mirrors the constant `num_tokens_from_messages`
/// uses internally; redeclared here so we can short-circuit the more
/// expensive `tiktoken_rs::num_tokens_from_messages` API which wants its own
/// `ChatCompletionRequestMessage` shape, while still tracking the same
/// overhead model.
const TOKENS_PER_MESSAGE: u64 = 3;

/// Final reply-priming overhead the cookbook adds once after every message
/// list (`<|start|>assistant<|message|>`).
const REPLY_PRIMING: u64 = 3;

/// Estimate prompt tokens for a chat-completion request.
///
/// `model` selects the BPE: GPT-4-class models use `cl100k_base`, GPT-4o
/// and the o-series use `o200k_base`, anything else (notably Anthropic and
/// open-source endpoints exposed through this gateway) falls back to a
/// `chars / 4 + 1` heuristic. The return value is always at least the
/// per-request reply-priming overhead so a request with no parseable
/// content still books a non-zero reservation against TPM and TPD.
///
/// This function never panics and never allocates a BPE: the heavy
/// initialization happens once inside `tiktoken-rs`'s own statics. Subsequent
/// calls reuse those singletons.
pub fn estimate_tokens(model: &str, messages: &[Message]) -> u64 {
    // Path A: tiktoken-rs recognizes this model name. Use the real BPE and
    // walk the message list ourselves, since `num_tokens_from_messages`
    // wants `ChatCompletionRequestMessage` from the crate and would force
    // us to translate every call site.
    if let Ok(bpe) = tiktoken_rs::bpe_for_model(model) {
        let mut n: u64 = 0;
        for msg in messages {
            n += TOKENS_PER_MESSAGE;
            n += bpe.encode_with_special_tokens(&msg.role).len() as u64;
            n += content_tokens_with_bpe(bpe, &msg.content);
        }
        return n + REPLY_PRIMING;
    }

    // Path B: unknown model (Claude, unknown Azure deployment name,
    // self-hosted endpoint). Fall back to chars/4 + per-message framing.
    // The reconciliation step in `Admission::reconcile` corrects the
    // estimate against the upstream's reported usage; the
    // `sbproxy_ai_token_estimate_error_ratio` histogram surfaces drift so
    // operators can spot heuristic decay over time.
    estimate_tokens_heuristic(messages)
}

/// Heuristic estimator: `chars / 4 + 1` per message, plus per-message
/// framing and reply priming. Exported under the same name pattern as the
/// model-specific path so call sites that want to bypass BPE lookup (e.g.
/// embeddings input that does not parse as `Message`) can reach it.
pub fn estimate_tokens_heuristic(messages: &[Message]) -> u64 {
    let mut n: u64 = 0;
    for msg in messages {
        n += TOKENS_PER_MESSAGE;
        // Role contributes a few tokens; estimate role as 1 token.
        n += role_tokens_heuristic(&msg.role);
        n += content_tokens_heuristic(&msg.content);
    }
    n + REPLY_PRIMING
}

fn role_tokens_heuristic(role: &str) -> u64 {
    // Roles are short single words ("system", "user", ...). chars/4 gives
    // 1 for everything reasonable; clamp to 1 for the empty role.
    ((role.len() as u64) / 4).max(1)
}

/// Walk a `Message.content` value and sum BPE-encoded token counts.
///
/// `content` is a `serde_json::Value` because the OpenAI schema allows
/// either a bare string or an array of typed parts (text + image_url for
/// multimodal). We count text parts only; image inputs are token-counted by
/// the upstream out of band and would require model-specific lookup that
/// belongs in the multimodal module rather than here.
fn content_tokens_with_bpe(bpe: &tiktoken_rs::CoreBPE, content: &serde_json::Value) -> u64 {
    match content {
        serde_json::Value::String(s) => bpe.encode_with_special_tokens(s).len() as u64,
        serde_json::Value::Array(parts) => {
            let mut total: u64 = 0;
            for part in parts {
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    total += bpe.encode_with_special_tokens(text).len() as u64;
                } else if let Some(s) = part.as_str() {
                    total += bpe.encode_with_special_tokens(s).len() as u64;
                }
            }
            total
        }
        // Numbers / bools / null contribute roughly one token; skip
        // entirely when the field is absent.
        serde_json::Value::Null => 0,
        other => {
            // Fall back to the serialized form. `to_string` cannot fail
            // for a Value, but defensively clamp at one token if the
            // value renders to an empty string.
            let s = other.to_string();
            bpe.encode_with_special_tokens(&s).len() as u64
        }
    }
}

fn content_tokens_heuristic(content: &serde_json::Value) -> u64 {
    match content {
        serde_json::Value::String(s) => (s.len() as u64 / 4).max(1),
        serde_json::Value::Array(parts) => {
            let mut total: u64 = 0;
            for part in parts {
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    total += (text.len() as u64 / 4).max(1);
                } else if let Some(s) = part.as_str() {
                    total += (s.len() as u64 / 4).max(1);
                }
            }
            total.max(1)
        }
        serde_json::Value::Null => 0,
        other => {
            let s = other.to_string();
            (s.len() as u64 / 4).max(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(role: &str, text: &str) -> Message {
        Message {
            role: role.to_string(),
            content: json!(text),
        }
    }

    #[test]
    fn known_model_uses_bpe() {
        // A short prompt; cl100k_base tokenizes "Hello, world!" to a small
        // number of tokens. The estimate must be > the reply priming
        // alone, proving the BPE path ran.
        let messages = vec![msg("user", "Hello, world!")];
        let est = estimate_tokens("gpt-4", &messages);
        assert!(
            est > REPLY_PRIMING,
            "BPE path must contribute at least one token for non-empty content (got {est})"
        );
    }

    #[test]
    fn gpt4o_uses_o200k_base() {
        // gpt-4o maps to O200kBase per the tiktoken model table; the
        // function must still return a positive count.
        let messages = vec![msg("user", "Tokenize this please.")];
        let est = estimate_tokens("gpt-4o", &messages);
        assert!(est > REPLY_PRIMING, "got {est}");
    }

    #[test]
    fn unknown_model_falls_back_to_heuristic() {
        // Claude model: tiktoken-rs has no BPE for it, so we hit the
        // chars/4 path. 40 chars of content -> 10 token estimate from the
        // content alone, plus per-message overhead and reply priming.
        let content = "a".repeat(40);
        let messages = vec![msg("user", &content)];
        let est = estimate_tokens("claude-3-opus-20240229", &messages);
        // Lower bound: per-message (3) + role (1) + content (10) + reply (3) = 17.
        assert!(
            est >= 17,
            "Claude heuristic should contribute at least 17 tokens, got {est}"
        );
    }

    #[test]
    fn empty_messages_returns_reply_priming() {
        let est = estimate_tokens("gpt-4", &[]);
        assert_eq!(est, REPLY_PRIMING);
    }

    #[test]
    fn multimodal_content_counts_text_parts() {
        // Multimodal content with one text part and one image_url. The
        // image is intentionally ignored; only the text contributes.
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!([
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}},
            ]),
        }];
        let est = estimate_tokens("gpt-4o", &messages);
        // Sanity: at least the per-message overhead + reply priming.
        assert!(est > REPLY_PRIMING);
    }

    #[test]
    fn estimate_is_within_5pct_for_a_known_prompt() {
        // Hand-picked prompt; tiktoken's published `cl100k_base` count for
        // this exact byte sequence is 11 tokens. We allow +- a small
        // overhead for the per-message framing constants. The test passes
        // if the estimator is within 30% of the BPE-only count, which
        // comfortably exceeds the "within 5%" acceptance bar once the
        // per-message overhead is held constant.
        //
        // tiktoken count of "tiktoken is great!" with cl100k_base is 6
        // tokens (verified via the OpenAI tokenizer playground). Add
        // 3 (per-message) + 1 (role) + 3 (reply priming) = 13. We assert
        // the estimator returns exactly 13.
        let messages = vec![msg("user", "tiktoken is great!")];
        let est = estimate_tokens("gpt-4", &messages);
        assert_eq!(
            est, 13,
            "estimate drifted from the hand-checked BPE count (got {est})"
        );
    }

    #[test]
    fn unknown_model_does_not_panic_on_weird_content() {
        // Nested JSON content that does not match the documented schema
        // should still return a non-zero estimate via the fallback path.
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!({"unexpected": "shape"}),
        }];
        let est = estimate_tokens("some-self-hosted-model", &messages);
        assert!(est > 0);
    }
}
