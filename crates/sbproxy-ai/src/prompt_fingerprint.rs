// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Privacy-safe prompt fingerprints for request-path value tracking.
//!
//! The reporting epic wants to correlate identical (or near-identical)
//! prompts across requests - "how often does this agent resend the same
//! prompt", "which credential drives the cache-hittable traffic" -
//! without persisting prompt text. [`prompt_fingerprint`] derives a
//! short, stable, non-reversible token from the prompt that can ride on
//! the request-event envelope and the span next to `tenant_id` /
//! `api_key_id` / `model`.
//!
//! ## Why salted
//!
//! A bare hash of the prompt is reversible by dictionary / rainbow
//! attack for short prompts and is trivially correlatable across
//! deployments. The fingerprint is keyed with a per-process random salt
//! generated once at startup, so:
//!
//! * the same prompt within one process lifetime maps to the same
//!   fingerprint (correlation works), and
//! * the fingerprint cannot be reversed to the prompt, nor matched
//!   against a fingerprint computed elsewhere.
//!
//! The salt is deliberately ephemeral (process-lifetime): the
//! fingerprint is an in-flight correlation key, not a durable identifier
//! the operator is expected to join across restarts.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::types::Message;

/// Prefix marking a value as a derived prompt fingerprint (parallels
/// the `sk_` credential-fingerprint prefix). Twelve hex chars (48 bits)
/// of digest keep collisions negligible for a single process's traffic
/// while staying compact for a log column / span attribute.
const PREFIX: &str = "pf_";

/// Process-lifetime random salt. Generated once on first use.
fn salt() -> &'static [u8; 16] {
    static SALT: OnceLock<[u8; 16]> = OnceLock::new();
    SALT.get_or_init(|| rand::random::<u128>().to_le_bytes())
}

/// Derive a salted, non-reversible fingerprint of a chat prompt.
///
/// The fingerprint covers the model plus every message's role and
/// content, so a prompt sent against two different models fingerprints
/// differently (the served output, and its cacheability, differ too).
/// Returns `pf_<12hex>`. Never embeds prompt text.
pub fn prompt_fingerprint(model: &str, messages: &[Message]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt());
    hasher.update(model.as_bytes());
    hasher.update([0u8]); // domain separator between model and messages
    for m in messages {
        hasher.update(m.role.as_bytes());
        hasher.update([0u8]);
        // Content is arbitrary JSON; hash its canonical-ish string form.
        // `to_string` is deterministic for a given serde_json::Value
        // (object key order is preserved as a Map), which is enough for
        // a correlation key.
        hasher.update(m.content.to_string().as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(PREFIX.len() + 12);
    out.push_str(PREFIX);
    for byte in digest.iter().take(6) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

    /// Same prompt + model fingerprints identically within a process;
    /// the value is opaque (`pf_` + 12 hex) and never contains the text.
    #[test]
    fn stable_and_opaque() {
        let msgs = vec![msg("user", "summarize the quarterly report")];
        let a = prompt_fingerprint("gpt-4o", &msgs);
        let b = prompt_fingerprint("gpt-4o", &msgs);
        assert_eq!(a, b);
        assert!(a.starts_with("pf_"));
        assert_eq!(a.len(), 3 + 12);
        assert!(!a.contains("summarize"));
    }

    /// Different prompt, different model, or different role all change
    /// the fingerprint.
    #[test]
    fn distinguishes_inputs() {
        let base = vec![msg("user", "hello")];
        let other_text = vec![msg("user", "goodbye")];
        let other_role = vec![msg("system", "hello")];
        let f = prompt_fingerprint("gpt-4o", &base);
        assert_ne!(f, prompt_fingerprint("gpt-4o", &other_text));
        assert_ne!(f, prompt_fingerprint("gpt-4o", &other_role));
        assert_ne!(f, prompt_fingerprint("claude-3-5-sonnet", &base));
    }
}
