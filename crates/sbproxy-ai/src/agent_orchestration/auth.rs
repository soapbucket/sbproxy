//! Centralised authentication for Agent-to-Agent (A2A) communication.
//!
//! Agents prove their identity by presenting a token derived from their ID and
//! a shared secret.  The same derivation is used to verify tokens, so no
//! token database is required.

use sha2::{Digest, Sha256};

/// Configuration for A2A authentication.
pub struct A2AAuthConfig {
    /// Secret shared between all participating agents.
    pub shared_secret: String,
}

/// Derive a deterministic token for `agent_id` using `secret`.
///
/// The token is the hex-encoded SHA-256 digest of `"<agent_id>:<secret>"`.
pub fn generate_agent_token(agent_id: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(b":");
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Return `true` if `token` is the correct token for `agent_id` and `secret`.
pub fn verify_agent_token(agent_id: &str, token: &str, secret: &str) -> bool {
    generate_agent_token(agent_id, secret) == token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_round_trip() {
        let token = generate_agent_token("agent-1", "my_secret");
        assert!(verify_agent_token("agent-1", &token, "my_secret"));
    }

    #[test]
    fn wrong_token_fails_verification() {
        assert!(!verify_agent_token("agent-1", "wrong_token", "my_secret"));
    }

    #[test]
    fn different_agents_produce_different_tokens() {
        let t1 = generate_agent_token("agent-a", "shared");
        let t2 = generate_agent_token("agent-b", "shared");
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_secrets_produce_different_tokens() {
        let t1 = generate_agent_token("agent-x", "secret1");
        let t2 = generate_agent_token("agent-x", "secret2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_is_64_hex_chars() {
        let token = generate_agent_token("agent", "secret");
        // SHA-256 produces 32 bytes = 64 hex characters.
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_with_wrong_agent_id_fails() {
        let token = generate_agent_token("agent-real", "secret");
        assert!(!verify_agent_token("agent-fake", &token, "secret"));
    }

    #[test]
    fn a2a_auth_config_holds_secret() {
        let config = A2AAuthConfig {
            shared_secret: "top_secret".to_string(),
        };
        let token = generate_agent_token("bot", &config.shared_secret);
        assert!(verify_agent_token("bot", &token, &config.shared_secret));
    }
}
