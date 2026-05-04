//! Web Bot Auth (F1.6): verify cryptographically-signed AI agents.
//!
//! Implements the IETF "Web Bot Auth" pattern: AI agents (crawlers,
//! research bots, indexers) sign each request with an Ed25519 key
//! using RFC 9421 HTTP Message Signatures and advertise their key id
//! in `Signature-Input`. The gateway verifies the signature against a
//! pre-loaded directory of agent public keys; verification success is
//! a strong signal that the request is from the agent it claims to
//! be.
//!
//! The OSS implementation ships a static directory configured inline
//! in YAML. Periodic refresh of a hosted directory (JWKS-shaped) is
//! tracked as a follow-up that wires onto the same `Directory` trait.

use sbproxy_middleware::signatures::{
    parse_signature_input, MessageSignatureConfig, MessageSignatureVerifier, SignatureAlgorithm,
    VerifyVerdict,
};
use serde::Deserialize;

use crate::auth::bot_auth_directory::{self, DirectoryConfig};

/// One agent in the directory.
#[derive(Debug, Clone, Deserialize)]
pub struct BotAuthAgent {
    /// Human-readable agent name (e.g. `"openai-gptbot"`,
    /// `"anthropic-claudebot"`). Surfaced in metrics labels and on
    /// the upstream request.
    pub name: String,
    /// `keyid` parameter the agent advertises in its
    /// `Signature-Input` header.
    pub key_id: String,
    /// Signature algorithm (today: `ed25519` or `hmac_sha256`).
    pub algorithm: SignatureAlgorithm,
    /// Public key (Ed25519: hex / base64 of raw 32 bytes; HMAC: any
    /// shared secret string).
    pub public_key: String,
    /// Optional list of signature components every accepted request
    /// must cover. Defaults to `["@method", "@target-uri"]` so a
    /// signature that only covers a header cannot be replayed against
    /// a different verb or URL.
    #[serde(default)]
    pub required_components: Vec<String>,
}

fn default_required_components() -> Vec<String> {
    vec!["@method".to_string(), "@target-uri".to_string()]
}

/// Configuration for the Web Bot Auth provider.
#[derive(Debug, Deserialize)]
pub struct BotAuthConfig {
    /// Directory of known agents. Each entry's `key_id` must be
    /// unique. May be empty when `directory` is set: the dynamic
    /// directory provides the agent set.
    #[serde(default)]
    pub agents: Vec<BotAuthAgent>,
    /// Clock skew tolerance applied to every agent's verifier in
    /// seconds. Defaults to 30s.
    #[serde(default = "default_skew_seconds")]
    pub clock_skew_seconds: u64,
    /// Optional dynamic directory configuration (Wave 1 / G1.7).
    /// When set, the provider can resolve `Signature-Agent` headers
    /// by fetching the JWKS-shaped hosted directory.
    #[serde(default)]
    pub directory: Option<DirectoryConfig>,
}

fn default_skew_seconds() -> u64 {
    30
}

/// Verdict surfaced by the auth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotAuthVerdict {
    /// Signature verified against an agent in the directory.
    Verified {
        /// The matched agent's display name.
        agent_name: String,
    },
    /// No `Signature-Input` header on the request. The auth provider
    /// returns `Deny(401)` so layered policies can interpret this as
    /// "unsigned crawler" without further plumbing.
    Missing,
    /// Signature header present but the keyid is not in the directory.
    UnknownAgent {
        /// The keyid the request claimed.
        key_id: String,
    },
    /// Signature verification failed for a known agent.
    Failed {
        /// Agent name (when known).
        agent_name: Option<String>,
        /// Failure reason from the underlying verifier.
        reason: String,
    },
    /// The request named a `Signature-Agent` directory the proxy
    /// could not consult. Distinct from [`BotAuthVerdict::UnknownAgent`]:
    /// `UnknownAgent` means "we have a directory and the keyid is not
    /// in it"; `DirectoryUnavailable` means "we could not fetch or
    /// validate the directory at all" (HTTPS-only violation,
    /// allowlist mismatch, fetch deadline exceeded, signature-invalid
    /// fall-through past `stale_grace`). The auth provider maps this
    /// to a 401 deny like the other unsigned variants. Operators
    /// alert on `sbproxy_bot_auth_directory_fetch_failures_total`
    /// to catch the underlying directory issue.
    DirectoryUnavailable {
        /// One of the closed reason strings from
        /// `docs/adr-bot-auth-directory.md` failure-mode table:
        /// `not_https`, `not_allowlisted`, `fetch_deadline_exceeded`,
        /// `network`, `http_5xx`, `http_4xx`, `signature_invalid`,
        /// `parse_error`, `stale_grace_exceeded`.
        reason: String,
    },
}

/// Web Bot Auth provider.
pub struct BotAuthProvider {
    /// `key_id` -> (agent_name, verifier).
    by_key_id: std::collections::HashMap<String, (String, MessageSignatureVerifier)>,
    /// Clock-skew tolerance carried over from config, reused when
    /// constructing on-the-fly verifiers for directory-resolved keys.
    clock_skew_seconds: u64,
    /// Dynamic directory configuration (G1.7). When set, the
    /// `verify_async` path can consult a hosted directory for
    /// `Signature-Agent`-named requests. The static `verify` path
    /// ignores this field and continues to use the inline `agents`
    /// list for backward compatibility.
    directory: Option<DirectoryConfig>,
}

impl std::fmt::Debug for BotAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys: Vec<(&String, &String)> =
            self.by_key_id.iter().map(|(k, v)| (k, &v.0)).collect();
        keys.sort_by(|a, b| a.0.cmp(b.0));
        f.debug_struct("BotAuthProvider")
            .field("agents", &keys)
            .finish()
    }
}

impl BotAuthProvider {
    /// Build the provider from JSON config.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: BotAuthConfig = serde_json::from_value(value)?;
        // A provider must have either inline agents or a directory.
        // An empty config with neither is a misconfiguration.
        if cfg.agents.is_empty() && cfg.directory.is_none() {
            anyhow::bail!(
                "bot_auth requires at least one agent in `agents` or a `directory` configuration"
            );
        }
        if let Some(dir) = &cfg.directory {
            dir.validate()?;
        }
        let mut by_key_id = std::collections::HashMap::with_capacity(cfg.agents.len());
        for agent in cfg.agents {
            if by_key_id.contains_key(&agent.key_id) {
                anyhow::bail!(
                    "bot_auth: duplicate key_id {:?} (agent {:?})",
                    agent.key_id,
                    agent.name
                );
            }
            let required = if agent.required_components.is_empty() {
                default_required_components()
            } else {
                agent.required_components.clone()
            };
            let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
                algorithm: agent.algorithm,
                key_id: agent.key_id.clone(),
                key: agent.public_key.clone(),
                required_components: required,
                clock_skew_seconds: cfg.clock_skew_seconds,
            })
            .map_err(|e| {
                anyhow::anyhow!("bot_auth agent {:?}: verifier init failed: {e}", agent.name)
            })?;
            by_key_id.insert(agent.key_id.clone(), (agent.name, verifier));
        }
        Ok(Self {
            by_key_id,
            clock_skew_seconds: cfg.clock_skew_seconds,
            directory: cfg.directory,
        })
    }

    /// True when this provider is configured with a dynamic
    /// directory. Used by the auth dispatcher to decide whether to
    /// invoke the async resolution path.
    pub fn has_directory(&self) -> bool {
        self.directory.is_some()
    }

    /// Verify a request, consulting the dynamic directory when the
    /// request carries a `Signature-Agent` header and the provider
    /// is configured with one.
    ///
    /// Falls back to the static [`Self::verify`] path when no
    /// `Signature-Agent` header is present, preserving the OSS
    /// inline-agent flow.
    pub async fn verify_async(
        &self,
        req: &http::Request<bytes::Bytes>,
        client: &reqwest::Client,
    ) -> BotAuthVerdict {
        let sig_agent = req
            .headers()
            .get("signature-agent")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let Some(sig_agent) = sig_agent else {
            // No Signature-Agent header: fall through to the
            // synchronous static path.
            return self.verify(req);
        };

        let Some(directory) = &self.directory else {
            // Request advertised a directory but the provider is
            // not configured to consult one. Per ADR, treat as
            // DirectoryUnavailable so operators see a distinct
            // signal in metrics.
            return BotAuthVerdict::DirectoryUnavailable {
                reason: "directory_not_configured".to_string(),
            };
        };

        let keys =
            match bot_auth_directory::resolve_signature_agent(sig_agent, directory, client).await {
                Ok(k) => k,
                Err(reason) => {
                    return BotAuthVerdict::DirectoryUnavailable { reason };
                }
            };

        // Pull the keyid the request advertised. We need to find a
        // matching key in the resolved directory snapshot.
        let Some(input_header) = req.headers().get("signature-input") else {
            return BotAuthVerdict::Missing;
        };
        let Ok(input_str) = input_header.to_str() else {
            return BotAuthVerdict::Missing;
        };
        let entries = match parse_signature_input(input_str) {
            Ok(e) => e,
            Err(e) => {
                return BotAuthVerdict::Failed {
                    agent_name: None,
                    reason: format!("malformed signature-input: {e}"),
                };
            }
        };
        let advertised_kid = entries
            .iter()
            .find_map(|(_, e)| e.params.keyid.clone())
            .unwrap_or_default();
        let Some(matched) = keys.iter().find(|k| k.kid == advertised_kid) else {
            return BotAuthVerdict::UnknownAgent {
                key_id: advertised_kid,
            };
        };

        // Build a per-request verifier on the matched key. Today we
        // only verify Ed25519 directory keys; RSA / EC fall through
        // to UnknownAgent until those paths land.
        let Some(pubkey_bytes) = matched.ed25519_pubkey else {
            return BotAuthVerdict::UnknownAgent {
                key_id: matched.kid.clone(),
            };
        };
        let pk_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pubkey_bytes);
        let verifier = match MessageSignatureVerifier::new(MessageSignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: matched.kid.clone(),
            key: pk_b64,
            required_components: default_required_components(),
            clock_skew_seconds: self.clock_skew_seconds,
        }) {
            Ok(v) => v,
            Err(e) => {
                return BotAuthVerdict::Failed {
                    agent_name: matched.agent.clone(),
                    reason: format!("verifier init failed: {e}"),
                };
            }
        };

        match verifier.verify_request(req) {
            VerifyVerdict::Ok { .. } => BotAuthVerdict::Verified {
                agent_name: matched.agent.clone().unwrap_or_else(|| matched.kid.clone()),
            },
            VerifyVerdict::Failed { reason } => BotAuthVerdict::Failed {
                agent_name: matched.agent.clone(),
                reason,
            },
        }
    }

    /// Number of registered agents.
    pub fn agent_count(&self) -> usize {
        self.by_key_id.len()
    }

    /// Verify the signature on `req` against the directory.
    pub fn verify(&self, req: &http::Request<bytes::Bytes>) -> BotAuthVerdict {
        let Some(input) = req.headers().get("signature-input") else {
            return BotAuthVerdict::Missing;
        };
        let Ok(input_str) = input.to_str() else {
            return BotAuthVerdict::Missing;
        };
        let entries = match parse_signature_input(input_str) {
            Ok(e) => e,
            Err(e) => {
                return BotAuthVerdict::Failed {
                    agent_name: None,
                    reason: format!("malformed signature-input: {e}"),
                };
            }
        };
        // Pick the first signature with a recognised keyid; an inbound
        // crawler typically advertises one.
        let mut matched_key_id: Option<String> = None;
        for (_label, entry) in &entries {
            if let Some(kid) = entry.params.keyid.as_deref() {
                if self.by_key_id.contains_key(kid) {
                    matched_key_id = Some(kid.to_string());
                    break;
                }
            }
        }
        let Some(kid) = matched_key_id else {
            // Surface the first claimed keyid so logs name what the
            // crawler advertised.
            let claimed = entries
                .into_iter()
                .find_map(|(_, e)| e.params.keyid)
                .unwrap_or_else(|| "<unset>".to_string());
            return BotAuthVerdict::UnknownAgent { key_id: claimed };
        };
        let (agent_name, verifier) = self
            .by_key_id
            .get(&kid)
            .expect("checked contains_key above");
        match verifier.verify_request(req) {
            VerifyVerdict::Ok { .. } => BotAuthVerdict::Verified {
                agent_name: agent_name.clone(),
            },
            VerifyVerdict::Failed { reason } => BotAuthVerdict::Failed {
                agent_name: Some(agent_name.clone()),
                reason,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    fn ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = kp.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), public)
    }

    #[test]
    fn empty_directory_rejected() {
        let err = BotAuthProvider::from_config(serde_json::json!({"agents": []})).unwrap_err();
        assert!(err.to_string().contains("at least one agent"));
    }

    #[test]
    fn duplicate_key_id_rejected() {
        let err = BotAuthProvider::from_config(serde_json::json!({
            "agents": [
                {"name": "a", "key_id": "k", "algorithm": "hmac_sha256", "public_key": "secret-a"},
                {"name": "b", "key_id": "k", "algorithm": "hmac_sha256", "public_key": "secret-b"}
            ]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate key_id"));
    }

    #[test]
    fn agent_count_matches_config() {
        let provider = BotAuthProvider::from_config(serde_json::json!({
            "agents": [
                {"name": "a", "key_id": "k1", "algorithm": "hmac_sha256", "public_key": "secret-a"},
                {"name": "b", "key_id": "k2", "algorithm": "hmac_sha256", "public_key": "secret-b"}
            ]
        }))
        .unwrap();
        assert_eq!(provider.agent_count(), 2);
    }

    #[test]
    fn missing_signature_input_returns_missing() {
        let provider = BotAuthProvider::from_config(serde_json::json!({
            "agents": [
                {"name": "a", "key_id": "k1", "algorithm": "hmac_sha256", "public_key": "secret-a"}
            ]
        }))
        .unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(bytes::Bytes::new())
            .unwrap();
        assert_eq!(provider.verify(&req), BotAuthVerdict::Missing);
    }

    #[test]
    fn unknown_keyid_surfaces_in_verdict() {
        let provider = BotAuthProvider::from_config(serde_json::json!({
            "agents": [
                {"name": "a", "key_id": "k1", "algorithm": "hmac_sha256", "public_key": "secret-a"}
            ]
        }))
        .unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header(
                "signature-input",
                "sig1=(\"@method\");keyid=\"unknown\";created=1700000000",
            )
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match provider.verify(&req) {
            BotAuthVerdict::UnknownAgent { key_id } => {
                assert_eq!(key_id, "unknown");
            }
            other => panic!("expected UnknownAgent, got {:?}", other),
        }
    }

    #[test]
    fn ed25519_signed_request_verifies() {
        let (pkcs8, public) = ed25519_keypair();
        let public_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &public);

        // Sign a representative signature base.
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();

        // Build a minimal Signature-Input + Signature for a GET. The
        // signature base for ("@method";"@target-uri") + the
        // @signature-params component is what the verifier reconstructs.
        let created = 1_700_000_000u64;
        let key_id = "gptbot-key-2026";
        let label = "sig1";
        let sig_input_value = format!(
            "{label}=(\"@method\" \"@target-uri\");created={created};keyid=\"{key_id}\";alg=\"ed25519\""
        );

        // Reconstruct the same base the verifier computes. Use the
        // public helper to keep the test honest if the implementation
        // shifts.
        let req_base = http::Request::builder()
            .method("GET")
            .uri("https://example.com/article")
            .header("signature-input", &sig_input_value)
            .body(bytes::Bytes::new())
            .unwrap();

        let entries = parse_signature_input(&sig_input_value).unwrap();
        let (_, entry) = &entries[0];
        let base = sbproxy_middleware::signatures::build_signature_base(&req_base, entry).unwrap();

        let sig = kp.sign(base.as_bytes());
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.as_ref());
        let sig_value = format!("{label}=:{sig_b64}:");

        let provider = BotAuthProvider::from_config(serde_json::json!({
            "agents": [
                {
                    "name": "openai-gptbot",
                    "key_id": key_id,
                    "algorithm": "ed25519",
                    "public_key": public_b64,
                    "required_components": ["@method", "@target-uri"],
                }
            ]
        }))
        .unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/article")
            .header("signature-input", sig_input_value)
            .header("signature", sig_value)
            .body(bytes::Bytes::new())
            .unwrap();

        match provider.verify(&req) {
            BotAuthVerdict::Verified { agent_name } => {
                assert_eq!(agent_name, "openai-gptbot");
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }
}
