//! The two record kinds the key store holds.
//!
//! A [`KeyRecord`] is an inbound virtual key (hashed at rest, governs what a
//! caller may do). A [`CredentialRecord`] is an upstream provider credential
//! (encrypted at rest or a vault reference, used to authenticate outbound).
//! Both are runtime records, not config types, so they carry no `JsonSchema`
//! derive; the `key_management:` config seed lowers into them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::{self, Envelope};

/// Lifecycle status shared by both record kinds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    /// Usable.
    #[default]
    Active,
    /// Temporarily disabled; can be unblocked back to `Active`.
    Blocked,
    /// Permanently disabled; terminal.
    Revoked,
}

/// Where a record came from, which drives reload precedence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordSource {
    /// Lowered from the `key_management:` config seed. Authoritative on reload
    /// unless the operator set `allow_api_override`.
    Config,
    /// Created at runtime through the admin API.
    #[default]
    Api,
}

/// Per-key budget caps. Kept independent of `sbproxy-ai::KeyBudget` so this
/// crate has no dependency on the AI gateway; the AI layer maps between them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecordBudget {
    /// Maximum total tokens for this key over its budget window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Maximum total cost in USD for this key over its budget window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
}

fn default_hash_alg() -> String {
    "hmac-sha256.v1".to_string()
}

fn default_policy_revision() -> u64 {
    1
}

/// An inbound virtual-key record. The plaintext secret is never stored: only
/// `secret_hash` (and, during a rotation grace window, `prev_secret_hash`) is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Stable public identifier and the token prefix (`sk-<key_id>-<secret>`).
    pub key_id: String,
    /// Monotonic revision of this key's policy, starting at one.
    #[serde(default = "default_policy_revision")]
    pub policy_revision: u64,
    /// `HMAC-SHA256(secret, pepper)`, hex. The at-rest verifier.
    pub secret_hash: String,
    /// A second hash accepted during a rotation grace window (the prior secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_secret_hash: Option<String>,
    /// When the `prev_secret_hash` stops being accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash_expires_at: Option<DateTime<Utc>>,
    /// Hash scheme tag, for forward migration.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
    /// Human-readable name, surfaced on access logs (never the secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Lifecycle status.
    #[serde(default)]
    pub status: RecordStatus,
    /// Max requests per minute (None = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_minute: Option<u64>,
    /// Max tokens (input + output) per minute (None = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_per_minute: Option<u64>,
    /// SLO priority lane: `interactive`, `standard`, or `batch`.
    /// Validated at the admin boundary and re-validated at the AI-gateway
    /// seam (like `principal_selectors`) so this leaf crate stays free of
    /// the gateway's enum. `None` behaves as `standard`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Per-key budget caps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<RecordBudget>,
    /// Models this key may use (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_models: Vec<String>,
    /// Models this key may not use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_models: Vec<String>,
    /// Providers this key may use (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_providers: Vec<String>,
    /// Providers this key may not use. Blocks take precedence over allows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_providers: Vec<String>,
    /// Named PII redaction rules that must be active on the request body before
    /// this key can dispatch upstream (empty = none required).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_pii_redaction: Vec<String>,
    /// Inbound principal selectors allowed to present this key (empty = any
    /// principal). Each entry is a `PrincipalSelectorConfig`-shaped JSON object,
    /// kept opaque here so this leaf crate stays free of the AI gateway types;
    /// the auth path deserializes it at use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_selectors: Vec<serde_json::Value>,
    /// Pin a model for requests on this key. When set, the gateway overwrites
    /// the request body `model` before routing, so the caller cannot pick a
    /// different one. `None` leaves the client's choice unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_to_model: Option<String>,
    /// Tool names this key may expose. None is unrestricted, an empty list
    /// denies every caller-supplied tool, and a non-empty list is an allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    /// Provider tool definitions injected into the request when this key
    /// authenticates, replacing any client-supplied tools. Opaque,
    /// provider-shaped JSON. Empty leaves the request's tools untouched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject_tools: Vec<serde_json::Value>,
    /// Reference to a federated MCP gateway whose live catalogue is
    /// injected as this key's tool surface. Opaque JSON (the AI
    /// gateway's `InjectMcpRef` shape: `{"ref": ..., "format": ...,
    /// "filter": [...]}`), kept unvalidated here like
    /// `principal_selectors`; the AI seam deserializes it at use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_mcp: Option<serde_json::Value>,
    /// Skip the body-aware prompt-injection scan for this key. Default false
    /// (every key is scanned). Set true for trusted callers (eval, red-team)
    /// that legitimately submit injection-shaped prompts.
    #[serde(default)]
    pub bypass_prompt_injection: bool,
    /// Project attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// User attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Free-form grouping tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Free-form metadata, surfaced on access logs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Owning tenant, if multi-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Expiry; past this instant the key is unusable regardless of status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Provenance, for reload precedence.
    #[serde(default)]
    pub source: RecordSource,
}

impl KeyRecord {
    /// Construct an active record from a freshly minted hash. Callers stamp
    /// policy/attribution fields afterward.
    pub fn new(
        key_id: impl Into<String>,
        secret_hash: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            policy_revision: default_policy_revision(),
            secret_hash: secret_hash.into(),
            prev_secret_hash: None,
            prev_hash_expires_at: None,
            hash_alg: default_hash_alg(),
            name: None,
            status: RecordStatus::Active,
            max_requests_per_minute: None,
            max_tokens_per_minute: None,
            priority: None,
            budget: None,
            allowed_models: Vec::new(),
            blocked_models: Vec::new(),
            allowed_providers: Vec::new(),
            blocked_providers: Vec::new(),
            require_pii_redaction: Vec::new(),
            principal_selectors: Vec::new(),
            route_to_model: None,
            allowed_tools: None,
            inject_tools: Vec::new(),
            inject_mcp: None,
            bypass_prompt_injection: false,
            project: None,
            user: None,
            tags: Vec::new(),
            metadata: BTreeMap::new(),
            tenant_id: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
            source: RecordSource::Api,
        }
    }

    /// Whether the record is `Active` and not past its expiry at `now`.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.status == RecordStatus::Active && self.expires_at.is_none_or(|exp| exp > now)
    }

    /// Constant-time check that `secret` matches this record's current hash, or
    /// its `prev_secret_hash` if a rotation grace window is still open at `now`.
    /// Does not consider status/expiry; callers gate on [`Self::is_usable`].
    pub fn verify_secret(&self, secret: &str, pepper: &[u8], now: DateTime<Utc>) -> bool {
        if crypto::verify_secret(secret, pepper, &self.secret_hash) {
            return true;
        }
        if let (Some(prev), Some(exp)) =
            (self.prev_secret_hash.as_deref(), self.prev_hash_expires_at)
        {
            if exp > now && crypto::verify_secret(secret, pepper, prev) {
                return true;
            }
        }
        false
    }

    /// Whether `model` is permitted by this record's allow/block lists.
    pub fn is_model_allowed(&self, model: &str) -> bool {
        if self.blocked_models.iter().any(|m| m == model) {
            return false;
        }
        if !self.allowed_models.is_empty() {
            return self.allowed_models.iter().any(|m| m == model);
        }
        true
    }
}

/// How an upstream credential's secret is held at rest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialMaterial {
    /// A secret reference resolved by `sbproxy-vault` at use time (`vault://`,
    /// `awssm://`, `gcpsm://`, `k8ssecret://`, ...). The first-class path; the
    /// secret never lives in the store.
    VaultRef {
        /// The scheme-prefixed reference string.
        reference: String,
    },
    /// An AEAD envelope: encrypted at rest, decrypted at dispatch.
    Envelope {
        /// The sealed envelope.
        envelope: Envelope,
    },
    /// Plaintext. Only for config-seeded credentials where the operator opted
    /// out of encryption; discouraged and never produced by the admin API.
    Plaintext {
        /// The raw secret.
        value: String,
    },
}

/// An upstream provider credential record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Stable identifier.
    pub id: String,
    /// Operator-facing name.
    pub name: String,
    /// Provider this credential authenticates to (e.g. `openai`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Credential kind (`ai_provider`, `bearer`, `api_key`, ...).
    #[serde(default = "default_cred_kind")]
    pub kind: String,
    /// How the secret is held at rest.
    pub material: CredentialMaterial,
    /// Lifecycle status.
    #[serde(default)]
    pub status: RecordStatus,
    /// Owning tenant, if multi-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Free-form metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Provenance, for reload precedence.
    #[serde(default)]
    pub source: RecordSource,
}

fn default_cred_kind() -> String {
    "ai_provider".to_string()
}

impl CredentialRecord {
    /// Whether the credential is `Active`.
    pub fn is_usable(&self) -> bool {
        self.status == RecordStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mint_key;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn usable_gates_status_and_expiry() {
        let mut r = KeyRecord::new("id", "hash", now());
        assert!(r.is_usable(now()));

        r.status = RecordStatus::Blocked;
        assert!(!r.is_usable(now()));

        r.status = RecordStatus::Active;
        r.expires_at = Some(now() - Duration::seconds(1));
        assert!(!r.is_usable(now()));

        r.expires_at = Some(now() + Duration::seconds(60));
        assert!(r.is_usable(now()));
    }

    #[test]
    fn verify_secret_accepts_current_and_graced_prev() {
        let pepper = b"pep";
        let minted = mint_key(pepper);
        let (_, secret) = crate::crypto::parse_token(&minted.token).unwrap();
        let mut r = KeyRecord::new(&minted.key_id, &minted.secret_hash, now());
        assert!(r.verify_secret(secret, pepper, now()));

        // Rotate: the old secret becomes prev with a grace window.
        let rotated = mint_key(pepper);
        let (_, new_secret) = crate::crypto::parse_token(&rotated.token).unwrap();
        r.prev_secret_hash = Some(r.secret_hash.clone());
        r.prev_hash_expires_at = Some(now() + Duration::seconds(60));
        r.secret_hash = rotated.secret_hash.clone();

        // Both work inside the grace window.
        assert!(r.verify_secret(new_secret, pepper, now()));
        assert!(r.verify_secret(secret, pepper, now()));
        // After grace, only the new one works.
        let later = now() + Duration::seconds(61);
        assert!(r.verify_secret(new_secret, pepper, later));
        assert!(!r.verify_secret(secret, pepper, later));
    }

    #[test]
    fn model_allow_block_lists() {
        let mut r = KeyRecord::new("id", "hash", now());
        assert!(r.is_model_allowed("gpt-4"));
        r.allowed_models = vec!["gpt-4".into()];
        assert!(r.is_model_allowed("gpt-4"));
        assert!(!r.is_model_allowed("claude-3"));
        r.blocked_models = vec!["gpt-4".into()];
        assert!(!r.is_model_allowed("gpt-4"));
    }

    #[test]
    fn key_record_serde_roundtrips_minimal() {
        let json = serde_json::json!({
            "key_id": "abcd",
            "secret_hash": "deadbeef",
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let r: KeyRecord = serde_json::from_value(json).unwrap();
        assert_eq!(r.key_id, "abcd");
        assert_eq!(r.status, RecordStatus::Active);
        assert_eq!(r.source, RecordSource::Api);
        assert_eq!(r.hash_alg, "hmac-sha256.v1");
    }

    #[test]
    fn key_policy_contract_defaults_are_backward_compatible() {
        let created = KeyRecord::new("abcd", "deadbeef", now());
        assert_eq!(created.policy_revision, 1);
        assert!(created.blocked_providers.is_empty());
        assert!(created.allowed_tools.is_none());

        let legacy_json = serde_json::json!({
            "key_id": "abcd",
            "secret_hash": "deadbeef",
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let restored: KeyRecord = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(restored.policy_revision, 1);
        assert!(restored.blocked_providers.is_empty());
        assert!(restored.allowed_tools.is_none());
    }

    #[test]
    fn key_policy_contract_fields_roundtrip() {
        let mut record = KeyRecord::new("abcd", "deadbeef", now());
        record.policy_revision = 9;
        record.blocked_providers = vec!["vertex".into(), "bedrock".into()];
        record.allowed_tools = Some(vec!["search".into(), "calculator".into()]);

        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["policy_revision"], 9);
        assert_eq!(
            json["blocked_providers"],
            serde_json::json!(["vertex", "bedrock"])
        );
        assert_eq!(
            json["allowed_tools"],
            serde_json::json!(["search", "calculator"])
        );

        let restored: KeyRecord = serde_json::from_value(json).unwrap();
        assert_eq!(restored.policy_revision, 9);
        assert_eq!(restored.blocked_providers, ["vertex", "bedrock"]);
        assert_eq!(
            restored.allowed_tools,
            Some(vec!["search".to_string(), "calculator".to_string()])
        );
    }

    #[test]
    fn credential_material_tagged_serde() {
        let r = CredentialRecord {
            id: "c1".into(),
            name: "openai-prod".into(),
            provider: Some("openai".into()),
            kind: "ai_provider".into(),
            material: CredentialMaterial::VaultRef {
                reference: "vault://openai".into(),
            },
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: BTreeMap::new(),
            created_at: now(),
            updated_at: now(),
            source: RecordSource::Config,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"kind\":\"vault_ref\""), "{json}");
        let back: CredentialRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
