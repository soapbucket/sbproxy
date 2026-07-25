//! Signed configuration bundles published by a config authority.
//!
//! A config authority hands subscribers a YAML fragment (or a whole
//! configuration) wrapped in a signed, content-addressed envelope. The
//! envelope is the same shape the cluster authority already uses for model
//! deployments: Ed25519 over RFC 8785 canonical JSON, a monotonic authority
//! revision, an independent content digest, and a durable cursor that refuses
//! rollback and same-revision content drift.
//!
//! # Wire shape
//!
//! [`SignedConfigBundle`] is the transport type. It carries a
//! [`ConfigBundle`] payload plus the signer's key ID, the algorithm, and a
//! base64 signature. Both types reject unknown fields so a subscriber never
//! silently ignores a field a newer authority added.
//!
//! # Signing input
//!
//! Signatures cover [`CONFIG_BUNDLE_CONTEXT`], a single `0x00` separator
//! byte, and then the RFC 8785 (JCS) canonical JSON of the [`ConfigBundle`].
//! Canonical JSON means the signature survives any re-serialization that
//! preserves the parsed values, and the domain-separation prefix means a
//! bundle signature can never be replayed as a cluster-state or
//! model-dispatch signature even when the same key signs all three.
//!
//! # Verification order
//!
//! [`SignedConfigBundle::verify_at`] applies these checks in order, and each
//! one is independently observable through [`BundleError`]:
//!
//! 1. `schema_version` equals [`CONFIG_BUNDLE_SCHEMA_VERSION`].
//! 2. `config_yaml` is within [`MAX_CONFIG_YAML_BYTES`].
//! 3. `content_digest` matches SHA-256 of `config_yaml`, checked without
//!    reference to the signature so a corrupt payload is caught even when
//!    the signing key is compromised or the digest was mis-asserted.
//! 4. `key_id` resolves inside the [`VerifyingKeySet`].
//! 5. The algorithm is permitted. `hmac_sha256` needs an explicit
//!    acknowledgement, see [`VerifyingKeySet::allow_shared_secret`].
//! 6. The signature verifies over the canonical signing bytes.
//! 7. `expires_at_unix_ms`, when set, is not in the past, allowing
//!    [`CONFIG_BUNDLE_CLOCK_SKEW_MS`] of clock skew.
//!
//! # Key files
//!
//! [`VerifyingKeySet::from_file`] reads a JSON object mapping key ID to key
//! material, so an authority rotates by publishing a new key ID alongside the
//! old one and retiring the old entry a window later. No synchronized fleet
//! restart is needed:
//!
//! ```json
//! {
//!   "authority-2026-07": { "algorithm": "ed25519", "key": "<base64 32-byte public key>" },
//!   "authority-2026-08": { "algorithm": "ed25519", "key": "<base64 32-byte public key>" }
//! }
//! ```

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// Current signed config-bundle schema version.
pub const CONFIG_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Domain-separation context prefixed to every config-bundle signature.
///
/// Sits alongside the existing `sbproxy.cluster-state.v1` and
/// `sbproxy.model-dispatch.v1` contexts. A signature produced under one
/// context never validates under another.
pub const CONFIG_BUNDLE_CONTEXT: &str = "sbproxy.config-bundle.v1";

/// Largest `config_yaml` payload a subscriber accepts, in bytes.
///
/// Four mebibytes is far above any hand-written configuration and still small
/// enough that a hostile authority cannot exhaust a subscriber's memory by
/// publishing one bundle. Oversized bundles are rejected at verify time,
/// before any signature work.
pub const MAX_CONFIG_YAML_BYTES: usize = 4 * 1024 * 1024;

/// Clock skew tolerated when checking `expires_at_unix_ms`, in milliseconds.
///
/// A subscriber whose clock runs one minute fast still applies a bundle that
/// just expired, which keeps a fleet with imperfect NTP from tearing itself
/// apart at every rotation boundary.
pub const CONFIG_BUNDLE_CLOCK_SKEW_MS: u64 = 60_000;

/// Separator between the context string and the canonical bundle bytes.
///
/// A byte that cannot appear inside the context string means the boundary is
/// unambiguous, so no context/payload pair can be re-cut into another.
const CONTEXT_SEPARATOR: u8 = 0x00;

/// Prefix on every content digest, naming the hash that produced it.
const DIGEST_PREFIX: &str = "sha256:";

/// Hexadecimal characters in a SHA-256 digest.
const DIGEST_HEX_LEN: usize = 64;

/// Largest accepted signed envelope, in bytes.
///
/// JSON string escaping can roughly double a YAML payload made mostly of
/// newlines, so the envelope bound is twice the payload bound plus room for
/// the surrounding fields.
const MAX_SIGNED_BUNDLE_BYTES: usize = 2 * MAX_CONFIG_YAML_BYTES + 64 * 1024;

/// Largest accepted verifying-key file, in bytes.
const MAX_KEY_FILE_BYTES: u64 = 256 * 1024;

/// Largest accepted cursor file, in bytes.
const MAX_CURSOR_BYTES: u64 = 4 * 1024;

/// Largest accepted authority identifier, in bytes.
const MAX_AUTHORITY_ID_BYTES: usize = 128;

/// Largest accepted key identifier, in bytes.
const MAX_KEY_ID_BYTES: usize = 128;

/// Largest accepted base64 signature, in bytes.
const MAX_SIGNATURE_BYTES: usize = 256;

/// Most key entries one verifying-key file may declare.
const MAX_KEYS: usize = 256;

/// Shortest accepted HMAC shared secret, in bytes.
const MIN_SHARED_SECRET_BYTES: usize = 32;

/// Exact length of an Ed25519 public key, in bytes.
const ED25519_KEY_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// How a subscriber applies a verified bundle to its local configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleMode {
    /// Merge the bundle over the subscriber's own configuration, leaving
    /// anything the bundle does not mention untouched.
    Overlay,
    /// Replace the subscriber's configuration wholesale. Anything absent
    /// from the bundle is dropped.
    Replace,
}

/// Signature algorithm protecting a config bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleAlgorithm {
    /// Detached Ed25519 signature. The default and the only algorithm safe
    /// for a fleet with more than one subscriber.
    #[default]
    Ed25519,
    /// HMAC-SHA256 over a secret shared by the authority and every
    /// subscriber. Symmetric, so every holder can both verify and forge.
    HmacSha256,
}

impl BundleAlgorithm {
    /// Stable wire name, matching the serde representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::HmacSha256 => "hmac_sha256",
        }
    }
}

impl std::fmt::Display for BundleAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Content-addressed configuration payload published at one authority revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundle {
    /// Stable identifier of the publishing authority.
    pub authority_id: String,
    /// Monotonic authority-assigned revision. Always positive.
    pub revision: u64,
    /// How the subscriber applies this payload.
    pub mode: BundleMode,
    /// `sha256:<hex>` over the exact bytes of `config_yaml`.
    pub content_digest: String,
    /// Configuration payload, bounded by [`MAX_CONFIG_YAML_BYTES`].
    pub config_yaml: String,
    /// Publication time in unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Optional expiry in unix milliseconds. `None` means the bundle stays
    /// valid until a later revision supersedes it.
    #[serde(default)]
    pub expires_at_unix_ms: Option<u64>,
}

impl ConfigBundle {
    /// Build a bundle, computing the content digest and validating the shape.
    pub fn new(
        authority_id: impl Into<String>,
        revision: u64,
        mode: BundleMode,
        config_yaml: impl Into<String>,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: Option<u64>,
    ) -> Result<Self, BundleError> {
        let config_yaml = config_yaml.into();
        let bundle = Self {
            authority_id: authority_id.into(),
            revision,
            mode,
            content_digest: Self::content_digest_of(&config_yaml),
            config_yaml,
            issued_at_unix_ms,
            expires_at_unix_ms,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    /// Canonical `sha256:<hex>` digest of one configuration payload.
    pub fn content_digest_of(config_yaml: &str) -> String {
        format!(
            "{DIGEST_PREFIX}{}",
            hex::encode(Sha256::digest(config_yaml.as_bytes()))
        )
    }

    /// Validate bounds and field shape. Does not check the content digest,
    /// which [`Self::verify_content_digest`] owns so the two failures stay
    /// distinguishable.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.config_yaml.len() > MAX_CONFIG_YAML_BYTES {
            return Err(BundleError::ConfigTooLarge {
                bytes: self.config_yaml.len(),
                limit: MAX_CONFIG_YAML_BYTES,
            });
        }
        if self.config_yaml.is_empty() {
            return Err(BundleError::invalid("config_yaml must not be empty"));
        }
        if !valid_identifier(&self.authority_id, MAX_AUTHORITY_ID_BYTES) {
            return Err(BundleError::invalid(
                "authority_id is empty, invalid, or oversized",
            ));
        }
        if self.revision == 0 {
            return Err(BundleError::invalid("revision must be positive"));
        }
        validate_digest(&self.content_digest)?;
        if self.issued_at_unix_ms == 0 {
            return Err(BundleError::invalid("issued_at_unix_ms must be positive"));
        }
        if self
            .expires_at_unix_ms
            .is_some_and(|expires| expires < self.issued_at_unix_ms)
        {
            return Err(BundleError::invalid(
                "expires_at_unix_ms precedes issued_at_unix_ms",
            ));
        }
        Ok(())
    }

    /// Recompute the payload digest and compare it in constant time.
    ///
    /// Independent of the signature by construction: a bundle whose digest
    /// disagrees with its payload is refused even when the signature over
    /// the whole bundle is valid.
    pub fn verify_content_digest(&self) -> Result<(), BundleError> {
        let expected = Self::content_digest_of(&self.config_yaml);
        if digests_equal(&expected, &self.content_digest) {
            Ok(())
        } else {
            Err(BundleError::DigestMismatch)
        }
    }

    /// Exact bytes a signature covers.
    ///
    /// Context, one `0x00` separator, then RFC 8785 canonical JSON of this
    /// bundle. Exposed so an external signer (an HSM, a detached signing
    /// service) can produce the same bytes without importing the payload
    /// serialization.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, BundleError> {
        let canonical = serde_json_canonicalizer::to_vec(self)
            .map_err(|error| BundleError::Canonical(error.to_string()))?;
        let mut bytes = Vec::with_capacity(CONFIG_BUNDLE_CONTEXT.len() + 1 + canonical.len());
        bytes.extend_from_slice(CONFIG_BUNDLE_CONTEXT.as_bytes());
        bytes.push(CONTEXT_SEPARATOR);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    /// Whether this bundle is past its expiry at `now_unix_ms`, allowing
    /// [`CONFIG_BUNDLE_CLOCK_SKEW_MS`] of skew.
    pub fn is_expired_at(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms.is_some_and(|expires| {
            now_unix_ms > expires.saturating_add(CONFIG_BUNDLE_CLOCK_SKEW_MS)
        })
    }

    /// Cursor position this bundle occupies once a subscriber applies it.
    pub fn cursor(&self) -> ConfigBundleCursor {
        ConfigBundleCursor {
            revision: self.revision,
            content_digest: self.content_digest.clone(),
        }
    }
}

/// Signer identity and detached signature wrapped around a [`ConfigBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConfigBundle {
    /// Wire schema version. Always [`CONFIG_BUNDLE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Signed configuration payload.
    pub bundle: ConfigBundle,
    /// Key ID selecting which entry of the [`VerifyingKeySet`] verifies this
    /// signature. Rotation adds a new ID and trusts both for a window.
    pub key_id: String,
    /// Algorithm that produced the signature.
    pub algorithm: BundleAlgorithm,
    /// Base64 signature over [`ConfigBundle::signing_bytes`].
    pub signature: String,
}

impl SignedConfigBundle {
    /// Strictly decode one bounded signed envelope. Does not verify it.
    pub fn from_json(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_BUNDLE_BYTES {
            return Err(BundleError::invalid(
                "signed bundle is empty or exceeds the envelope limit",
            ));
        }
        serde_json::from_slice(bytes).map_err(|source| BundleError::Json {
            operation: "decode signed bundle",
            source,
        })
    }

    /// Encode one signed envelope.
    pub fn to_json(&self) -> Result<Vec<u8>, BundleError> {
        let bytes = serde_json::to_vec(self).map_err(|source| BundleError::Json {
            operation: "encode signed bundle",
            source,
        })?;
        if bytes.len() > MAX_SIGNED_BUNDLE_BYTES {
            return Err(BundleError::invalid(
                "signed bundle exceeds the envelope limit",
            ));
        }
        Ok(bytes)
    }

    /// Verify against the host clock. See [`Self::verify_at`].
    pub fn verify(&self, keys: &VerifyingKeySet) -> Result<&ConfigBundle, BundleError> {
        self.verify_at(keys, now_unix_ms())
    }

    /// Verify at an explicit wall-clock time in unix milliseconds.
    ///
    /// Runs the module's documented verification order and returns the
    /// payload only when every step passes.
    pub fn verify_at(
        &self,
        keys: &VerifyingKeySet,
        now_unix_ms: u64,
    ) -> Result<&ConfigBundle, BundleError> {
        // 1. Schema version.
        if self.schema_version != CONFIG_BUNDLE_SCHEMA_VERSION {
            return Err(BundleError::UnsupportedSchemaVersion {
                found: self.schema_version,
            });
        }
        // 2. Bounds and shape, payload size first.
        self.bundle.validate()?;
        if !valid_identifier(&self.key_id, MAX_KEY_ID_BYTES) {
            return Err(BundleError::invalid(
                "key_id is empty, invalid, or oversized",
            ));
        }
        if self.signature.is_empty() || self.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(BundleError::invalid("signature is empty or oversized"));
        }
        // 3. Content digest, independent of the signature.
        self.bundle.verify_content_digest()?;
        // 4. Key resolution.
        let material = keys
            .get(&self.key_id)
            .ok_or_else(|| BundleError::UnknownKeyId(self.key_id.clone()))?;
        // 5. Algorithm permission.
        if material.algorithm() != self.algorithm {
            return Err(BundleError::AlgorithmMismatch {
                key_id: self.key_id.clone(),
                expected: material.algorithm(),
                found: self.algorithm,
            });
        }
        if self.algorithm == BundleAlgorithm::HmacSha256 && !keys.shared_secret_allowed() {
            return Err(BundleError::SharedSecretNotAcknowledged);
        }
        // 6. Signature.
        let signing_bytes = self.bundle.signing_bytes()?;
        match material {
            VerifyingKeyMaterial::Ed25519(key) => {
                let raw = BASE64
                    .decode(&self.signature)
                    .map_err(|_| BundleError::SignatureInvalid)?;
                let signature =
                    Signature::from_slice(&raw).map_err(|_| BundleError::SignatureInvalid)?;
                // `verify_strict` also rejects small-order keys and
                // non-canonical signature encodings.
                key.verify_strict(&signing_bytes, &signature)
                    .map_err(|_| BundleError::SignatureInvalid)?;
            }
            VerifyingKeyMaterial::SharedSecret(secret) => {
                if secret.len() < MIN_SHARED_SECRET_BYTES {
                    return Err(BundleError::Crypto(format!(
                        "shared secret must contain at least {MIN_SHARED_SECRET_BYTES} bytes"
                    )));
                }
                let mut mac = HmacSha256::new_from_slice(secret)
                    .map_err(|_| BundleError::Crypto("HMAC rejected the key".to_string()))?;
                mac.update(&signing_bytes);
                let expected = BASE64.encode(mac.finalize().into_bytes());
                if !bool::from(expected.as_bytes().ct_eq(self.signature.as_bytes())) {
                    return Err(BundleError::SignatureInvalid);
                }
            }
        }
        // 7. Expiry, with documented skew.
        if let Some(expires_at_unix_ms) = self.bundle.expires_at_unix_ms {
            if self.bundle.is_expired_at(now_unix_ms) {
                return Err(BundleError::Expired {
                    expires_at_unix_ms,
                    now_unix_ms,
                });
            }
        }
        Ok(&self.bundle)
    }
}

/// Secret material an authority signs config bundles with.
enum SigningMaterial {
    /// Ed25519 private key. Boxed because the expanded key dwarfs the
    /// shared-secret variant.
    Ed25519(Box<SigningKey>),
    /// Symmetric HMAC-SHA256 secret.
    SharedSecret(Vec<u8>),
}

/// Authority-side signer producing [`SignedConfigBundle`] envelopes.
pub struct ConfigBundleSigner {
    key_id: String,
    material: SigningMaterial,
}

impl std::fmt::Debug for ConfigBundleSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigBundleSigner")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl ConfigBundleSigner {
    /// Build an Ed25519 signer, the default and recommended mode.
    pub fn ed25519(key_id: impl Into<String>, key: SigningKey) -> Result<Self, BundleError> {
        let key_id = key_id.into();
        if !valid_identifier(&key_id, MAX_KEY_ID_BYTES) {
            return Err(BundleError::invalid(
                "key_id is empty, invalid, or oversized",
            ));
        }
        Ok(Self {
            key_id,
            material: SigningMaterial::Ed25519(Box::new(key)),
        })
    }

    /// Build a shared-secret signer.
    ///
    /// Every subscriber holding this secret can forge a bundle for every
    /// other subscriber, so verification refuses these bundles unless the
    /// subscriber's key set opts in through
    /// [`VerifyingKeySet::allow_shared_secret`].
    pub fn shared_secret(
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, BundleError> {
        let key_id = key_id.into();
        if !valid_identifier(&key_id, MAX_KEY_ID_BYTES) {
            return Err(BundleError::invalid(
                "key_id is empty, invalid, or oversized",
            ));
        }
        let secret = secret.into();
        if secret.len() < MIN_SHARED_SECRET_BYTES {
            return Err(BundleError::Crypto(format!(
                "shared secret must contain at least {MIN_SHARED_SECRET_BYTES} bytes"
            )));
        }
        Ok(Self {
            key_id,
            material: SigningMaterial::SharedSecret(secret),
        })
    }

    /// Key ID stamped into every envelope this signer produces.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Algorithm this signer produces.
    pub fn algorithm(&self) -> BundleAlgorithm {
        match self.material {
            SigningMaterial::Ed25519(_) => BundleAlgorithm::Ed25519,
            SigningMaterial::SharedSecret(_) => BundleAlgorithm::HmacSha256,
        }
    }

    /// Public material a subscriber installs to verify this signer.
    pub fn verifying_material(&self) -> VerifyingKeyMaterial {
        match &self.material {
            SigningMaterial::Ed25519(key) => {
                VerifyingKeyMaterial::Ed25519(Box::new(key.verifying_key()))
            }
            SigningMaterial::SharedSecret(secret) => {
                VerifyingKeyMaterial::SharedSecret(secret.clone())
            }
        }
    }

    /// Sign one bundle.
    ///
    /// Validates the bundle's shape but deliberately does not recompute
    /// `content_digest`: the digest is the authority's own assertion about
    /// the payload, and the subscriber checks it independently of the
    /// signature.
    pub fn sign(&self, bundle: ConfigBundle) -> Result<SignedConfigBundle, BundleError> {
        bundle.validate()?;
        let signing_bytes = bundle.signing_bytes()?;
        let signature = match &self.material {
            SigningMaterial::Ed25519(key) => BASE64.encode(key.sign(&signing_bytes).to_bytes()),
            SigningMaterial::SharedSecret(secret) => {
                let mut mac = HmacSha256::new_from_slice(secret)
                    .map_err(|_| BundleError::Crypto("HMAC rejected the key".to_string()))?;
                mac.update(&signing_bytes);
                BASE64.encode(mac.finalize().into_bytes())
            }
        };
        Ok(SignedConfigBundle {
            schema_version: CONFIG_BUNDLE_SCHEMA_VERSION,
            bundle,
            key_id: self.key_id.clone(),
            algorithm: self.algorithm(),
            signature,
        })
    }
}

/// Public material verifying one key ID.
#[derive(Clone)]
pub enum VerifyingKeyMaterial {
    /// Ed25519 public key. Boxed to keep the enum small.
    Ed25519(Box<VerifyingKey>),
    /// Symmetric HMAC-SHA256 secret, usable only with an explicit
    /// acknowledgement on the owning [`VerifyingKeySet`].
    SharedSecret(Vec<u8>),
}

impl std::fmt::Debug for VerifyingKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519(key) => formatter
                .debug_tuple("Ed25519")
                .field(&BASE64.encode(key.to_bytes()))
                .finish(),
            Self::SharedSecret(_) => formatter
                .debug_tuple("SharedSecret")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

impl VerifyingKeyMaterial {
    /// Decode one base64 Ed25519 public key.
    pub fn ed25519_from_base64(encoded: &str) -> Result<Self, BundleError> {
        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|_| BundleError::Crypto("verification key is invalid base64".to_string()))?;
        let bytes: [u8; ED25519_KEY_BYTES] = bytes.try_into().map_err(|_| {
            BundleError::Crypto(format!(
                "verification key must contain exactly {ED25519_KEY_BYTES} bytes"
            ))
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            BundleError::Crypto("verification key is invalid Ed25519 material".to_string())
        })?;
        Ok(Self::Ed25519(Box::new(key)))
    }

    /// Decode one base64 HMAC shared secret.
    pub fn shared_secret_from_base64(encoded: &str) -> Result<Self, BundleError> {
        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|_| BundleError::Crypto("shared secret is invalid base64".to_string()))?;
        if bytes.len() < MIN_SHARED_SECRET_BYTES {
            return Err(BundleError::Crypto(format!(
                "shared secret must contain at least {MIN_SHARED_SECRET_BYTES} bytes"
            )));
        }
        Ok(Self::SharedSecret(bytes))
    }

    /// Algorithm this material verifies.
    pub fn algorithm(&self) -> BundleAlgorithm {
        match self {
            Self::Ed25519(_) => BundleAlgorithm::Ed25519,
            Self::SharedSecret(_) => BundleAlgorithm::HmacSha256,
        }
    }
}

/// One entry of an on-disk verifying-key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyingKeyFileEntry {
    algorithm: BundleAlgorithm,
    key: String,
}

/// Every key a subscriber trusts, keyed by key ID.
///
/// Holding several keys at once is what makes rotation survivable: the
/// authority publishes under a new key ID while subscribers still trust the
/// old one, and the old entry is dropped a window later. No restart has to be
/// synchronized across the fleet.
#[derive(Debug, Clone, Default)]
pub struct VerifyingKeySet {
    keys: BTreeMap<String, VerifyingKeyMaterial>,
    allow_shared_secret: bool,
}

impl VerifyingKeySet {
    /// Empty key set that refuses shared secrets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Key set built from prepared material. Refuses shared secrets until
    /// [`Self::allow_shared_secret`] says otherwise.
    pub fn with_keys(keys: BTreeMap<String, VerifyingKeyMaterial>) -> Self {
        Self {
            keys,
            allow_shared_secret: false,
        }
    }

    /// Add or replace one key, so a rotation window can be opened without
    /// rebuilding the set.
    pub fn add_key(
        &mut self,
        key_id: impl Into<String>,
        material: VerifyingKeyMaterial,
    ) -> Result<(), BundleError> {
        let key_id = key_id.into();
        if !valid_identifier(&key_id, MAX_KEY_ID_BYTES) {
            return Err(BundleError::invalid(
                "key_id is empty, invalid, or oversized",
            ));
        }
        if self.keys.len() >= MAX_KEYS && !self.keys.contains_key(&key_id) {
            return Err(BundleError::invalid(
                "verifying key set may hold at most 256 keys",
            ));
        }
        self.keys.insert(key_id, material);
        Ok(())
    }

    /// Acknowledge, or withdraw the acknowledgement, that shared-secret
    /// bundles may verify.
    ///
    /// Off by default and deliberately explicit, the same way
    /// `ClusterSecurityConfig` gates `shared_key` behind `development: true`.
    /// A shared secret is symmetric: every subscriber that can verify a
    /// bundle can also forge one for every other subscriber.
    pub fn allow_shared_secret(mut self, acknowledged: bool) -> Self {
        self.allow_shared_secret = acknowledged;
        self
    }

    /// Whether shared-secret bundles are acknowledged.
    pub const fn shared_secret_allowed(&self) -> bool {
        self.allow_shared_secret
    }

    /// Resolve one key ID.
    pub fn get(&self, key_id: &str) -> Option<&VerifyingKeyMaterial> {
        self.keys.get(key_id)
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is trusted.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Parse a JSON object mapping key ID to key material.
    pub fn from_json(bytes: &[u8]) -> Result<Self, BundleError> {
        let entries: BTreeMap<String, VerifyingKeyFileEntry> = serde_json::from_slice(bytes)
            .map_err(|source| BundleError::Json {
                operation: "decode verifying key file",
                source,
            })?;
        if entries.len() > MAX_KEYS {
            return Err(BundleError::invalid(
                "verifying key file may hold at most 256 keys",
            ));
        }
        let mut set = Self::new();
        for (key_id, entry) in entries {
            let material = match entry.algorithm {
                BundleAlgorithm::Ed25519 => VerifyingKeyMaterial::ed25519_from_base64(&entry.key)?,
                BundleAlgorithm::HmacSha256 => {
                    VerifyingKeyMaterial::shared_secret_from_base64(&entry.key)?
                }
            };
            set.add_key(key_id, material)?;
        }
        Ok(set)
    }

    /// Load a bounded verifying-key file from disk.
    ///
    /// The returned set does not acknowledge shared secrets; the caller opts
    /// in through [`Self::allow_shared_secret`] so the acknowledgement lives
    /// in the subscriber's own configuration rather than in a file the
    /// authority ships.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_KEY_FILE_BYTES {
            return Err(BundleError::invalid(
                "verifying key file is empty, not regular, or oversized",
            ));
        }
        Self::from_json(&std::fs::read(path)?)
    }
}

/// Highest bundle a subscriber has applied.
///
/// The cursor is what makes a replayed bundle useless: an attacker who
/// captures revision 4 and re-serves it after revision 9 is rejected, and the
/// same holds across a process restart because the cursor is persisted before
/// the next bundle is considered.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundleCursor {
    /// Highest applied revision. Zero means nothing has been applied.
    pub revision: u64,
    /// Content digest applied at exactly that revision. Empty at revision
    /// zero.
    pub content_digest: String,
}

impl ConfigBundleCursor {
    /// Cursor at an explicit position.
    pub fn new(revision: u64, content_digest: impl Into<String>) -> Self {
        Self {
            revision,
            content_digest: content_digest.into(),
        }
    }

    /// Advance to a candidate bundle.
    ///
    /// Rejects a lower revision as rollback and an equal revision carrying
    /// different content as drift. An equal revision with an equal digest is
    /// a no-op, so re-applying the bundle a subscriber already holds is
    /// idempotent rather than an error.
    pub fn advance(&mut self, candidate: &ConfigBundle) -> Result<(), CursorError> {
        validate_digest(&candidate.content_digest)
            .map_err(|error| CursorError::Invalid(error.to_string()))?;
        if candidate.revision < self.revision {
            return Err(CursorError::Rollback {
                current: self.revision,
                candidate: candidate.revision,
            });
        }
        if candidate.revision == self.revision {
            if digests_equal(&self.content_digest, &candidate.content_digest) {
                return Ok(());
            }
            return Err(CursorError::ContentDrift {
                revision: candidate.revision,
            });
        }
        self.revision = candidate.revision;
        self.content_digest.clone_from(&candidate.content_digest);
        Ok(())
    }

    /// Load a persisted cursor. `Ok(None)` means no cursor exists yet.
    pub fn load(path: impl AsRef<Path>) -> Result<Option<Self>, CursorError> {
        let path = path.as_ref();
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CURSOR_BYTES {
            return Err(CursorError::Invalid(
                "cursor file is empty, not regular, or oversized".to_string(),
            ));
        }
        let cursor: Self =
            serde_json::from_slice(&std::fs::read(path)?).map_err(|source| CursorError::Json {
                operation: "decode cursor",
                source,
            })?;
        if cursor.revision > 0 {
            validate_digest(&cursor.content_digest)
                .map_err(|error| CursorError::Invalid(error.to_string()))?;
        }
        Ok(Some(cursor))
    }

    /// Persist the cursor atomically.
    ///
    /// Writes a temporary file in the same directory, flushes it, then
    /// renames over the target, so a crash mid-write leaves either the old
    /// cursor or the new one and never a truncated file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CursorError> {
        let path = path.as_ref();
        let mut body = serde_json::to_vec(self).map_err(|source| CursorError::Json {
            operation: "encode cursor",
            source,
        })?;
        body.push(b'\n');
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config-bundle-cursor.json");
        // Nanosecond timestamp plus pid keeps two concurrent writers in the
        // same directory from colliding; the rename is the atomic step, not
        // the temporary-file creation.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let temporary = parent.join(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));
        let result = (|| {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&body)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            Ok::<_, std::io::Error>(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result.map_err(CursorError::from)
    }
}

/// Config-bundle construction, encoding, signing, or verification failure.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// One bounded semantic rule failed.
    #[error("invalid config bundle: {0}")]
    Invalid(String),
    /// The envelope declares a schema this build cannot verify.
    #[error(
        "unsupported config bundle schema_version {found}; expected {CONFIG_BUNDLE_SCHEMA_VERSION}"
    )]
    UnsupportedSchemaVersion {
        /// Schema version found on the wire.
        found: u32,
    },
    /// The payload exceeds [`MAX_CONFIG_YAML_BYTES`].
    #[error("config bundle payload is {bytes} bytes; the limit is {limit} bytes")]
    ConfigTooLarge {
        /// Payload size found on the wire.
        bytes: usize,
        /// Accepted limit.
        limit: usize,
    },
    /// `content_digest` disagrees with SHA-256 of `config_yaml`.
    #[error("config bundle content_digest does not match config_yaml")]
    DigestMismatch,
    /// No trusted key carries the envelope's key ID.
    #[error("config bundle key ID {0:?} is not in the verifying key set")]
    UnknownKeyId(String),
    /// The key ID resolves to material for a different algorithm.
    #[error("config bundle key ID {key_id:?} verifies {expected} bundles, not {found} bundles")]
    AlgorithmMismatch {
        /// Key ID from the envelope.
        key_id: String,
        /// Algorithm the installed key material verifies.
        expected: BundleAlgorithm,
        /// Algorithm the envelope declared.
        found: BundleAlgorithm,
    },
    /// A shared-secret bundle arrived without an explicit acknowledgement.
    #[error("refusing an hmac_sha256 config bundle: a shared secret lets any subscriber forge configs for every other subscriber, so it verifies only when the key set explicitly acknowledges that risk")]
    SharedSecretNotAcknowledged,
    /// The signature did not validate over the canonical signing bytes.
    #[error("config bundle signature verification failed")]
    SignatureInvalid,
    /// The bundle expired even after allowing the documented clock skew.
    #[error("config bundle expired at {expires_at_unix_ms} ms; now is {now_unix_ms} ms, beyond the {CONFIG_BUNDLE_CLOCK_SKEW_MS} ms skew allowance")]
    Expired {
        /// Expiry carried by the bundle.
        expires_at_unix_ms: u64,
        /// Verifier wall clock at check time.
        now_unix_ms: u64,
    },
    /// Canonical JSON generation failed.
    #[error("canonicalize config bundle: {0}")]
    Canonical(String),
    /// Strict JSON processing failed.
    #[error("config bundle JSON {operation} failed: {source}")]
    Json {
        /// Stable operation label.
        operation: &'static str,
        /// JSON parser or encoder failure.
        source: serde_json::Error,
    },
    /// Key material was malformed or unusable.
    #[error("config bundle key material failed: {0}")]
    Crypto(String),
    /// Bounded key-file access failed.
    #[error("config bundle file access failed: {0}")]
    Io(#[from] std::io::Error),
}

impl BundleError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

/// Cursor advance or persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum CursorError {
    /// A lower revision tried to replace the applied one.
    #[error("config bundle revision {candidate} rolls back the applied revision {current}")]
    Rollback {
        /// Applied revision.
        current: u64,
        /// Attempted revision.
        candidate: u64,
    },
    /// One revision number named two different payloads.
    #[error("config bundle revision {revision} was already applied with different content")]
    ContentDrift {
        /// Conflicting revision.
        revision: u64,
    },
    /// The persisted cursor or the candidate failed a bounded rule.
    #[error("invalid config bundle cursor: {0}")]
    Invalid(String),
    /// Strict JSON processing failed.
    #[error("config bundle cursor JSON {operation} failed: {source}")]
    Json {
        /// Stable operation label.
        operation: &'static str,
        /// JSON parser or encoder failure.
        source: serde_json::Error,
    },
    /// Cursor file access failed.
    #[error("config bundle cursor file access failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Compare two digests in constant time, so a comparison never reveals by
/// timing how far two digests agree.
fn digests_equal(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

/// Validate the `sha256:<64 lowercase hex>` digest shape.
fn validate_digest(digest: &str) -> Result<(), BundleError> {
    let Some(digest_hex) = digest.strip_prefix(DIGEST_PREFIX) else {
        return Err(BundleError::invalid(
            "content_digest must start with \"sha256:\"",
        ));
    };
    if digest_hex.len() != DIGEST_HEX_LEN
        || !digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BundleError::invalid(
            "content_digest must carry 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

/// Bounded identifier: printable ASCII, no separators that could be parsed as
/// structure by a downstream consumer.
fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// Host wall clock in unix milliseconds, saturating rather than panicking on a
/// clock set before the epoch.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed wall clock so every expiry assertion is deterministic.
    const NOW: u64 = 1_700_000_000_000;

    const YAML: &str = "proxy:\n  listen: \":8080\"\n";

    fn ed25519_signer() -> ConfigBundleSigner {
        ConfigBundleSigner::ed25519("authority-2026-07", SigningKey::from_bytes(&[7u8; 32]))
            .expect("signer")
    }

    fn hmac_signer() -> ConfigBundleSigner {
        ConfigBundleSigner::shared_secret("lab-shared", vec![9u8; 32]).expect("signer")
    }

    fn key_set_for(signer: &ConfigBundleSigner) -> VerifyingKeySet {
        let mut keys = VerifyingKeySet::new();
        keys.add_key(signer.key_id(), signer.verifying_material())
            .expect("add key");
        keys
    }

    fn bundle() -> ConfigBundle {
        ConfigBundle::new(
            "authority-2026-07",
            7,
            BundleMode::Overlay,
            YAML,
            NOW - 1_000,
            None,
        )
        .expect("bundle")
    }

    fn bundle_at(revision: u64, yaml: &str) -> ConfigBundle {
        ConfigBundle::new(
            "authority-2026-07",
            revision,
            BundleMode::Overlay,
            yaml,
            NOW - 1_000,
            None,
        )
        .expect("bundle")
    }

    #[test]
    fn valid_ed25519_bundle_round_trips() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let signed = signer.sign(bundle()).expect("sign");
        assert_eq!(signed.schema_version, CONFIG_BUNDLE_SCHEMA_VERSION);
        assert_eq!(signed.algorithm, BundleAlgorithm::Ed25519);

        let encoded = signed.to_json().expect("encode");
        let decoded = SignedConfigBundle::from_json(&encoded).expect("decode");
        assert_eq!(decoded, signed);

        let verified = decoded.verify_at(&keys, NOW).expect("verify");
        assert_eq!(verified.config_yaml, YAML);
        assert_eq!(verified.revision, 7);
        assert_eq!(verified.mode, BundleMode::Overlay);
    }

    #[test]
    fn signing_bytes_are_domain_separated() {
        let bytes = bundle().signing_bytes().expect("signing bytes");
        let prefix = CONFIG_BUNDLE_CONTEXT.len();
        assert_eq!(&bytes[..prefix], CONFIG_BUNDLE_CONTEXT.as_bytes());
        assert_eq!(bytes[prefix], CONTEXT_SEPARATOR);
        assert_eq!(bytes[prefix + 1], b'{');
    }

    /// A named edit to one field of a signed bundle, used to prove each
    /// field is covered by the signature.
    type FieldMutation = (&'static str, fn(&mut ConfigBundle));

    #[test]
    fn mutating_any_bundle_field_breaks_verification() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let signed = signer.sign(bundle()).expect("sign");

        let mutations: [FieldMutation; 7] = [
            ("authority_id", |bundle| {
                bundle.authority_id = "authority-2026-08".to_string();
            }),
            ("revision", |bundle| bundle.revision += 1),
            ("mode", |bundle| bundle.mode = BundleMode::Replace),
            ("content_digest", |bundle| {
                bundle.content_digest = ConfigBundle::content_digest_of("other: true\n");
            }),
            ("config_yaml", |bundle| {
                bundle.config_yaml = "proxy:\n  listen: \":9090\"\n".to_string();
            }),
            ("issued_at_unix_ms", |bundle| {
                bundle.issued_at_unix_ms -= 500;
            }),
            ("expires_at_unix_ms", |bundle| {
                bundle.expires_at_unix_ms = Some(NOW + 3_600_000);
            }),
        ];

        for (field, mutate) in mutations {
            let mut tampered = signed.clone();
            mutate(&mut tampered.bundle);
            assert_ne!(tampered.bundle, signed.bundle, "{field} was not mutated");
            let error = tampered
                .verify_at(&keys, NOW)
                .expect_err("a mutated field must not verify");
            assert!(
                matches!(
                    error,
                    BundleError::SignatureInvalid | BundleError::DigestMismatch
                ),
                "mutating {field} produced an unexpected error: {error}"
            );
        }
    }

    #[test]
    fn wrong_key_id_fails() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let mut signed = signer.sign(bundle()).expect("sign");
        signed.key_id = "authority-2026-08".to_string();
        let error = signed.verify_at(&keys, NOW).expect_err("unknown key");
        assert!(matches!(error, BundleError::UnknownKeyId(ref id) if id == "authority-2026-08"));
    }

    #[test]
    fn unknown_schema_version_fails() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let mut signed = signer.sign(bundle()).expect("sign");
        signed.schema_version = CONFIG_BUNDLE_SCHEMA_VERSION + 1;
        let error = signed.verify_at(&keys, NOW).expect_err("bad schema");
        assert!(matches!(
            error,
            BundleError::UnsupportedSchemaVersion { found } if found == 2
        ));
    }

    #[test]
    fn algorithm_mismatch_against_installed_material_fails() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let mut signed = signer.sign(bundle()).expect("sign");
        signed.algorithm = BundleAlgorithm::HmacSha256;
        let error = signed
            .verify_at(&keys, NOW)
            .expect_err("algorithm mismatch");
        assert!(
            matches!(error, BundleError::AlgorithmMismatch { .. }),
            "{error}"
        );
    }

    #[test]
    fn hmac_without_acknowledgement_fails_and_names_forgery() {
        let signer = hmac_signer();
        let keys = key_set_for(&signer);
        assert!(!keys.shared_secret_allowed());
        let signed = signer.sign(bundle()).expect("sign");
        let error = signed.verify_at(&keys, NOW).expect_err("unacknowledged");
        assert!(matches!(error, BundleError::SharedSecretNotAcknowledged));
        let message = error.to_string();
        assert!(message.contains("forge"), "{message}");
        assert!(message.contains("every other subscriber"), "{message}");
    }

    #[test]
    fn hmac_with_acknowledgement_verifies() {
        let signer = hmac_signer();
        let keys = key_set_for(&signer).allow_shared_secret(true);
        assert!(keys.shared_secret_allowed());
        let signed = signer.sign(bundle()).expect("sign");
        assert_eq!(signed.algorithm, BundleAlgorithm::HmacSha256);
        let verified = signed.verify_at(&keys, NOW).expect("verify");
        assert_eq!(verified.config_yaml, YAML);
    }

    #[test]
    fn hmac_signature_tampering_fails() {
        let signer = hmac_signer();
        let keys = key_set_for(&signer).allow_shared_secret(true);
        let mut signed = signer.sign(bundle()).expect("sign");
        signed.signature = BASE64.encode([0u8; 32]);
        let error = signed.verify_at(&keys, NOW).expect_err("bad tag");
        assert!(matches!(error, BundleError::SignatureInvalid));
    }

    #[test]
    fn digest_mismatch_fails_even_with_a_valid_signature() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let mut payload = bundle();
        // Well formed but wrong: the digest names content the payload does
        // not carry. Signing covers the digest field too, so the signature
        // over this bundle is genuinely valid.
        payload.content_digest = ConfigBundle::content_digest_of("proxy:\n  listen: \":9090\"\n");
        let signed = signer.sign(payload).expect("sign");
        let error = signed.verify_at(&keys, NOW).expect_err("digest mismatch");
        assert!(matches!(error, BundleError::DigestMismatch));

        // The same envelope with a correct digest verifies, which pins the
        // failure above on the digest check and not on the signature.
        let repaired = signer.sign(bundle()).expect("sign");
        assert!(repaired.verify_at(&keys, NOW).is_ok());
    }

    #[test]
    fn oversized_config_yaml_fails() {
        let oversized = "y".repeat(MAX_CONFIG_YAML_BYTES + 1);
        let construction = ConfigBundle::new(
            "authority-2026-07",
            7,
            BundleMode::Overlay,
            oversized.clone(),
            NOW - 1_000,
            None,
        );
        assert!(matches!(
            construction,
            Err(BundleError::ConfigTooLarge { bytes, limit })
                if bytes == MAX_CONFIG_YAML_BYTES + 1 && limit == MAX_CONFIG_YAML_BYTES
        ));

        // The size gate runs before the digest and the signature, so a
        // hand-built envelope never reaches the expensive checks.
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let signed = SignedConfigBundle {
            schema_version: CONFIG_BUNDLE_SCHEMA_VERSION,
            bundle: ConfigBundle {
                authority_id: "authority-2026-07".to_string(),
                revision: 7,
                mode: BundleMode::Overlay,
                content_digest: format!("{DIGEST_PREFIX}{}", "0".repeat(DIGEST_HEX_LEN)),
                config_yaml: oversized,
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: None,
            },
            key_id: signer.key_id().to_string(),
            algorithm: BundleAlgorithm::Ed25519,
            signature: BASE64.encode([0u8; 64]),
        };
        let error = signed.verify_at(&keys, NOW).expect_err("oversized");
        assert!(
            matches!(error, BundleError::ConfigTooLarge { .. }),
            "{error}"
        );
    }

    #[test]
    fn expiry_honours_the_documented_skew_window() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);

        // (label, expiry, expected to verify)
        let cases = [
            ("no expiry", None, true),
            ("future expiry", Some(NOW + 60_000), true),
            (
                "expired inside the skew window",
                Some(NOW - CONFIG_BUNDLE_CLOCK_SKEW_MS / 2),
                true,
            ),
            (
                "expired exactly at the skew boundary",
                Some(NOW - CONFIG_BUNDLE_CLOCK_SKEW_MS),
                true,
            ),
            (
                "expired outside the skew window",
                Some(NOW - CONFIG_BUNDLE_CLOCK_SKEW_MS - 1),
                false,
            ),
            ("long expired", Some(NOW - 86_400_000), false),
        ];

        for (label, expires_at_unix_ms, expected_ok) in cases {
            let payload = ConfigBundle::new(
                "authority-2026-07",
                7,
                BundleMode::Overlay,
                YAML,
                NOW - 86_400_001,
                expires_at_unix_ms,
            )
            .expect("bundle");
            let signed = signer.sign(payload).expect("sign");
            let result = signed.verify_at(&keys, NOW);
            assert_eq!(result.is_ok(), expected_ok, "{label}: {result:?}");
            if !expected_ok {
                assert!(
                    matches!(result.unwrap_err(), BundleError::Expired { .. }),
                    "{label} failed for the wrong reason"
                );
            }
        }
    }

    #[test]
    fn verifying_key_set_loads_a_rotation_window_from_a_file() {
        let signer = ed25519_signer();
        let next =
            ConfigBundleSigner::ed25519("authority-2026-08", SigningKey::from_bytes(&[8u8; 32]))
                .expect("signer");
        let VerifyingKeyMaterial::Ed25519(current_key) = signer.verifying_material() else {
            panic!("ed25519 material");
        };
        let VerifyingKeyMaterial::Ed25519(next_key) = next.verifying_material() else {
            panic!("ed25519 material");
        };
        let file = serde_json::json!({
            "authority-2026-07": {
                "algorithm": "ed25519",
                "key": BASE64.encode(current_key.to_bytes()),
            },
            "authority-2026-08": {
                "algorithm": "ed25519",
                "key": BASE64.encode(next_key.to_bytes()),
            },
        });
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("authority-keys.json");
        std::fs::write(&path, serde_json::to_vec(&file).expect("encode")).expect("write");

        let keys = VerifyingKeySet::from_file(&path).expect("load");
        assert_eq!(keys.len(), 2);
        assert!(!keys.is_empty());
        assert!(!keys.shared_secret_allowed());
        // Both the outgoing and the incoming key verify during the window.
        assert!(signer
            .sign(bundle())
            .expect("sign")
            .verify_at(&keys, NOW)
            .is_ok());
        assert!(next
            .sign(bundle())
            .expect("sign")
            .verify_at(&keys, NOW)
            .is_ok());
    }

    #[test]
    fn cursor_rejects_rollback_and_drift_but_accepts_replay_of_the_same_content() {
        let mut cursor = ConfigBundleCursor::default();
        assert_eq!(cursor.revision, 0);

        cursor.advance(&bundle_at(7, YAML)).expect("forward");
        assert_eq!(cursor.revision, 7);
        assert_eq!(cursor.content_digest, ConfigBundle::content_digest_of(YAML));

        // Same revision, same content: idempotent re-apply.
        cursor.advance(&bundle_at(7, YAML)).expect("idempotent");
        assert_eq!(cursor.revision, 7);

        // Same revision, different content: drift.
        let drift = cursor
            .advance(&bundle_at(7, "proxy:\n  listen: \":9090\"\n"))
            .expect_err("drift");
        assert!(
            matches!(drift, CursorError::ContentDrift { revision: 7 }),
            "{drift}"
        );

        // Lower revision: rollback.
        let rollback = cursor.advance(&bundle_at(6, YAML)).expect_err("rollback");
        assert!(
            matches!(
                rollback,
                CursorError::Rollback {
                    current: 7,
                    candidate: 6
                }
            ),
            "{rollback}"
        );

        // Forward again.
        cursor.advance(&bundle_at(8, YAML)).expect("forward");
        assert_eq!(cursor.revision, 8);
    }

    #[test]
    fn cursor_survives_a_save_and_load_round_trip() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("state").join("config-bundle-cursor.json");
        assert!(ConfigBundleCursor::load(&path).expect("load").is_none());

        let mut cursor = ConfigBundleCursor::default();
        cursor.advance(&bundle_at(9, YAML)).expect("forward");
        cursor.save(&path).expect("save");

        let mut reloaded = ConfigBundleCursor::load(&path)
            .expect("load")
            .expect("cursor present");
        assert_eq!(reloaded, cursor);

        // A replayed old bundle is still refused after a restart.
        let rollback = reloaded.advance(&bundle_at(4, YAML)).expect_err("rollback");
        assert!(matches!(
            rollback,
            CursorError::Rollback {
                current: 9,
                candidate: 4
            }
        ));

        // Overwriting an existing cursor is atomic and leaves no temp files.
        reloaded.advance(&bundle_at(10, YAML)).expect("forward");
        reloaded.save(&path).expect("save");
        assert_eq!(
            ConfigBundleCursor::load(&path)
                .expect("load")
                .expect("cursor"),
            reloaded
        );
        let leftovers = std::fs::read_dir(path.parent().expect("parent"))
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn bundle_cursor_matches_the_payload() {
        let payload = bundle();
        let cursor = payload.cursor();
        assert_eq!(cursor.revision, payload.revision);
        assert_eq!(cursor.content_digest, payload.content_digest);
        assert_eq!(
            cursor,
            ConfigBundleCursor::new(payload.revision, payload.content_digest.clone())
        );
    }

    #[test]
    fn malformed_envelopes_are_refused() {
        let signer = ed25519_signer();
        let keys = key_set_for(&signer);
        let signed = signer.sign(bundle()).expect("sign");

        let mut empty_key = signed.clone();
        empty_key.key_id = String::new();
        assert!(matches!(
            empty_key.verify_at(&keys, NOW),
            Err(BundleError::Invalid(_))
        ));

        let mut empty_signature = signed.clone();
        empty_signature.signature = String::new();
        assert!(matches!(
            empty_signature.verify_at(&keys, NOW),
            Err(BundleError::Invalid(_))
        ));

        let mut bad_digest = signed;
        bad_digest.bundle.content_digest = "md5:beef".to_string();
        assert!(matches!(
            bad_digest.verify_at(&keys, NOW),
            Err(BundleError::Invalid(_))
        ));

        // Unknown fields are rejected rather than ignored.
        let json = br#"{"schema_version":1,"bundle":{},"key_id":"a","algorithm":"ed25519","signature":"a","extra":1}"#;
        assert!(matches!(
            SignedConfigBundle::from_json(json),
            Err(BundleError::Json { .. })
        ));
    }
}
