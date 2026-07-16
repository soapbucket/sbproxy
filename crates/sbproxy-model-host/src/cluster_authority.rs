// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Strict signed deployment bundles for cluster-authority desired state.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use fs2::FileExt as _;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ColdStartPolicy, DeploymentRevisionDraft, DeploymentSourceMode, EngineChoice, ModelDeployment,
    PullPolicy, RolloutPolicy,
};

/// Current restricted deployment-bundle schema.
pub const RESTRICTED_DEPLOYMENT_BUNDLE_SCHEMA_VERSION: u32 = 1;
const SIGNING_DOMAIN: &str = "sbproxy/restricted-deployment-bundle/v1";
/// Largest canonical signed deployment bundle accepted by the authority plane.
pub const MAX_BUNDLE_BYTES: usize = 512 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 1_024;
const MAX_CURSOR_BYTES: u64 = 4 * 1024;
static CURSOR_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Strict model and placement policy allowed inside a signed bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedModelDeployment {
    model: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    heterogeneous_variants: bool,
    #[serde(default = "one_replica")]
    replicas: u32,
    #[serde(default)]
    required_labels: BTreeMap<String, String>,
    #[serde(default)]
    spread_by: Vec<String>,
    #[serde(default)]
    pull: PullPolicy,
    #[serde(default)]
    warm: bool,
    cold_start: ColdStartPolicy,
    #[serde(default)]
    keep_alive_secs: Option<u64>,
    #[serde(default)]
    max_concurrency: Option<u32>,
    #[serde(default = "default_max_queue_depth")]
    max_queue_depth: usize,
    #[serde(default = "default_queue_timeout_ms")]
    queue_timeout_ms: u64,
    #[serde(default)]
    engine: EngineChoice,
    #[serde(default)]
    rollout: RolloutPolicy,
}

const fn one_replica() -> u32 {
    1
}

const fn default_max_queue_depth() -> usize {
    128
}

const fn default_queue_timeout_ms() -> u64 {
    30_000
}

impl From<ModelDeployment> for RestrictedModelDeployment {
    fn from(deployment: ModelDeployment) -> Self {
        Self {
            model: deployment.model,
            variant: deployment.variant,
            heterogeneous_variants: deployment.heterogeneous_variants,
            replicas: deployment.replicas,
            required_labels: deployment.required_labels,
            spread_by: deployment.spread_by,
            pull: deployment.pull,
            warm: deployment.warm,
            cold_start: deployment.cold_start,
            keep_alive_secs: deployment.keep_alive_secs,
            max_concurrency: deployment.max_concurrency,
            max_queue_depth: deployment.max_queue_depth,
            queue_timeout_ms: deployment.queue_timeout_ms,
            engine: deployment.engine,
            rollout: deployment.rollout,
        }
    }
}

impl From<RestrictedModelDeployment> for ModelDeployment {
    fn from(deployment: RestrictedModelDeployment) -> Self {
        Self {
            model: deployment.model,
            variant: deployment.variant,
            heterogeneous_variants: deployment.heterogeneous_variants,
            replicas: deployment.replicas,
            // Signed cluster bundles do not carry a fixed tensor-parallel
            // degree yet; the node fit planner picks the degree there.
            tensor_parallel: None,
            required_labels: deployment.required_labels,
            spread_by: deployment.spread_by,
            pull: deployment.pull,
            warm: deployment.warm,
            cold_start: deployment.cold_start,
            keep_alive_secs: deployment.keep_alive_secs,
            max_concurrency: deployment.max_concurrency,
            max_queue_depth: deployment.max_queue_depth,
            queue_timeout_ms: deployment.queue_timeout_ms,
            engine: deployment.engine,
            rollout: deployment.rollout,
        }
    }
}

/// Strict unsigned publication request accepted by an authority node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedDeploymentBundleDraft {
    /// Exact certified catalog revision used by every worker.
    pub catalog_revision: String,
    /// Monotonic authority-assigned deployment revision.
    pub revision: u64,
    /// Model deployment and placement policy only.
    #[serde(deserialize_with = "deserialize_unique_deployments")]
    deployments: BTreeMap<String, RestrictedModelDeployment>,
}

impl RestrictedDeploymentBundleDraft {
    /// Create a strict bundle draft from the shared deployment contract.
    pub fn new(
        catalog_revision: impl Into<String>,
        revision: u64,
        deployments: BTreeMap<String, ModelDeployment>,
    ) -> Self {
        Self {
            catalog_revision: catalog_revision.into(),
            revision,
            deployments: deployments
                .into_iter()
                .map(|(id, deployment)| (id, deployment.into()))
                .collect(),
        }
    }

    /// Strictly decode one bounded admin or GitOps publication request.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DeploymentAuthorityError> {
        validate_bundle_size(bytes)?;
        serde_json::from_slice(bytes).map_err(|source| DeploymentAuthorityError::Json {
            operation: "decode draft",
            source,
        })
    }

    /// Validate and assign the canonical content digest.
    pub fn into_bundle(self) -> Result<RestrictedDeploymentBundle, DeploymentAuthorityError> {
        RestrictedDeploymentBundle::from_restricted(
            self.catalog_revision,
            self.revision,
            self.deployments,
        )
    }
}

/// Strict, content-addressed desired state signed by one cluster authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedDeploymentBundle {
    /// Wire schema version.
    pub schema_version: u32,
    /// Exact certified catalog revision used by every worker.
    pub catalog_revision: String,
    /// Monotonic authority-assigned deployment revision.
    pub revision: u64,
    /// Model deployment and placement policy only.
    #[serde(deserialize_with = "deserialize_unique_deployments")]
    deployments: BTreeMap<String, RestrictedModelDeployment>,
    /// SHA-256 of canonical bundle material excluding this field.
    pub content_digest: String,
}

#[derive(Serialize)]
struct BundleDigestMaterial<'a> {
    schema_version: u32,
    catalog_revision: &'a str,
    revision: u64,
    deployments: &'a BTreeMap<String, RestrictedModelDeployment>,
}

impl RestrictedDeploymentBundle {
    /// Validate and create one content-addressed bundle.
    pub fn new(
        catalog_revision: impl Into<String>,
        revision: u64,
        deployments: BTreeMap<String, ModelDeployment>,
    ) -> Result<Self, DeploymentAuthorityError> {
        Self::from_restricted(
            catalog_revision.into(),
            revision,
            deployments
                .into_iter()
                .map(|(id, deployment)| (id, deployment.into()))
                .collect(),
        )
    }

    fn from_restricted(
        catalog_revision: String,
        revision: u64,
        deployments: BTreeMap<String, RestrictedModelDeployment>,
    ) -> Result<Self, DeploymentAuthorityError> {
        let mut bundle = Self {
            schema_version: RESTRICTED_DEPLOYMENT_BUNDLE_SCHEMA_VERSION,
            catalog_revision,
            revision,
            deployments,
            content_digest: String::new(),
        };
        bundle.content_digest = bundle.recompute_digest()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Strictly decode one bounded JSON bundle.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DeploymentAuthorityError> {
        validate_bundle_size(bytes)?;
        let bundle = serde_json::from_slice::<Self>(bytes).map_err(|source| {
            DeploymentAuthorityError::Json {
                operation: "decode",
                source,
            }
        })?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Encode one validated bundle without revealing any external configuration.
    pub fn to_json(&self) -> Result<Vec<u8>, DeploymentAuthorityError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|source| DeploymentAuthorityError::Json {
            operation: "encode",
            source,
        })?;
        validate_bundle_size(&bytes)?;
        Ok(bytes)
    }

    /// Canonical content-addressed state key.
    pub fn content_key(&self) -> String {
        self.content_digest.clone()
    }

    /// Model deployments lowered into the shared runtime contract.
    pub fn deployments(&self) -> BTreeMap<String, ModelDeployment> {
        self.deployments
            .iter()
            .map(|(id, deployment)| (id.clone(), deployment.clone().into()))
            .collect()
    }

    /// Normalize verified bundle data into the same draft used by file mode.
    pub fn revision_draft(&self) -> DeploymentRevisionDraft {
        DeploymentRevisionDraft {
            source_mode: DeploymentSourceMode::ClusterAuthority,
            source_revision: format!("cluster:{}:{}", self.revision, self.content_digest),
            catalog_revision: self.catalog_revision.clone(),
            deployments: self.deployments(),
        }
    }

    /// Validate schema, bounds, deployment semantics, and stored digest.
    pub fn validate(&self) -> Result<(), DeploymentAuthorityError> {
        if self.schema_version != RESTRICTED_DEPLOYMENT_BUNDLE_SCHEMA_VERSION {
            return invalid(format!(
                "unsupported schema_version {}; expected {RESTRICTED_DEPLOYMENT_BUNDLE_SCHEMA_VERSION}",
                self.schema_version
            ));
        }
        if self.revision == 0 {
            return invalid("deployment revision must be positive");
        }
        if !valid_bounded_text(&self.catalog_revision, 256) {
            return invalid("catalog revision is empty, invalid, or oversized");
        }
        validate_restricted_deployments(&self.deployments)?;
        self.revision_draft()
            .validate()
            .map_err(|error| DeploymentAuthorityError::Invalid(error.to_string()))?;
        validate_digest(&self.content_digest)?;
        let expected = self.recompute_digest()?;
        if self.content_digest != expected {
            return invalid(format!(
                "content digest mismatch: stored {}, computed {expected}",
                self.content_digest
            ));
        }
        let encoded =
            serde_json::to_vec(self).map_err(|source| DeploymentAuthorityError::Json {
                operation: "validate encoded size",
                source,
            })?;
        validate_bundle_size(&encoded)?;
        Ok(())
    }

    fn recompute_digest(&self) -> Result<String, DeploymentAuthorityError> {
        let material = BundleDigestMaterial {
            schema_version: self.schema_version,
            catalog_revision: &self.catalog_revision,
            revision: self.revision,
            deployments: &self.deployments,
        };
        let canonical = serde_json_canonicalizer::to_vec(&material)
            .map_err(|error| DeploymentAuthorityError::Canonical(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }
}

/// Stable installed authority cursor used for monotonic verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBundleCursor {
    /// Highest accepted authority revision.
    pub revision: u64,
    /// Content digest accepted at that exact revision.
    pub content_digest: String,
}

/// Durable monotonic cursor committed only after runtime publication succeeds.
#[derive(Debug, Clone)]
pub struct FileDeploymentBundleCursorStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl FileDeploymentBundleCursorStore {
    /// Open a cursor file, creating its parent directory when needed.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DeploymentAuthorityError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return invalid("deployment cursor path must not be empty");
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut lock_name: OsString = path.as_os_str().to_owned();
        lock_name.push(".lock");
        Ok(Self {
            path,
            lock_path: PathBuf::from(lock_name),
        })
    }

    /// Load and validate the last runtime-committed cursor.
    pub fn load(&self) -> Result<Option<DeploymentBundleCursor>, DeploymentAuthorityError> {
        let lock = self.open_lock()?;
        lock.lock_shared()?;
        self.load_unlocked()
    }

    /// Atomically advance the cursor, rejecting rollback or same-revision drift.
    pub fn commit(
        &self,
        candidate: &DeploymentBundleCursor,
    ) -> Result<(), DeploymentAuthorityError> {
        validate_cursor(candidate)?;
        let lock = self.open_lock()?;
        lock.lock_exclusive()?;
        if let Some(current) = self.load_unlocked()? {
            if candidate.revision < current.revision {
                return Err(DeploymentAuthorityError::StaleRevision {
                    current: current.revision,
                    attempted: candidate.revision,
                });
            }
            if candidate.revision == current.revision {
                if candidate.content_digest == current.content_digest {
                    return Ok(());
                }
                return Err(DeploymentAuthorityError::RevisionConflict {
                    revision: candidate.revision,
                });
            }
        }
        self.write_atomic(candidate)
    }

    fn open_lock(&self) -> Result<File, DeploymentAuthorityError> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)?)
    }

    fn load_unlocked(&self) -> Result<Option<DeploymentBundleCursor>, DeploymentAuthorityError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CURSOR_BYTES {
            return invalid("deployment cursor file is empty, not regular, or oversized");
        }
        let cursor = serde_json::from_slice::<DeploymentBundleCursor>(&fs::read(&self.path)?)
            .map_err(|source| DeploymentAuthorityError::Json {
                operation: "decode cursor",
                source,
            })?;
        validate_cursor(&cursor)?;
        Ok(Some(cursor))
    }

    fn write_atomic(
        &self,
        cursor: &DeploymentBundleCursor,
    ) -> Result<(), DeploymentAuthorityError> {
        let mut bytes =
            serde_json::to_vec(cursor).map_err(|source| DeploymentAuthorityError::Json {
                operation: "encode cursor",
                source,
            })?;
        bytes.push(b'\n');
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let sequence = CURSOR_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("deployment-cursor");
        let temporary = parent.join(format!(".{name}.tmp.{}.{}", std::process::id(), sequence));
        let result = (|| {
            let mut file = create_private_file(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok::<_, DeploymentAuthorityError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

/// Signer identity and detached Ed25519 signature around a restricted bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeploymentBundle {
    /// Strict deployment payload.
    pub bundle: RestrictedDeploymentBundle,
    /// Authority node whose role and key authorize publication.
    pub signer_node_id: String,
    /// SHA-256 identifier of the configured verification key.
    pub signer_key_id: String,
    /// URL-safe base64 detached Ed25519 signature.
    pub signature: String,
}

#[derive(Serialize)]
struct BundleSigningMaterial<'a> {
    domain: &'static str,
    signer_node_id: &'a str,
    signer_key_id: &'a str,
    bundle: &'a RestrictedDeploymentBundle,
}

impl SignedDeploymentBundle {
    /// Sign a validated bundle with one configured authority key.
    pub fn sign(
        bundle: RestrictedDeploymentBundle,
        signer_node_id: &str,
        key: &DeploymentSigningKey,
    ) -> Result<Self, DeploymentAuthorityError> {
        bundle.validate()?;
        validate_node_id(signer_node_id)?;
        let signer_key_id = key.verifying_key().key_id().to_string();
        let signing_bytes = signing_bytes(&bundle, signer_node_id, &signer_key_id)?;
        let signature = key.0.sign(&signing_bytes);
        Ok(Self {
            bundle,
            signer_node_id: signer_node_id.to_string(),
            signer_key_id,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    /// Strictly decode one bounded signed envelope before cryptographic verification.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DeploymentAuthorityError> {
        validate_bundle_size(bytes)?;
        let signed = serde_json::from_slice::<Self>(bytes).map_err(|source| {
            DeploymentAuthorityError::Json {
                operation: "decode signed envelope",
                source,
            }
        })?;
        signed.validate_envelope()?;
        Ok(signed)
    }

    /// Encode one structurally and semantically valid signed envelope.
    pub fn to_json(&self) -> Result<Vec<u8>, DeploymentAuthorityError> {
        self.validate_envelope()?;
        let bytes = serde_json::to_vec(self).map_err(|source| DeploymentAuthorityError::Json {
            operation: "encode signed envelope",
            source,
        })?;
        validate_bundle_size(&bytes)?;
        Ok(bytes)
    }

    /// Verify signer identity, signature, digest, and monotonic cursor.
    pub fn verify(
        &self,
        key: &DeploymentVerifyingKey,
        current: Option<&DeploymentBundleCursor>,
    ) -> Result<VerifiedDeploymentBundle, DeploymentAuthorityError> {
        self.validate_envelope()?;
        if self.signer_key_id != key.key_id {
            return Err(DeploymentAuthorityError::Crypto(
                "deployment signer key ID does not match configured authority".to_string(),
            ));
        }
        if let Some(current) = current {
            validate_cursor(current)?;
            if self.bundle.revision < current.revision {
                return Err(DeploymentAuthorityError::StaleRevision {
                    current: current.revision,
                    attempted: self.bundle.revision,
                });
            }
            if self.bundle.revision == current.revision
                && self.bundle.content_digest != current.content_digest
            {
                return Err(DeploymentAuthorityError::RevisionConflict {
                    revision: self.bundle.revision,
                });
            }
        }
        let signature_bytes = URL_SAFE_NO_PAD.decode(&self.signature).map_err(|_| {
            DeploymentAuthorityError::Crypto("deployment signature is invalid base64".to_string())
        })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
            DeploymentAuthorityError::Crypto("deployment signature has invalid length".to_string())
        })?;
        let signing_bytes = signing_bytes(&self.bundle, &self.signer_node_id, &self.signer_key_id)?;
        key.key.verify(&signing_bytes, &signature).map_err(|_| {
            DeploymentAuthorityError::Crypto(
                "deployment bundle signature verification failed".to_string(),
            )
        })?;
        Ok(VerifiedDeploymentBundle {
            bundle: self.bundle.clone(),
            signer_node_id: self.signer_node_id.clone(),
            signer_key_id: self.signer_key_id.clone(),
        })
    }

    fn validate_envelope(&self) -> Result<(), DeploymentAuthorityError> {
        self.bundle.validate()?;
        validate_node_id(&self.signer_node_id)?;
        if !valid_bounded_text(&self.signer_key_id, 128) {
            return invalid("signer key ID is empty, invalid, or oversized");
        }
        if self.signature.is_empty() || self.signature.len() > 256 {
            return invalid("deployment signature is empty or oversized");
        }
        Ok(())
    }
}

/// Cryptographically verified restricted desired state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeploymentBundle {
    bundle: RestrictedDeploymentBundle,
    signer_node_id: String,
    signer_key_id: String,
}

impl VerifiedDeploymentBundle {
    /// Verified restricted bundle.
    pub const fn bundle(&self) -> &RestrictedDeploymentBundle {
        &self.bundle
    }

    /// Verified signing authority node.
    pub fn signer_node_id(&self) -> &str {
        &self.signer_node_id
    }

    /// Verified authority key ID.
    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    /// Cursor safe to persist after the runtime commit succeeds.
    pub fn cursor(&self) -> DeploymentBundleCursor {
        DeploymentBundleCursor {
            revision: self.bundle.revision,
            content_digest: self.bundle.content_digest.clone(),
        }
    }

    /// Normalize into the shared deployment revision draft.
    pub fn revision_draft(&self) -> DeploymentRevisionDraft {
        self.bundle.revision_draft()
    }
}

/// Secret Ed25519 deployment signing key.
pub struct DeploymentSigningKey(SigningKey);

impl std::fmt::Debug for DeploymentSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentSigningKey")
            .field("secret", &"<redacted>")
            .field("key_id", &self.verifying_key().key_id())
            .finish()
    }
}

impl DeploymentSigningKey {
    /// Construct a key from one exact 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Load one bounded URL-safe base64 seed file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DeploymentAuthorityError> {
        validate_private_key_permissions(path.as_ref())?;
        let encoded = read_bounded_key(path.as_ref())?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded.trim()).map_err(|_| {
            DeploymentAuthorityError::Crypto("deployment signing key is invalid base64".to_string())
        })?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            DeploymentAuthorityError::Crypto(
                "deployment signing key must contain exactly 32 bytes".to_string(),
            )
        })?;
        Ok(Self::from_seed(seed))
    }

    /// Public verification key and stable key ID.
    pub fn verifying_key(&self) -> DeploymentVerifyingKey {
        DeploymentVerifyingKey::from_key(self.0.verifying_key())
    }
}

/// Public Ed25519 key configured on every cluster node.
#[derive(Clone)]
pub struct DeploymentVerifyingKey {
    key: VerifyingKey,
    encoded: String,
    key_id: String,
}

impl std::fmt::Debug for DeploymentVerifyingKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentVerifyingKey")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl DeploymentVerifyingKey {
    /// Decode one URL-safe base64 Ed25519 verification key.
    pub fn from_encoded(encoded: &str) -> Result<Self, DeploymentAuthorityError> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded.trim()).map_err(|_| {
            DeploymentAuthorityError::Crypto(
                "deployment verification key is invalid base64".to_string(),
            )
        })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            DeploymentAuthorityError::Crypto(
                "deployment verification key must contain exactly 32 bytes".to_string(),
            )
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            DeploymentAuthorityError::Crypto(
                "deployment verification key is invalid Ed25519 material".to_string(),
            )
        })?;
        Ok(Self::from_key(key))
    }

    /// Load one bounded URL-safe base64 public-key file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DeploymentAuthorityError> {
        Self::from_encoded(&read_bounded_key(path.as_ref())?)
    }

    /// URL-safe base64 public key suitable for an installed key file.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Stable SHA-256 key identifier.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn from_key(key: VerifyingKey) -> Self {
        let encoded = URL_SAFE_NO_PAD.encode(key.to_bytes());
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(key.to_bytes()));
        Self {
            key,
            encoded,
            key_id,
        }
    }
}

/// Strict bundle construction, encoding, signing, or verification failure.
#[derive(Debug, thiserror::Error)]
pub enum DeploymentAuthorityError {
    /// One bounded semantic rule failed.
    #[error("invalid deployment authority bundle: {0}")]
    Invalid(String),
    /// Strict JSON processing failed.
    #[error("deployment authority JSON {operation} failed: {source}")]
    Json {
        /// Stable operation label.
        operation: &'static str,
        /// JSON parser or encoder failure.
        source: serde_json::Error,
    },
    /// Canonical JSON generation failed.
    #[error("canonicalize deployment authority bundle: {0}")]
    Canonical(String),
    /// Key or signature verification failed.
    #[error("deployment authority cryptography failed: {0}")]
    Crypto(String),
    /// A lower revision attempted to replace active state.
    #[error("stale deployment authority revision {attempted}; active revision is {current}")]
    StaleRevision {
        /// Active revision.
        current: u64,
        /// Attempted revision.
        attempted: u64,
    },
    /// One revision number named two different content digests.
    #[error("deployment authority revision {revision} conflicts with active content")]
    RevisionConflict {
        /// Conflicting revision.
        revision: u64,
    },
    /// Bounded key-file access failed.
    #[error("deployment authority key file failed: {0}")]
    Io(#[from] std::io::Error),
}

fn signing_bytes(
    bundle: &RestrictedDeploymentBundle,
    signer_node_id: &str,
    signer_key_id: &str,
) -> Result<Vec<u8>, DeploymentAuthorityError> {
    serde_json_canonicalizer::to_vec(&BundleSigningMaterial {
        domain: SIGNING_DOMAIN,
        signer_node_id,
        signer_key_id,
        bundle,
    })
    .map_err(|error| DeploymentAuthorityError::Canonical(error.to_string()))
}

fn validate_bundle_size(bytes: &[u8]) -> Result<(), DeploymentAuthorityError> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
        return invalid(format!(
            "bundle must contain between 1 and {MAX_BUNDLE_BYTES} bytes"
        ));
    }
    Ok(())
}

fn validate_cursor(cursor: &DeploymentBundleCursor) -> Result<(), DeploymentAuthorityError> {
    if cursor.revision == 0 {
        return invalid("active deployment cursor revision must be positive");
    }
    validate_digest(&cursor.content_digest)
}

fn validate_restricted_deployments(
    deployments: &BTreeMap<String, RestrictedModelDeployment>,
) -> Result<(), DeploymentAuthorityError> {
    if deployments.len() > 1_024 {
        return invalid("deployment bundle may contain at most 1024 deployments");
    }
    for (id, deployment) in deployments {
        if !valid_bounded_text(&deployment.model, 256) {
            return invalid(format!("deployment {id:?} model is invalid or oversized"));
        }
        if deployment.replicas > 1_024 {
            return invalid(format!("deployment {id:?} replicas may not exceed 1024"));
        }
        if deployment.required_labels.len() > 64 {
            return invalid(format!(
                "deployment {id:?} required labels may contain at most 64 entries"
            ));
        }
        for (key, value) in &deployment.required_labels {
            if key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
                })
                || !valid_bounded_text(value, 256)
            {
                return invalid(format!(
                    "deployment {id:?} contains an invalid required label"
                ));
            }
        }
        if deployment
            .max_concurrency
            .is_some_and(|value| value > 1_000_000)
            || deployment.max_queue_depth > 1_000_000
        {
            return invalid(format!("deployment {id:?} admission bounds exceed 1000000"));
        }
        if deployment.queue_timeout_ms > 24 * 60 * 60 * 1_000 {
            return invalid(format!("deployment {id:?} queue timeout exceeds 24 hours"));
        }
        if deployment
            .keep_alive_secs
            .is_some_and(|seconds| seconds > 365 * 24 * 60 * 60)
        {
            return invalid(format!("deployment {id:?} keep-alive exceeds one year"));
        }
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), DeploymentAuthorityError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid("content digest must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_node_id(node_id: &str) -> Result<(), DeploymentAuthorityError> {
    if node_id.is_empty()
        || node_id.len() > 128
        || !node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return invalid("signer node ID is empty, invalid, or oversized");
    }
    Ok(())
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DeploymentAuthorityError> {
    Err(DeploymentAuthorityError::Invalid(message.into()))
}

fn read_bounded_key(path: &Path) -> Result<String, DeploymentAuthorityError> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_KEY_FILE_BYTES {
        return invalid("key file is empty, not regular, or oversized");
    }
    Ok(std::fs::read_to_string(path)?)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<File, DeploymentAuthorityError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<File, DeploymentAuthorityError> {
    Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<(), DeploymentAuthorityError> {
    use std::os::unix::fs::MetadataExt as _;

    if std::fs::metadata(path)?.mode() & 0o077 != 0 {
        return invalid("deployment signing key must be owner-only");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_path: &Path) -> Result<(), DeploymentAuthorityError> {
    Ok(())
}

fn deserialize_unique_deployments<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, RestrictedModelDeployment>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueDeployments;

    impl<'de> Visitor<'de> for UniqueDeployments {
        type Value = BTreeMap<String, RestrictedModelDeployment>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a deployment object with unique keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut deployments = BTreeMap::new();
            while let Some(id) = map.next_key::<String>()? {
                if deployments.contains_key(&id) {
                    return Err(A::Error::custom(format!("duplicate deployment ID {id:?}")));
                }
                let deployment = map.next_value::<RestrictedModelDeployment>()?;
                deployments.insert(id, deployment);
            }
            Ok(deployments)
        }
    }

    deserializer.deserialize_map(UniqueDeployments)
}
