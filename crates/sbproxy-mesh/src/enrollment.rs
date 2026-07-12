//! Durable cluster authority and one-time worker enrollment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::{ClusterIdentity, ClusterNodeRole};

const IDENTITY_SCHEMA_VERSION: u32 = 1;
const TOKEN_STORE_SCHEMA_VERSION: u32 = 1;
const MAX_TOKEN_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_CSR_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_SERVER_NAME_BYTES: usize = 253;
const CA_CERT_FILE: &str = "ca.pem";
const CA_KEY_FILE: &str = "ca-key.pem";
const NODE_CERT_FILE: &str = "node.pem";
const NODE_KEY_FILE: &str = "node-key.pem";
const GOSSIP_KEY_FILE: &str = "gossip.key";
const SIGNING_KEY_FILE: &str = "authority-signing.key";
const VERIFYING_KEY_FILE: &str = "authority-verifying.key";
const IDENTITY_FILE: &str = "identity.json";
const TOKENS_FILE: &str = "tokens.json";
const TOKENS_LOCK_FILE: &str = ".tokens.lock";

/// Stable rejection reason for an enrollment token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentTokenRejection {
    /// Token syntax, identifier, or hash did not match.
    Invalid,
    /// Token lifetime elapsed.
    Expired,
    /// Token was already used successfully.
    Consumed,
    /// Requested roles or labels exceed the token grant.
    Constraints,
}

/// Durable authority or enrollment operation failure.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// Input failed bounded semantic validation.
    #[error("invalid cluster enrollment request: {0}")]
    InvalidRequest(String),
    /// The requested authority or installation directory already exists.
    #[error("cluster enrollment directory already exists: {0:?}")]
    AlreadyExists(PathBuf),
    /// Required authority state is absent or incomplete.
    #[error("cluster authority is missing or incomplete: {0}")]
    AuthorityMissing(String),
    /// Durable authority state failed validation.
    #[error("cluster authority state is corrupt: {0}")]
    Corrupt(String),
    /// A one-time token failed authentication or authorization.
    #[error("cluster enrollment token rejected: {0:?}")]
    TokenRejected(EnrollmentTokenRejection),
    /// Filesystem operation failed.
    #[error("cluster enrollment storage failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encoding or decoding failed.
    #[error("cluster enrollment JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Certificate, signature, or key operation failed.
    #[error("cluster enrollment cryptography failed: {0}")]
    Crypto(String),
}

impl EnrollmentError {
    /// Return the stable token rejection, if this failure came from a token.
    pub const fn token_rejection(&self) -> Option<EnrollmentTokenRejection> {
        match self {
            Self::TokenRejected(reason) => Some(*reason),
            _ => None,
        }
    }
}

/// Inputs used once to create a durable cluster authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityInit {
    /// Logical cluster ID.
    pub cluster_id: String,
    /// Stable authority node ID.
    pub node_id: String,
    /// Roles installed on the authority identity.
    pub roles: BTreeSet<ClusterNodeRole>,
    /// Placement and failure-domain labels.
    pub labels: BTreeMap<String, String>,
    /// DNS SAN expected by the mesh mTLS transport.
    pub server_name: String,
}

/// Signed public identity installed on one cluster node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterIdentityDocument {
    /// Wire schema version.
    pub schema_version: u32,
    /// Logical cluster ID.
    pub cluster_id: String,
    /// Stable node ID.
    pub node_id: String,
    /// Roles granted to the certificate holder.
    pub roles: BTreeSet<ClusterNodeRole>,
    /// Labels granted by the enrollment token.
    pub labels: BTreeMap<String, String>,
    /// Shared certificate SAN used for peer verification.
    pub server_name: String,
    /// SHA-256 fingerprint of the issued leaf certificate DER.
    pub certificate_sha256: String,
    /// Unix issue time in seconds.
    pub issued_at_unix_secs: u64,
    /// Unix certificate expiry time in seconds.
    pub expires_at_unix_secs: u64,
    /// SHA-256 identifier of the authority verification key.
    pub authority_key_id: String,
}

impl ClusterIdentityDocument {
    /// Lower the signed identity into the runtime identity shape.
    pub fn to_cluster_identity(&self) -> Result<ClusterIdentity, EnrollmentError> {
        validate_identity_document(self)?;
        let identity = ClusterIdentity {
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            roles: self.roles.clone(),
            labels: self.labels.clone(),
            peer_address: None,
            model_endpoint: None,
        };
        identity
            .validate()
            .map_err(|error| EnrollmentError::InvalidRequest(error.to_string()))?;
        Ok(identity)
    }
}

/// Identity document plus detached Ed25519 authority signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedClusterIdentity {
    /// Signed identity payload.
    pub document: ClusterIdentityDocument,
    /// URL-safe base64 Ed25519 signature.
    pub signature: String,
}

/// Roles and exact labels granted by one enrollment token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentTokenConstraints {
    /// Maximum role set the enrollment request may select.
    pub allowed_roles: BTreeSet<ClusterNodeRole>,
    /// Exact labels installed on the resulting identity.
    pub labels: BTreeMap<String, String>,
}

/// One clear one-time token. The token value is returned only at creation.
pub struct IssuedEnrollmentToken {
    token: String,
    token_id: String,
    expires_at_unix_secs: u64,
    constraints: EnrollmentTokenConstraints,
}

impl std::fmt::Debug for IssuedEnrollmentToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedEnrollmentToken")
            .field("token", &"<redacted>")
            .field("token_id", &self.token_id)
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .field("constraints", &self.constraints)
            .finish()
    }
}

impl IssuedEnrollmentToken {
    /// Clear token value to show exactly once.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Public token identifier retained in the authority store.
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Absolute expiry in Unix seconds.
    pub const fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }

    /// Grant carried by this token.
    pub const fn constraints(&self) -> &EnrollmentTokenConstraints {
        &self.constraints
    }

    /// Consume the result and return its clear token.
    pub fn into_token(self) -> String {
        self.token
    }
}

/// Bounded public request sent from a worker to the authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    /// One-time token.
    pub token: String,
    /// Stable requested node ID.
    pub node_id: String,
    /// Requested subset of token roles.
    pub roles: BTreeSet<ClusterNodeRole>,
    /// Exact labels granted by the token.
    pub labels: BTreeMap<String, String>,
    /// PKCS#10 PEM CSR whose private key remains on the worker.
    pub csr_pem: String,
}

/// Successful enrollment response. It never contains a worker private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResponse {
    /// CA-signed worker leaf certificate.
    pub certificate_pem: String,
    /// Cluster CA certificate.
    pub ca_pem: String,
    /// Shared authenticated gossip key.
    pub gossip_key: String,
    /// Signed node identity bound to the leaf certificate.
    pub identity: SignedClusterIdentity,
    /// URL-safe base64 Ed25519 authority verification key.
    pub authority_verifying_key: String,
}

/// Locally generated worker key and CSR.
pub struct WorkerEnrollment {
    node_id: String,
    server_name: String,
    private_key_pem: String,
    csr_pem: String,
}

impl std::fmt::Debug for WorkerEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerEnrollment")
            .field("node_id", &self.node_id)
            .field("server_name", &self.server_name)
            .field("private_key_pem", &"<redacted>")
            .field("csr_pem", &"<bounded CSR>")
            .finish()
    }
}

/// Paths and runtime identity installed for one enrolled worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledClusterIdentity {
    /// Validated runtime identity.
    pub identity: ClusterIdentity,
    /// Installed worker certificate.
    pub node_cert_file: PathBuf,
    /// Installed worker private key.
    pub node_key_file: PathBuf,
    /// Installed cluster CA.
    pub ca_file: PathBuf,
    /// Installed gossip key.
    pub gossip_key_file: PathBuf,
    /// Installed signed identity manifest.
    pub identity_file: PathBuf,
    /// Installed authority verification key.
    pub authority_verifying_key_file: PathBuf,
}

/// Open durable authority capable of issuing and consuming one-time tokens.
#[derive(Debug, Clone)]
pub struct EnrollmentAuthority {
    directory: PathBuf,
    identity: SignedClusterIdentity,
    verifying_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentTokenStore {
    schema_version: u32,
    hash_algorithm: String,
    tokens: BTreeMap<String, EnrollmentTokenRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentTokenRecord {
    token_sha256: String,
    created_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    constraints: EnrollmentTokenConstraints,
    consumed_at_unix_secs: Option<u64>,
}

impl WorkerEnrollment {
    /// Generate a worker private key and signed CSR entirely on this machine.
    pub fn generate(node_id: &str, server_name: &str) -> Result<Self, EnrollmentError> {
        validate_server_name(server_name)?;
        validate_runtime_identity(
            "pending",
            node_id,
            &BTreeSet::from([ClusterNodeRole::Worker]),
            &BTreeMap::new(),
        )?;
        let key_pair = KeyPair::generate().map_err(crypto_error)?;
        let params = leaf_params(node_id, server_name, unix_time_secs()?)?;
        let csr_pem = params
            .serialize_request(&key_pair)
            .and_then(|request| request.pem())
            .map_err(crypto_error)?;
        Ok(Self {
            node_id: node_id.to_string(),
            server_name: server_name.to_string(),
            private_key_pem: key_pair.serialize_pem(),
            csr_pem,
        })
    }

    /// Build the public wire request without copying the private key into it.
    pub fn request(
        &self,
        token: String,
        roles: BTreeSet<ClusterNodeRole>,
        labels: BTreeMap<String, String>,
    ) -> EnrollmentRequest {
        EnrollmentRequest {
            token,
            node_id: self.node_id.clone(),
            roles,
            labels,
            csr_pem: self.csr_pem.clone(),
        }
    }

    /// Public CSR PEM for HTTP adapters.
    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }

    /// Requested node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

impl EnrollmentAuthority {
    /// Atomically create a new authority directory and its initial identity.
    pub fn initialize(
        directory: impl AsRef<Path>,
        init: AuthorityInit,
    ) -> Result<Self, EnrollmentError> {
        validate_authority_init(&init)?;
        let directory = directory.as_ref();
        if directory.exists() {
            return Err(EnrollmentError::AlreadyExists(directory.to_path_buf()));
        }
        let parent = directory.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let stage = create_stage_directory(parent, directory.file_name())?;
        let mut guard = StageDirectoryGuard::new(stage.clone());
        set_directory_permissions(&stage)?;

        let now = unix_time_secs()?;
        let (ca_cert, ca_key) = generate_ca(&init.cluster_id, now)?;
        let node_key = KeyPair::generate().map_err(crypto_error)?;
        let node_cert = leaf_params(&init.node_id, &init.server_name, now)?
            .signed_by(&node_key, &ca_cert, &ca_key)
            .map_err(crypto_error)?;

        let signing_key = generate_signing_key();
        let verifying_key = encode_verifying_key(&signing_key.verifying_key());
        let authority_key_id = key_id(&signing_key.verifying_key().to_bytes());
        let identity_document = ClusterIdentityDocument {
            schema_version: IDENTITY_SCHEMA_VERSION,
            cluster_id: init.cluster_id,
            node_id: init.node_id,
            roles: init.roles,
            labels: init.labels,
            server_name: init.server_name,
            certificate_sha256: certificate_fingerprint(node_cert.der()),
            issued_at_unix_secs: now,
            expires_at_unix_secs: certificate_expiry(now)?,
            authority_key_id,
        };
        let identity = sign_identity(identity_document, &signing_key)?;
        let gossip_key = random_secret(32);
        let token_store = EnrollmentTokenStore {
            schema_version: TOKEN_STORE_SCHEMA_VERSION,
            hash_algorithm: "sha256".to_string(),
            tokens: BTreeMap::new(),
        };

        write_new_secure(&stage.join(CA_CERT_FILE), ca_cert.pem().as_bytes())?;
        write_new_secure(&stage.join(CA_KEY_FILE), ca_key.serialize_pem().as_bytes())?;
        write_new_secure(&stage.join(NODE_CERT_FILE), node_cert.pem().as_bytes())?;
        write_new_secure(
            &stage.join(NODE_KEY_FILE),
            node_key.serialize_pem().as_bytes(),
        )?;
        write_new_secure(&stage.join(GOSSIP_KEY_FILE), gossip_key.as_bytes())?;
        write_new_secure(
            &stage.join(SIGNING_KEY_FILE),
            URL_SAFE_NO_PAD.encode(signing_key.to_bytes()).as_bytes(),
        )?;
        write_new_secure(&stage.join(VERIFYING_KEY_FILE), verifying_key.as_bytes())?;
        write_new_secure(
            &stage.join(IDENTITY_FILE),
            &serde_json::to_vec_pretty(&identity)?,
        )?;
        write_new_secure(
            &stage.join(TOKENS_FILE),
            &serde_json::to_vec_pretty(&token_store)?,
        )?;
        write_new_secure(&stage.join(TOKENS_LOCK_FILE), b"")?;
        sync_directory(&stage)?;
        std::fs::rename(&stage, directory)?;
        guard.commit();
        sync_directory(parent)?;
        Self::open(directory)
    }

    /// Open and validate an existing authority directory.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, EnrollmentError> {
        let directory = directory.as_ref().to_path_buf();
        if !directory.is_dir() {
            return Err(EnrollmentError::AuthorityMissing(format!(
                "directory {directory:?} does not exist"
            )));
        }
        validate_owner_only(&directory, true)?;
        for name in [
            CA_CERT_FILE,
            CA_KEY_FILE,
            NODE_CERT_FILE,
            NODE_KEY_FILE,
            GOSSIP_KEY_FILE,
            SIGNING_KEY_FILE,
            VERIFYING_KEY_FILE,
            IDENTITY_FILE,
            TOKENS_FILE,
            TOKENS_LOCK_FILE,
        ] {
            if !directory.join(name).is_file() {
                return Err(EnrollmentError::AuthorityMissing(format!(
                    "required authority file {name:?} is absent"
                )));
            }
            validate_owner_only(&directory.join(name), false)?;
        }
        let verifying_key = read_bounded_text(&directory.join(VERIFYING_KEY_FILE), 1024)?;
        let identity: SignedClusterIdentity =
            serde_json::from_slice(&read_bounded(&directory.join(IDENTITY_FILE), 64 * 1024)?)?;
        verify_signed_identity(&identity, &verifying_key)?;
        identity.document.to_cluster_identity()?;
        let store: EnrollmentTokenStore = serde_json::from_slice(&read_bounded(
            &directory.join(TOKENS_FILE),
            4 * 1024 * 1024,
        )?)?;
        validate_token_store(&store)?;
        let signing_key =
            decode_signing_key(&read_bounded_text(&directory.join(SIGNING_KEY_FILE), 1024)?)?;
        if encode_verifying_key(&signing_key.verifying_key()) != verifying_key {
            return Err(EnrollmentError::Corrupt(
                "authority signing and verification keys do not match".to_string(),
            ));
        }
        let ca_pem = read_bounded_text(&directory.join(CA_CERT_FILE), 256 * 1024)?;
        let ca_key_pem = read_bounded_text(&directory.join(CA_KEY_FILE), 256 * 1024)?;
        let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(crypto_error)?;
        let ca_cert = CertificateParams::from_ca_cert_pem(&ca_pem)
            .map_err(crypto_error)?
            .self_signed(&ca_key)
            .map_err(crypto_error)?;
        let probe_key = KeyPair::generate().map_err(crypto_error)?;
        let probe = leaf_params(
            "authority-key-check",
            &identity.document.server_name,
            unix_time_secs()?,
        )?
        .signed_by(&probe_key, &ca_cert, &ca_key)
        .map_err(crypto_error)?;
        let peer_auth = crate::peer_auth::PeerAuth::new(crate::peer_auth::PeerAuthConfig {
            enabled: true,
            ca_cert: Some(ca_pem.clone()),
        });
        if !peer_auth.verify_peer(probe.pem().as_bytes()) {
            return Err(EnrollmentError::Corrupt(
                "authority CA certificate and private key do not match".to_string(),
            ));
        }
        let node_pem = read_bounded_text(&directory.join(NODE_CERT_FILE), 256 * 1024)?;
        let node_key_pem = read_bounded_text(&directory.join(NODE_KEY_FILE), 256 * 1024)?;
        crate::transport::tls::build_acceptor(&crate::transport::tls::MeshTlsConfig {
            cert_pem: node_pem.clone(),
            key_pem: node_key_pem,
            ca_pem,
        })
        .map_err(|error| EnrollmentError::Corrupt(error.to_string()))?;
        let node_certificate = CertificateDer::from_pem_slice(node_pem.as_bytes())
            .map_err(|error| EnrollmentError::Corrupt(error.to_string()))?;
        if certificate_fingerprint(&node_certificate) != identity.document.certificate_sha256 {
            return Err(EnrollmentError::Corrupt(
                "authority certificate fingerprint does not match signed identity".to_string(),
            ));
        }
        Ok(Self {
            directory,
            identity,
            verifying_key,
        })
    }

    /// Authority directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Signed authority-node identity.
    pub const fn identity(&self) -> &SignedClusterIdentity {
        &self.identity
    }

    /// Public authority verification key.
    pub fn verifying_key(&self) -> &str {
        &self.verifying_key
    }

    /// Create and durably record a one-time token.
    pub fn create_token(
        &self,
        constraints: EnrollmentTokenConstraints,
        ttl: Duration,
    ) -> Result<IssuedEnrollmentToken, EnrollmentError> {
        validate_token_constraints(&constraints)?;
        if ttl.is_zero() || ttl > MAX_TOKEN_TTL {
            return Err(EnrollmentError::InvalidRequest(format!(
                "token TTL must be between one second and {} seconds",
                MAX_TOKEN_TTL.as_secs()
            )));
        }
        let now = unix_time_secs()?;
        let expires_at_unix_secs = now.checked_add(ttl.as_secs()).ok_or_else(|| {
            EnrollmentError::InvalidRequest("token expiry overflowed".to_string())
        })?;
        let token_id = random_secret(12);
        let token = format!("sbce1.{token_id}.{}", random_secret(32));
        let record = EnrollmentTokenRecord {
            token_sha256: token_sha256(&token),
            created_at_unix_secs: now,
            expires_at_unix_secs,
            constraints: constraints.clone(),
            consumed_at_unix_secs: None,
        };
        self.mutate_token_store(|store| {
            if store.tokens.insert(token_id.clone(), record).is_some() {
                return Err(EnrollmentError::Corrupt(
                    "random token identifier collision".to_string(),
                ));
            }
            Ok(())
        })?;
        Ok(IssuedEnrollmentToken {
            token,
            token_id,
            expires_at_unix_secs,
            constraints,
        })
    }

    /// Verify, consume, and issue one worker enrollment.
    pub fn enroll(
        &self,
        request: EnrollmentRequest,
    ) -> Result<EnrollmentResponse, EnrollmentError> {
        validate_enrollment_request(&request, &self.identity.document.cluster_id)?;
        let mut csr = CertificateSigningRequestParams::from_pem(&request.csr_pem)
            .map_err(|error| EnrollmentError::InvalidRequest(format!("CSR rejected: {error}")))?;
        validate_csr_binding(
            &csr.params,
            &request.node_id,
            &self.identity.document.server_name,
        )?;

        // Load and validate every signing input before consuming the token.
        let ca_pem = read_bounded_text(&self.directory.join(CA_CERT_FILE), 256 * 1024)?;
        let ca_key_pem = read_bounded_text(&self.directory.join(CA_KEY_FILE), 256 * 1024)?;
        let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(crypto_error)?;
        let ca_cert = CertificateParams::from_ca_cert_pem(&ca_pem)
            .map_err(crypto_error)?
            .self_signed(&ca_key)
            .map_err(crypto_error)?;
        let authority_signing_key = decode_signing_key(&read_bounded_text(
            &self.directory.join(SIGNING_KEY_FILE),
            1024,
        )?)?;
        let gossip_key = read_bounded_text(&self.directory.join(GOSSIP_KEY_FILE), 1024)?;
        if gossip_key.len() < 16 {
            return Err(EnrollmentError::Corrupt(
                "gossip key is shorter than 16 bytes".to_string(),
            ));
        }

        let now = unix_time_secs()?;
        self.consume_token(&request, now)?;

        csr.params = leaf_params(&request.node_id, &self.identity.document.server_name, now)?;
        let certificate = csr.signed_by(&ca_cert, &ca_key).map_err(crypto_error)?;
        let document = ClusterIdentityDocument {
            schema_version: IDENTITY_SCHEMA_VERSION,
            cluster_id: self.identity.document.cluster_id.clone(),
            node_id: request.node_id,
            roles: request.roles,
            labels: request.labels,
            server_name: self.identity.document.server_name.clone(),
            certificate_sha256: certificate_fingerprint(certificate.der()),
            issued_at_unix_secs: now,
            expires_at_unix_secs: certificate_expiry(now)?,
            authority_key_id: key_id(&authority_signing_key.verifying_key().to_bytes()),
        };
        let identity = sign_identity(document, &authority_signing_key)?;
        Ok(EnrollmentResponse {
            certificate_pem: certificate.pem(),
            ca_pem,
            gossip_key,
            identity,
            authority_verifying_key: self.verifying_key.clone(),
        })
    }

    fn consume_token(&self, request: &EnrollmentRequest, now: u64) -> Result<(), EnrollmentError> {
        let token_id = parse_token_id(&request.token)?;
        let actual_hash = Sha256::digest(request.token.as_bytes());
        self.mutate_token_store(|store| {
            let record = store
                .tokens
                .get_mut(token_id)
                .ok_or(EnrollmentError::TokenRejected(
                    EnrollmentTokenRejection::Invalid,
                ))?;
            let expected_hash = URL_SAFE_NO_PAD.decode(&record.token_sha256).map_err(|_| {
                EnrollmentError::Corrupt("token hash is invalid base64".to_string())
            })?;
            if !bool::from(expected_hash.ct_eq(actual_hash.as_slice())) {
                return Err(EnrollmentError::TokenRejected(
                    EnrollmentTokenRejection::Invalid,
                ));
            }
            if record.consumed_at_unix_secs.is_some() {
                return Err(EnrollmentError::TokenRejected(
                    EnrollmentTokenRejection::Consumed,
                ));
            }
            if now >= record.expires_at_unix_secs {
                return Err(EnrollmentError::TokenRejected(
                    EnrollmentTokenRejection::Expired,
                ));
            }
            if request.roles.is_empty()
                || !request.roles.is_subset(&record.constraints.allowed_roles)
                || request.labels != record.constraints.labels
            {
                return Err(EnrollmentError::TokenRejected(
                    EnrollmentTokenRejection::Constraints,
                ));
            }
            record.consumed_at_unix_secs = Some(now);
            Ok(())
        })
    }

    fn mutate_token_store<T>(
        &self,
        operation: impl FnOnce(&mut EnrollmentTokenStore) -> Result<T, EnrollmentError>,
    ) -> Result<T, EnrollmentError> {
        let lock_path = self.directory.join(TOKENS_LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        set_file_permissions(&lock)?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let mut store: EnrollmentTokenStore = serde_json::from_slice(&read_bounded(
                &self.directory.join(TOKENS_FILE),
                4 * 1024 * 1024,
            )?)?;
            validate_token_store(&store)?;
            let value = operation(&mut store)?;
            atomic_write_secure(
                &self.directory.join(TOKENS_FILE),
                &serde_json::to_vec_pretty(&store)?,
            )?;
            Ok(value)
        })();
        let unlock_result = FileExt::unlock(&lock);
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(EnrollmentError::Io(error)),
        }
    }
}

/// Verify a signed identity against an authority verification key.
pub fn verify_signed_identity(
    signed: &SignedClusterIdentity,
    authority_verifying_key: &str,
) -> Result<(), EnrollmentError> {
    validate_identity_document(&signed.document)?;
    let verifying_bytes = URL_SAFE_NO_PAD
        .decode(authority_verifying_key)
        .map_err(|_| EnrollmentError::Crypto("verification key is invalid base64".to_string()))?;
    let verifying_bytes: [u8; 32] = verifying_bytes
        .try_into()
        .map_err(|_| EnrollmentError::Crypto("verification key must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_bytes)
        .map_err(|error| EnrollmentError::Crypto(error.to_string()))?;
    if signed.document.authority_key_id != key_id(&verifying_bytes) {
        return Err(EnrollmentError::Crypto(
            "identity authority key ID does not match verification key".to_string(),
        ));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| EnrollmentError::Crypto("identity signature is invalid base64".to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| EnrollmentError::Crypto(error.to_string()))?;
    verifying_key
        .verify(&identity_signing_bytes(&signed.document)?, &signature)
        .map_err(|_| {
            EnrollmentError::Crypto("identity signature verification failed".to_string())
        })?;
    let now = unix_time_secs()?;
    if now.saturating_add(300) < signed.document.issued_at_unix_secs
        || now >= signed.document.expires_at_unix_secs
    {
        return Err(EnrollmentError::Crypto(
            "signed cluster identity is not currently valid".to_string(),
        ));
    }
    Ok(())
}

/// Return the URL-safe base64 SHA-256 fingerprint of the first PEM certificate.
pub fn certificate_sha256_from_pem(pem: &str) -> Result<String, EnrollmentError> {
    let certificate = CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|error| EnrollmentError::Crypto(format!("parse certificate: {error}")))?;
    Ok(certificate_fingerprint(&certificate))
}

/// Verify and atomically install an enrolled worker identity and its local key.
pub fn install_worker_enrollment(
    directory: impl AsRef<Path>,
    worker: WorkerEnrollment,
    response: EnrollmentResponse,
) -> Result<InstalledClusterIdentity, EnrollmentError> {
    verify_signed_identity(&response.identity, &response.authority_verifying_key)?;
    if response.identity.document.node_id != worker.node_id
        || response.identity.document.server_name != worker.server_name
    {
        return Err(EnrollmentError::InvalidRequest(
            "enrollment response identity does not match local CSR identity".to_string(),
        ));
    }
    let certificate = CertificateDer::from_pem_slice(response.certificate_pem.as_bytes())
        .map_err(|error| EnrollmentError::Crypto(format!("parse worker certificate: {error}")))?;
    if certificate_fingerprint(&certificate) != response.identity.document.certificate_sha256 {
        return Err(EnrollmentError::Crypto(
            "worker certificate fingerprint does not match identity".to_string(),
        ));
    }
    crate::transport::tls::build_acceptor(&crate::transport::tls::MeshTlsConfig {
        cert_pem: response.certificate_pem.clone(),
        key_pem: worker.private_key_pem.clone(),
        ca_pem: response.ca_pem.clone(),
    })
    .map_err(|error| EnrollmentError::Crypto(error.to_string()))?;
    let identity = response.identity.document.to_cluster_identity()?;

    let directory = directory.as_ref();
    if directory.exists() {
        return Err(EnrollmentError::AlreadyExists(directory.to_path_buf()));
    }
    let parent = directory.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let stage = create_stage_directory(parent, directory.file_name())?;
    let mut guard = StageDirectoryGuard::new(stage.clone());
    set_directory_permissions(&stage)?;
    write_new_secure(
        &stage.join(NODE_CERT_FILE),
        response.certificate_pem.as_bytes(),
    )?;
    write_new_secure(
        &stage.join(NODE_KEY_FILE),
        worker.private_key_pem.as_bytes(),
    )?;
    write_new_secure(&stage.join(CA_CERT_FILE), response.ca_pem.as_bytes())?;
    write_new_secure(&stage.join(GOSSIP_KEY_FILE), response.gossip_key.as_bytes())?;
    write_new_secure(
        &stage.join(IDENTITY_FILE),
        &serde_json::to_vec_pretty(&response.identity)?,
    )?;
    write_new_secure(
        &stage.join(VERIFYING_KEY_FILE),
        response.authority_verifying_key.as_bytes(),
    )?;
    sync_directory(&stage)?;
    std::fs::rename(&stage, directory)?;
    guard.commit();
    sync_directory(parent)?;

    Ok(InstalledClusterIdentity {
        identity,
        node_cert_file: directory.join(NODE_CERT_FILE),
        node_key_file: directory.join(NODE_KEY_FILE),
        ca_file: directory.join(CA_CERT_FILE),
        gossip_key_file: directory.join(GOSSIP_KEY_FILE),
        identity_file: directory.join(IDENTITY_FILE),
        authority_verifying_key_file: directory.join(VERIFYING_KEY_FILE),
    })
}

fn validate_authority_init(init: &AuthorityInit) -> Result<(), EnrollmentError> {
    if !init.roles.contains(&ClusterNodeRole::Authority) {
        return Err(EnrollmentError::InvalidRequest(
            "authority initialization requires the authority role".to_string(),
        ));
    }
    validate_server_name(&init.server_name)?;
    validate_runtime_identity(&init.cluster_id, &init.node_id, &init.roles, &init.labels)
}

fn validate_token_constraints(
    constraints: &EnrollmentTokenConstraints,
) -> Result<(), EnrollmentError> {
    if constraints.allowed_roles.is_empty() {
        return Err(EnrollmentError::InvalidRequest(
            "token must allow at least one role".to_string(),
        ));
    }
    validate_runtime_identity(
        "constraints",
        "token",
        &constraints.allowed_roles,
        &constraints.labels,
    )
}

fn validate_enrollment_request(
    request: &EnrollmentRequest,
    cluster_id: &str,
) -> Result<(), EnrollmentError> {
    if request.token.is_empty() || request.token.len() > MAX_TOKEN_BYTES {
        return Err(EnrollmentError::TokenRejected(
            EnrollmentTokenRejection::Invalid,
        ));
    }
    if request.csr_pem.is_empty() || request.csr_pem.len() > MAX_CSR_BYTES {
        return Err(EnrollmentError::InvalidRequest(format!(
            "CSR must contain at most {MAX_CSR_BYTES} bytes"
        )));
    }
    validate_runtime_identity(
        cluster_id,
        &request.node_id,
        &request.roles,
        &request.labels,
    )
}

fn validate_runtime_identity(
    cluster_id: &str,
    node_id: &str,
    roles: &BTreeSet<ClusterNodeRole>,
    labels: &BTreeMap<String, String>,
) -> Result<(), EnrollmentError> {
    ClusterIdentity {
        cluster_id: cluster_id.to_string(),
        node_id: node_id.to_string(),
        roles: roles.clone(),
        labels: labels.clone(),
        peer_address: None,
        model_endpoint: None,
    }
    .validate()
    .map_err(|error| EnrollmentError::InvalidRequest(error.to_string()))
}

fn validate_server_name(server_name: &str) -> Result<(), EnrollmentError> {
    if server_name.is_empty()
        || server_name.len() > MAX_SERVER_NAME_BYTES
        || !server_name.is_ascii()
        || server_name.chars().any(char::is_whitespace)
    {
        return Err(EnrollmentError::InvalidRequest(format!(
            "server name must be nonempty ASCII without whitespace and at most {MAX_SERVER_NAME_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_identity_document(document: &ClusterIdentityDocument) -> Result<(), EnrollmentError> {
    if document.schema_version != IDENTITY_SCHEMA_VERSION {
        return Err(EnrollmentError::Corrupt(format!(
            "unsupported identity schema {}",
            document.schema_version
        )));
    }
    validate_server_name(&document.server_name)?;
    validate_runtime_identity(
        &document.cluster_id,
        &document.node_id,
        &document.roles,
        &document.labels,
    )?;
    if document.certificate_sha256.len() != 43 || document.authority_key_id.len() != 43 {
        return Err(EnrollmentError::Corrupt(
            "identity fingerprints must be URL-safe base64 SHA-256 values".to_string(),
        ));
    }
    if document.issued_at_unix_secs >= document.expires_at_unix_secs {
        return Err(EnrollmentError::Corrupt(
            "identity issue time must precede expiry".to_string(),
        ));
    }
    Ok(())
}

fn validate_token_store(store: &EnrollmentTokenStore) -> Result<(), EnrollmentError> {
    if store.schema_version != TOKEN_STORE_SCHEMA_VERSION || store.hash_algorithm != "sha256" {
        return Err(EnrollmentError::Corrupt(
            "unsupported token-store schema or hash algorithm".to_string(),
        ));
    }
    if store.tokens.len() > 100_000 {
        return Err(EnrollmentError::Corrupt(
            "token store exceeds 100000 entries".to_string(),
        ));
    }
    for (token_id, record) in &store.tokens {
        if token_id.is_empty()
            || token_id.len() > 64
            || record.token_sha256.len() != 43
            || record.created_at_unix_secs >= record.expires_at_unix_secs
        {
            return Err(EnrollmentError::Corrupt(
                "token record has invalid bounds or timestamps".to_string(),
            ));
        }
        validate_token_constraints(&record.constraints).map_err(|error| {
            EnrollmentError::Corrupt(format!("stored token constraints are invalid: {error}"))
        })?;
    }
    Ok(())
}

fn validate_csr_binding(
    params: &CertificateParams,
    node_id: &str,
    server_name: &str,
) -> Result<(), EnrollmentError> {
    let common_name_matches = params
        .distinguished_name
        .get(&DnType::CommonName)
        .and_then(dn_value_str)
        == Some(node_id);
    let node_san_matches = params.subject_alt_names.iter().any(|san| match san {
        rcgen::SanType::DnsName(name) => name.as_str() == node_id,
        _ => false,
    });
    let server_san_matches = params.subject_alt_names.iter().any(|san| match san {
        rcgen::SanType::DnsName(name) => name.as_str() == server_name,
        _ => false,
    });
    if !common_name_matches || !node_san_matches || !server_san_matches {
        return Err(EnrollmentError::InvalidRequest(
            "CSR subject must bind the requested node ID and cluster server name".to_string(),
        ));
    }
    Ok(())
}

fn dn_value_str(value: &DnValue) -> Option<&str> {
    match value {
        DnValue::Ia5String(value) => Some(value.as_str()),
        DnValue::PrintableString(value) => Some(value.as_str()),
        DnValue::TeletexString(value) => Some(value.as_str()),
        DnValue::Utf8String(value) => Some(value),
        _ => None,
    }
}

fn leaf_params(
    node_id: &str,
    server_name: &str,
    now: u64,
) -> Result<CertificateParams, EnrollmentError> {
    let mut params = CertificateParams::new(vec![server_name.to_string(), node_id.to_string()])
        .map_err(crypto_error)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, node_id);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    set_certificate_validity(&mut params, now, 825)?;
    Ok(params)
}

fn generate_ca(cluster_id: &str, now: u64) -> Result<(Certificate, KeyPair), EnrollmentError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(crypto_error)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("sbproxy cluster {cluster_id}"));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    set_certificate_validity(&mut params, now, 3650)?;
    let key = KeyPair::generate().map_err(crypto_error)?;
    let cert = params.self_signed(&key).map_err(crypto_error)?;
    Ok((cert, key))
}

fn set_certificate_validity(
    params: &mut CertificateParams,
    now: u64,
    days: i64,
) -> Result<(), EnrollmentError> {
    let now = OffsetDateTime::from_unix_timestamp(
        i64::try_from(now)
            .map_err(|_| EnrollmentError::Crypto("certificate time overflowed".to_string()))?,
    )
    .map_err(|error| EnrollmentError::Crypto(error.to_string()))?;
    params.not_before = now - TimeDuration::minutes(5);
    params.not_after = now + TimeDuration::days(days);
    Ok(())
}

fn certificate_expiry(now: u64) -> Result<u64, EnrollmentError> {
    now.checked_add(825 * 24 * 60 * 60)
        .ok_or_else(|| EnrollmentError::Crypto("certificate expiry overflowed".to_string()))
}

fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn decode_signing_key(encoded: &str) -> Result<SigningKey, EnrollmentError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| EnrollmentError::Corrupt("signing key is invalid base64".to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnrollmentError::Corrupt("signing key must be 32 bytes".to_string()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn encode_verifying_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

fn sign_identity(
    document: ClusterIdentityDocument,
    signing_key: &SigningKey,
) -> Result<SignedClusterIdentity, EnrollmentError> {
    let signature = signing_key.sign(&identity_signing_bytes(&document)?);
    Ok(SignedClusterIdentity {
        document,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn identity_signing_bytes(document: &ClusterIdentityDocument) -> Result<Vec<u8>, EnrollmentError> {
    serde_json::to_vec(document).map_err(EnrollmentError::from)
}

fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(certificate.as_ref()))
}

fn key_id(verifying_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifying_key))
}

fn token_sha256(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn parse_token_id(token: &str) -> Result<&str, EnrollmentError> {
    let mut parts = token.split('.');
    let valid = matches!(parts.next(), Some("sbce1"));
    let token_id = parts.next().unwrap_or_default();
    let secret = parts.next().unwrap_or_default();
    if !valid
        || token_id.is_empty()
        || token_id.len() > 64
        || secret.len() < 32
        || parts.next().is_some()
    {
        return Err(EnrollmentError::TokenRejected(
            EnrollmentTokenRejection::Invalid,
        ));
    }
    Ok(token_id)
}

fn random_secret(bytes: usize) -> String {
    let mut secret = vec![0u8; bytes];
    OsRng.fill_bytes(&mut secret);
    URL_SAFE_NO_PAD.encode(secret)
}

fn unix_time_secs() -> Result<u64, EnrollmentError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| EnrollmentError::Crypto("system clock is before Unix epoch".to_string()))
}

fn crypto_error(error: impl std::fmt::Display) -> EnrollmentError {
    EnrollmentError::Crypto(error.to_string())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, EnrollmentError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > maximum as u64 {
        return Err(EnrollmentError::Corrupt(format!(
            "authority file exceeds {maximum} bytes"
        )));
    }
    Ok(std::fs::read(path)?)
}

fn read_bounded_text(path: &Path, maximum: usize) -> Result<String, EnrollmentError> {
    String::from_utf8(read_bounded(path, maximum)?)
        .map_err(|_| EnrollmentError::Corrupt("authority text is not UTF-8".to_string()))
}

fn create_stage_directory(
    parent: &Path,
    destination_name: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, EnrollmentError> {
    let destination_name = destination_name
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            EnrollmentError::InvalidRequest(
                "authority or installation directory must have a file name".to_string(),
            )
        })?;
    for _ in 0..16 {
        let candidate = parent.join(format!(".{destination_name}.stage-{}", random_secret(12)));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(EnrollmentError::Io(error)),
        }
    }
    Err(EnrollmentError::Corrupt(
        "could not allocate a unique staging directory".to_string(),
    ))
}

struct StageDirectoryGuard {
    path: PathBuf,
    committed: bool,
}

impl StageDirectoryGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for StageDirectoryGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn write_new_secure(path: &Path, contents: &[u8]) -> Result<(), EnrollmentError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    set_file_permissions(&file)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_write_secure(path: &Path, contents: &[u8]) -> Result<(), EnrollmentError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..16 {
        let temp = parent.join(format!(".tokens-{}.tmp", random_secret(12)));
        match write_new_secure(&temp, contents) {
            Ok(()) => {
                let rename_result = std::fs::rename(&temp, path);
                if rename_result.is_err() {
                    let _ = std::fs::remove_file(&temp);
                }
                rename_result?;
                sync_directory(parent)?;
                return Ok(());
            }
            Err(EnrollmentError::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(EnrollmentError::Corrupt(
        "could not allocate a unique token-store temporary file".to_string(),
    ))
}

#[cfg(unix)]
fn validate_owner_only(path: &Path, directory: bool) -> Result<(), EnrollmentError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        let kind = if directory { "directory" } else { "file" };
        return Err(EnrollmentError::Corrupt(format!(
            "authority {kind} permissions are not owner-only"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only(_path: &Path, _directory: bool) -> Result<(), EnrollmentError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(file: &File) -> Result<(), EnrollmentError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_file: &File) -> Result<(), EnrollmentError> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), EnrollmentError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), EnrollmentError> {
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), EnrollmentError> {
    File::open(path)?.sync_all()?;
    Ok(())
}
