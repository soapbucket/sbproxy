// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Authority-signed node identity proofs for canonical mTLS clusters.
//!
//! A CA-signed certificate only proves that a peer belongs to the same PKI.
//! These proofs additionally bind the certificate key to the enrolled node ID,
//! roles, labels, and logical cluster before accepting gossip advertisements or
//! typed state published by that node.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use fs2::FileExt;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::SigningKey;
use rustls::SignatureScheme;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::enrollment::{
    certificate_sha256_from_pem, verify_signed_identity, SignedClusterIdentity,
};
use crate::transport::tls::MeshTlsConfig;
use crate::ClusterIdentity;

const IDENTITY_FILE: &str = "identity.json";
const VERIFYING_KEY_FILE: &str = "authority-verifying.key";
const MAX_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_VERIFYING_KEY_BYTES: usize = 1024;
const MAX_CERTIFICATES: usize = 4;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;
const MANUAL_IDENTITY_URI_PREFIX: &str = "urn:sbproxy:identity:v1:";
const BOOT_EPOCH_FILE: &str = "boot-epoch.json";
const BOOT_EPOCH_LOCK_FILE: &str = ".boot-epoch.lock";
const PEER_HIGH_WATER_FILE: &str = "peer-identity-high-water.json";
const MAX_PEER_HIGH_WATER_BYTES: usize = 1024 * 1024;
const MAX_PEER_HIGH_WATER_ENTRIES: usize = 4_096;

/// Authenticated claims common to enrolled and operator-issued PKI identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPeerIdentity {
    /// Logical cluster ID.
    pub cluster_id: String,
    /// Stable node ID.
    pub node_id: String,
    /// Roles authenticated for this certificate.
    pub roles: std::collections::BTreeSet<crate::ClusterNodeRole>,
    /// Placement labels authenticated for this certificate.
    pub labels: std::collections::BTreeMap<String, String>,
    /// Cluster server-name claim.
    pub server_name: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: String,
    /// Monotonic certificate identity epoch for this stable node ID.
    pub identity_epoch: u64,
    /// Absolute certificate or enrolled-identity expiry.
    pub expires_at_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualPkiIdentityClaims {
    schema_version: u32,
    cluster_id: String,
    node_id: String,
    roles: std::collections::BTreeSet<crate::ClusterNodeRole>,
    labels: std::collections::BTreeMap<String, String>,
    server_name: String,
    identity_epoch: u64,
}

/// Source that authenticated the certificate's node claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerIdentityAttestation {
    /// Claims signed by the built-in enrollment authority.
    Enrolled {
        /// Detached authority-signed identity document.
        identity: Box<SignedClusterIdentity>,
    },
    /// Claims embedded in a CA-signed manual-PKI certificate URI SAN.
    ManualPki,
}

/// Certificate-key proof carrying the peer's authority-signed claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentityProof {
    /// Enrollment or manual-PKI attestation mode.
    pub attestation: PeerIdentityAttestation,
    /// Leaf-first DER certificate chain encoded as URL-safe base64.
    pub certificate_chain: Vec<String>,
    /// TLS signature scheme used by the enrolled certificate key.
    pub signature_scheme: u16,
    /// Signature over the domain-separated payload digest.
    pub signature: String,
}

/// Loaded local identity and trust material used to issue and verify proofs.
#[derive(Clone)]
pub struct PeerIdentityAuthenticator {
    local_identity: AuthenticatedPeerIdentity,
    attestation: PeerIdentityAttestation,
    authority_verifying_key: Option<String>,
    certificate_chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<dyn SigningKey>,
    verifier: Arc<rustls::client::WebPkiServerVerifier>,
    supported_algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    boot_epoch: u64,
    peer_high_water: Arc<PeerIdentityHighWaterStore>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBootEpoch {
    schema_version: u32,
    boot_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerIdentityHighWater {
    identity_epoch: u64,
    certificate_sha256: String,
    boot_epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPeerIdentityHighWater {
    schema_version: u32,
    peers: std::collections::BTreeMap<String, PeerIdentityHighWater>,
}

#[derive(Debug)]
struct PeerIdentityHighWaterStore {
    path: Option<PathBuf>,
    peers: Mutex<std::collections::BTreeMap<String, PeerIdentityHighWater>>,
}

impl PeerIdentityHighWaterStore {
    fn ephemeral() -> Self {
        Self {
            path: None,
            peers: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn durable(directory: &Path) -> Result<Self> {
        let path = directory.join(PEER_HIGH_WATER_FILE);
        let peers = match std::fs::read(&path) {
            Ok(bytes) => decode_peer_high_water(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::collections::BTreeMap::new()
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path: Some(path),
            peers: Mutex::new(peers),
        })
    }

    fn observe(&self, identity: &AuthenticatedPeerIdentity, boot_epoch: Option<u64>) -> Result<()> {
        if boot_epoch == Some(0) {
            anyhow::bail!("peer boot epoch must be positive");
        }
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next_boot_epoch = boot_epoch.unwrap_or(0);
        let replacement = match peers.get(&identity.node_id) {
            Some(current) if identity.identity_epoch < current.identity_epoch => {
                anyhow::bail!("peer identity epoch regressed")
            }
            Some(current)
                if identity.identity_epoch == current.identity_epoch
                    && identity.certificate_sha256 != current.certificate_sha256 =>
            {
                anyhow::bail!("peer certificate changed without a newer identity epoch")
            }
            Some(current)
                if identity.identity_epoch == current.identity_epoch
                    && boot_epoch.is_some()
                    && next_boot_epoch < current.boot_epoch =>
            {
                anyhow::bail!("peer boot epoch regressed")
            }
            Some(current)
                if identity.identity_epoch == current.identity_epoch
                    && (boot_epoch.is_none() || next_boot_epoch == current.boot_epoch) =>
            {
                None
            }
            _ => Some(PeerIdentityHighWater {
                identity_epoch: identity.identity_epoch,
                certificate_sha256: identity.certificate_sha256.clone(),
                boot_epoch: next_boot_epoch,
            }),
        };
        if let Some(replacement) = replacement {
            let mut updated = peers.clone();
            updated.insert(identity.node_id.clone(), replacement);
            self.persist(&updated)?;
            *peers = updated;
        }
        Ok(())
    }

    fn persist(
        &self,
        peers: &std::collections::BTreeMap<String, PeerIdentityHighWater>,
    ) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        if peers.len() > MAX_PEER_HIGH_WATER_ENTRIES {
            anyhow::bail!("peer identity high-water entry count exceeds the limit");
        }
        let bytes = serde_json::to_vec(&StoredPeerIdentityHighWater {
            schema_version: 1,
            peers: peers.clone(),
        })?;
        if bytes.len() > MAX_PEER_HIGH_WATER_BYTES {
            anyhow::bail!("peer identity high-water file exceeds the size limit");
        }
        atomic_write_owner_only(path, &bytes)?;
        Ok(())
    }
}

fn decode_peer_high_water(
    bytes: &[u8],
) -> Result<std::collections::BTreeMap<String, PeerIdentityHighWater>> {
    if bytes.len() > MAX_PEER_HIGH_WATER_BYTES {
        anyhow::bail!("peer identity high-water file exceeds the size limit");
    }
    let stored: StoredPeerIdentityHighWater =
        serde_json::from_slice(bytes).context("decode peer identity high-water file")?;
    if stored.schema_version != 1
        || stored.peers.len() > MAX_PEER_HIGH_WATER_ENTRIES
        || stored.peers.iter().any(|(node_id, record)| {
            node_id.is_empty()
                || node_id.len() > 128
                || record.identity_epoch == 0
                || record.certificate_sha256.is_empty()
                || record.certificate_sha256.len() > 128
        })
    {
        anyhow::bail!("peer identity high-water file is invalid");
    }
    Ok(stored.peers)
}

impl std::fmt::Debug for PeerIdentityAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerIdentityAuthenticator")
            .field("node_id", &self.local_identity.node_id)
            .field("cluster_id", &self.local_identity.cluster_id)
            .finish_non_exhaustive()
    }
}

impl PeerIdentityAuthenticator {
    /// Load and validate one installed enrollment identity.
    pub fn load_installed(
        directory: impl AsRef<Path>,
        expected: &ClusterIdentity,
        expected_server_name: &str,
        tls: &MeshTlsConfig,
    ) -> Result<Self> {
        let directory = directory.as_ref();
        let identity_bytes = std::fs::read(directory.join(IDENTITY_FILE))
            .with_context(|| format!("read installed cluster identity in {directory:?}"))?;
        if identity_bytes.len() > MAX_IDENTITY_BYTES {
            anyhow::bail!("installed cluster identity exceeds {MAX_IDENTITY_BYTES} bytes");
        }
        let local_identity: SignedClusterIdentity =
            serde_json::from_slice(&identity_bytes).context("decode installed cluster identity")?;
        let authority_verifying_key =
            std::fs::read_to_string(directory.join(VERIFYING_KEY_FILE))
                .with_context(|| format!("read installed authority key in {directory:?}"))?;
        if authority_verifying_key.len() > MAX_VERIFYING_KEY_BYTES {
            anyhow::bail!(
                "installed authority verification key exceeds {MAX_VERIFYING_KEY_BYTES} bytes"
            );
        }
        Self::new_with_boot_epoch(
            local_identity,
            authority_verifying_key.trim().to_string(),
            expected,
            expected_server_name,
            tls,
            reserve_boot_epoch(directory)?,
            Arc::new(PeerIdentityHighWaterStore::durable(directory)?),
        )
    }

    /// Validate already-loaded identity and TLS material.
    pub fn new(
        local_identity: SignedClusterIdentity,
        authority_verifying_key: String,
        expected: &ClusterIdentity,
        expected_server_name: &str,
        tls: &MeshTlsConfig,
    ) -> Result<Self> {
        Self::new_with_boot_epoch(
            local_identity,
            authority_verifying_key,
            expected,
            expected_server_name,
            tls,
            1,
            Arc::new(PeerIdentityHighWaterStore::ephemeral()),
        )
    }

    fn new_with_boot_epoch(
        local_identity: SignedClusterIdentity,
        authority_verifying_key: String,
        expected: &ClusterIdentity,
        expected_server_name: &str,
        tls: &MeshTlsConfig,
        boot_epoch: u64,
        peer_high_water: Arc<PeerIdentityHighWaterStore>,
    ) -> Result<Self> {
        verify_signed_identity(&local_identity, &authority_verifying_key)
            .context("verify installed cluster identity")?;
        let authenticated_identity = enrolled_identity(&local_identity);
        validate_expected_claims(&authenticated_identity, expected, expected_server_name)?;

        Self::build(
            authenticated_identity,
            PeerIdentityAttestation::Enrolled {
                identity: Box::new(local_identity),
            },
            Some(authority_verifying_key),
            expected,
            tls,
            boot_epoch,
            peer_high_water,
        )
    }

    /// Load an operator-issued certificate whose URI SAN authenticates cluster claims.
    pub fn load_manual(
        directory: impl AsRef<Path>,
        expected: &ClusterIdentity,
        expected_server_name: &str,
        tls: &MeshTlsConfig,
    ) -> Result<Self> {
        let certificate_chain = crate::transport::tls::load_chain(&tls.cert_pem)?;
        let authenticated_identity = manual_identity_from_certificate(&certificate_chain[0])?;
        validate_expected_claims(&authenticated_identity, expected, expected_server_name)?;
        Self::build(
            authenticated_identity,
            PeerIdentityAttestation::ManualPki,
            None,
            expected,
            tls,
            reserve_boot_epoch(directory.as_ref())?,
            Arc::new(PeerIdentityHighWaterStore::durable(directory.as_ref())?),
        )
    }

    fn build(
        local_identity: AuthenticatedPeerIdentity,
        attestation: PeerIdentityAttestation,
        authority_verifying_key: Option<String>,
        expected: &ClusterIdentity,
        tls: &MeshTlsConfig,
        boot_epoch: u64,
        peer_high_water: Arc<PeerIdentityHighWaterStore>,
    ) -> Result<Self> {
        if boot_epoch == 0 {
            anyhow::bail!("peer identity boot epoch must be positive");
        }
        let certificate_chain = crate::transport::tls::load_chain(&tls.cert_pem)?;
        if certificate_chain.len() > MAX_CERTIFICATES
            || certificate_chain
                .iter()
                .any(|certificate| certificate.len() > MAX_CERTIFICATE_BYTES)
        {
            anyhow::bail!("installed certificate chain exceeds identity proof bounds");
        }
        let actual_fingerprint = certificate_sha256_from_pem(&tls.cert_pem)
            .context("fingerprint installed cluster certificate")?;
        if actual_fingerprint != local_identity.certificate_sha256 {
            anyhow::bail!("installed certificate does not match the signed cluster identity");
        }

        let provider = rustls::crypto::ring::default_provider();
        let supported_algorithms = provider.signature_verification_algorithms;
        let roots = Arc::new(crate::transport::tls::load_roots(&tls.ca_pem)?);
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(roots, Arc::new(provider))
                .build()
                .context("build enrolled peer identity verifier")?;
        verify_certificate_identity(
            verifier.as_ref(),
            &certificate_chain,
            &local_identity.node_id,
        )?;

        let private_key = crate::transport::tls::load_key(&tls.key_pem)?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
            .context("load enrolled identity signing key")?;
        let authenticator = Self {
            local_identity,
            attestation,
            authority_verifying_key,
            certificate_chain,
            signing_key,
            verifier,
            supported_algorithms,
            boot_epoch,
            peer_high_water,
        };
        let probe = authenticator.sign("sbproxy.peer-identity.self-test.v1", b"self-test")?;
        authenticator
            .verify(
                "sbproxy.peer-identity.self-test.v1",
                b"self-test",
                Some(expected.node_id.as_str()),
                &probe,
            )
            .context("installed private key does not match enrolled certificate")?;
        Ok(authenticator)
    }

    /// Local enrolled identity carried by proofs issued from this process.
    pub const fn local_identity(&self) -> &AuthenticatedPeerIdentity {
        &self.local_identity
    }

    /// Durable process boot epoch signed into gossip joins.
    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    /// Sign a domain-separated payload with this node's enrolled TLS key.
    pub fn sign(&self, context: &str, payload: &[u8]) -> Result<PeerIdentityProof> {
        let schemes = self.supported_algorithms.supported_schemes();
        let signer = self
            .signing_key
            .choose_scheme(&schemes)
            .context("enrolled key has no supported signature scheme")?;
        let message = proof_message(context, payload)?;
        let signature = signer.sign(&message).context("sign peer identity proof")?;
        if signature.len() > MAX_SIGNATURE_BYTES {
            anyhow::bail!("peer identity signature exceeds {MAX_SIGNATURE_BYTES} bytes");
        }
        Ok(PeerIdentityProof {
            attestation: self.attestation.clone(),
            certificate_chain: self
                .certificate_chain
                .iter()
                .map(|certificate| URL_SAFE_NO_PAD.encode(certificate.as_ref()))
                .collect(),
            signature_scheme: u16::from(signer.scheme()),
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }

    /// Verify a peer proof and return its authenticated cluster claims.
    pub fn verify(
        &self,
        context: &str,
        payload: &[u8],
        expected_node_id: Option<&str>,
        proof: &PeerIdentityProof,
    ) -> Result<AuthenticatedPeerIdentity> {
        let encoded_identity = serde_json::to_vec(&proof.attestation)
            .context("encode bounded peer identity during verification")?;
        if encoded_identity.len() > MAX_IDENTITY_BYTES {
            anyhow::bail!("peer identity exceeds {MAX_IDENTITY_BYTES} bytes");
        }
        let certificate_chain = decode_certificate_chain(&proof.certificate_chain)?;
        let document = match (&self.attestation, &proof.attestation) {
            (
                PeerIdentityAttestation::Enrolled { .. },
                PeerIdentityAttestation::Enrolled { identity },
            ) => {
                let verifying_key = self
                    .authority_verifying_key
                    .as_deref()
                    .context("enrolled verifier has no authority key")?;
                verify_signed_identity(identity, verifying_key)
                    .context("verify peer authority signature")?;
                enrolled_identity(identity)
            }
            (PeerIdentityAttestation::ManualPki, PeerIdentityAttestation::ManualPki) => {
                manual_identity_from_certificate(&certificate_chain[0])?
            }
            _ => anyhow::bail!("peer identity attestation mode differs from this cluster"),
        };
        if document.cluster_id != self.local_identity.cluster_id {
            anyhow::bail!("peer identity belongs to a different cluster");
        }
        if document.server_name != self.local_identity.server_name {
            anyhow::bail!("peer identity uses a different cluster server name");
        }
        if expected_node_id.is_some_and(|expected| document.node_id != expected) {
            anyhow::bail!("peer identity does not match the claimed node ID");
        }

        let fingerprint = URL_SAFE_NO_PAD.encode(Sha256::digest(certificate_chain[0].as_ref()));
        if fingerprint != document.certificate_sha256 {
            anyhow::bail!("peer certificate does not match its signed identity");
        }
        verify_certificate_identity(
            self.verifier.as_ref(),
            &certificate_chain,
            &document.node_id,
        )?;

        let signature = URL_SAFE_NO_PAD
            .decode(&proof.signature)
            .context("decode peer identity signature")?;
        if signature.len() > MAX_SIGNATURE_BYTES {
            anyhow::bail!("peer identity signature exceeds {MAX_SIGNATURE_BYTES} bytes");
        }
        let scheme = SignatureScheme::from(proof.signature_scheme);
        let algorithms = self
            .supported_algorithms
            .mapping
            .iter()
            .find_map(|(candidate, algorithms)| (*candidate == scheme).then_some(*algorithms))
            .context("peer identity signature scheme is unsupported")?;
        let end_entity = webpki::EndEntityCert::try_from(&certificate_chain[0])
            .context("parse peer identity certificate")?;
        let message = proof_message(context, payload)?;
        if !algorithms.iter().any(|algorithm| {
            end_entity
                .verify_signature(*algorithm, &message, &signature)
                .is_ok()
        }) {
            anyhow::bail!("peer identity payload signature verification failed");
        }
        self.peer_high_water.observe(&document, None)?;
        Ok(document)
    }

    /// Persist an authenticated join boot epoch after proof verification.
    pub(crate) fn observe_join(
        &self,
        identity: &AuthenticatedPeerIdentity,
        boot_epoch: u64,
    ) -> Result<()> {
        self.peer_high_water.observe(identity, Some(boot_epoch))
    }
}

fn validate_expected_claims(
    document: &AuthenticatedPeerIdentity,
    expected: &ClusterIdentity,
    expected_server_name: &str,
) -> Result<()> {
    if document.cluster_id != expected.cluster_id
        || document.node_id != expected.node_id
        || document.roles != expected.roles
        || document.labels != expected.labels
    {
        anyhow::bail!("configured cluster claims do not match the installed signed identity");
    }
    if document.server_name != expected_server_name {
        anyhow::bail!("configured cluster server name does not match the signed identity");
    }
    Ok(())
}

fn enrolled_identity(identity: &SignedClusterIdentity) -> AuthenticatedPeerIdentity {
    let document = &identity.document;
    AuthenticatedPeerIdentity {
        cluster_id: document.cluster_id.clone(),
        node_id: document.node_id.clone(),
        roles: document.roles.clone(),
        labels: document.labels.clone(),
        server_name: document.server_name.clone(),
        certificate_sha256: document.certificate_sha256.clone(),
        identity_epoch: document.identity_epoch,
        expires_at_unix_secs: document.expires_at_unix_secs,
    }
}

/// Build the URI SAN value required on an operator-issued manual-PKI leaf certificate.
pub fn manual_pki_identity_uri(
    identity: &ClusterIdentity,
    server_name: &str,
    identity_epoch: u64,
) -> Result<String> {
    identity.validate().map_err(anyhow::Error::msg)?;
    if server_name.is_empty() || server_name.len() > 253 || identity_epoch == 0 {
        anyhow::bail!("manual PKI server name and identity epoch are invalid");
    }
    let claims = ManualPkiIdentityClaims {
        schema_version: 1,
        cluster_id: identity.cluster_id.clone(),
        node_id: identity.node_id.clone(),
        roles: identity.roles.clone(),
        labels: identity.labels.clone(),
        server_name: server_name.to_string(),
        identity_epoch,
    };
    let encoded = serde_json::to_vec(&claims).context("encode manual PKI identity claims")?;
    if encoded.len() > MAX_IDENTITY_BYTES {
        anyhow::bail!("manual PKI identity claims exceed {MAX_IDENTITY_BYTES} bytes");
    }
    Ok(format!(
        "{MANUAL_IDENTITY_URI_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(encoded)
    ))
}

fn manual_identity_from_certificate(
    certificate: &CertificateDer<'static>,
) -> Result<AuthenticatedPeerIdentity> {
    use x509_parser::prelude::*;

    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|error| anyhow::anyhow!("parse manual PKI certificate: {error}"))?;
    let encoded = parsed
        .extensions()
        .iter()
        .filter_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => Some(names),
            _ => None,
        })
        .flat_map(|names| names.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::URI(uri) => uri.strip_prefix(MANUAL_IDENTITY_URI_PREFIX),
            _ => None,
        })
        .collect::<Vec<_>>();
    if encoded.len() != 1 {
        anyhow::bail!("manual PKI certificate requires exactly one SBproxy identity URI SAN");
    }
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(encoded[0])
        .context("decode manual PKI identity URI SAN")?;
    if claims_bytes.len() > MAX_IDENTITY_BYTES {
        anyhow::bail!("manual PKI identity claims exceed {MAX_IDENTITY_BYTES} bytes");
    }
    let claims: ManualPkiIdentityClaims =
        serde_json::from_slice(&claims_bytes).context("decode manual PKI identity claims")?;
    if claims.schema_version != 1 || claims.identity_epoch == 0 {
        anyhow::bail!("manual PKI identity schema or epoch is invalid");
    }
    let identity = ClusterIdentity {
        cluster_id: claims.cluster_id.clone(),
        node_id: claims.node_id.clone(),
        roles: claims.roles.clone(),
        labels: claims.labels.clone(),
        peer_address: None,
        model_endpoint: None,
    };
    identity.validate().map_err(anyhow::Error::msg)?;
    let expires_at_unix_secs = u64::try_from(parsed.validity().not_after.timestamp())
        .context("manual PKI certificate expiry is before the Unix epoch")?;
    Ok(AuthenticatedPeerIdentity {
        cluster_id: claims.cluster_id,
        node_id: claims.node_id,
        roles: claims.roles,
        labels: claims.labels,
        server_name: claims.server_name,
        certificate_sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(certificate.as_ref())),
        identity_epoch: claims.identity_epoch,
        expires_at_unix_secs,
    })
}

fn reserve_boot_epoch(directory: &Path) -> Result<u64> {
    std::fs::create_dir_all(directory)
        .with_context(|| format!("create cluster identity state directory {directory:?}"))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(BOOT_EPOCH_LOCK_FILE))?;
    set_owner_only(&lock)?;
    FileExt::lock_exclusive(&lock)?;
    let result = (|| {
        let path = directory.join(BOOT_EPOCH_FILE);
        let current = match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > 1_024 {
                    anyhow::bail!("cluster boot epoch file exceeds 1024 bytes");
                }
                let stored: StoredBootEpoch =
                    serde_json::from_slice(&bytes).context("decode cluster boot epoch")?;
                if stored.schema_version != 1 || stored.boot_epoch == 0 {
                    anyhow::bail!("cluster boot epoch file is invalid");
                }
                stored.boot_epoch
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let boot_epoch = current
            .checked_add(1)
            .context("cluster boot epoch overflowed")?;
        let bytes = serde_json::to_vec(&StoredBootEpoch {
            schema_version: 1,
            boot_epoch,
        })?;
        atomic_write_owner_only(&path, &bytes)?;
        Ok(boot_epoch)
    })();
    let unlock = FileExt::unlock(&lock);
    match (result, unlock) {
        (Ok(epoch), Ok(())) => Ok(epoch),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn atomic_write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("cluster state path has no UTF-8 file name")?;
    for attempt in 0..16u8 {
        let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), attempt));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => {
                set_owner_only(&file)?;
                let write_result = (|| {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&temporary, path)?;
                    sync_directory(parent)?;
                    Ok::<_, std::io::Error>(())
                })();
                if write_result.is_err() {
                    let _ = std::fs::remove_file(&temporary);
                }
                write_result?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("could not allocate a cluster state temporary file")
}

#[cfg(unix)]
fn set_owner_only(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn decode_certificate_chain(encoded: &[String]) -> Result<Vec<CertificateDer<'static>>> {
    if encoded.is_empty() || encoded.len() > MAX_CERTIFICATES {
        anyhow::bail!("peer identity certificate chain has invalid length");
    }
    encoded
        .iter()
        .map(|certificate| {
            let der = URL_SAFE_NO_PAD
                .decode(certificate)
                .context("decode peer identity certificate")?;
            if der.len() > MAX_CERTIFICATE_BYTES {
                anyhow::bail!("peer identity certificate exceeds {MAX_CERTIFICATE_BYTES} bytes");
            }
            Ok(CertificateDer::from(der))
        })
        .collect()
}

fn verify_certificate_identity(
    verifier: &rustls::client::WebPkiServerVerifier,
    chain: &[CertificateDer<'static>],
    node_id: &str,
) -> Result<()> {
    let (leaf, intermediates) = chain
        .split_first()
        .context("peer identity certificate chain is empty")?;
    let server_name = ServerName::try_from(node_id.to_string())
        .context("peer node ID is not a valid certificate DNS name")?;
    verifier
        .verify_server_cert(leaf, intermediates, &server_name, &[], UnixTime::now())
        .context("verify peer certificate chain and node-specific SAN")?;
    Ok(())
}

fn proof_message(context: &str, payload: &[u8]) -> Result<[u8; 32]> {
    if context.is_empty() || context.len() > 128 || context.chars().any(char::is_control) {
        anyhow::bail!("peer identity proof context is invalid");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"sbproxy-peer-identity-proof-v1\0");
    hasher.update((context.len() as u64).to_be_bytes());
    hasher.update(context.as_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use crate::enrollment::{
        install_worker_enrollment, AuthorityInit, EnrollmentAuthority, EnrollmentTokenConstraints,
        WorkerEnrollment,
    };
    use crate::ClusterNodeRole;

    use super::*;

    struct EnrolledPair {
        _temp: tempfile::TempDir,
        authority_dir: PathBuf,
        authority: PeerIdentityAuthenticator,
        worker: PeerIdentityAuthenticator,
    }

    fn enrolled_pair() -> EnrolledPair {
        let temp = tempfile::tempdir().unwrap();
        let authority_dir = temp.path().join("authority");
        let roles = BTreeSet::from([ClusterNodeRole::Authority, ClusterNodeRole::Gateway]);
        let authority = EnrollmentAuthority::initialize(
            &authority_dir,
            AuthorityInit {
                cluster_id: "production".to_string(),
                node_id: "authority-a".to_string(),
                roles: roles.clone(),
                labels: BTreeMap::from([("zone".to_string(), "west-a".to_string())]),
                server_name: "sbproxy-mesh".to_string(),
            },
        )
        .unwrap();
        let token = authority
            .create_token(
                EnrollmentTokenConstraints {
                    allowed_roles: BTreeSet::from([ClusterNodeRole::Worker]),
                    labels: BTreeMap::from([("zone".to_string(), "west-b".to_string())]),
                },
                Duration::from_secs(60),
            )
            .unwrap();
        let worker_enrollment = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").unwrap();
        let response = authority
            .enroll(worker_enrollment.request(
                token.into_token(),
                BTreeSet::from([ClusterNodeRole::Worker]),
                BTreeMap::from([("zone".to_string(), "west-b".to_string())]),
            ))
            .unwrap();
        let worker_dir = temp.path().join("worker");
        let installed =
            install_worker_enrollment(&worker_dir, worker_enrollment, response).unwrap();

        let authority_tls = tls_from(&authority_dir);
        let authority_identity = authority.identity().document.to_cluster_identity().unwrap();
        let authority_auth = PeerIdentityAuthenticator::load_installed(
            &authority_dir,
            &authority_identity,
            "sbproxy-mesh",
            &authority_tls,
        )
        .unwrap();
        let worker_tls = tls_from(&worker_dir);
        let worker_auth = PeerIdentityAuthenticator::load_installed(
            &worker_dir,
            &installed.identity,
            "sbproxy-mesh",
            &worker_tls,
        )
        .unwrap();
        EnrolledPair {
            _temp: temp,
            authority_dir,
            authority: authority_auth,
            worker: worker_auth,
        }
    }

    fn tls_from(directory: &Path) -> MeshTlsConfig {
        MeshTlsConfig {
            cert_pem: std::fs::read_to_string(directory.join("node.pem")).unwrap(),
            key_pem: std::fs::read_to_string(directory.join("node-key.pem")).unwrap(),
            ca_pem: std::fs::read_to_string(directory.join("ca.pem")).unwrap(),
        }
    }

    fn manual_tls(
        ca: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
        identity: &ClusterIdentity,
        identity_epoch: u64,
    ) -> MeshTlsConfig {
        use rcgen::{
            CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
        };
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![identity.node_id.clone()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.subject_alt_names.push(SanType::URI(
            manual_pki_identity_uri(identity, "sbproxy-mesh", identity_epoch)
                .unwrap()
                .try_into()
                .unwrap(),
        ));
        let certificate = params.signed_by(&key, ca, ca_key).unwrap();
        MeshTlsConfig {
            cert_pem: certificate.pem(),
            key_pem: key.serialize_pem(),
            ca_pem: ca.pem(),
        }
    }

    fn manual_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let certificate = params.self_signed(&key).unwrap();
        (certificate, key)
    }

    #[test]
    fn enrolled_peer_proof_binds_node_claims_and_payload() {
        let pair = enrolled_pair();
        let proof = pair
            .worker
            .sign("sbproxy.gossip.join.v1", b"worker-b|127.0.0.1:7946")
            .unwrap();
        let document = pair
            .authority
            .verify(
                "sbproxy.gossip.join.v1",
                b"worker-b|127.0.0.1:7946",
                Some("worker-b"),
                &proof,
            )
            .unwrap();
        assert_eq!(document.node_id, "worker-b");
        assert_eq!(document.roles, BTreeSet::from([ClusterNodeRole::Worker]));

        let join = crate::gossip_loop::GossipMsg::Join {
            node_id: "worker-b".to_string(),
            advertise_addr: "10.0.0.12:7946".to_string(),
            transport_addr: Some("10.0.0.12:8946".to_string()),
            boot_epoch: 1,
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            proof: Some(Box::new(
                pair.worker
                    .sign(
                        "sbproxy.gossip.join.v1",
                        &super::proof_message(
                            "test-size-only",
                            b"worker-b|10.0.0.12:7946|10.0.0.12:8946",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
            )),
        };
        let encoded = crate::transport::wire::encode(&join).unwrap();
        assert_eq!(
            crate::transport::wire::decode::<crate::gossip_loop::GossipMsg>(&encoded).unwrap(),
            join,
        );
        assert!(
            encoded.len() <= 1_472,
            "signed join is {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn enrolled_peer_proof_rejects_claim_and_payload_tampering() {
        let pair = enrolled_pair();
        let proof = pair
            .worker
            .sign("sbproxy.gossip.join.v1", b"original")
            .unwrap();
        assert!(pair
            .authority
            .verify(
                "sbproxy.gossip.join.v1",
                b"original",
                Some("authority-a"),
                &proof,
            )
            .is_err());
        assert!(pair
            .authority
            .verify(
                "sbproxy.gossip.join.v1",
                b"tampered",
                Some("worker-b"),
                &proof,
            )
            .is_err());
    }

    #[test]
    fn enrolled_peer_proof_rejects_certificate_substitution() {
        let pair = enrolled_pair();
        let mut proof = pair
            .worker
            .sign("sbproxy.cluster-state.v1", b"snapshot")
            .unwrap();
        let authority_proof = pair
            .authority
            .sign("sbproxy.cluster-state.v1", b"snapshot")
            .unwrap();
        proof.certificate_chain = authority_proof.certificate_chain;
        proof.signature = authority_proof.signature;
        proof.signature_scheme = authority_proof.signature_scheme;
        assert!(pair
            .authority
            .verify(
                "sbproxy.cluster-state.v1",
                b"snapshot",
                Some("worker-b"),
                &proof,
            )
            .is_err());
    }

    #[test]
    fn rotated_identity_epoch_durably_fences_the_old_certificate() {
        let pair = enrolled_pair();
        let old_proof = pair
            .worker
            .sign("sbproxy.cluster-state.v1", b"snapshot")
            .unwrap();
        pair.authority
            .verify(
                "sbproxy.cluster-state.v1",
                b"snapshot",
                Some("worker-b"),
                &old_proof,
            )
            .unwrap();

        let authority = EnrollmentAuthority::open(&pair.authority_dir).unwrap();
        let constraints = EnrollmentTokenConstraints {
            allowed_roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::from([("zone".to_string(), "west-b".to_string())]),
        };
        let token = authority
            .create_token(constraints.clone(), Duration::from_secs(60))
            .unwrap();
        let enrollment = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").unwrap();
        let response = authority
            .enroll(enrollment.request(
                token.into_token(),
                constraints.allowed_roles,
                constraints.labels,
            ))
            .unwrap();
        let rotated_dir = pair._temp.path().join("worker-rotated");
        let installed = install_worker_enrollment(&rotated_dir, enrollment, response).unwrap();
        let rotated = PeerIdentityAuthenticator::load_installed(
            &rotated_dir,
            &installed.identity,
            "sbproxy-mesh",
            &tls_from(&rotated_dir),
        )
        .unwrap();
        let rotated_proof = rotated
            .sign("sbproxy.cluster-state.v1", b"snapshot")
            .unwrap();
        let identity = pair
            .authority
            .verify(
                "sbproxy.cluster-state.v1",
                b"snapshot",
                Some("worker-b"),
                &rotated_proof,
            )
            .unwrap();
        assert_eq!(identity.identity_epoch, 2);

        let authority_identity = authority.identity().document.to_cluster_identity().unwrap();
        let reopened = PeerIdentityAuthenticator::load_installed(
            &pair.authority_dir,
            &authority_identity,
            "sbproxy-mesh",
            &tls_from(&pair.authority_dir),
        )
        .unwrap();
        assert!(reopened
            .verify(
                "sbproxy.cluster-state.v1",
                b"snapshot",
                Some("worker-b"),
                &old_proof,
            )
            .is_err());
    }

    #[test]
    fn observed_boot_epoch_survives_verifier_restart() {
        let pair = enrolled_pair();
        let proof = pair.worker.sign("sbproxy.gossip.join.v1", b"join").unwrap();
        let identity = pair
            .authority
            .verify("sbproxy.gossip.join.v1", b"join", Some("worker-b"), &proof)
            .unwrap();
        pair.authority.observe_join(&identity, 2).unwrap();

        let authority = EnrollmentAuthority::open(&pair.authority_dir).unwrap();
        let authority_identity = authority.identity().document.to_cluster_identity().unwrap();
        let reopened = PeerIdentityAuthenticator::load_installed(
            &pair.authority_dir,
            &authority_identity,
            "sbproxy-mesh",
            &tls_from(&pair.authority_dir),
        )
        .unwrap();
        let identity = reopened
            .verify("sbproxy.gossip.join.v1", b"join", Some("worker-b"), &proof)
            .unwrap();
        assert!(reopened.observe_join(&identity, 1).is_err());
    }

    #[test]
    fn manual_pki_uri_san_authenticates_node_roles_labels_and_payload() {
        let temp = tempfile::tempdir().unwrap();
        let (ca, ca_key) = manual_ca();
        let authority_identity = ClusterIdentity {
            cluster_id: "production".to_string(),
            node_id: "authority-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Authority]),
            labels: BTreeMap::from([("zone".to_string(), "west-a".to_string())]),
            peer_address: None,
            model_endpoint: None,
        };
        let worker_identity = ClusterIdentity {
            cluster_id: "production".to_string(),
            node_id: "worker-b".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::from([("zone".to_string(), "west-b".to_string())]),
            peer_address: None,
            model_endpoint: None,
        };
        let authority_tls = manual_tls(&ca, &ca_key, &authority_identity, 1);
        let worker_tls = manual_tls(&ca, &ca_key, &worker_identity, 7);
        let authority_dir = temp.path().join("manual-authority");
        let worker_dir = temp.path().join("manual-worker");
        let authority = PeerIdentityAuthenticator::load_manual(
            &authority_dir,
            &authority_identity,
            "sbproxy-mesh",
            &authority_tls,
        )
        .unwrap();
        let worker = PeerIdentityAuthenticator::load_manual(
            &worker_dir,
            &worker_identity,
            "sbproxy-mesh",
            &worker_tls,
        )
        .unwrap();
        assert_eq!(authority.boot_epoch(), 1);
        assert_eq!(worker.boot_epoch(), 1);
        let restarted_worker = PeerIdentityAuthenticator::load_manual(
            &worker_dir,
            &worker_identity,
            "sbproxy-mesh",
            &worker_tls,
        )
        .unwrap();
        assert_eq!(restarted_worker.boot_epoch(), 2);
        let proof = worker
            .sign("sbproxy.cluster-state.v1", b"manual-pki-payload")
            .unwrap();
        let claims = authority
            .verify(
                "sbproxy.cluster-state.v1",
                b"manual-pki-payload",
                Some("worker-b"),
                &proof,
            )
            .unwrap();
        assert_eq!(claims.roles, BTreeSet::from([ClusterNodeRole::Worker]));
        assert_eq!(claims.labels["zone"], "west-b");
        assert_eq!(claims.identity_epoch, 7);

        let mut forged_config = worker_identity;
        forged_config.roles.insert(ClusterNodeRole::Authority);
        assert!(PeerIdentityAuthenticator::load_manual(
            &worker_dir,
            &forged_config,
            "sbproxy-mesh",
            &worker_tls,
        )
        .is_err());
    }
}
