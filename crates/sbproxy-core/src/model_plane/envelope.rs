use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sbproxy_mesh::peer_identity::{AuthenticatedPeerIdentity, PeerIdentityProof};
use sbproxy_mesh::{ClusterHandle, ClusterNodeRole};
use sbproxy_model_host::PriorityClass;

type HmacSha256 = Hmac<Sha256>;

/// Current dispatch-envelope schema.
pub const DISPATCH_ENVELOPE_SCHEMA_VERSION: u32 = 1;
/// Domain separator used for enrolled peer-identity proofs.
pub const DISPATCH_PROOF_CONTEXT: &str = "sbproxy.model-dispatch.v1";

const MAX_SIGNED_ENVELOPE_BYTES: usize = 128 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_POLICY_REVISION_BYTES: usize = 256;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 128;
const MAX_DISPATCH_LIFETIME_MS: u64 = 30_000;
const MAX_CLOCK_SKEW_MS: u64 = 5_000;
const MIN_DEVELOPMENT_KEY_BYTES: usize = 16;

const ALLOWED_PATHS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/v1/embeddings",
    "/v1/audio/transcriptions",
    "/v1/audio/translations",
    "/v1/images/generations",
];

/// Request metadata authenticated between one gateway and one worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Authenticated gateway node ID.
    pub issuer_node_id: String,
    /// Intended worker node ID.
    pub audience_node_id: String,
    /// Public request correlation ID.
    pub request_id: String,
    /// Unique replay-protection nonce.
    pub nonce: String,
    /// Gateway issue time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Absolute expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Peer hop count, which must be exactly one.
    pub hop_count: u8,
    /// Bounded tenant identifier, never a bearer credential.
    pub tenant_id: String,
    /// Non-secret governed key identifier.
    pub governed_key_id: String,
    /// Effective policy revision evaluated by the gateway.
    pub policy_revision: String,
    /// Managed deployment ID.
    pub deployment: String,
    /// Generation fence for the managed deployment.
    pub deployment_generation: u64,
    /// Public logical model name.
    pub logical_model: String,
    /// Worker admission priority.
    pub priority: PriorityClass,
    /// Allowlisted HTTP method.
    pub method: String,
    /// Allowlisted OpenAI-compatible inference path.
    pub path: String,
    /// Bounded request content type.
    pub content_type: Option<String>,
    /// Lowercase hexadecimal SHA-256 of the exact request body.
    pub body_sha256: String,
}

/// Authentication proof attached to one dispatch envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchAuthProof {
    /// Enrolled certificate-key proof for production mTLS.
    PeerIdentity {
        /// Authority-bound peer proof.
        proof: PeerIdentityProof,
    },
    /// HMAC used only by explicitly configured development clusters.
    DevelopmentHmac {
        /// URL-safe base64 HMAC-SHA256 signature.
        signature: String,
    },
}

/// Envelope plus the authentication proof over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDispatchEnvelope {
    /// Authenticated request metadata.
    pub envelope: DispatchEnvelope,
    /// Proof over the canonical serialized envelope.
    pub auth: DispatchAuthProof,
}

/// Authentication source used to sign an outbound dispatch.
pub enum DispatchSigner<'a> {
    /// Production enrolled peer identity.
    PeerIdentity(&'a ClusterHandle),
    /// Explicit development shared key.
    DevelopmentSharedKey(&'a [u8]),
}

/// Authentication source used to verify an inbound dispatch.
pub enum DispatchVerifier<'a> {
    /// Production proof verification bound to the TLS peer leaf.
    PeerIdentity {
        /// Installed cluster authenticator.
        cluster: &'a ClusterHandle,
        /// URL-safe base64 SHA-256 fingerprint of the negotiated TLS leaf.
        tls_peer_certificate_sha256: &'a str,
    },
    /// Explicit development shared key.
    DevelopmentSharedKey(&'a [u8]),
}

/// Successfully authenticated dispatch metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDispatch {
    /// Validated request envelope.
    pub envelope: DispatchEnvelope,
    /// Enrolled peer claims in production mode.
    pub authenticated_peer: Option<AuthenticatedPeerIdentity>,
}

/// Stable dispatch-envelope validation or authentication failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DispatchEnvelopeError {
    /// JSON, field shape, route, or field bound was invalid.
    #[error("invalid dispatch envelope")]
    InvalidEnvelope,
    /// Serialized envelope exceeded the fixed wire bound.
    #[error("dispatch envelope exceeds the wire bound")]
    EnvelopeTooLarge,
    /// Envelope targeted another worker.
    #[error("dispatch audience does not match this worker")]
    AudienceMismatch,
    /// Envelope reached or passed its expiry.
    #[error("dispatch envelope expired")]
    DispatchExpired,
    /// Envelope issue time is beyond the allowed clock skew.
    #[error("dispatch envelope is not yet valid")]
    DispatchNotYetValid,
    /// Issue and expiry times violate the fixed lifetime.
    #[error("dispatch envelope lifetime is invalid")]
    InvalidLifetime,
    /// Request attempted zero or multiple worker hops.
    #[error("dispatch envelope hop count must equal one")]
    HopLimitExceeded,
    /// Request body did not match the authenticated digest.
    #[error("dispatch request body digest does not match")]
    RequestDigestMismatch,
    /// Signature, peer claims, gateway role, or TLS binding failed.
    #[error("dispatch peer authentication failed")]
    AuthenticationFailed,
    /// Issuer and nonce were already accepted while live.
    #[error("dispatch replay detected")]
    ReplayDetected,
    /// Replay state is full of live entries and fails closed.
    #[error("dispatch replay fence is full")]
    ReplayFenceFull,
}

impl DispatchEnvelopeError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "invalid_envelope",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::AudienceMismatch => "audience_mismatch",
            Self::DispatchExpired => "dispatch_expired",
            Self::DispatchNotYetValid => "dispatch_not_yet_valid",
            Self::InvalidLifetime => "invalid_dispatch_lifetime",
            Self::HopLimitExceeded => "hop_limit_exceeded",
            Self::RequestDigestMismatch => "request_digest_mismatch",
            Self::AuthenticationFailed => "peer_authentication_failed",
            Self::ReplayDetected => "replay_detected",
            Self::ReplayFenceFull => "replay_fence_full",
        }
    }

    /// Whether another replica may safely be attempted before output.
    pub const fn retryable(&self) -> bool {
        false
    }
}

impl DispatchEnvelope {
    /// Attach an enrolled-peer or explicit development proof.
    pub fn sign(
        self,
        signer: DispatchSigner<'_>,
    ) -> Result<SignedDispatchEnvelope, DispatchEnvelopeError> {
        self.validate_shape()?;
        let signing_bytes = signing_bytes(&self)?;
        let auth = match signer {
            DispatchSigner::PeerIdentity(cluster) => DispatchAuthProof::PeerIdentity {
                proof: cluster
                    .sign_peer_payload(DISPATCH_PROOF_CONTEXT, &signing_bytes)
                    .map_err(|_| DispatchEnvelopeError::AuthenticationFailed)?,
            },
            DispatchSigner::DevelopmentSharedKey(key) => DispatchAuthProof::DevelopmentHmac {
                signature: sign_hmac(key, &signing_bytes)?,
            },
        };
        let signed = SignedDispatchEnvelope {
            envelope: self,
            auth,
        };
        signed.to_json()?;
        Ok(signed)
    }

    fn validate_shape(&self) -> Result<(), DispatchEnvelopeError> {
        if self.schema_version != DISPATCH_ENVELOPE_SCHEMA_VERSION
            || self.deployment_generation == 0
            || self.method != "POST"
            || !ALLOWED_PATHS.contains(&self.path.as_str())
            || !valid_identifier(&self.issuer_node_id, false)
            || !valid_identifier(&self.audience_node_id, false)
            || !valid_identifier(&self.request_id, true)
            || self.nonce.len() < 16
            || !valid_identifier(&self.nonce, true)
            || !valid_identifier(&self.tenant_id, true)
            || !valid_identifier(&self.governed_key_id, true)
            || !valid_bounded_text(&self.policy_revision, MAX_POLICY_REVISION_BYTES)
            || !valid_identifier(&self.deployment, true)
            || !valid_identifier(&self.logical_model, true)
            || self.content_type.as_deref().is_some_and(|value| {
                !valid_bounded_text(value, MAX_CONTENT_TYPE_BYTES)
                    || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
            })
            || self.body_sha256.len() != 64
            || !self
                .body_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(DispatchEnvelopeError::InvalidEnvelope);
        }
        Ok(())
    }
}

impl SignedDispatchEnvelope {
    /// Strictly decode one bounded signed envelope.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, DispatchEnvelopeError> {
        if bytes.len() > MAX_SIGNED_ENVELOPE_BYTES {
            return Err(DispatchEnvelopeError::EnvelopeTooLarge);
        }
        let signed: Self =
            serde_json::from_slice(bytes).map_err(|_| DispatchEnvelopeError::InvalidEnvelope)?;
        signed.envelope.validate_shape()?;
        signed.validate_auth_shape()?;
        Ok(signed)
    }

    /// Encode one bounded signed envelope.
    pub fn to_json(&self) -> Result<Vec<u8>, DispatchEnvelopeError> {
        let bytes = serde_json::to_vec(self).map_err(|_| DispatchEnvelopeError::InvalidEnvelope)?;
        if bytes.len() > MAX_SIGNED_ENVELOPE_BYTES {
            return Err(DispatchEnvelopeError::EnvelopeTooLarge);
        }
        Ok(bytes)
    }

    /// Authenticate and validate an inbound dispatch and its exact body.
    pub fn verify(
        &self,
        verifier: DispatchVerifier<'_>,
        expected_audience: &str,
        now_unix_ms: u64,
        body: &[u8],
    ) -> Result<VerifiedDispatch, DispatchEnvelopeError> {
        self.envelope.validate_shape()?;
        self.validate_auth_shape()?;
        let signing_bytes = signing_bytes(&self.envelope)?;
        let authenticated_peer = self.verify_auth(verifier, &signing_bytes)?;

        if self.envelope.audience_node_id != expected_audience {
            return Err(DispatchEnvelopeError::AudienceMismatch);
        }
        if self.envelope.hop_count != 1 {
            return Err(DispatchEnvelopeError::HopLimitExceeded);
        }
        if self.envelope.expires_at_unix_ms <= now_unix_ms {
            return Err(DispatchEnvelopeError::DispatchExpired);
        }
        if self.envelope.issued_at_unix_ms > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(DispatchEnvelopeError::DispatchNotYetValid);
        }
        let lifetime = self
            .envelope
            .expires_at_unix_ms
            .checked_sub(self.envelope.issued_at_unix_ms)
            .ok_or(DispatchEnvelopeError::InvalidLifetime)?;
        if lifetime == 0 || lifetime > MAX_DISPATCH_LIFETIME_MS {
            return Err(DispatchEnvelopeError::InvalidLifetime);
        }
        if body_sha256_hex(body) != self.envelope.body_sha256 {
            return Err(DispatchEnvelopeError::RequestDigestMismatch);
        }

        Ok(VerifiedDispatch {
            envelope: self.envelope.clone(),
            authenticated_peer,
        })
    }

    fn validate_auth_shape(&self) -> Result<(), DispatchEnvelopeError> {
        match &self.auth {
            DispatchAuthProof::PeerIdentity { .. } => Ok(()),
            DispatchAuthProof::DevelopmentHmac { signature } => {
                if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
                    return Err(DispatchEnvelopeError::InvalidEnvelope);
                }
                let decoded = URL_SAFE_NO_PAD
                    .decode(signature)
                    .map_err(|_| DispatchEnvelopeError::InvalidEnvelope)?;
                if decoded.len() != 32 {
                    return Err(DispatchEnvelopeError::InvalidEnvelope);
                }
                Ok(())
            }
        }
    }

    fn verify_auth(
        &self,
        verifier: DispatchVerifier<'_>,
        signing_bytes: &[u8],
    ) -> Result<Option<AuthenticatedPeerIdentity>, DispatchEnvelopeError> {
        match (verifier, &self.auth) {
            (
                DispatchVerifier::PeerIdentity {
                    cluster,
                    tls_peer_certificate_sha256,
                },
                DispatchAuthProof::PeerIdentity { proof },
            ) => {
                let identity = cluster
                    .verify_peer_payload(
                        DISPATCH_PROOF_CONTEXT,
                        signing_bytes,
                        Some(&self.envelope.issuer_node_id),
                        proof,
                    )
                    .map_err(|_| DispatchEnvelopeError::AuthenticationFailed)?;
                if !identity.roles.contains(&ClusterNodeRole::Gateway)
                    || identity.certificate_sha256 != tls_peer_certificate_sha256
                {
                    return Err(DispatchEnvelopeError::AuthenticationFailed);
                }
                Ok(Some(identity))
            }
            (
                DispatchVerifier::DevelopmentSharedKey(key),
                DispatchAuthProof::DevelopmentHmac { signature },
            ) => {
                verify_hmac(key, signing_bytes, signature)?;
                Ok(None)
            }
            _ => Err(DispatchEnvelopeError::AuthenticationFailed),
        }
    }
}

/// Return the lowercase hexadecimal SHA-256 of an exact request body.
pub fn body_sha256_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

fn signing_bytes(envelope: &DispatchEnvelope) -> Result<Vec<u8>, DispatchEnvelopeError> {
    serde_json::to_vec(envelope).map_err(|_| DispatchEnvelopeError::InvalidEnvelope)
}

fn sign_hmac(key: &[u8], payload: &[u8]) -> Result<String, DispatchEnvelopeError> {
    if key.len() < MIN_DEVELOPMENT_KEY_BYTES {
        return Err(DispatchEnvelopeError::AuthenticationFailed);
    }
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| DispatchEnvelopeError::AuthenticationFailed)?;
    mac.update(payload);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify_hmac(key: &[u8], payload: &[u8], signature: &str) -> Result<(), DispatchEnvelopeError> {
    if key.len() < MIN_DEVELOPMENT_KEY_BYTES {
        return Err(DispatchEnvelopeError::AuthenticationFailed);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| DispatchEnvelopeError::AuthenticationFailed)?;
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| DispatchEnvelopeError::AuthenticationFailed)?;
    mac.update(payload);
    mac.verify_slice(&signature)
        .map_err(|_| DispatchEnvelopeError::AuthenticationFailed)
}

fn valid_identifier(value: &str, allow_slash: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'_' | b':' | b'@')
                || (allow_slash && byte == b'/')
        })
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
}
