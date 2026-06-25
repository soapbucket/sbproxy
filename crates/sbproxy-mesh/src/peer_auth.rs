// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Automatic mTLS between sbproxy mesh instances.
//!
//! `PeerAuth` provides certificate-based peer authentication for
//! inter-proxy connections.  When enabled, outbound connections present
//! the proxy's own certificate and incoming connections are validated
//! against the configured CA bundle.
//!
//! # Verification model
//!
//! `verify_peer` runs the standard X.509 path-building algorithm via
//! `rustls-webpki` against the operator-configured CA. The leaf must:
//!
//! 1. Parse as DER from a PEM block.
//! 2. Be signed (directly or via a chain of intermediates also bundled
//!    in the input PEM) by the configured CA.
//! 3. Carry a `client_auth` Extended Key Usage extension. Mesh peers
//!    open mTLS connections to each other, so client-auth is the
//!    semantically correct EKU; nodes that need server-auth as well
//!    must include both EKUs in their leaf.
//! 4. Be valid at the current wall-clock time (not before / not after).
//!
//! All other failure modes (malformed PEM, no chain, expired cert,
//! wrong EKU) collapse to `false`. A probing peer can therefore not
//! distinguish "I'm using the wrong CA" from "my clock is skewed", which
//! is the safe behavior on the trust boundary.
//!
//! When `enabled = false` the verifier short-circuits to `true` so a
//! cluster operator can deploy the rest of the mesh stack without
//! provisioning certificates first.

use serde::{Deserialize, Serialize};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

// --- Config ---

/// Configuration for peer authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuthConfig {
    /// When `true`, peer certificates are verified against `ca_cert`.
    /// When `false`, peer authentication is skipped entirely.
    pub enabled: bool,
    /// PEM-encoded CA certificate used to verify peer certificates.
    /// Required when `enabled = true`; ignored otherwise.
    #[serde(default)]
    pub ca_cert: Option<String>,
}

// --- PeerAuth ---

/// Runtime peer authentication state.
pub struct PeerAuth {
    config: PeerAuthConfig,
    /// CA cert pre-decoded to DER at construction time so each call to
    /// `verify_peer` does not redo PEM parsing.
    ca_der: Option<Vec<u8>>,
}

impl PeerAuth {
    /// Create a new `PeerAuth` from the given configuration.
    ///
    /// When `config.enabled` is true and `config.ca_cert` contains a
    /// PEM-encoded certificate, the CA DER is decoded once here. Decode
    /// failure leaves the verifier in a fail-closed state: every
    /// subsequent `verify_peer` call returns `false`.
    pub fn new(config: PeerAuthConfig) -> Self {
        let ca_der = if config.enabled {
            config
                .ca_cert
                .as_deref()
                .and_then(|pem| CertificateDer::from_pem_slice(pem.as_bytes()).ok())
                .map(|cert| cert.as_ref().to_vec())
        } else {
            None
        };
        Self { config, ca_der }
    }

    /// Returns `true` if peer authentication is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Verify a peer certificate against the trusted CA.
    ///
    /// Returns `true` when:
    /// - peer auth is disabled (no verification performed), OR
    /// - the leaf certificate parses as PEM, chains to the configured
    ///   CA via `rustls-webpki`'s path-building, carries a `client_auth`
    ///   EKU, and is currently valid (not before / not after).
    ///
    /// Returns `false` for all other inputs, including:
    /// - peer auth enabled but no CA configured,
    /// - the input is not a PEM `CERTIFICATE` block,
    /// - chain validation fails (signature mismatch, wrong CA, expired,
    ///   missing EKU, etc.).
    ///
    /// `cert_pem` may include a chain of certificates (leaf + zero or
    /// more intermediates). The first PEM block is treated as the leaf;
    /// any additional `CERTIFICATE` blocks are added to the
    /// intermediate-cert pool for path building.
    pub fn verify_peer(&self, cert_pem: &[u8]) -> bool {
        // --- Disabled path: short-circuit ---
        if !self.config.enabled {
            return true;
        }

        // --- Locate trust anchor ---
        let Some(ca_der) = self.ca_der.as_deref() else {
            // Enabled but no usable CA: refuse everything. This is the
            // safe behavior: a missing CA must not silently grant trust.
            return false;
        };
        let ca_cert_der = CertificateDer::from(ca_der);
        let Ok(trust_anchor) = anchor_from_trusted_cert(&ca_cert_der) else {
            return false;
        };
        let trust_anchors = [trust_anchor];

        // --- Decode the peer chain ---
        let mut peer_certs: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(cert_pem)
            .filter_map(Result::ok)
            .collect();
        if peer_certs.is_empty() {
            return false;
        }
        // First block is the end entity; the remainder, if any, are
        // intermediates supplied alongside the leaf.
        let leaf = peer_certs.remove(0);
        let intermediates: Vec<CertificateDer<'_>> = peer_certs;

        // --- Build + verify the chain ---
        let Ok(end_entity) = EndEntityCert::try_from(&leaf) else {
            return false;
        };

        // `UnixTime::now()` itself never fails (it panics on a clock
        // before 1970, which is fine for a server context).
        let now = UnixTime::now();

        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &trust_anchors,
                &intermediates,
                now,
                KeyUsage::client_auth(),
                None, // no CRL
                None, // no extra path policy
            )
            .is_ok()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny CA + leaf-cert generator built on rcgen. Returns
    /// (ca_pem, leaf_pem). The leaf carries `client_auth` EKU because
    /// that is what `verify_peer` requires; tests that need the
    /// "wrong EKU" scenario build their own params explicitly.
    fn make_test_ca_and_leaf(common_name: &str) -> (String, String) {
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["Test CA".into()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self_signed");

        let mut leaf_params =
            rcgen::CertificateParams::new(vec![common_name.into()]).expect("leaf params");
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        // Mesh peer auth verifies with `KeyUsage::client_auth()`, so
        // every test leaf must carry the matching EKU.
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf signed_by ca");

        (ca_cert.pem(), leaf_cert.pem())
    }

    #[test]
    fn peer_auth_disabled_is_not_enabled() {
        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: false,
            ca_cert: None,
        });
        assert!(!auth.is_enabled());
    }

    #[test]
    fn peer_auth_enabled_is_enabled() {
        let (ca_pem, _) = make_test_ca_and_leaf("node-1");
        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: Some(ca_pem),
        });
        assert!(auth.is_enabled());
    }

    #[test]
    fn verify_peer_returns_true_when_disabled() {
        // When peer auth is off the verifier must accept anything so
        // operators can deploy the mesh without provisioning certs.
        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: false,
            ca_cert: None,
        });
        assert!(auth.verify_peer(b"any garbage at all"));
    }

    #[test]
    fn verify_peer_accepts_cert_chained_to_configured_ca() {
        let (ca_pem, leaf_pem) = make_test_ca_and_leaf("node-A");
        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: Some(ca_pem),
        });
        assert!(
            auth.verify_peer(leaf_pem.as_bytes()),
            "leaf chained to the configured CA should verify"
        );
    }

    #[test]
    fn verify_peer_rejects_self_signed_cert() {
        // A cert that is its own CA is not chained to the configured
        // trust anchor, so verification must fail.
        let (configured_ca_pem, _) = make_test_ca_and_leaf("node-A");

        let mut params = rcgen::CertificateParams::new(vec!["selfie".into()]).expect("params");
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let key = rcgen::KeyPair::generate().expect("key");
        let self_signed = params.self_signed(&key).expect("self_signed");

        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: Some(configured_ca_pem),
        });
        assert!(
            !auth.verify_peer(self_signed.pem().as_bytes()),
            "self-signed cert must not verify against an external CA"
        );
    }

    #[test]
    fn verify_peer_rejects_cert_chained_to_different_ca() {
        // CA A is configured. CA B's leaf must not verify even though
        // B is structurally a valid CA, because the trust anchor is A.
        let (ca_a_pem, _) = make_test_ca_and_leaf("node-A");
        let (_ca_b_pem, leaf_b_pem) = make_test_ca_and_leaf("node-B");

        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: Some(ca_a_pem),
        });
        assert!(
            !auth.verify_peer(leaf_b_pem.as_bytes()),
            "cert chained to CA B must not verify against trust anchor A"
        );
    }

    #[test]
    fn verify_peer_rejects_garbage_input() {
        let (ca_pem, _) = make_test_ca_and_leaf("node-A");
        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: Some(ca_pem),
        });
        assert!(!auth.verify_peer(b"not a pem block"));
        assert!(!auth.verify_peer(b""));
    }

    #[test]
    fn verify_peer_rejects_when_enabled_but_ca_missing() {
        // Enabled with no CA must fail closed: refuse every cert
        // rather than silently trust everything.
        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: None,
        });
        let (_, leaf_pem) = make_test_ca_and_leaf("node-A");
        assert!(!auth.verify_peer(leaf_pem.as_bytes()));
    }

    #[test]
    fn verify_peer_rejects_cert_without_client_auth_eku() {
        // Mesh leaves use `client_auth`. A leaf with only `server_auth`
        // EKU must not pass.
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["Test CA".into()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca");

        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["server-only".into()]).expect("leaf params");
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf");

        let auth = PeerAuth::new(PeerAuthConfig {
            enabled: true,
            ca_cert: Some(ca_cert.pem()),
        });
        assert!(
            !auth.verify_peer(leaf_cert.pem().as_bytes()),
            "leaf without client_auth EKU must not verify"
        );
    }

    #[test]
    fn peer_auth_config_deserializes() {
        let json = serde_json::json!({
            "enabled": true,
            "ca_cert": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
        });
        let config: PeerAuthConfig = serde_json::from_value(json).unwrap();
        assert!(config.enabled);
        assert!(config.ca_cert.is_some());
    }

    #[test]
    fn peer_auth_config_defaults_ca_cert_to_none() {
        let json = serde_json::json!({"enabled": false});
        let config: PeerAuthConfig = serde_json::from_value(json).unwrap();
        assert!(!config.enabled);
        assert!(config.ca_cert.is_none());
    }

    #[test]
    fn peer_auth_config_serializes_roundtrip() {
        let config = PeerAuthConfig {
            enabled: true,
            ca_cert: Some("pem-data".to_string()),
        };
        let serialized = serde_json::to_value(&config).unwrap();
        let deserialized: PeerAuthConfig = serde_json::from_value(serialized).unwrap();
        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.ca_cert, deserialized.ca_cert);
    }
}
