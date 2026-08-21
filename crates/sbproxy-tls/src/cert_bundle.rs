// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! One versioned certificate record, published and read as a unit (WOR-2635).
//!
//! The cert store used to hold a certificate, its private key, and its
//! metadata under three keys and write them with three calls. The doc
//! comment said "atomically" and the code did not: a crash between the first
//! write and the second left a new certificate paired with the previous
//! generation's private key, which reads back as a perfectly plausible
//! bundle and cannot complete a handshake. A peer that read the metadata in
//! between saw a generation the store could not actually serve, and skipped
//! the issuance that would have repaired it.
//!
//! A [`CertBundle`] closes that by being one value:
//!
//! * one `put` publishes it, so every backend's own write atomicity is the
//!   whole story rather than one third of it,
//! * a `generation` counts publications so a follower can tell a bundle it
//!   has already installed from one it has not, and so a superseded issuer
//!   can be refused,
//! * a `digest` over the encoded body turns a torn or corrupted record into
//!   a rejection instead of into serving material.
//!
//! The digest is an unkeyed SHA-256 stored inside the record it covers, so
//! it detects damage and not tampering: anyone who can write the store can
//! recompute it over whatever they please. It is an integrity check against
//! a half-finished write, a truncated read, or a corrupted block, and it is
//! not an authenticity check against a writer. Whatever keeps an attacker
//! out of the store (file permissions, a Redis ACL, bucket IAM) is what
//! keeps them out of the certificate.
//!
//! Private key bytes live in this record exactly as they lived in the
//! previous layout: whatever protection the backend gives (file permissions,
//! a Redis ACL, bucket encryption) is the protection they have. Nothing here
//! logs the record's bytes, and [`CertBundle`]'s `Debug` prints lengths and
//! a digest rather than PEM.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cert_store::CertMeta;

/// Record layout version. A reader refuses a version it does not know rather
/// than guessing at fields it cannot see.
pub const BUNDLE_VERSION: u32 = 1;

/// A certificate, its private key, and its metadata as one published unit.
#[derive(Clone, Serialize, Deserialize)]
pub struct CertBundle {
    /// Record layout version, always [`BUNDLE_VERSION`] on write.
    pub version: u32,
    /// Publication counter for this hostname. Strictly increases.
    pub generation: u64,
    /// The hostname this material is for.
    pub hostname: String,
    /// Certificate chain, PEM encoded.
    pub cert_pem: Vec<u8>,
    /// Private key, PEM encoded.
    pub key_pem: Vec<u8>,
    /// Issuance metadata.
    pub meta: CertMeta,
    /// Hex SHA-256 over the record body, checked on every read.
    pub digest: String,
}

impl std::fmt::Debug for CertBundle {
    /// Never prints certificate or key bytes. A bundle ends up in a log line
    /// or a panic message eventually, and the private key must not go with
    /// it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertBundle")
            .field("version", &self.version)
            .field("generation", &self.generation)
            .field("hostname", &self.hostname)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem_len", &self.key_pem.len())
            .field("expires_at", &self.meta.expires_at)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Why a stored bundle was refused. Every variant is safe to log: none of
/// them carries certificate or key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleReject {
    /// The record did not deserialize (truncated, or not a bundle at all).
    Undecodable,
    /// The record's layout version is not one this build understands.
    UnknownVersion,
    /// The digest does not cover the bytes that are there.
    DigestMismatch,
    /// The record is for a different hostname than the key it was read from.
    HostnameMismatch,
    /// The certificate and the private key are not a pair.
    KeyMismatch,
    /// Legacy three-key state whose certificate and key do not match.
    TornLegacy,
}

impl BundleReject {
    /// A short, bounded label for structured logs.
    ///
    /// Deliberately not a metric label yet. `digest_mismatch` and
    /// `torn_legacy` are exactly what an operator would alert on, and no
    /// counter carries them today: the metric registry lives in
    /// `sbproxy-observe`, which this change does not touch, so a refused
    /// bundle is visible in the log line and in nothing else. The set is
    /// kept closed and bounded so it can become label values unchanged
    /// when the counter is wired.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undecodable => "undecodable",
            Self::UnknownVersion => "unknown_version",
            Self::DigestMismatch => "digest_mismatch",
            Self::HostnameMismatch => "hostname_mismatch",
            Self::KeyMismatch => "key_mismatch",
            Self::TornLegacy => "torn_legacy",
        }
    }
}

impl std::fmt::Display for BundleReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for BundleReject {}

/// SHA-256 over the fields that make the record what it is, hex encoded.
///
/// The digest field itself is excluded, which is what lets a reader
/// recompute it. Lengths are mixed in before the byte runs so a record
/// cannot be re-cut between the certificate and the key without changing
/// the digest.
///
/// Unkeyed, and stored beside the bytes it covers: see this module's header
/// for what that does and does not buy.
fn digest_of(
    generation: u64,
    hostname: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
    meta: &CertMeta,
) -> String {
    // Destructured rather than field-accessed on purpose. A fourth field on
    // `CertMeta` would otherwise fall outside the integrity check in
    // silence, and the record would keep verifying with that field free to
    // say anything. This pattern stops compiling the moment the struct
    // grows, which turns "remember to update the digest" into a build
    // error. `CertMeta` is not `#[non_exhaustive]`, so the pattern is
    // exhaustive and stays that way.
    let CertMeta {
        issued_at,
        expires_at,
        serial,
    } = meta;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(&BUNDLE_VERSION.to_be_bytes());
    ctx.update(&generation.to_be_bytes());
    ctx.update(&(hostname.len() as u64).to_be_bytes());
    ctx.update(hostname.as_bytes());
    ctx.update(&(cert_pem.len() as u64).to_be_bytes());
    ctx.update(cert_pem);
    ctx.update(&(key_pem.len() as u64).to_be_bytes());
    ctx.update(key_pem);
    for field in [issued_at, expires_at, serial] {
        ctx.update(&(field.len() as u64).to_be_bytes());
        ctx.update(field.as_bytes());
    }
    hex::encode(ctx.finish().as_ref())
}

impl CertBundle {
    /// Build a record, proving the certificate and key are a pair first.
    ///
    /// Publishing material that cannot complete a handshake is the failure
    /// this refuses at the point it is cheapest to refuse: before anything
    /// is written, rather than on a peer that reads it back.
    pub fn new(
        hostname: &str,
        generation: u64,
        cert_pem: &[u8],
        key_pem: &[u8],
        meta: CertMeta,
    ) -> Result<Self> {
        crate::cert_resolver::load_certified_key(cert_pem, key_pem)
            .context("the certificate and private key being published are not a pair")?;
        let digest = digest_of(generation, hostname, cert_pem, key_pem, &meta);
        Ok(Self {
            version: BUNDLE_VERSION,
            generation,
            hostname: hostname.to_string(),
            cert_pem: cert_pem.to_vec(),
            key_pem: key_pem.to_vec(),
            meta,
            digest,
        })
    }

    /// Serialize for storage.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("encode certificate bundle")
    }

    /// Parse and fully validate a stored record.
    ///
    /// Every refusal is a [`BundleReject`], so a caller can count the reason
    /// on a bounded metric label and keep serving its last good certificate
    /// rather than installing something it cannot verify.
    pub fn decode(bytes: &[u8], expect_hostname: &str) -> std::result::Result<Self, BundleReject> {
        let bundle: Self = serde_json::from_slice(bytes).map_err(|_| BundleReject::Undecodable)?;
        if bundle.version != BUNDLE_VERSION {
            return Err(BundleReject::UnknownVersion);
        }
        let expected = digest_of(
            bundle.generation,
            &bundle.hostname,
            &bundle.cert_pem,
            &bundle.key_pem,
            &bundle.meta,
        );
        if expected != bundle.digest {
            return Err(BundleReject::DigestMismatch);
        }
        if bundle.hostname != expect_hostname {
            return Err(BundleReject::HostnameMismatch);
        }
        if crate::cert_resolver::load_certified_key(&bundle.cert_pem, &bundle.key_pem).is_err() {
            return Err(BundleReject::KeyMismatch);
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> CertMeta {
        CertMeta {
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            serial: "01ABCDEF".into(),
        }
    }

    #[test]
    fn every_cert_meta_field_moves_the_digest() {
        // `digest_of` destructures `CertMeta`, so a field added to the
        // struct is a compile error there until the digest covers it. This
        // is the other half of that binding: proof that every field which
        // does exist actually reaches the hash, so someone restoring the
        // old hand-enumerated field list has to break this too.
        let base = meta();
        let baseline = digest_of(1, "example.com", b"CERT", b"KEY", &base);
        assert_eq!(
            digest_of(1, "example.com", b"CERT", b"KEY", &base),
            baseline,
            "the digest has to be a function of its inputs alone"
        );
        for (what, mutated) in [
            (
                "issued_at",
                CertMeta {
                    issued_at: "2020-01-01T00:00:00Z".into(),
                    ..base.clone()
                },
            ),
            (
                "expires_at",
                CertMeta {
                    expires_at: "2099-01-01T00:00:00Z".into(),
                    ..base.clone()
                },
            ),
            (
                "serial",
                CertMeta {
                    serial: "DEADBEEF".into(),
                    ..base.clone()
                },
            ),
        ] {
            assert_ne!(
                digest_of(1, "example.com", b"CERT", b"KEY", &mutated),
                baseline,
                "editing {what} left the digest unchanged, so a reader would \
                 believe whatever it says"
            );
        }
    }
}
