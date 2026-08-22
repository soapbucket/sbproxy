//! RFC 9421 HTTP Message Signatures.
//!
//! Implements the verification path for the most common subset of
//! [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html): the request
//! verification flow with the HMAC-SHA256, Ed25519, and
//! ECDSA-P256-SHA256 algorithms over the standard derived components
//! (`@method`, `@target-uri`, `@authority`, `@scheme`, `@path`,
//! `@query`) and arbitrary HTTP header references. Signing the response
//! and the remaining registry algorithms (RSA-PSS-SHA512, RSA-v1_5-SHA256,
//! ECDSA-P384-SHA384) are explicit non-goals for this implementation; the
//! verification API is shaped so they can be added without breaking
//! callers.
//!
//! # Wire format recap
//!
//! ```text
//! Signature-Input: sig1=("@method" "@target-uri" "host" "content-digest");\
//!     created=1700000000;keyid="proxy-key-1";alg="ed25519"
//! Signature: sig1=:base64-encoded-signature-bytes:
//! ```
//!
//! The signer computes the canonical signature base by concatenating
//! one line per covered component (`"<name>": <canonical-value>`) and
//! a final `"@signature-params": (...);<params>` line. The verifier
//! reconstructs the base from the live request, then runs the
//! configured crypto over `(base_bytes, raw_signature_bytes)`.
//!
//! # What is covered
//!
//! - HMAC-SHA256 verification with shared secrets.
//! - Ed25519 verification with raw 32-byte public keys.
//! - ECDSA-P256-SHA256 verification with uncompressed SEC1 public
//!   points (65 bytes, `0x04 || X || Y`).
//! - Derived components: `@method`, `@target-uri`, `@authority`,
//!   `@scheme`, `@path`, `@query`.
//! - Arbitrary HTTP header references (case-insensitive name match;
//!   multi-value headers joined with `, ` per RFC 9421 §2.1).
//! - `created` and `expires` parameter enforcement when present. The
//!   `created` window is symmetric: a signature more than
//!   `clock_skew_seconds` old is refused as stale, which is the only
//!   replay bound a Web Bot Auth signature without a `nonce` has.
//! - Body coverage: a signature that covers `content-digest` is only
//!   accepted when the `Content-Digest` header the signature attests to
//!   also matches the bytes of the body handed to the verifier. See
//!   "Body coverage" below.
//!
//! # `@target-uri` and `@request-target`
//!
//! Both derivations were wrong until they were fixed, in opposite
//! directions: `@target-uri` emitted the origin-form request target
//! where RFC 9421 §2.2.2 defines the full absolute URI, and
//! `@request-target` emitted `METHOD /path`, which is draft-cavage's
//! shape rather than §2.2.5's bare request target. Nothing conformant
//! could interoperate with either.
//!
//! Verification accepts the old derivation as a fallback for a
//! deprecation window: a signature covering one of the two that fails
//! against the conformant base is retried against the legacy one, with
//! the same key and after the same freshness check. A success there
//! counts `sbproxy_signature_legacy_derivation_total{component}` and
//! logs the deprecation once per process, naming the verifier's key id;
//! the counter is what tells an operator whether the window can close.
//! Signing always produces the conformant base.
//!
//! One more candidate exists for a request line in origin form, which
//! carries no scheme: an `http::Request` has no connection behind it,
//! so this module cannot tell a TLS listener from a plaintext one, and
//! a signature covering `@target-uri` or `@scheme` is tried against
//! both schemes rather than guessed at. The caller that does know
//! stamps the scheme onto the URI before handing the request over
//! (`build_signature_verification_request` in `sbproxy-core` does), and
//! the second candidate then never runs.
//!
//! # Body coverage
//!
//! `content-digest` is an ordinary HTTP header reference as far as the
//! signature base is concerned, so the cryptography binds the *header
//! value* and nothing else. On its own that proves only that the signer
//! wrote some digest down; anyone able to replace the body afterwards
//! leaves the signature verifying over a message it no longer describes.
//! RFC 9421 §2.1 is explicit that a verifier is responsible for checking
//! the integrity of any content-related field it accepts as covered.
//!
//! [`MessageSignatureVerifier::verify_request`] therefore recomputes the
//! digest over `req.body()` whenever the matched signature covers
//! `content-digest`, and fails closed when it does not match. A caller
//! that hands the verifier an empty body for a body-bearing request will
//! see that failure, which is the intended direction: a signature we
//! cannot check must not pass.
//!
//! One caller genuinely cannot supply the body at verification time. The
//! Web Bot Auth path in `sbproxy-modules` verifies headers during the
//! auth phase and completes the body binding later, in the request body
//! filter, against the complete pre-transform body. That caller uses
//! [`MessageSignatureVerifier::verify_request_deferring_body_binding`]
//! and owns finishing the check; nothing else should.

use std::collections::HashMap;

use anyhow::Context as _;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use http::{HeaderMap, Method, Uri};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// --- Configuration ---

/// Verification algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// HMAC-SHA256 with a shared secret.
    HmacSha256,
    /// Ed25519 with a raw 32-byte public key.
    Ed25519,
    /// ECDSA on NIST P-256 with SHA-256, the `ecdsa-p256-sha256`
    /// entry in the RFC 9421 §6.2.2 algorithm registry.
    ///
    /// The public key is the uncompressed SEC1 point: 65 bytes,
    /// `0x04 || X || Y`. The signature is the fixed-width `r || s`
    /// concatenation the registry mandates (64 bytes), not the ASN.1
    /// DER form some tooling emits by default.
    EcdsaP256Sha256,
}

impl SignatureAlgorithm {
    /// Match an algorithm against the wire-format `alg` parameter
    /// from the `Signature-Input` header (RFC 9421 §6.2.2).
    pub fn matches_wire(&self, value: &str) -> bool {
        matches!(
            (*self, value),
            (SignatureAlgorithm::HmacSha256, "hmac-sha256")
                | (SignatureAlgorithm::Ed25519, "ed25519")
                | (SignatureAlgorithm::EcdsaP256Sha256, "ecdsa-p256-sha256")
        )
    }

    /// Whether this algorithm setting pins verification to a single
    /// concrete algorithm.
    ///
    /// Every variant today is concrete, so this always returns
    /// `true`. The function exists so that the alg-required check in
    /// [`MessageSignatureVerifier::verify_request`] remains correct
    /// if a future variant ever represents "any supported algorithm".
    pub fn is_pinned(&self) -> bool {
        match self {
            SignatureAlgorithm::HmacSha256
            | SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::EcdsaP256Sha256 => true,
        }
    }
}

/// Configuration for RFC 9421 message signature verification.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageSignatureConfig {
    /// Required signature algorithm.
    pub algorithm: SignatureAlgorithm,
    /// `keyid` value the signer is expected to advertise.
    pub key_id: String,
    /// Verification key material. Format depends on algorithm:
    /// - `hmac_sha256`: raw bytes of the shared secret (any UTF-8
    ///   string works), or hex/base64 if your keying flow encodes
    ///   them.
    /// - `ed25519`: hex- or base64-encoded raw 32-byte public key.
    /// - `ecdsa_p256_sha256`: hex- or base64-encoded uncompressed
    ///   SEC1 public point, 65 bytes beginning with `0x04`.
    ///
    /// The value may also be a secret reference rather than the
    /// material itself: `env:NAME`, `file:PATH`, `${VAR}`, or a
    /// provider URI such as `vault://prod/signing-key`. References
    /// resolve through the process secret resolver before any
    /// decoding happens, so the resolved value is decoded exactly as
    /// the same value inlined here would be. A provider URI that no
    /// installed backend can resolve is refused rather than becoming
    /// the key (WOR-2301).
    pub key: String,
    /// Optional list of components every accepted signature must
    /// cover. Verification rejects requests whose `Signature-Input`
    /// covers a strict subset.
    #[serde(default)]
    pub required_components: Vec<String>,
    /// Clock skew tolerance in seconds, applied symmetrically to
    /// `created`: a signature may be at most this far in the future and
    /// at most this far in the past. `expires`, when the signer sends
    /// one, may shorten that window but never extend it. Defaults to
    /// 30s.
    ///
    /// This window is the replay bound. A signature whose `created` is
    /// outside it is refused before any crypto runs.
    #[serde(default = "default_skew_seconds")]
    pub clock_skew_seconds: u64,
}

fn default_skew_seconds() -> u64 {
    30
}

// --- Verifier ---

/// Top-level verifier that holds the configured algorithm + key
/// material. Call [`MessageSignatureVerifier::verify_request`] per
/// inbound request.
pub struct MessageSignatureVerifier {
    config: MessageSignatureConfig,
    /// Decoded shared secret bytes (HMAC), raw public key bytes
    /// (Ed25519), or the uncompressed SEC1 point (ECDSA P-256).
    /// Decoded once at construction so the verify path never
    /// re-parses the configured key string.
    key_bytes: Vec<u8>,
}

/// Whether the verifier is responsible for the body half of a signature
/// that covers `content-digest`.
///
/// See the module-level "Body coverage" section for why this is a choice
/// at all: the cryptography binds only the `Content-Digest` header value,
/// so something has to recompute the digest over the actual bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyBinding {
    /// The request handed to the verifier carries the complete body.
    /// A covered `content-digest` is checked against it and a mismatch
    /// fails the signature.
    Enforce,
    /// The body is not available yet and the caller completes the
    /// binding itself once it is. Only the Web Bot Auth path, which
    /// verifies headers in the auth phase and finishes the proof in the
    /// request body filter, is allowed to ask for this.
    Defer,
}

/// Verification verdict for a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyVerdict {
    /// Signature verified successfully against `signature_label`.
    Ok {
        /// The label (e.g. `"sig1"`) of the matched signature within
        /// the dictionary form of `Signature-Input`.
        signature_label: String,
    },
    /// Verification failed for the indicated reason. The reason is
    /// safe to log but should not be returned to the client verbatim
    /// since some forms (algorithm mismatch, key mismatch) leak
    /// information to active probes.
    Failed {
        /// Human-readable failure reason, suitable for logs.
        reason: String,
    },
}

impl MessageSignatureVerifier {
    /// Build a verifier, resolving then validating and decoding the key
    /// material.
    ///
    /// Fails when `config.key` is a secret reference nothing installed can
    /// resolve, so an unresolvable reference rejects every request for the
    /// origin instead of becoming the key itself (WOR-2301).
    pub fn new(config: MessageSignatureConfig) -> anyhow::Result<Self> {
        let key_bytes = match config.algorithm {
            SignatureAlgorithm::HmacSha256 => {
                // HMAC keys can be any byte sequence. Accept the
                // configured value as-is; most operators set a
                // base64 or hex string.
                decode_secret(&config.key)?
            }
            SignatureAlgorithm::Ed25519 => {
                let bytes = decode_public_key(&config.key)?;
                if bytes.len() != 32 {
                    anyhow::bail!("ed25519 public key must be 32 bytes, got {}", bytes.len());
                }
                bytes
            }
            SignatureAlgorithm::EcdsaP256Sha256 => {
                // Same decode path as Ed25519 (hex, then base64, then
                // base64url), so an operator moves between the two
                // algorithms by changing the key and nothing else.
                //
                // The shape check is stricter than Ed25519's because
                // P-256 keys travel in three encodings. Only the
                // uncompressed SEC1 point is accepted: a compressed
                // point (33 bytes, `0x02`/`0x03`) and a SPKI/DER
                // wrapper are both common exports and both would
                // otherwise reach the verify path as an opaque byte
                // string that fails every request with a generic
                // crypto error. Naming them here turns a silent
                // outage into a startup message an operator can act
                // on.
                let bytes = decode_public_key(&config.key)?;
                match bytes.first() {
                    Some(0x04) if bytes.len() == 65 => bytes,
                    Some(0x02 | 0x03) if bytes.len() == 33 => anyhow::bail!(
                        "ecdsa-p256-sha256 public key is a compressed SEC1 point; supply the \
                         uncompressed form (65 bytes beginning with 0x04)"
                    ),
                    Some(0x30) => anyhow::bail!(
                        "ecdsa-p256-sha256 public key looks like a DER/SPKI structure; supply the \
                         raw uncompressed SEC1 point (65 bytes beginning with 0x04)"
                    ),
                    _ => anyhow::bail!(
                        "ecdsa-p256-sha256 public key must be an uncompressed SEC1 point of 65 \
                         bytes beginning with 0x04, got {} bytes",
                        bytes.len()
                    ),
                }
            }
        };
        Ok(Self { config, key_bytes })
    }

    /// Verify a signature against an inbound request.
    ///
    /// Looks up the signature labelled by the configured `key_id`
    /// (RFC 9421 dictionaries can carry several signatures), parses
    /// the `Signature-Input` parameters, reconstructs the canonical
    /// signature base from the live request, and runs the algorithm
    /// over `(base, raw_signature)`.
    ///
    /// `req` must carry the complete request body. A signature that
    /// covers `content-digest` is additionally checked against those
    /// bytes, so passing an empty body for a body-bearing request
    /// fails the signature rather than passing it. See the
    /// module-level "Body coverage" section.
    pub fn verify_request(&self, req: &http::Request<bytes::Bytes>) -> VerifyVerdict {
        self.verify_with_body_binding(req, BodyBinding::Enforce)
    }

    /// Verify a signature without the body half of `content-digest`
    /// coverage, leaving that check to the caller.
    ///
    /// Only for a caller that verifies headers before the body has
    /// arrived and completes the binding itself afterwards, which in
    /// this workspace means the Web Bot Auth provider: it verifies in
    /// the auth phase and re-checks `Content-Digest` in the request
    /// body filter against the complete pre-transform body, downgrading
    /// or rejecting there. Anything else should call
    /// [`Self::verify_request`], which is safe by default.
    pub fn verify_request_deferring_body_binding(
        &self,
        req: &http::Request<bytes::Bytes>,
    ) -> VerifyVerdict {
        self.verify_with_body_binding(req, BodyBinding::Defer)
    }

    fn verify_with_body_binding(
        &self,
        req: &http::Request<bytes::Bytes>,
        body_binding: BodyBinding,
    ) -> VerifyVerdict {
        let sig_input = match header_str(req.headers(), "signature-input") {
            Some(s) => s,
            None => {
                return VerifyVerdict::Failed {
                    reason: "missing Signature-Input header".to_string(),
                }
            }
        };
        let sig_header = match header_str(req.headers(), "signature") {
            Some(s) => s,
            None => {
                return VerifyVerdict::Failed {
                    reason: "missing Signature header".to_string(),
                }
            }
        };

        let inputs = match parse_signature_input(sig_input) {
            Ok(i) => i,
            Err(e) => {
                return VerifyVerdict::Failed {
                    reason: format!("invalid Signature-Input: {e}"),
                }
            }
        };
        let signatures = match parse_signature_dict(sig_header) {
            Ok(s) => s,
            Err(e) => {
                return VerifyVerdict::Failed {
                    reason: format!("invalid Signature: {e}"),
                }
            }
        };

        // Pick the signature labelled with our configured key_id. RFC
        // 9421 lets a request carry multiple signatures so each hop
        // can verify the one matched to its own key.
        let (label, input) = match inputs
            .iter()
            .find(|(_, v)| v.params.keyid.as_deref() == Some(self.config.key_id.as_str()))
        {
            Some((label, v)) => (label.clone(), v),
            None => {
                return VerifyVerdict::Failed {
                    reason: format!("no signature for keyid {}", self.config.key_id),
                }
            }
        };
        let raw_sig = match signatures.get(&label) {
            Some(s) => s,
            None => {
                return VerifyVerdict::Failed {
                    reason: format!("no Signature entry for label {}", label),
                }
            }
        };

        // Algorithm enforcement (OPENSOURCE.md H8).
        //
        // The verifier always pins a specific algorithm via its config
        // and may also pin a set of required components. In both cases
        // the `alg` parameter on the wire is mandatory: an attacker
        // who can omit `alg` would otherwise bypass the algorithm
        // pin and slip a signature past whichever crypto path the
        // verifier happens to default to. Reject signatures missing
        // `alg` outright when policy is in force, then check that the
        // declared algorithm matches the configured one.
        let policy_pins_algorithm =
            !self.config.required_components.is_empty() || self.config.algorithm.is_pinned();
        match input.params.alg.as_deref() {
            None => {
                if policy_pins_algorithm {
                    return VerifyVerdict::Failed {
                        reason:
                            "Signature-Input missing required `alg` parameter; algorithm pinning requires explicit alg"
                                .to_string(),
                    };
                }
            }
            Some(alg) => {
                if !self.config.algorithm.matches_wire(alg) {
                    return VerifyVerdict::Failed {
                        reason: format!("alg mismatch: got {}", alg),
                    };
                }
            }
        }

        // Required-component enforcement.
        for required in &self.config.required_components {
            if !input
                .components
                .iter()
                .any(|c| c.eq_ignore_ascii_case(required))
            {
                return VerifyVerdict::Failed {
                    reason: format!("missing required component: {}", required),
                };
            }
        }

        // Time-bound enforcement.
        if let Some(reason) = check_freshness(input, self.config.clock_skew_seconds) {
            return VerifyVerdict::Failed { reason };
        }

        // Reconstruct the signature base.
        let base = match build_signature_base_in(req, input, BaseDialect::Rfc9421) {
            Ok(b) => b,
            Err(e) => {
                return VerifyVerdict::Failed {
                    reason: format!("signature base failed: {e}"),
                }
            }
        };

        let mut ok = match self.verify_base(&base, raw_sig) {
            Ok(verified) => verified,
            Err(verdict) => return verdict,
        };

        // Two fallback bases, both tried only after the conformant one
        // has already failed, and only for a signature whose covered
        // set makes them different from it. Neither weakens anything:
        // each candidate is verified with the same key, over the same
        // covered components, after the same freshness check.
        //
        // 1. The other scheme, for an origin-form request line. The
        //    scheme is not on the wire there and this layer cannot see
        //    the listener's TLS state, so a signature over
        //    `https://host/path` and one over `http://host/path` are
        //    both plausibly what the client signed. A caller that does
        //    know stamps the scheme onto the URI it hands over, and
        //    this candidate then never runs.
        // 2. The pre-conformance derivations of `@target-uri` and
        //    `@request-target`, which a signer built against this
        //    proxy still produces. That one is a deprecation window and
        //    says so in the log.
        if !ok {
            let fallbacks = [
                (req.uri().scheme_str().is_none() && covers_scheme_sensitive_component(input))
                    .then_some(BaseDialect::Rfc9421OtherScheme),
                covers_retargeted_component(input).then_some(BaseDialect::Legacy),
            ];
            for dialect in fallbacks.into_iter().flatten() {
                let Ok(candidate) = build_signature_base_in(req, input, dialect) else {
                    continue;
                };
                ok = match self.verify_base(&candidate, raw_sig) {
                    Ok(verified) => verified,
                    Err(verdict) => return verdict,
                };
                if ok {
                    if dialect == BaseDialect::Legacy {
                        record_legacy_target_derivation(input, &self.config.key_id);
                    }
                    break;
                }
            }
        }

        if !ok {
            return VerifyVerdict::Failed {
                reason: "cryptographic verification failed".to_string(),
            };
        }

        // Body coverage. The crypto above bound the `Content-Digest`
        // header value; nothing so far has bound it to any bytes. Do
        // that now, unless the caller has taken the job on itself.
        if body_binding == BodyBinding::Enforce {
            if let Some(reason) = check_covered_body_digest(req, input) {
                return VerifyVerdict::Failed { reason };
            }
        }

        VerifyVerdict::Ok {
            signature_label: label,
        }
    }

    /// Run the configured algorithm over one candidate signature base.
    ///
    /// `Ok(true)` verified, `Ok(false)` did not. `Err(verdict)` is for a
    /// key or a signature that is malformed whatever the base is, so a
    /// caller trying a second base must not retry on it.
    fn verify_base(&self, base: &str, raw_sig: &[u8]) -> Result<bool, VerifyVerdict> {
        match self.config.algorithm {
            SignatureAlgorithm::HmacSha256 => {
                let mut mac = match HmacSha256::new_from_slice(&self.key_bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        return Err(VerifyVerdict::Failed {
                            reason: "invalid hmac key".to_string(),
                        })
                    }
                };
                mac.update(base.as_bytes());
                Ok(mac.verify_slice(raw_sig).is_ok())
            }
            SignatureAlgorithm::Ed25519 => {
                let key_arr: [u8; 32] = self
                    .key_bytes
                    .as_slice()
                    .try_into()
                    .expect("ed25519 key length validated at construction");
                let key = match VerifyingKey::from_bytes(&key_arr) {
                    Ok(k) => k,
                    Err(_) => {
                        return Err(VerifyVerdict::Failed {
                            reason: "invalid ed25519 public key".to_string(),
                        })
                    }
                };
                let sig_arr: [u8; 64] = match raw_sig.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return Err(VerifyVerdict::Failed {
                            reason: format!(
                                "ed25519 signature must be 64 bytes, got {}",
                                raw_sig.len()
                            ),
                        })
                    }
                };
                let signature = Signature::from_bytes(&sig_arr);
                Ok(key.verify(base.as_bytes(), &signature).is_ok())
            }
            SignatureAlgorithm::EcdsaP256Sha256 => {
                // RFC 9421 §3.3.5 pins the `ecdsa-p256-sha256`
                // signature to the fixed-width `r || s` form, so a
                // 64-byte length check is a real conformance check
                // and not just defence against a short read. DER-
                // encoded signatures land here as the wrong length
                // and are named as such, because a signer emitting
                // DER is the likeliest way this fails in the field.
                if raw_sig.len() != 64 {
                    return Err(VerifyVerdict::Failed {
                        reason: format!(
                            "ecdsa-p256-sha256 signature must be 64 bytes of r||s, got {}",
                            raw_sig.len()
                        ),
                    });
                }
                Ok(verify_ecdsa_p256_sha256(
                    &self.key_bytes,
                    base.as_bytes(),
                    raw_sig,
                ))
            }
        }
    }
}

/// Whether this signature covers a component whose derivation changed
/// when `@target-uri` and `@request-target` were made RFC 9421
/// conformant. Only those two signatures are worth a legacy attempt.
fn covers_retargeted_component(input: &SignatureInputEntry) -> bool {
    covers_any(input, &["@target-uri", "@request-target"])
}

/// Whether this signature covers a component whose value depends on the
/// request scheme. Only those are worth an other-scheme attempt.
fn covers_scheme_sensitive_component(input: &SignatureInputEntry) -> bool {
    covers_any(input, &["@target-uri", "@scheme"])
}

fn covers_any(input: &SignatureInputEntry, names: &[&str]) -> bool {
    input.components.iter().any(|c| {
        let component = c.trim_matches('"');
        names
            .iter()
            .any(|name| component.eq_ignore_ascii_case(name))
    })
}

/// Record that a signer is still on the pre-RFC-9421 derivation.
///
/// Counted every time, logged once. The count is the number that lets
/// the deprecation window close: a line logged once per process says
/// some signer somewhere has not moved and nothing about whether that
/// is still true this week, and per-request it would be a log flood on
/// the hot path of every request from a signer that has not moved yet.
/// The line names the first `keyid` seen so the operator has somewhere
/// to start; `sbproxy_signature_legacy_derivation_total{component}` has
/// the rest.
fn record_legacy_target_derivation(input: &SignatureInputEntry, key_id: &str) {
    // Closed set, and the label has to be `&'static str`: these are the
    // only two components whose derivation moved.
    for component in ["@target-uri", "@request-target"] {
        if covers_any(input, &[component]) {
            sbproxy_observe::metrics::record_signature_legacy_derivation(component);
        }
    }
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            // The verifier's own configured key id, not the one the
            // wire claimed, so this names an operator's key rather than
            // echoing a caller-supplied string into the log.
            keyid = %key_id,
            "message signature verified only against the pre-RFC-9421 derivation of \
             `@target-uri` / `@request-target`; the signer should move to a conformant \
             RFC 9421 library. Acceptance of the old derivation is a deprecation window \
             and will be removed. Logged once per process; every occurrence is counted \
             on sbproxy_signature_legacy_derivation_total"
        );
    });
}

/// Verify that a covered `content-digest` component describes the body
/// actually present on `req`.
///
/// Returns `None` when the signature does not cover `content-digest` (so
/// there is nothing to bind) or when the header matches the body, and
/// `Some(reason)` on any failure. Failing closed is the whole point: a
/// signature that claims body coverage we cannot confirm must not pass.
///
/// The `Content-Digest` header itself is guaranteed present by the time
/// this runs, because [`build_signature_base`] refuses to reconstruct a
/// base for a covered header the request does not carry. The `None` arm
/// below therefore only fires if that invariant is ever broken, and it
/// fires closed.
fn check_covered_body_digest(
    req: &http::Request<bytes::Bytes>,
    input: &SignatureInputEntry,
) -> Option<String> {
    let covers_digest = input
        .components
        .iter()
        .any(|c| c.trim_matches('"').eq_ignore_ascii_case("content-digest"));
    if !covers_digest {
        return None;
    }
    let Some(header_value) = header_str(req.headers(), "content-digest") else {
        return Some("signature covers content-digest but the header is absent".to_string());
    };
    if crate::digest::verify_content_digest(header_value, req.body()) {
        return None;
    }
    // Deliberately carries no digest values and no body length. The
    // caller logs this reason on every rejected request, and both would
    // hand an active prober a size oracle for a body it cannot read.
    Some("content-digest does not match the request body".to_string())
}

/// Verify an `ecdsa-p256-sha256` signature (RFC 9421 §3.3.5).
///
/// `public_key` is the uncompressed SEC1 point validated at verifier
/// construction; `signature` is the fixed-width 64-byte `r || s` form.
///
/// Backed by `ring`, already the workspace's crypto provider. ECDSA
/// verification touches no secret, so unlike the HMAC path there is
/// nothing here for a timing side channel to leak; `ring` returns a
/// plain `Result` and the boolean conversion matches how the Ed25519
/// arm above treats `ed25519_dalek`'s.
fn verify_ecdsa_p256_sha256(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(message, signature)
        .is_ok()
}

// --- Header / signature-input parsing ---

/// Parsed parameters on a Signature-Input entry.
#[derive(Debug, Default, Clone)]
pub struct SignatureInputParams {
    /// `created` parameter (Unix epoch seconds).
    pub created: Option<i64>,
    /// `expires` parameter (Unix epoch seconds).
    pub expires: Option<i64>,
    /// `keyid` parameter, the signer's identifier.
    pub keyid: Option<String>,
    /// `alg` parameter, the wire-format algorithm name.
    pub alg: Option<String>,
    /// `nonce` parameter, an opaque per-signature nonce.
    pub nonce: Option<String>,
    /// `tag` parameter, application-specific identifier.
    pub tag: Option<String>,
}

/// Parsed Signature-Input entry: covered components + parameters.
#[derive(Debug, Clone)]
pub struct SignatureInputEntry {
    /// Covered component names (e.g. `"@method"`, `"host"`), in the
    /// order they were declared.
    pub components: Vec<String>,
    /// Parsed parameter dictionary.
    pub params: SignatureInputParams,
    /// Original parameter section (everything after the `)` in the
    /// inner-list form). Reused verbatim when reconstructing the
    /// `"@signature-params"` line for the canonical base.
    pub raw_params: String,
    /// Original component-list section (the parenthesised inner
    /// list). Reused verbatim in `"@signature-params"`.
    pub raw_inner_list: String,
}

/// Parse the dictionary form of `Signature-Input`.
///
/// Whether any signature in the request's `Signature-Input` header
/// covers the `content-digest` component. WOR-805 F1.6.1: callers
/// that verify a Web Bot Auth signature need to know up front whether
/// the body has to be buffered for a follow-on
/// [`crate::digest::verify_content_digest`] check against the
/// `Content-Digest` header value the signature attests to. The check
/// is deliberately case-insensitive so `"Content-Digest"` and
/// `"content-digest"` both trip it.
///
/// Returns `false` when the header is absent, unparseable, or carries
/// only signatures whose covered component list does not include
/// `content-digest`. Returns `true` otherwise.
pub fn signature_input_covers_content_digest(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get("signature-input").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(entries) = parse_signature_input(raw) else {
        return false;
    };
    for (_label, entry) in entries {
        if entry
            .components
            .iter()
            .any(|c| c.eq_ignore_ascii_case("content-digest"))
        {
            return true;
        }
    }
    false
}

/// Example input: `sig1=("@method" "@authority");keyid="k1";alg="ed25519"`
///
/// Returns a vector of `(label, entry)` preserving order.
pub fn parse_signature_input(value: &str) -> anyhow::Result<Vec<(String, SignatureInputEntry)>> {
    let mut out = Vec::new();
    for raw_entry in split_top_level_commas(value) {
        let raw_entry = raw_entry.trim();
        if raw_entry.is_empty() {
            continue;
        }
        let (label, rest) = raw_entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Signature-Input entry missing label: {raw_entry}"))?;
        let label = label.trim().to_string();
        let rest = rest.trim();
        // The rest must start with `(`.
        let open = rest
            .find('(')
            .ok_or_else(|| anyhow::anyhow!("Signature-Input missing inner list"))?;
        let close = rest
            .find(')')
            .ok_or_else(|| anyhow::anyhow!("Signature-Input missing inner list close"))?;
        if close < open {
            anyhow::bail!("Signature-Input mis-ordered parens");
        }
        let inner = &rest[open + 1..close];
        let after = rest[close + 1..].trim();
        let raw_params = after.trim_start_matches(';').to_string();

        let components = parse_inner_list(inner)?;
        let params = parse_params(&raw_params)?;
        out.push((
            label,
            SignatureInputEntry {
                components,
                params,
                raw_params,
                raw_inner_list: inner.to_string(),
            },
        ));
    }
    Ok(out)
}

/// Parse the dictionary form of `Signature` and return raw bytes per
/// label.
pub fn parse_signature_dict(value: &str) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let mut out = HashMap::new();
    for raw_entry in split_top_level_commas(value) {
        let raw_entry = raw_entry.trim();
        if raw_entry.is_empty() {
            continue;
        }
        let (label, rest) = raw_entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Signature entry missing label: {raw_entry}"))?;
        let label = label.trim().to_string();
        let rest = rest.trim();
        // Byte sequences are wrapped in colons per RFC 8941.
        let inner = rest
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(|| anyhow::anyhow!("Signature value not a byte sequence"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(inner.trim().as_bytes())
            .map_err(|e| anyhow::anyhow!("Signature base64 decode failed: {e}"))?;
        out.insert(label, bytes);
    }
    Ok(out)
}

fn parse_inner_list(inner: &str) -> anyhow::Result<Vec<String>> {
    let mut components = Vec::new();
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(components);
    }
    // Each component is wrapped in double quotes and separated by
    // whitespace. We don't yet support component parameters
    // (e.g. `"x-foo";bs`).
    let mut chars = inner.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c != '"' {
            anyhow::bail!("expected `\"` in component list, found `{c}`");
        }
        chars.next();
        let mut s = String::new();
        loop {
            match chars.next() {
                Some('"') => break,
                Some(ch) => s.push(ch),
                None => anyhow::bail!("unterminated component string"),
            }
        }
        components.push(s);
    }
    Ok(components)
}

fn parse_params(raw: &str) -> anyhow::Result<SignatureInputParams> {
    let mut p = SignatureInputParams::default();
    for piece in raw.split(';') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let (k, v) = piece
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("malformed parameter: {piece}"))?;
        let k = k.trim();
        let v = v.trim();
        match k {
            "created" => p.created = Some(parse_int_param(v)?),
            "expires" => p.expires = Some(parse_int_param(v)?),
            "keyid" => p.keyid = Some(strip_quotes(v).to_string()),
            "alg" => p.alg = Some(strip_quotes(v).to_string()),
            "nonce" => p.nonce = Some(strip_quotes(v).to_string()),
            "tag" => p.tag = Some(strip_quotes(v).to_string()),
            _ => {
                // Unknown parameters are tolerated per RFC 9421 §2.3:
                // verifiers MUST ignore parameters they don't
                // understand.
            }
        }
    }
    Ok(p)
}

fn parse_int_param(value: &str) -> anyhow::Result<i64> {
    value
        .parse::<i64>()
        .map_err(|e| anyhow::anyhow!("malformed integer parameter: {e}"))
}

fn strip_quotes(value: &str) -> &str {
    value.trim().trim_matches('"')
}

/// Split a dictionary string on top-level commas only, ignoring
/// commas inside parentheses or quoted strings.
fn split_top_level_commas(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut in_quote = false;
    let mut buf = String::new();
    for c in input.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                buf.push(c);
            }
            '(' if !in_quote => {
                depth += 1;
                buf.push(c);
            }
            ')' if !in_quote => {
                depth -= 1;
                buf.push(c);
            }
            ',' if depth == 0 && !in_quote => {
                out.push(std::mem::take(&mut buf));
            }
            _ => buf.push(c),
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

// --- Signature base construction ---

/// Which derivation to use for the two request-target components.
///
/// Everything else in the base is identical between the two, so this
/// only reaches `@target-uri` and `@request-target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseDialect {
    /// RFC 9421 as written, with the scheme [`request_scheme`] resolves.
    Rfc9421,
    /// RFC 9421 with the opposite scheme. Tried on verification only,
    /// and only for an origin-form request line, whose scheme this layer
    /// genuinely cannot know. Never produced when signing.
    Rfc9421OtherScheme,
    /// What this proxy emitted before the conformance fix: `@target-uri`
    /// as the origin-form request target and `@request-target` as
    /// draft-cavage's `METHOD /path`. Accepted on inbound verification
    /// for a deprecation window and never produced when signing.
    Legacy,
}

/// Build the canonical signature base for an inbound request.
///
/// Mirrors RFC 9421 §2 byte-for-byte for the components we support,
/// including the absolute-URI form of `@target-uri` (§2.2.2) and the
/// bare request target of `@request-target` (§2.2.5). Unsupported
/// component types are surfaced as errors so the verifier can fail
/// closed rather than silently signing a different base than the signer
/// did.
pub fn build_signature_base(
    req: &http::Request<bytes::Bytes>,
    input: &SignatureInputEntry,
) -> anyhow::Result<String> {
    build_signature_base_in(req, input, BaseDialect::Rfc9421)
}

fn build_signature_base_in(
    req: &http::Request<bytes::Bytes>,
    input: &SignatureInputEntry,
    dialect: BaseDialect,
) -> anyhow::Result<String> {
    let mut out = String::new();
    for component in &input.components {
        let value = canonical_component_value(req, component, dialect)?;
        out.push('"');
        out.push_str(&component.to_ascii_lowercase());
        out.push('"');
        out.push_str(": ");
        out.push_str(&value);
        out.push('\n');
    }
    out.push_str("\"@signature-params\": (");
    out.push_str(&input.raw_inner_list);
    out.push(')');
    if !input.raw_params.is_empty() {
        out.push(';');
        out.push_str(&input.raw_params);
    }
    Ok(out)
}

/// Resolve a single covered component into its canonical string
/// representation per RFC 9421.
fn canonical_component_value(
    req: &http::Request<bytes::Bytes>,
    name: &str,
    dialect: BaseDialect,
) -> anyhow::Result<String> {
    if let Some(rest) = name.strip_prefix('@') {
        return derived_component(req, rest, dialect);
    }
    // Non-derived: HTTP header reference.
    let header_name = name.trim_matches('"').to_ascii_lowercase();
    let mut values: Vec<&str> = Vec::new();
    for (h, v) in req.headers() {
        if h.as_str().eq_ignore_ascii_case(&header_name) {
            if let Ok(s) = v.to_str() {
                values.push(s.trim());
            }
        }
    }
    if values.is_empty() {
        anyhow::bail!("missing header for component: {}", name);
    }
    Ok(values.join(", "))
}

/// Scheme for the `@scheme` and `@target-uri` derivations.
///
/// An origin-form request line carries no scheme, so it has to come from
/// somewhere else. What this function CANNOT see is the listener's TLS
/// state: an `http::Request` has no connection behind it. The caller
/// that does own that state stamps the scheme onto the URI before
/// handing the request over (`build_signature_verification_request` in
/// `sbproxy-core`), which is why `uri.scheme_str()` is the first branch
/// and the rest is a fallback for a caller that did not.
fn request_scheme(req: &http::Request<bytes::Bytes>) -> &str {
    if let Some(scheme) = req.uri().scheme_str() {
        return scheme;
    }
    if req.uri().host().is_some() {
        "https"
    } else {
        "http"
    }
}

/// Authority for the `@authority` and `@target-uri` derivations: the URI
/// when the request line is absolute-form, the `Host` header otherwise.
fn request_authority(req: &http::Request<bytes::Bytes>) -> Option<&str> {
    req.uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| header_str(req.headers(), "host"))
}

/// The scheme `dialect` asks for: the resolved one, or its opposite for
/// the other-scheme verification attempt.
fn dialect_scheme(req: &http::Request<bytes::Bytes>, dialect: BaseDialect) -> &str {
    let resolved = request_scheme(req);
    match dialect {
        BaseDialect::Rfc9421OtherScheme => {
            if resolved.eq_ignore_ascii_case("https") {
                "http"
            } else {
                "https"
            }
        }
        BaseDialect::Rfc9421 | BaseDialect::Legacy => resolved,
    }
}

fn derived_component(
    req: &http::Request<bytes::Bytes>,
    name: &str,
    dialect: BaseDialect,
) -> anyhow::Result<String> {
    let uri: &Uri = req.uri();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    Ok(match name {
        "method" => req.method().as_str().to_string(),
        // RFC 9421 §2.2.2: the full absolute target URI, assembled from
        // the scheme and authority when the request line is origin-form.
        // This used to emit `path_and_query`, which is `@request-target`
        // semantics, so no conformant peer could interoperate in either
        // direction.
        "target-uri" => match dialect {
            BaseDialect::Legacy => path_and_query.to_string(),
            BaseDialect::Rfc9421 | BaseDialect::Rfc9421OtherScheme => {
                match request_authority(req) {
                    Some(authority) => format!(
                        "{}://{}{}",
                        dialect_scheme(req, dialect),
                        authority,
                        path_and_query
                    ),
                    // No authority on the URI and no Host header, which
                    // is an HTTP/1.0 request line. There is no absolute
                    // URI to assemble, so emit the target alone: it is
                    // what the peer's own reconstruction has to fall
                    // back to too.
                    None => path_and_query.to_string(),
                }
            }
        },
        "authority" => request_authority(req).unwrap_or_default().to_string(),
        "scheme" => dialect_scheme(req, dialect).to_string(),
        "path" => uri.path().to_string(),
        "query" => match uri.query() {
            Some(q) if !q.is_empty() => format!("?{}", q),
            _ => "?".to_string(),
        },
        // RFC 9421 §2.2.5: the request target as it appears in the
        // request line, which for the origin-form requests a proxy sees
        // is the path and query alone. The legacy shape prefixed the
        // uppercased method, which is draft-cavage's `(request-target)`
        // and matches neither spec. The scheme is not part of either
        // shape, so the other-scheme attempt derives this component
        // identically to the conformant one.
        "request-target" => match dialect {
            BaseDialect::Legacy => format!("{} {}", req.method().as_str(), path_and_query),
            BaseDialect::Rfc9421 | BaseDialect::Rfc9421OtherScheme => path_and_query.to_string(),
        },
        other => anyhow::bail!("unsupported derived component: @{}", other),
    })
}

/// Enforce the `created` / `expires` window against the wall clock.
///
/// The window is symmetric around `created`, which is what
/// `clock_skew_seconds` has always been documented as: at most `skew`
/// seconds in the future and at most `skew` seconds in the past.
///
/// The past half used to be missing entirely, and the timestamp window
/// is the only replay defense a Web Bot Auth signature has: `nonce` is
/// optional in the profile, `required_components` can require a
/// component but never a parameter, and `bot_auth`'s nonce store is
/// never wired by any caller in this tree. A captured `Signature-Input`
/// / `Signature` pair with no `expires` was therefore an unexpiring
/// bearer token for whatever identity its `keyid` carried.
///
/// `expires` can only shorten the window. A signer that wants a longer
/// one is asking the verifying operator to widen
/// `clock_skew_seconds`, which is a decision that belongs on the
/// verifying side rather than in a parameter the signer picks.
fn check_freshness(input: &SignatureInputEntry, skew: u64) -> Option<String> {
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => return Some("system clock before epoch".to_string()),
    };
    let skew = i64::try_from(skew).unwrap_or(i64::MAX);
    if let Some(created) = input.params.created {
        if created > now.saturating_add(skew) {
            return Some(format!(
                "signature created in future: {} > {}",
                created, now
            ));
        }
        if created < now.saturating_sub(skew) {
            return Some(format!(
                "signature created timestamp is stale: created={created}, now={now}, window={skew}s"
            ));
        }
    }
    if let Some(expires) = input.params.expires {
        if expires.saturating_add(skew) < now {
            return Some(format!("signature expired: {} < {}", expires, now));
        }
    }
    None
}

// --- Helpers for key decoding ---

/// Resolve a configured `message_signatures.key` value into its material.
///
/// Delegates to the installed process secret resolver (WOR-2301), so
/// `env:NAME`, `file:PATH`, `${VAR}`, and every provider URI resolve the
/// same way they do everywhere else in the config. Without a resolver
/// installed (`sbproxy validate`, unit tests, a run whose config declares no
/// `proxy.secrets` backends), only `env:NAME`, `file:PATH`, `${VAR}`, and an
/// inline literal value resolve; a provider URI is refused rather than
/// becoming the key.
fn resolve_key_material(value: &str) -> anyhow::Result<String> {
    if let Some(resolver) = sbproxy_vault::process_resolver() {
        return resolver
            .resolve(value)
            // Deliberately does NOT echo the configured value. This context is
            // reached for an inline literal as well as a reference, and the
            // caller logs the error at warn on every request for the origin, so
            // echoing it would write the signing key itself into the log on a
            // misconfiguration. The resolver's own error already names the safe
            // part (the missing env var, the file, the backend); it owns knowing
            // what is a pointer and what is material.
            .context("message_signatures.key could not be resolved");
    }
    // A provider URI this site cannot resolve without an installed resolver
    // is an error, never key material.
    //
    // Without this, the reference *string* became the key: set
    // `message_signatures.key` to `vault://prod/signing-key` and the HMAC
    // shared secret was those 24 ASCII characters, identical for every
    // deployment that pasted the same example, while verification kept
    // reporting success for anyone who guessed it. WOR-2283 established this
    // rule for the other two sites that had it; this one predates it and now
    // delegates to the same resolver above instead of re-implementing a
    // subset of its parsing.
    if sbproxy_vault::looks_like_secret_reference_uri(value) {
        anyhow::bail!(
            "message_signatures.key references the secret '{value}' but no secret backend \
             is installed to resolve it; declare one under proxy.secrets.backends. Without one, \
             this field resolves only `env:NAME`, `file:PATH`, `${{VAR}}`, and inline literal \
             values."
        );
    }
    // No resolver installed. A stock resolver still resolves the
    // backend-free reference forms and hands an inline literal straight
    // back, so even this fallback stays on the shared parser rather than a
    // private copy of it (same shape as `sbproxy-modules`'
    // `aiproxy::resolve_runtime_credential`).
    sbproxy_vault::SecretResolver::new()
        .resolve(value)
        // Deliberately does NOT echo the configured value. This context is
        // reached for an inline literal as well as a reference, and the
        // caller logs the error at warn on every request for the origin, so
        // echoing it would write the signing key itself into the log on a
        // misconfiguration. The resolver's own error already names the safe
        // part (the missing env var, the file, the backend); it owns knowing
        // what is a pointer and what is material.
        .context("message_signatures.key could not be resolved")
}

/// Resolve, then decode, the configured HMAC shared secret.
///
/// Resolution runs first and decoding second: the configured value may be a
/// reference, and hex/base64 decoding a reference string decodes the wrong
/// thing. Applying the decode to the *resolved* material means a secret held
/// in a backend produces exactly the key bytes the identical value inlined in
/// `sb.yml` would produce. An inline literal resolves to itself, so its bytes
/// are unchanged from before WOR-2301.
fn decode_secret(value: &str) -> anyhow::Result<Vec<u8>> {
    let resolved = resolve_key_material(value)?;
    // Try hex first (most common machine-generated form), then
    // base64 (also common), then fall through to raw UTF-8 bytes.
    if let Ok(bytes) = hex::decode(resolved.as_str()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(resolved.as_str()) {
        return Ok(bytes);
    }
    Ok(resolved.into_bytes())
}

/// Resolve, then decode, the configured Ed25519 verification key.
///
/// Same resolve-before-decode ordering as [`decode_secret`], for the same
/// reason. An Ed25519 public key is not itself secret, but it reaches this
/// function from the same `message_signatures.key` field, so it accepts the
/// same reference forms.
fn decode_public_key(value: &str) -> anyhow::Result<Vec<u8>> {
    let resolved = resolve_key_material(value)?;
    if let Ok(bytes) = hex::decode(resolved.as_str()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(resolved.as_str()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(resolved.as_str()) {
        return Ok(bytes);
    }
    anyhow::bail!("public_key is neither hex nor base64")
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[allow(dead_code)] // kept for parity with builder API; future use.
fn dummy_method() -> Method {
    Method::GET
}

// --- Sign side (WOR-805 AC#3) ---

/// Sign a request per RFC 9421.
///
/// The verifier already lives above; the signer is the "we are the
/// signing agent" counterpart. Construct with an Ed25519 signing
/// key, then call [`Self::sign_request`] on the outbound request to
/// attach the `Signature-Input` and `Signature` headers Cloudflare,
/// AWS WAF, and other Web Bot Auth verifiers expect.
///
/// Today only Ed25519 is supported (HmacSha256 is asymmetric-by-
/// configuration for the verifier but symmetric-keyed shared-secret
/// signing is rarely what an outbound agent wants).
pub struct MessageSignatureSigner {
    signing_key: ed25519_dalek::SigningKey,
    key_id: String,
    /// Optional `tag` parameter the Web Bot Auth draft pins to
    /// `"web-bot-auth"`. None omits the parameter.
    tag: Option<String>,
}

/// One signed-request invocation's inputs. Pulled into a struct so
/// the `sign_request` signature stays one positional arg.
#[derive(Debug, Clone)]
pub struct SignRequestParams {
    /// Covered components in declaration order (e.g.
    /// `["@method", "@authority", "@path", "content-digest"]`).
    /// Verbatim into the signature base inner list.
    pub components: Vec<String>,
    /// Dictionary label (e.g. `"sig1"`). Identifies this signature
    /// in the `Signature-Input` and `Signature` headers.
    pub label: String,
    /// `created` parameter as unix-seconds. The verifier checks
    /// this against its `max_clock_skew_secs`; pass
    /// `SystemTime::now()` from the caller to avoid embedding a
    /// clock in this module.
    pub created_unix: u64,
    /// Optional `expires` parameter, unix-seconds. None omits the
    /// parameter so the signature is treated as never-expiring by
    /// the verifier (which falls back to its own skew window).
    pub expires_unix: Option<u64>,
    /// Optional `nonce` parameter for replay defence. None omits
    /// it; verifiers that require it will reject.
    pub nonce: Option<String>,
}

impl MessageSignatureSigner {
    /// Build a signer from a raw 32-byte Ed25519 secret key + the
    /// `kid` the directory publishes. `tag` is the optional Web
    /// Bot Auth tag (`"web-bot-auth"` for that protocol; None for
    /// generic RFC 9421 signing).
    pub fn new_ed25519(
        secret_key_bytes: &[u8; 32],
        key_id: impl Into<String>,
        tag: Option<String>,
    ) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(secret_key_bytes),
            key_id: key_id.into(),
            tag,
        }
    }

    /// Public-key bytes for the kid this signer holds. Surface so
    /// the publish side ([`crate::digest`] and the
    /// `bot_auth_publish` module on top) can build the directory
    /// JWK without re-deriving the key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The `kid` this signer advertises.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Sign `req` and attach `Signature-Input` + `Signature`
    /// headers per RFC 9421. Returns the canonical signature base
    /// the request was signed over so callers can audit-log it
    /// (without having to recompute).
    pub fn sign_request(
        &self,
        req: &mut http::Request<bytes::Bytes>,
        params: &SignRequestParams,
    ) -> anyhow::Result<String> {
        if params.components.is_empty() {
            anyhow::bail!("sign_request: components must not be empty");
        }
        if params.label.is_empty() {
            anyhow::bail!("sign_request: label must not be empty");
        }
        let inner_list = build_inner_list(&params.components);
        let raw_params = build_raw_params(
            &self.key_id,
            &self.tag,
            params.created_unix,
            params.expires_unix,
            params.nonce.as_deref(),
        );
        let entry = SignatureInputEntry {
            components: params.components.clone(),
            params: SignatureInputParams::default(),
            raw_params: raw_params.clone(),
            raw_inner_list: inner_list.clone(),
        };
        let base = build_signature_base(req, &entry)?;
        let signature = self.signing_key.sign(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let signature_input_value = format!(
            "{}=({}){}",
            params.label,
            inner_list,
            if raw_params.is_empty() {
                String::new()
            } else {
                format!(";{raw_params}")
            }
        );
        let signature_value = format!("{}=:{}:", params.label, sig_b64);

        req.headers_mut().insert(
            http::HeaderName::from_static("signature-input"),
            http::HeaderValue::from_str(&signature_input_value)?,
        );
        req.headers_mut().insert(
            http::HeaderName::from_static("signature"),
            http::HeaderValue::from_str(&signature_value)?,
        );
        Ok(base)
    }
}

/// Compose the parenthesised inner list of `Signature-Input`. The
/// build-side counterpart of the parser; the parser stores the
/// inner list verbatim so the verifier sees byte-identical bases
/// across implementations.
fn build_inner_list(components: &[String]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(components.len());
    for c in components {
        let trimmed = c.trim_matches('"');
        parts.push(format!("\"{trimmed}\""));
    }
    parts.join(" ")
}

/// Compose the parameter section that follows the inner list in
/// `Signature-Input`. `tag` is the Web Bot Auth draft's extension;
/// `created` is required when the verifier enforces freshness;
/// `expires` and `nonce` are optional.
fn build_raw_params(
    key_id: &str,
    tag: &Option<String>,
    created_unix: u64,
    expires_unix: Option<u64>,
    nonce: Option<&str>,
) -> String {
    let mut bits: Vec<String> = Vec::with_capacity(5);
    bits.push(format!("keyid=\"{}\"", key_id));
    bits.push("alg=\"ed25519\"".to_string());
    bits.push(format!("created={created_unix}"));
    if let Some(exp) = expires_unix {
        bits.push(format!("expires={exp}"));
    }
    if let Some(nonce) = nonce {
        bits.push(format!("nonce=\"{nonce}\""));
    }
    if let Some(tag) = tag {
        bits.push(format!("tag=\"{tag}\""));
    }
    bits.join(";")
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn config_hmac(secret_hex: &str) -> MessageSignatureConfig {
        MessageSignatureConfig {
            algorithm: SignatureAlgorithm::HmacSha256,
            key_id: "test-key".to_string(),
            key: secret_hex.to_string(),
            required_components: Vec::new(),
            clock_skew_seconds: 30,
        }
    }

    /// Wall-clock seconds, for a fixture whose `created` has to sit
    /// inside the verifier's freshness window.
    ///
    /// Signatures in these tests are computed at run time, so a live
    /// `created` costs nothing. The one fixture that cannot move is the
    /// ECDSA known-answer vector, whose signature is a published
    /// constant over a base containing `created=1700000000`; it widens
    /// the skew instead and says so where it does.
    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the epoch")
            .as_secs()
    }

    #[test]
    fn parse_signature_input_basic() {
        let inputs = parse_signature_input(
            r#"sig1=("@method" "@target-uri" "host");created=1700000000;keyid="k1";alg="hmac-sha256""#,
        )
        .unwrap();
        assert_eq!(inputs.len(), 1);
        let (label, entry) = &inputs[0];
        assert_eq!(label, "sig1");
        assert_eq!(entry.components, vec!["@method", "@target-uri", "host"]);
        assert_eq!(entry.params.keyid.as_deref(), Some("k1"));
        assert_eq!(entry.params.alg.as_deref(), Some("hmac-sha256"));
        assert_eq!(entry.params.created, Some(1700000000));
    }

    #[test]
    fn parse_signature_input_multiple() {
        let inputs =
            parse_signature_input(r#"sig1=("@method");keyid="k1", sig2=("@authority");keyid="k2""#)
                .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].0, "sig1");
        assert_eq!(inputs[1].0, "sig2");
    }

    #[test]
    fn parse_signature_dict_basic() {
        let dict = parse_signature_dict(r#"sig1=:dGVzdA==:"#).unwrap();
        assert_eq!(dict.get("sig1").unwrap(), b"test");
    }

    #[test]
    fn build_base_handles_method_and_target_uri() {
        let req = http::Request::builder()
            .method("POST")
            .uri("/api/items?x=1")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        let entry = parse_signature_input(
            r#"sig1=("@method" "@target-uri" "host");created=1700000000;keyid="k1""#,
        )
        .unwrap()
        .pop()
        .unwrap()
        .1;
        let base = build_signature_base(&req, &entry).unwrap();
        // Expected per RFC 9421 §2: components first, then the
        // @signature-params line. Each component line is lower-case.
        // `@target-uri` is the absolute URI of §2.2.2, assembled from
        // the scheme and the Host header because the request line is
        // origin-form.
        let expected = "\"@method\": POST\n\
            \"@target-uri\": http://api.example.com/api/items?x=1\n\
            \"host\": api.example.com\n\
            \"@signature-params\": (\"@method\" \"@target-uri\" \"host\");created=1700000000;keyid=\"k1\"";
        assert_eq!(base, expected);
    }

    #[test]
    fn target_uri_is_the_absolute_uri_a_conformant_peer_signs() {
        // The interop case: a partner signs `https://api.example.com/v1/orders`
        // with any conformant RFC 9421 library. The proxy used to
        // reconstruct `/v1/orders` and 401 every such request with the
        // same generic reason a forged signature gets.
        let req = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/v1/orders?page=2")
            .body(bytes::Bytes::new())
            .unwrap();
        let entry = parse_signature_input(r#"sig1=("@target-uri");keyid="k1""#)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        let base = build_signature_base(&req, &entry).unwrap();
        assert!(
            base.starts_with("\"@target-uri\": https://api.example.com/v1/orders?page=2\n"),
            "got: {base}"
        );
    }

    #[test]
    fn target_uri_falls_back_to_the_request_target_with_no_authority() {
        // HTTP/1.0 with no Host: there is no absolute URI to assemble,
        // and inventing an authority would sign a name nobody sent.
        let req = http::Request::builder()
            .method("GET")
            .uri("/health")
            .body(bytes::Bytes::new())
            .unwrap();
        let entry = parse_signature_input(r#"sig1=("@target-uri");keyid="k1""#)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        assert!(build_signature_base(&req, &entry)
            .unwrap()
            .starts_with("\"@target-uri\": /health\n"));
    }

    #[test]
    fn request_target_is_the_bare_target_not_cavages_method_prefix() {
        // RFC 9421 §2.2.5 is the request target alone. The old shape,
        // `GET /v1/orders`, is draft-cavage's `(request-target)` with an
        // uppercased method and matches neither spec.
        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/orders?page=2")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        let entry = parse_signature_input(r#"sig1=("@request-target");keyid="k1""#)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        let base = build_signature_base(&req, &entry).unwrap();
        assert!(
            base.starts_with("\"@request-target\": /v1/orders?page=2\n"),
            "got: {base}"
        );
        assert!(!base.contains("GET /v1/orders"), "got: {base}");
    }

    /// Sign `req` over `components` with the shared HMAC test key, using
    /// whichever derivation `dialect` names, and stamp the two headers.
    fn sign_hmac_with_dialect(
        req: &mut http::Request<bytes::Bytes>,
        secret_hex: &str,
        components: &str,
        dialect: BaseDialect,
    ) {
        let raw_input = format!(
            r#"sig1=({components});created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let entry = parse_signature_input(&raw_input).unwrap().pop().unwrap().1;
        let base = build_signature_base_in(req, &entry, dialect).unwrap();
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        req.headers_mut()
            .insert("signature-input", raw_input.parse().unwrap());
        req.headers_mut()
            .insert("signature", format!("sig1=:{sig_b64}:").parse().unwrap());
    }

    #[test]
    fn a_conformant_target_uri_signature_verifies() {
        let secret_hex = "00112233445566778899aabbccddeeff";
        let mut req = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        sign_hmac_with_dialect(
            &mut req,
            secret_hex,
            r#""@method" "@target-uri""#,
            BaseDialect::Rfc9421,
        );
        assert!(matches!(
            MessageSignatureVerifier::new(config_hmac(secret_hex))
                .unwrap()
                .verify_request(&req),
            VerifyVerdict::Ok { .. }
        ));
    }

    #[test]
    fn a_legacy_target_uri_signature_still_verifies_during_the_deprecation() {
        // A signer built against the old origin-form derivation keeps
        // working: the fallback runs only after the conformant base has
        // failed, with the same key and the same freshness window.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let mut req = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        sign_hmac_with_dialect(
            &mut req,
            secret_hex,
            r#""@method" "@target-uri""#,
            BaseDialect::Legacy,
        );
        assert!(matches!(
            MessageSignatureVerifier::new(config_hmac(secret_hex))
                .unwrap()
                .verify_request(&req),
            VerifyVerdict::Ok { .. }
        ));

        // The window can only close on evidence, and the log line is
        // emitted once per process. Presence assertion only: the
        // registry is process-global and counters never decrease.
        let scrape = sbproxy_observe::metrics::metrics().render();
        assert!(
            scrape
                .lines()
                .filter(|line| line.starts_with("sbproxy_signature_legacy_derivation_total{"))
                .any(|line| line.contains("component=\"@target-uri\"")),
            "taking the legacy fallback must be scrapeable: {scrape}"
        );
    }

    #[test]
    fn the_legacy_fallback_does_not_admit_a_forged_signature() {
        // The fallback must widen the accepted bases and nothing else.
        // A signature over a base neither dialect produces still fails.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let mut req = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        sign_hmac_with_dialect(
            &mut req,
            secret_hex,
            r#""@method" "@target-uri""#,
            BaseDialect::Rfc9421,
        );
        // Re-point the request: neither derivation of `@target-uri`
        // matches what was signed.
        *req.uri_mut() = "/v1/refunds".parse().unwrap();
        match MessageSignatureVerifier::new(config_hmac(secret_hex))
            .unwrap()
            .verify_request(&req)
        {
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("cryptographic"), "got: {reason}")
            }
            VerifyVerdict::Ok { .. } => panic!("a tampered target must not verify either way"),
        }
    }

    #[test]
    fn a_signature_over_the_other_scheme_verifies_when_the_request_line_has_none() {
        // An origin-form request line carries no scheme and this layer
        // cannot see the listener's TLS state, so a partner that signed
        // `https://api.example.com/v1/orders` must still verify against
        // a request whose scheme the middleware would guess as `http`.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let signed_over_https = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/v1/orders")
            .body(bytes::Bytes::new())
            .unwrap();
        let raw_input = format!(
            r#"sig1=("@method" "@target-uri");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let entry = parse_signature_input(&raw_input).unwrap().pop().unwrap().1;
        let base = build_signature_base(&signed_over_https, &entry).unwrap();
        assert!(base.contains("https://api.example.com/v1/orders"));
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        // The live request arrives origin-form with only a Host header,
        // which is every HTTP/1.1 request a proxy sees.
        let live = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .header("host", "api.example.com")
            .header("signature-input", raw_input.as_str())
            .header("signature", format!("sig1=:{sig_b64}:"))
            .body(bytes::Bytes::new())
            .unwrap();
        assert!(matches!(
            MessageSignatureVerifier::new(config_hmac(secret_hex))
                .unwrap()
                .verify_request(&live),
            VerifyVerdict::Ok { .. }
        ));
    }

    #[test]
    fn the_other_scheme_attempt_does_not_change_the_authority_or_the_path() {
        // The scheme is the only thing the alternate attempt moves. A
        // signature over another host or another path still fails.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let signed_elsewhere = http::Request::builder()
            .method("GET")
            .uri("https://evil.example/v1/orders")
            .body(bytes::Bytes::new())
            .unwrap();
        let raw_input = format!(
            r#"sig1=("@method" "@target-uri");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let entry = parse_signature_input(&raw_input).unwrap().pop().unwrap().1;
        let base = build_signature_base(&signed_elsewhere, &entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        let live = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .header("host", "api.example.com")
            .header("signature-input", raw_input.as_str())
            .header("signature", format!("sig1=:{sig_b64}:"))
            .body(bytes::Bytes::new())
            .unwrap();
        assert!(matches!(
            MessageSignatureVerifier::new(config_hmac(secret_hex))
                .unwrap()
                .verify_request(&live),
            VerifyVerdict::Failed { .. }
        ));
    }

    #[test]
    fn the_other_scheme_attempt_reaches_a_request_target_component() {
        // `@scheme` pulls a signature into the other-scheme attempt and
        // `@request-target` then has to derive under that dialect too.
        // The component is scheme-free, so both dialects must produce
        // the same bytes for it; deriving it differently, or refusing to
        // derive it at all, breaks a covered set a signer may well pick.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let signed_over_https = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/v1/orders?page=2")
            .body(bytes::Bytes::new())
            .unwrap();
        let raw_input = format!(
            r#"sig1=("@scheme" "@request-target");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let entry = parse_signature_input(&raw_input).unwrap().pop().unwrap().1;
        let base = build_signature_base(&signed_over_https, &entry).unwrap();
        assert!(base.starts_with("\"@scheme\": https\n\"@request-target\": /v1/orders?page=2\n"));
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        // Origin form: this layer guesses `http`, so only the
        // other-scheme candidate can match.
        let live = http::Request::builder()
            .method("GET")
            .uri("/v1/orders?page=2")
            .header("host", "api.example.com")
            .header("signature-input", raw_input.as_str())
            .header("signature", format!("sig1=:{sig_b64}:"))
            .body(bytes::Bytes::new())
            .unwrap();
        assert!(matches!(
            MessageSignatureVerifier::new(config_hmac(secret_hex))
                .unwrap()
                .verify_request(&live),
            VerifyVerdict::Ok { .. }
        ));
    }

    #[test]
    fn the_legacy_fallback_is_not_tried_for_a_signature_that_covers_neither_component() {
        // A signature covering only `@path` gets one attempt, because
        // the derivation of everything it covers is unchanged.
        let entry = parse_signature_input(r#"sig1=("@method" "@path");keyid="k1""#)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        assert!(!covers_retargeted_component(&entry));
        let entry = parse_signature_input(r#"sig1=("@method" "@target-uri");keyid="k1""#)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        assert!(covers_retargeted_component(&entry));
        let entry = parse_signature_input(r#"sig1=("@request-target");keyid="k1""#)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        assert!(covers_retargeted_component(&entry));
    }

    // --- Freshness: the window is symmetric ---

    #[test]
    fn a_stale_created_is_refused_even_with_no_expires() {
        // The Web Bot Auth replay shape: a captured Signature-Input /
        // Signature pair with no `expires` and no `nonce`, replayed
        // against the same method and path. `check_freshness` had no
        // lower bound on `created`, `check_nonce` returns Ok when no
        // nonce store is wired (no caller in this tree wires one), and
        // the crypto is over an identical base, so the two headers were
        // an unexpiring bearer token.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let raw_input = format!(
            r#"sig1=("@method" "@path");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix() - 3600
        );
        let entry = parse_signature_input(&raw_input).unwrap().pop().unwrap().1;
        let for_signing = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .body(bytes::Bytes::new())
            .unwrap();
        let base = build_signature_base(&for_signing, &entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/orders")
            .header("signature-input", raw_input.as_str())
            .header("signature", format!("sig1=:{sig_b64}:"))
            .body(bytes::Bytes::new())
            .unwrap();

        // The signature is cryptographically perfect. Only the clock
        // refuses it.
        match MessageSignatureVerifier::new(config_hmac(secret_hex))
            .unwrap()
            .verify_request(&req)
        {
            VerifyVerdict::Failed { reason } => assert!(
                reason.contains("stale"),
                "reason must name staleness: {reason}"
            ),
            VerifyVerdict::Ok { .. } => {
                panic!("an hour-old signature must not verify at a 30s skew")
            }
        }
    }

    #[test]
    fn expires_cannot_extend_the_window_past_the_skew() {
        // A signer cannot hand itself a longer replay window by writing
        // a distant `expires`: the window belongs to the verifying
        // operator's `clock_skew_seconds`.
        let now = now_unix() as i64;
        let entry = parse_signature_input(&format!(
            r#"sig1=("@method");keyid="k1";created={};expires={}"#,
            now - 3600,
            now + 3600
        ))
        .unwrap()
        .pop()
        .unwrap()
        .1;
        let reason = check_freshness(&entry, 30).expect("a stale created is refused");
        assert!(reason.contains("stale"), "got: {reason}");
    }

    #[test]
    fn a_created_inside_the_window_passes_freshness() {
        let entry = parse_signature_input(&format!(
            r#"sig1=("@method");keyid="k1";created={}"#,
            now_unix() - 10
        ))
        .unwrap()
        .pop()
        .unwrap()
        .1;
        assert!(check_freshness(&entry, 30).is_none());
    }

    #[test]
    fn end_to_end_hmac_sha256_verifies_self_signed_request() {
        // We sign a request with a known HMAC key, set the
        // Signature/Signature-Input headers, and run the verifier.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let cfg = config_hmac(secret_hex);

        let body = bytes::Bytes::from_static(b"");
        let req_for_signing = http::Request::builder()
            .method("GET")
            .uri("/v1/health")
            .header("host", "api.example.com")
            .body(body.clone())
            .unwrap();

        // `created` is live: the freshness window is symmetric now, so a
        // fixture pinned to 2023 would be refused as stale before any
        // crypto ran.
        let raw_input = format!(
            r#"sig1=("@method" "@target-uri" "host");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let raw_input = raw_input.as_str();
        let entry = parse_signature_input(raw_input).unwrap().pop().unwrap().1;
        let base = build_signature_base(&req_for_signing, &entry).unwrap();

        let key_bytes = hex::decode(secret_hex).unwrap();
        let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
        mac.update(base.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);

        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/health")
            .header("host", "api.example.com")
            .header("signature-input", raw_input)
            .header("signature", format!("sig1=:{}:", sig_b64))
            .body(body)
            .unwrap();

        let verifier = MessageSignatureVerifier::new(cfg).unwrap();
        let verdict = verifier.verify_request(&req);
        assert!(
            matches!(verdict, VerifyVerdict::Ok { .. }),
            "expected Ok, got {:?}",
            verdict
        );
    }

    #[test]
    fn end_to_end_hmac_rejects_tampered_body() {
        // Body is a covered component via content-digest in real
        // RFC 9421 use; here we confirm that changing a covered
        // header (host) post-signing breaks verification.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let cfg = config_hmac(secret_hex);

        let raw_input = format!(
            r#"sig1=("@method" "host");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let raw_input = raw_input.as_str();
        let entry = parse_signature_input(raw_input).unwrap().pop().unwrap().1;
        let req_for_signing = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        let base = build_signature_base(&req_for_signing, &entry).unwrap();
        let key_bytes = hex::decode(secret_hex).unwrap();
        let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        // Verify against a request with a different `host` header.
        let tampered = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "evil.example.com")
            .header("signature-input", raw_input)
            .header("signature", format!("sig1=:{}:", sig_b64))
            .body(bytes::Bytes::new())
            .unwrap();
        let verifier = MessageSignatureVerifier::new(cfg).unwrap();
        match verifier.verify_request(&tampered) {
            VerifyVerdict::Ok { .. } => panic!("tampered host should fail"),
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("cryptographic"), "got {reason}")
            }
        }
    }

    #[test]
    fn end_to_end_ed25519_verifies_self_signed_request() {
        use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
        use rand::RngCore;
        let mut csprng = rand::rngs::OsRng;
        let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
        csprng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        let cfg = MessageSignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "test-key".to_string(),
            key: hex::encode(verifying_key.to_bytes()),
            required_components: Vec::new(),
            clock_skew_seconds: 30,
        };

        let raw_input = format!(
            r#"sig1=("@method" "@path" "host");created={};keyid="test-key";alg="ed25519""#,
            now_unix()
        );
        let raw_input = raw_input.as_str();
        let entry = parse_signature_input(raw_input).unwrap().pop().unwrap().1;
        let req_for_signing = http::Request::builder()
            .method("PUT")
            .uri("/api/items/42")
            .header("host", "api.example.com")
            .body(bytes::Bytes::new())
            .unwrap();
        let base = build_signature_base(&req_for_signing, &entry).unwrap();
        let signature = signing_key.sign(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let req = http::Request::builder()
            .method("PUT")
            .uri("/api/items/42")
            .header("host", "api.example.com")
            .header("signature-input", raw_input)
            .header("signature", format!("sig1=:{}:", sig_b64))
            .body(bytes::Bytes::new())
            .unwrap();

        let verifier = MessageSignatureVerifier::new(cfg).unwrap();
        match verifier.verify_request(&req) {
            VerifyVerdict::Ok { signature_label } => assert_eq!(signature_label, "sig1"),
            VerifyVerdict::Failed { reason } => panic!("expected ok, got: {reason}"),
        }
    }

    #[test]
    fn missing_signature_header_is_rejected() {
        let cfg = config_hmac("00");
        let req = http::Request::builder().body(bytes::Bytes::new()).unwrap();
        let v = MessageSignatureVerifier::new(cfg).unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("Signature-Input") || reason.contains("Signature"))
            }
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn algorithm_mismatch_is_rejected() {
        let cfg = MessageSignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "k".to_string(),
            // 32 zero bytes -> valid ed25519 key shape.
            key: "0".repeat(64),
            required_components: Vec::new(),
            clock_skew_seconds: 30,
        };
        let v = MessageSignatureVerifier::new(cfg).unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("/x")
            .header(
                "signature-input",
                r#"sig1=("@method");keyid="k";alg="hmac-sha256""#,
            )
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("alg mismatch"), "got: {reason}")
            }
            _ => panic!("expected algorithm mismatch failure"),
        }
    }

    #[test]
    fn missing_required_component_is_rejected() {
        let cfg = MessageSignatureConfig {
            algorithm: SignatureAlgorithm::HmacSha256,
            key_id: "k".to_string(),
            key: "00".to_string(),
            required_components: vec!["content-digest".to_string()],
            clock_skew_seconds: 30,
        };
        let v = MessageSignatureVerifier::new(cfg).unwrap();
        let req = http::Request::builder()
            .header(
                "signature-input",
                r#"sig1=("@method");keyid="k";alg="hmac-sha256""#,
            )
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(
                    reason.contains("missing required component"),
                    "got {reason}"
                )
            }
            _ => panic!("expected required-component failure"),
        }
    }

    #[test]
    fn expired_signature_is_rejected() {
        let cfg = config_hmac("00");
        let v = MessageSignatureVerifier::new(cfg).unwrap();
        let raw_input = r#"sig1=("@method");keyid="test-key";alg="hmac-sha256";expires=1000000000"#;
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", raw_input)
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("expired"), "got {reason}")
            }
            _ => panic!("expected expired failure"),
        }
    }

    #[test]
    fn future_dated_signature_is_rejected() {
        let cfg = config_hmac("00");
        let v = MessageSignatureVerifier::new(cfg).unwrap();
        let raw_input =
            r#"sig1=("@method");keyid="test-key";alg="hmac-sha256";created=99999999999"#;
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", raw_input)
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("future"), "got {reason}")
            }
            _ => panic!("expected future-dated failure"),
        }
    }

    #[test]
    fn split_top_level_commas_respects_parens_and_quotes() {
        let s = r#"a=("x", "y", "z");p="1,2",b=("p");q="ok""#;
        let parts = split_top_level_commas(s);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].starts_with("a=("));
        assert!(parts[1].starts_with("b=("));
    }

    // --- H8 regression: alg parameter is mandatory under pinning ---

    #[test]
    fn signature_input_without_alg_is_rejected_when_algorithm_pinned() {
        // OPENSOURCE.md H8: omitting the `alg` parameter must not
        // bypass algorithm enforcement. The verifier is configured for
        // HmacSha256, so a signature that omits `alg` must be rejected
        // even if everything else lines up.
        let cfg = config_hmac("00112233445566778899aabbccddeeff");
        let v = MessageSignatureVerifier::new(cfg).unwrap();

        // Signature-Input with NO alg= parameter.
        let raw_input = r#"sig1=("@method");keyid="test-key";created=1700000000"#;
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", raw_input)
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(
                    reason.contains("missing required `alg`"),
                    "expected alg-required failure, got: {reason}"
                );
            }
            VerifyVerdict::Ok { .. } => panic!("alg-less signature must not verify"),
        }
    }

    #[test]
    fn signature_input_without_alg_is_rejected_when_required_components_set() {
        // Even if a future SignatureAlgorithm variant ever loses its
        // pinning, declaring required_components also constitutes a
        // pinned policy. Both gates must reject alg-less input.
        let cfg = MessageSignatureConfig {
            algorithm: SignatureAlgorithm::HmacSha256,
            key_id: "test-key".to_string(),
            key: "00".to_string(),
            required_components: vec!["@method".to_string()],
            clock_skew_seconds: 30,
        };
        let v = MessageSignatureVerifier::new(cfg).unwrap();
        let raw_input = r#"sig1=("@method");keyid="test-key";created=1700000000"#;
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", raw_input)
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match v.verify_request(&req) {
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("missing required `alg`"), "got: {reason}");
            }
            VerifyVerdict::Ok { .. } => panic!("alg-less signature must not verify"),
        }
    }

    #[test]
    fn config_deserializes_correctly() {
        let json = r#"{
            "algorithm": "hmac_sha256",
            "key_id": "proxy-key-1",
            "key": "00112233",
            "required_components": ["@method", "@target-uri"]
        }"#;
        let cfg: MessageSignatureConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.algorithm, SignatureAlgorithm::HmacSha256);
        assert_eq!(cfg.key_id, "proxy-key-1");
        assert_eq!(cfg.required_components.len(), 2);
        assert_eq!(cfg.clock_skew_seconds, 30);
    }

    // --- Signer round-trip tests (WOR-805 AC#3) ---

    fn fixed_ed25519_keypair() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        // Deterministic seed so the test is reproducible.
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        (sk, seed)
    }

    fn fresh_signed_request() -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .method("POST")
            .uri("/echo")
            .header("host", "api.example.com")
            .header("content-type", "application/json")
            .body(bytes::Bytes::from_static(b"{\"hello\":\"world\"}"))
            .unwrap()
    }

    #[test]
    fn signer_round_trips_through_verifier() {
        let (_sk, seed) = fixed_ed25519_keypair();
        let signer = MessageSignatureSigner::new_ed25519(&seed, "proxy-key-1", None);
        // The verifier needs the public key in hex/base64; pull it
        // from the signer's accessor.
        let pk = signer.public_key_bytes();
        let mut req = fresh_signed_request();
        let now = 1_700_000_000;
        let params = SignRequestParams {
            components: vec![
                "@method".to_string(),
                "@target-uri".to_string(),
                "host".to_string(),
            ],
            label: "sig1".to_string(),
            created_unix: now,
            expires_unix: None,
            nonce: None,
        };
        signer.sign_request(&mut req, &params).unwrap();
        assert!(req.headers().get("signature-input").is_some());
        assert!(req.headers().get("signature").is_some());

        // Independent verifier instance, given only the public key.
        let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "proxy-key-1".to_string(),
            key: hex::encode(pk),
            required_components: Vec::new(),
            clock_skew_seconds: 1_000_000_000, // disable freshness for the deterministic now
        })
        .unwrap();
        match verifier.verify_request(&req) {
            VerifyVerdict::Ok { signature_label } => {
                assert_eq!(signature_label, "sig1");
            }
            VerifyVerdict::Failed { reason } => panic!("verify failed: {reason}"),
        }
    }

    #[test]
    fn signer_attaches_web_bot_auth_tag_when_supplied() {
        let (_sk, seed) = fixed_ed25519_keypair();
        let signer = MessageSignatureSigner::new_ed25519(
            &seed,
            "proxy-key-1",
            Some("web-bot-auth".to_string()),
        );
        let mut req = fresh_signed_request();
        signer
            .sign_request(
                &mut req,
                &SignRequestParams {
                    components: vec!["@method".to_string(), "host".to_string()],
                    label: "sig1".to_string(),
                    created_unix: 1_700_000_000,
                    expires_unix: Some(1_700_003_600),
                    nonce: Some("n-42".to_string()),
                },
            )
            .unwrap();
        let sig_input = req
            .headers()
            .get("signature-input")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert!(sig_input.contains("tag=\"web-bot-auth\""));
        assert!(sig_input.contains("keyid=\"proxy-key-1\""));
        assert!(sig_input.contains("alg=\"ed25519\""));
        assert!(sig_input.contains("created=1700000000"));
        assert!(sig_input.contains("expires=1700003600"));
        assert!(sig_input.contains("nonce=\"n-42\""));
    }

    #[test]
    fn signer_rejects_empty_components() {
        let (_sk, seed) = fixed_ed25519_keypair();
        let signer = MessageSignatureSigner::new_ed25519(&seed, "k", None);
        let mut req = fresh_signed_request();
        let err = signer
            .sign_request(
                &mut req,
                &SignRequestParams {
                    components: Vec::new(),
                    label: "sig1".to_string(),
                    created_unix: 0,
                    expires_unix: None,
                    nonce: None,
                },
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("components"));
    }

    #[test]
    fn signer_rejects_empty_label() {
        let (_sk, seed) = fixed_ed25519_keypair();
        let signer = MessageSignatureSigner::new_ed25519(&seed, "k", None);
        let mut req = fresh_signed_request();
        let err = signer
            .sign_request(
                &mut req,
                &SignRequestParams {
                    components: vec!["@method".to_string()],
                    label: String::new(),
                    created_unix: 0,
                    expires_unix: None,
                    nonce: None,
                },
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("label"));
    }

    #[test]
    fn signer_public_key_accessor_returns_32_bytes() {
        let (_sk, seed) = fixed_ed25519_keypair();
        let signer = MessageSignatureSigner::new_ed25519(&seed, "k", None);
        assert_eq!(signer.public_key_bytes().len(), 32);
        assert_eq!(signer.key_id(), "k");
    }

    #[test]
    fn signer_round_trip_with_changed_component_fails_verification() {
        // Cross-check: if the request body changes after signing,
        // the verifier MUST reject. We approximate by changing the
        // method on the wire (the @method component is covered).
        let (_sk, seed) = fixed_ed25519_keypair();
        let signer = MessageSignatureSigner::new_ed25519(&seed, "proxy-key-1", None);
        let mut req = fresh_signed_request();
        signer
            .sign_request(
                &mut req,
                &SignRequestParams {
                    components: vec!["@method".to_string(), "host".to_string()],
                    label: "sig1".to_string(),
                    created_unix: 1_700_000_000,
                    expires_unix: None,
                    nonce: None,
                },
            )
            .unwrap();
        // Tamper.
        *req.method_mut() = http::Method::GET;
        let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "proxy-key-1".to_string(),
            key: hex::encode(signer.public_key_bytes()),
            required_components: Vec::new(),
            clock_skew_seconds: 1_000_000_000,
        })
        .unwrap();
        assert!(matches!(
            verifier.verify_request(&req),
            VerifyVerdict::Failed { .. }
        ));
    }

    // --- WOR-805 F1.6.1 helper tests -------------------------------------

    fn build_headers(sig_input: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = sig_input {
            h.insert("signature-input", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn signature_input_covers_content_digest_returns_true_when_listed() {
        let h = build_headers(Some(
            "sig1=(\"@method\" \"@authority\" \"content-digest\");keyid=\"k1\";alg=\"ed25519\"",
        ));
        assert!(signature_input_covers_content_digest(&h));
    }

    #[test]
    fn signature_input_covers_content_digest_case_insensitive() {
        let h = build_headers(Some(
            "sig1=(\"@method\" \"Content-Digest\");keyid=\"k1\";alg=\"ed25519\"",
        ));
        assert!(signature_input_covers_content_digest(&h));
    }

    #[test]
    fn signature_input_covers_content_digest_returns_false_when_absent() {
        let h = build_headers(Some(
            "sig1=(\"@method\" \"@authority\");keyid=\"k1\";alg=\"ed25519\"",
        ));
        assert!(!signature_input_covers_content_digest(&h));
    }

    #[test]
    fn signature_input_covers_content_digest_returns_false_when_header_missing() {
        let h = build_headers(None);
        assert!(!signature_input_covers_content_digest(&h));
    }

    #[test]
    fn signature_input_covers_content_digest_returns_false_when_unparseable() {
        let h = build_headers(Some("not a signature-input value"));
        assert!(!signature_input_covers_content_digest(&h));
    }

    #[test]
    fn signature_input_covers_content_digest_finds_match_across_multiple_signatures() {
        let h = build_headers(Some(
            "sig1=(\"@method\");keyid=\"k1\";alg=\"ed25519\", \
             sig2=(\"content-digest\");keyid=\"k2\";alg=\"ed25519\"",
        ));
        assert!(signature_input_covers_content_digest(&h));
    }

    // --- WOR-2301: `message_signatures.key` resolves through the central
    // secret resolver, and a reference it cannot resolve never becomes the
    // key.

    #[test]
    fn decode_secret_resolves_a_provider_uri_through_the_installed_resolver() {
        sbproxy_vault::reset_process_resolver_for_test();
        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("signing-key", "00112233445566778899aabbccddeeff")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register_backend(
            sbproxy_vault::VaultProviderType::HashiCorp,
            "prod",
            Box::new(vault),
        );
        sbproxy_vault::install_process_resolver(std::sync::Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(std::sync::Arc::new(manager)),
        ));

        let bytes = decode_secret("vault://prod/signing-key")
            .expect("a provider URI resolves once a backend is installed");

        // Resolution runs before decoding, so the hex string the backend
        // holds yields the same key bytes the identical value inlined in
        // sb.yml would have produced.
        assert_eq!(
            bytes,
            hex::decode("00112233445566778899aabbccddeeff").expect("fixture is hex")
        );
        assert_ne!(
            bytes,
            b"vault://prod/signing-key".to_vec(),
            "the reference text must never be the key"
        );

        sbproxy_vault::reset_process_resolver_for_test();
    }

    #[test]
    fn decode_secret_resolves_the_colon_form_env_reference_with_no_backend_installed() {
        // The colon form is the half `sbproxy-config`'s `${VAR}`
        // interpolation never covered, so before WOR-2301 an `env:NAME` key
        // became the 8-byte string `env:NAME`. Reads a variable every test
        // process already has rather than exporting one, so this test never
        // mutates the process environment.
        sbproxy_vault::reset_process_resolver_for_test();
        let expected = std::env::var("PATH").expect("PATH is set in the test environment");

        let bytes = decode_secret("env:PATH").expect("the colon-form env: reference resolves");

        assert_eq!(
            bytes,
            decode_secret(&expected).expect("the same value inlined decodes"),
            "a reference must decode to exactly what inlining its value would"
        );
        assert_ne!(
            bytes,
            b"env:PATH".to_vec(),
            "the reference text must never be the key"
        );
    }

    #[test]
    fn decode_secret_fails_closed_on_a_provider_uri_with_no_resolver_installed() {
        sbproxy_vault::reset_process_resolver_for_test();

        for reference in [
            "vault://prod/signing-key",
            "awssm://prod/signing-key",
            "secret://local/signing-key",
        ] {
            let error = decode_secret(reference)
                .expect_err("a provider URI must never become HMAC key material");
            let rendered = error.to_string();
            assert!(
                rendered.contains("message_signatures.key"),
                "the error must name the field, got: {rendered}"
            );
            assert!(
                rendered.contains("proxy.secrets.backends"),
                "the error must point at the backend config, got: {rendered}"
            );
        }
    }

    #[test]
    fn decode_secret_still_decodes_a_plain_inline_key_unchanged() {
        // The non-regression case: a genuine inline key carries no reference
        // shape, resolves to itself, and decodes byte-identically to the
        // pre-WOR-2301 behavior (hex, then base64, then raw UTF-8 bytes).
        assert_eq!(
            decode_secret("00112233445566778899aabbccddeeff").expect("hex literal"),
            vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert_eq!(
            decode_secret("c2hhcmVkLXNlY3JldA==").expect("base64 literal"),
            b"shared-secret".to_vec()
        );
        assert_eq!(
            decode_secret("not-hex-or-base64!!").expect("raw literal"),
            b"not-hex-or-base64!!".to_vec()
        );
    }

    #[test]
    fn verifier_build_fails_closed_on_an_unresolvable_key_reference() {
        // The failure has to reach the verifier build, because that is what
        // `cached_message_signature_verifier` turns into "reject every
        // request for this origin" rather than a silently wrong key.
        sbproxy_vault::reset_process_resolver_for_test();

        // `.err().expect(...)` rather than `.expect_err(...)`: the Ok type
        // withholds `Debug` on purpose, because a verifier holds live key
        // material and a derived `Debug` would print it. The test bends,
        // not the production type (WOR-2193).
        let error = MessageSignatureVerifier::new(config_hmac("awssm://prod/signing-key"))
            .err()
            .expect("an unresolvable key reference must fail the verifier build");

        assert!(
            error.to_string().contains("proxy.secrets.backends"),
            "{error}"
        );
    }

    #[test]
    fn a_failed_key_resolution_never_echoes_the_configured_value() {
        // `cached_message_signature_verifier` logs this error at warn for
        // EVERY request to the origin while the misconfiguration stands, so
        // anything this error carries is written to the log repeatedly. The
        // configured value may be the signing key itself rather than a
        // pointer to it, so it must never appear.
        //
        // `secret:NAME` (single colon) is the removed reference form the
        // resolver hard-errors on, which is the cheapest way to reach the
        // error path with a value we control.
        sbproxy_vault::reset_process_resolver_for_test();
        let secret = "secret:DISTINCTIVE_INLINE_KEY_9f2c";

        // `.expect_err(...)` here, but `.err().expect(...)` in the verifier
        // test above. The two are not interchangeable and the compiler
        // enforces opposite directions: this Ok type is `Vec<u8>`, which
        // implements `Debug`, so `.err().expect()` trips
        // `clippy::err_expect`; the verifier's Ok type withholds `Debug`, so
        // `.expect_err()` does not compile there (WOR-2193).
        let error = decode_secret(secret).expect_err("the removed colon form must not resolve");

        // `{error}` renders only the OUTERMOST context, which is the one this
        // module owns. Pinning it to a fixed string proves this layer adds no
        // echo of the configured value.
        assert_eq!(
            format!("{error}"),
            "message_signatures.key could not be resolved",
            "this module's own error context must name the field and nothing else"
        );

        // The full chain (`{error:#}`) still carries the resolver's own
        // wording, and the resolver DOES echo its input. That is safe for
        // every reference form, because a reference is a pointer rather than
        // the secret. It is not this module's call to make: see the note on
        // `resolve_key_material` for why an inline literal cannot reach an
        // error path here (a hex or base64 key matches no reference prefix,
        // so the resolver hands it straight back).
        assert!(
            format!("{error:#}").contains("message_signatures.key could not be resolved"),
            "the chain must still lead with the field an operator has to fix"
        );
    }

    // --- ECDSA-P256-SHA256 -----------------------------------------------
    //
    // The fixture is a published test key rather than a freshly generated
    // one: the private scalar is RFC 6979 appendix A.2.5's `x` for P-256,
    // and the public point below is the `Ux`/`Uy` that appendix publishes
    // for it. Anyone can re-derive the point from the scalar and check it
    // against the RFC, which a randomly generated keypair would not allow.
    //
    // The signature is a fixed vector over the exact base string
    // `ECDSA_KAT_BASE`, so this is a known-answer test rather than a
    // sign-then-verify round trip: it pins the public-key encoding
    // (uncompressed SEC1), the signature encoding (fixed-width `r || s`,
    // never DER), and the byte-for-byte signature base all at once.
    // ECDSA is randomized, so a re-signed fixture would differ every run
    // and could not pin any of them.

    /// Uncompressed SEC1 point, `0x04 || X || Y`.
    const ECDSA_KAT_PUBLIC_KEY_HEX: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa\
                                            6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc\
                                            64f2f1b20c2d7e9f5177a3c294d4462299";

    /// A second, unrelated P-256 point (the generator doubled), used as
    /// the wrong-key case.
    const ECDSA_OTHER_PUBLIC_KEY_HEX: &str = "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b\
                                              35a60b48fc4766997807775510db8ed040293d9ac69f7430\
                                              dbba7dade63ce982299e04b79d227873d1";

    const ECDSA_KAT_SIGNATURE_B64: &str =
        "3ME42scf5pJ9GBSzMWit/7nM+Zo93/IOJ0XzuauZJtIs13TcSI1A3VLwuq4RdbW/29IcT5tK9yX74XzG6NoybQ==";

    const ECDSA_KAT_SIGNATURE_INPUT: &str = "sig1=(\"@method\" \"@path\" \"host\" \
         \"content-digest\");created=1700000000;keyid=\"test-key-ecdsa-p256\";\
         alg=\"ecdsa-p256-sha256\"";

    /// The body the fixture signature covers, and the RFC 9530 §2 example
    /// body `digest.rs` already pins its own vectors against.
    const ECDSA_KAT_BODY: &[u8] = b"{\"hello\": \"world\"}";

    const ECDSA_KAT_CONTENT_DIGEST: &str = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";

    /// The canonical signature base the fixture signature was computed
    /// over. Asserted against the live builder before the crypto runs, so
    /// a change to base construction reports itself instead of surfacing
    /// as an inscrutable verification failure.
    const ECDSA_KAT_BASE: &str = concat!(
        "\"@method\": POST\n",
        "\"@path\": /v1/items\n",
        "\"host\": api.example.com\n",
        "\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n",
        "\"@signature-params\": (\"@method\" \"@path\" \"host\" \"content-digest\")",
        ";created=1700000000;keyid=\"test-key-ecdsa-p256\";alg=\"ecdsa-p256-sha256\""
    );

    fn ecdsa_kat_config(public_key_hex: &str) -> MessageSignatureConfig {
        MessageSignatureConfig {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            key_id: "test-key-ecdsa-p256".to_string(),
            key: public_key_hex.to_string(),
            required_components: Vec::new(),
            // The vector's `created=1700000000` is inside the base the
            // published signature was computed over, so it cannot move.
            // Widen the window instead: this file's freshness behavior
            // is pinned by its own tests, and pinning it again here
            // would only cost the known-answer property this fixture
            // exists for.
            clock_skew_seconds: 1_000_000_000,
        }
    }

    fn ecdsa_kat_request(path_and_query: &str, body: &'static [u8]) -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .method("POST")
            .uri(path_and_query)
            .header("host", "api.example.com")
            .header("content-digest", ECDSA_KAT_CONTENT_DIGEST)
            .header("signature-input", ECDSA_KAT_SIGNATURE_INPUT)
            .header("signature", format!("sig1=:{ECDSA_KAT_SIGNATURE_B64}:"))
            .body(bytes::Bytes::from_static(body))
            .unwrap()
    }

    #[test]
    fn ecdsa_p256_sha256_reconstructs_the_expected_signature_base() {
        let req = ecdsa_kat_request("/v1/items?page=2", ECDSA_KAT_BODY);
        let entry = parse_signature_input(ECDSA_KAT_SIGNATURE_INPUT)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        assert_eq!(build_signature_base(&req, &entry).unwrap(), ECDSA_KAT_BASE);
    }

    #[test]
    fn ecdsa_p256_sha256_accepts_the_known_answer_vector() {
        let verifier = MessageSignatureVerifier::new(ecdsa_kat_config(ECDSA_KAT_PUBLIC_KEY_HEX))
            .expect("uncompressed SEC1 point is accepted");
        match verifier.verify_request(&ecdsa_kat_request("/v1/items?page=2", ECDSA_KAT_BODY)) {
            VerifyVerdict::Ok { signature_label } => assert_eq!(signature_label, "sig1"),
            VerifyVerdict::Failed { reason } => panic!("expected ok, got: {reason}"),
        }
    }

    #[test]
    fn ecdsa_p256_sha256_rejects_a_tampered_request() {
        // `@path` is covered, so re-pointing the request at another route
        // must break the signature even though every header is intact.
        let verifier =
            MessageSignatureVerifier::new(ecdsa_kat_config(ECDSA_KAT_PUBLIC_KEY_HEX)).unwrap();
        match verifier.verify_request(&ecdsa_kat_request("/v1/other?page=2", ECDSA_KAT_BODY)) {
            VerifyVerdict::Ok { .. } => panic!("a tampered path must not verify"),
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("cryptographic"), "got: {reason}")
            }
        }
    }

    #[test]
    fn ecdsa_p256_sha256_rejects_the_wrong_key() {
        let verifier =
            MessageSignatureVerifier::new(ecdsa_kat_config(ECDSA_OTHER_PUBLIC_KEY_HEX)).unwrap();
        match verifier.verify_request(&ecdsa_kat_request("/v1/items?page=2", ECDSA_KAT_BODY)) {
            VerifyVerdict::Ok { .. } => panic!("an unrelated key must not verify"),
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("cryptographic"), "got: {reason}")
            }
        }
    }

    #[test]
    fn ecdsa_p256_sha256_rejects_a_body_the_content_digest_does_not_describe() {
        // The vector covers `content-digest`, so the same signature over
        // the same headers must stop working the moment the body changes.
        // Nothing about the crypto changes here: only the digest binding
        // catches it.
        let verifier =
            MessageSignatureVerifier::new(ecdsa_kat_config(ECDSA_KAT_PUBLIC_KEY_HEX)).unwrap();
        let swapped = ecdsa_kat_request("/v1/items?page=2", b"{\"hello\": \"WORLD\"}");
        match verifier.verify_request(&swapped) {
            VerifyVerdict::Ok { .. } => panic!("a swapped body must not verify"),
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("content-digest"), "got: {reason}")
            }
        }
    }

    #[test]
    fn ecdsa_p256_sha256_key_must_be_an_uncompressed_sec1_point() {
        // Compressed point: the same X with an 0x02 prefix and no Y.
        let compressed = format!("02{}", &ECDSA_KAT_PUBLIC_KEY_HEX[2..66]);
        let error = MessageSignatureVerifier::new(ecdsa_kat_config(&compressed))
            .err()
            .expect("a compressed point must be refused at construction");
        assert!(error.to_string().contains("compressed"), "{error}");

        // A DER/SPKI wrapper starts with a SEQUENCE tag.
        let error = MessageSignatureVerifier::new(ecdsa_kat_config("3059301306072a8648ce3d0201"))
            .err()
            .expect("a DER structure must be refused at construction");
        assert!(error.to_string().contains("DER/SPKI"), "{error}");

        // Anything else is named by length.
        let error = MessageSignatureVerifier::new(ecdsa_kat_config("04deadbeef"))
            .err()
            .expect("a short point must be refused at construction");
        assert!(error.to_string().contains("65"), "{error}");
    }

    #[test]
    fn ecdsa_p256_sha256_rejects_a_der_encoded_signature() {
        // RFC 9421 §3.3.5 pins `r || s`. A DER-wrapped signature is the
        // likeliest field mistake, and it must be named rather than
        // rejected as a generic crypto failure.
        let verifier =
            MessageSignatureVerifier::new(ecdsa_kat_config(ECDSA_KAT_PUBLIC_KEY_HEX)).unwrap();
        let der_ish = base64::engine::general_purpose::STANDARD.encode([0x30u8; 70]);
        let req = http::Request::builder()
            .method("POST")
            .uri("/v1/items?page=2")
            .header("host", "api.example.com")
            .header("content-digest", ECDSA_KAT_CONTENT_DIGEST)
            .header("signature-input", ECDSA_KAT_SIGNATURE_INPUT)
            .header("signature", format!("sig1=:{der_ish}:"))
            .body(bytes::Bytes::from_static(ECDSA_KAT_BODY))
            .unwrap();
        match verifier.verify_request(&req) {
            VerifyVerdict::Ok { .. } => panic!("a 70-byte signature must not verify"),
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("64 bytes of r||s"), "got: {reason}")
            }
        }
    }

    #[test]
    fn ecdsa_p256_sha256_matches_only_its_registry_token() {
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        assert!(alg.matches_wire("ecdsa-p256-sha256"));
        assert!(!alg.matches_wire("ed25519"));
        assert!(!alg.matches_wire("ecdsa-p384-sha384"));
        assert!(alg.is_pinned());
        // And the other two must not answer to it.
        assert!(!SignatureAlgorithm::Ed25519.matches_wire("ecdsa-p256-sha256"));
        assert!(!SignatureAlgorithm::HmacSha256.matches_wire("ecdsa-p256-sha256"));
    }

    #[test]
    fn config_deserializes_the_ecdsa_p256_sha256_algorithm_token() {
        let json = r#"{
            "algorithm": "ecdsa_p256_sha256",
            "key_id": "proxy-key-1",
            "key": "04aa"
        }"#;
        let cfg: MessageSignatureConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.algorithm, SignatureAlgorithm::EcdsaP256Sha256);
    }

    // --- Body coverage ----------------------------------------------------
    //
    // `content-digest` is a plain header reference in the signature base,
    // so the cryptography alone proves only that the signer wrote a digest
    // down. These tests pin the second half: the digest has to describe
    // the bytes the verifier was handed.

    /// The three headers a client sends for a `content-digest`-covering
    /// HMAC signature. `digest_over` is what the signer hashed, which a
    /// caller can deliberately make differ from the body it later serves.
    fn hmac_body_covering_headers(secret_hex: &str, digest_over: &[u8]) -> Vec<(String, String)> {
        let content_digest =
            crate::digest::compute_content_digest(crate::digest::Algorithm::Sha256, digest_over);
        let raw_input = format!(
            "sig1=(\"@method\" \"@path\" \"content-digest\");created={};\
             keyid=\"test-key\";alg=\"hmac-sha256\"",
            now_unix()
        );
        let raw_input = raw_input.as_str();
        let entry = parse_signature_input(raw_input).unwrap().pop().unwrap().1;
        let for_signing = http::Request::builder()
            .method("POST")
            .uri("/v1/items")
            .header("content-digest", &content_digest)
            .body(bytes::Bytes::new())
            .unwrap();
        let base = build_signature_base(&for_signing, &entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        vec![
            ("content-digest".to_string(), content_digest),
            ("signature-input".to_string(), raw_input.to_string()),
            ("signature".to_string(), format!("sig1=:{sig_b64}:")),
        ]
    }

    fn request_carrying(
        headers: &[(String, String)],
        body: &'static [u8],
    ) -> http::Request<bytes::Bytes> {
        let mut builder = http::Request::builder().method("POST").uri("/v1/items");
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder.body(bytes::Bytes::from_static(body)).unwrap()
    }

    const COVERED_BODY: &[u8] = b"{\"order\":\"1\"}";
    const SWAPPED_BODY: &[u8] = b"{\"order\":\"9999\"}";

    #[test]
    fn content_digest_coverage_accepts_the_body_it_describes() {
        let secret_hex = "00112233445566778899aabbccddeeff";
        let headers = hmac_body_covering_headers(secret_hex, COVERED_BODY);
        let verifier = MessageSignatureVerifier::new(config_hmac(secret_hex)).unwrap();
        match verifier.verify_request(&request_carrying(&headers, COVERED_BODY)) {
            VerifyVerdict::Ok { signature_label } => assert_eq!(signature_label, "sig1"),
            VerifyVerdict::Failed { reason } => panic!("expected ok, got: {reason}"),
        }
    }

    #[test]
    fn content_digest_coverage_rejects_a_swapped_body() {
        // Every header, including `Content-Digest`, is byte-identical to
        // the signed request; only the body differs. The signature base
        // is unchanged, so the crypto still passes and the digest binding
        // is the only thing standing between this request and the
        // upstream.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let headers = hmac_body_covering_headers(secret_hex, COVERED_BODY);
        let verifier = MessageSignatureVerifier::new(config_hmac(secret_hex)).unwrap();
        match verifier.verify_request(&request_carrying(&headers, SWAPPED_BODY)) {
            VerifyVerdict::Ok { .. } => {
                panic!("a signature covering content-digest must not accept a different body")
            }
            VerifyVerdict::Failed { reason } => assert!(
                reason.contains("content-digest does not match the request body"),
                "got: {reason}"
            ),
        }
    }

    #[test]
    fn content_digest_coverage_rejects_a_caller_that_supplies_no_body() {
        // The shape the request pipeline used to be in: headers verified
        // against an empty body stand-in. Passing that must be impossible,
        // because it accepts any body at all.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let headers = hmac_body_covering_headers(secret_hex, COVERED_BODY);
        let verifier = MessageSignatureVerifier::new(config_hmac(secret_hex)).unwrap();
        match verifier.verify_request(&request_carrying(&headers, b"")) {
            VerifyVerdict::Ok { .. } => panic!("an absent body must not satisfy body coverage"),
            VerifyVerdict::Failed { reason } => {
                assert!(reason.contains("content-digest"), "got: {reason}")
            }
        }
    }

    #[test]
    fn deferring_form_leaves_the_body_binding_to_the_caller() {
        // The Web Bot Auth carve-out. Header verification succeeds against
        // a body the digest does not describe, because that caller checks
        // the body itself once the request body filter has all of it.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let headers = hmac_body_covering_headers(secret_hex, COVERED_BODY);
        let verifier = MessageSignatureVerifier::new(config_hmac(secret_hex)).unwrap();
        let verdict = verifier
            .verify_request_deferring_body_binding(&request_carrying(&headers, SWAPPED_BODY));
        assert!(
            matches!(verdict, VerifyVerdict::Ok { .. }),
            "the deferring form must not check the body: {verdict:?}"
        );
    }

    #[test]
    fn a_signature_covering_no_body_component_ignores_the_body_entirely() {
        // The hot path: an origin whose signatures cover headers only must
        // keep verifying with whatever body the caller happens to pass, so
        // that nothing has to buffer a body to check a header signature.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let cfg = config_hmac(secret_hex);
        let raw_input = format!(
            r#"sig1=("@method" "@path");created={};keyid="test-key";alg="hmac-sha256""#,
            now_unix()
        );
        let raw_input = raw_input.as_str();
        let entry = parse_signature_input(raw_input).unwrap().pop().unwrap().1;
        let for_signing = http::Request::builder()
            .method("POST")
            .uri("/v1/items")
            .body(bytes::Bytes::new())
            .unwrap();
        let base = build_signature_base(&for_signing, &entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let req = http::Request::builder()
            .method("POST")
            .uri("/v1/items")
            .header("signature-input", raw_input)
            .header("signature", format!("sig1=:{sig_b64}:"))
            .body(bytes::Bytes::from_static(SWAPPED_BODY))
            .unwrap();
        let verifier = MessageSignatureVerifier::new(cfg).unwrap();
        assert!(matches!(
            verifier.verify_request(&req),
            VerifyVerdict::Ok { .. }
        ));
    }
}
