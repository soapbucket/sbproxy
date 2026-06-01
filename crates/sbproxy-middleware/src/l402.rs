//! WOR-807: L402 (Lightning HTTP 402) bearer credential surface.
//!
//! Implements the wire surface of the Lightning Labs L402 protocol on
//! top of the `crate::macaroon` primitive. SBproxy is the *server*
//! half: it mints a macaroon + Lightning invoice and challenges the
//! caller, then accepts a `Authorization: L402 <macaroon>:<preimage>`
//! header on the retry. Lightning invoice issuance is handed off to a
//! caller-supplied `InvoiceProvider` so the same code drives an LND,
//! CLN, or Phoenixd backend.
//!
//! # Wire shape
//!
//! Initial challenge:
//!
//! ```text
//! HTTP/1.1 402 Payment Required
//! WWW-Authenticate: L402 macaroon="<base64url>", invoice="lnbc..."
//! ```
//!
//! Client retry after paying:
//!
//! ```text
//! GET /resource HTTP/1.1
//! Authorization: L402 <macaroon>:<preimage_hex>
//! ```
//!
//! The verifier:
//!
//! 1. Parses the `Authorization` header into `(macaroon, preimage)`.
//! 2. Recomputes the macaroon HMAC chain from the root key.
//! 3. Checks the macaroon's `payment_hash=<hex>` caveat against
//!    `SHA-256(preimage)` so the client cannot present a stolen
//!    macaroon without the matching preimage.
//! 4. Runs the operator-supplied predicate over the remaining caveats
//!    (e.g. `valid_until=<unix>`, `route=/articles/*`).
//!
//! The first three checks are stateless: the verifier holds only the
//! root key, no session table. Attenuation lets a buyer mint a
//! narrower macaroon for a sub-agent without re-paying the invoice.
//!
//! # What this module is not
//!
//! - A Lightning client. `InvoiceProvider` is the seam to LND / CLN /
//!   Phoenixd; this module never talks to a Lightning node directly.
//! - A request-pipeline integration. The auth provider that arms
//!   `L402Verifier` on the request path lands in `sbproxy-modules`
//!   alongside the other auth providers.

use sha2::{Digest, Sha256};

use crate::macaroon::{Macaroon, MacaroonError};

/// Canonical wire label for the L402 scheme.
pub const L402_SCHEME: &str = "L402";

/// Canonical caveat key the verifier checks the preimage hash against.
pub const PAYMENT_HASH_CAVEAT: &str = "payment_hash";

/// A Lightning invoice + the payment hash the macaroon's caveat must
/// match. The invoice is opaque to this module (BOLT-11 string); the
/// payment hash is the 32-byte SHA-256 that ties the invoice to its
/// preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// BOLT-11 invoice string the client pays.
    pub bolt11: String,
    /// 32-byte SHA-256 of the invoice's preimage, hex-encoded so the
    /// macaroon caveat can be byte-compared without re-decoding.
    pub payment_hash: String,
}

/// Trait the L402 issuer uses to acquire a fresh invoice. Operators
/// supply an implementation talking to LND / CLN / Phoenixd; tests
/// supply a static stub that returns a fixed `(bolt11, payment_hash)`
/// pair so the round-trip can be exercised without a Lightning node.
pub trait InvoiceProvider: Send + Sync {
    /// Mint a fresh invoice for the supplied amount in millisatoshi.
    /// Returns the invoice + matching payment hash.
    fn create_invoice(&self, amount_msat: u64, memo: &str) -> Result<Invoice, InvoiceError>;
}

/// Errors an `InvoiceProvider` can return. The L402 layer surfaces
/// these as 503s so the caller knows to retry against the upstream
/// payment broker rather than the gateway.
#[derive(Debug, Clone)]
pub enum InvoiceError {
    /// The configured Lightning backend was unreachable.
    BackendUnavailable(String),
    /// The backend rejected the invoice request (insufficient
    /// liquidity, invalid amount, etc.).
    BackendRejected(String),
}

impl std::fmt::Display for InvoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable(s) => write!(f, "lightning backend unavailable: {s}"),
            Self::BackendRejected(s) => write!(f, "lightning backend rejected invoice: {s}"),
        }
    }
}

impl std::error::Error for InvoiceError {}

/// Issuer-side L402 surface. Owns the root key + invoice provider and
/// hands out `WWW-Authenticate: L402 ...` header values plus the
/// minted macaroon for the operator's audit log.
pub struct L402Issuer<P: InvoiceProvider> {
    root_key: Vec<u8>,
    location: String,
    provider: P,
}

impl<P: InvoiceProvider> L402Issuer<P> {
    /// Build a new issuer.
    pub fn new(root_key: Vec<u8>, location: impl Into<String>, provider: P) -> Self {
        Self {
            root_key,
            location: location.into(),
            provider,
        }
    }

    /// Issue a fresh L402 challenge: mint an invoice, then a
    /// macaroon bound to that invoice's payment hash, then build the
    /// `WWW-Authenticate` header value. Returns the macaroon
    /// alongside so the issuer can record it in audit / metrics.
    pub fn challenge(
        &self,
        token_id: impl Into<String>,
        amount_msat: u64,
        memo: &str,
        extra_caveats: Vec<String>,
    ) -> Result<(Macaroon, Invoice, String), InvoiceError> {
        let invoice = self.provider.create_invoice(amount_msat, memo)?;
        let mut caveats = vec![format!("{PAYMENT_HASH_CAVEAT}={}", invoice.payment_hash)];
        caveats.extend(extra_caveats);
        let macaroon = Macaroon::mint(&self.root_key, token_id, &self.location, caveats);
        let header = format!(
            "{L402_SCHEME} macaroon=\"{}\", invoice=\"{}\"",
            macaroon.serialize(),
            invoice.bolt11
        );
        Ok((macaroon, invoice, header))
    }
}

/// Verifier-side L402 surface. Owns the root key so the macaroon HMAC
/// chain can be replayed without a database lookup.
pub struct L402Verifier {
    root_key: Vec<u8>,
}

impl L402Verifier {
    /// Build a new verifier. The root key must match the
    /// [`L402Issuer`]'s key for any macaroon to verify.
    pub fn new(root_key: Vec<u8>) -> Self {
        Self { root_key }
    }

    /// Parse and verify an `Authorization: L402 <macaroon>:<preimage>`
    /// header value. The supplied predicate is called on every caveat
    /// *other than* the `payment_hash=<hex>` caveat (the verifier
    /// owns that one). Operators wire `valid_until`, `route`, etc.
    /// here.
    pub fn verify(
        &self,
        header_value: &str,
        mut caveat_satisfied: impl FnMut(&str) -> bool,
    ) -> Result<Macaroon, L402Error> {
        let body = strip_scheme(header_value).ok_or(L402Error::MissingScheme)?;
        let (macaroon_b64, preimage_hex) = body
            .split_once(':')
            .ok_or(L402Error::MalformedAuthorization)?;
        let macaroon = Macaroon::deserialize(macaroon_b64.trim())
            .map_err(|e| L402Error::Macaroon(e.to_string()))?;
        let preimage =
            hex::decode(preimage_hex.trim()).map_err(|_| L402Error::MalformedPreimage)?;
        let expected_hash = hex::encode(Sha256::digest(&preimage));
        let mut payment_hash_seen = false;
        macaroon
            .verify(&self.root_key, |c| {
                if let Some(rest) = c.strip_prefix(&format!("{PAYMENT_HASH_CAVEAT}=")) {
                    payment_hash_seen = true;
                    return rest.eq_ignore_ascii_case(&expected_hash);
                }
                caveat_satisfied(c)
            })
            .map_err(|e| match e {
                MacaroonError::SignatureMismatch => L402Error::SignatureMismatch,
                MacaroonError::CaveatNotSatisfied(c) => {
                    if c.starts_with(&format!("{PAYMENT_HASH_CAVEAT}=")) {
                        L402Error::PaymentHashMismatch
                    } else {
                        L402Error::CaveatNotSatisfied(c)
                    }
                }
                other => L402Error::Macaroon(other.to_string()),
            })?;
        if !payment_hash_seen {
            return Err(L402Error::MissingPaymentHash);
        }
        Ok(macaroon)
    }
}

/// L402 verifier errors. Distinct variants so the auth handler can
/// pick the right WWW-Authenticate error code for the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L402Error {
    /// The header did not start with `L402 `.
    MissingScheme,
    /// The body after `L402 ` did not contain the `:` separator.
    MalformedAuthorization,
    /// The preimage segment was not hex-encoded.
    MalformedPreimage,
    /// The macaroon's HMAC chain did not verify against the root key.
    SignatureMismatch,
    /// The macaroon carried no `payment_hash=<hex>` caveat. Either
    /// the caller stripped it or the macaroon was minted by a
    /// non-L402 issuer.
    MissingPaymentHash,
    /// The macaroon's `payment_hash` caveat did not match
    /// `SHA-256(preimage)`, so the caller did not actually pay.
    PaymentHashMismatch,
    /// An operator-defined caveat (non-`payment_hash`) was not
    /// satisfied at verify time.
    CaveatNotSatisfied(String),
    /// Underlying macaroon decode / structural error.
    Macaroon(String),
}

impl std::fmt::Display for L402Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingScheme => write!(f, "Authorization header missing L402 scheme"),
            Self::MalformedAuthorization => write!(f, "L402 Authorization malformed"),
            Self::MalformedPreimage => write!(f, "L402 preimage is not hex"),
            Self::SignatureMismatch => write!(f, "L402 macaroon signature mismatch"),
            Self::MissingPaymentHash => write!(f, "L402 macaroon missing payment_hash caveat"),
            Self::PaymentHashMismatch => write!(f, "L402 preimage does not match payment_hash"),
            Self::CaveatNotSatisfied(c) => write!(f, "L402 caveat not satisfied: {c:?}"),
            Self::Macaroon(m) => write!(f, "L402 macaroon error: {m}"),
        }
    }
}

impl std::error::Error for L402Error {}

fn strip_scheme(header: &str) -> Option<&str> {
    let trimmed = header.trim();
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case(L402_SCHEME) {
        return None;
    }
    Some(parts.next()?.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic stub. `payment_hash` is the SHA-256 of `preimage`
    /// so the round-trip test can present a matching preimage on the
    /// retry without talking to a Lightning node.
    struct StubProvider {
        preimage: [u8; 32],
    }

    impl InvoiceProvider for StubProvider {
        fn create_invoice(&self, amount_msat: u64, memo: &str) -> Result<Invoice, InvoiceError> {
            let payment_hash = hex::encode(Sha256::digest(self.preimage));
            Ok(Invoice {
                bolt11: format!("lnbc{amount_msat}u1stub-{memo}"),
                payment_hash,
            })
        }
    }

    fn stub_issuer_and_verifier() -> (L402Issuer<StubProvider>, L402Verifier, [u8; 32]) {
        let root: Vec<u8> = b"unit-test-root-key-32-bytes-long!".to_vec();
        let preimage = [7u8; 32];
        let issuer = L402Issuer::new(
            root.clone(),
            "https://gateway.example/",
            StubProvider { preimage },
        );
        let verifier = L402Verifier::new(root);
        (issuer, verifier, preimage)
    }

    #[test]
    fn challenge_includes_macaroon_and_invoice_in_www_authenticate() {
        let (issuer, _, _) = stub_issuer_and_verifier();
        let (_, _, header) = issuer
            .challenge("tok-1", 1000, "read article", Vec::new())
            .expect("challenge");
        assert!(header.starts_with("L402 "));
        assert!(header.contains("macaroon=\""));
        assert!(header.contains("invoice=\"lnbc"));
    }

    #[test]
    fn round_trip_verify_succeeds_with_matching_preimage() {
        let (issuer, verifier, preimage) = stub_issuer_and_verifier();
        let (macaroon, _, _) = issuer
            .challenge("tok-1", 1000, "read article", Vec::new())
            .expect("challenge");
        let authz = format!("L402 {}:{}", macaroon.serialize(), hex::encode(preimage));
        let verified = verifier.verify(&authz, |_| true).expect("verify");
        assert_eq!(verified.identifier, "tok-1");
    }

    #[test]
    fn round_trip_verify_rejects_wrong_preimage() {
        let (issuer, verifier, _) = stub_issuer_and_verifier();
        let (macaroon, _, _) = issuer
            .challenge("tok-1", 1000, "read article", Vec::new())
            .expect("challenge");
        let bad_preimage = [9u8; 32];
        let authz = format!(
            "L402 {}:{}",
            macaroon.serialize(),
            hex::encode(bad_preimage)
        );
        match verifier.verify(&authz, |_| true) {
            Err(L402Error::PaymentHashMismatch) => {}
            other => panic!("expected PaymentHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn attenuation_passes_through_verify_when_extra_caveat_satisfied() {
        let (issuer, verifier, preimage) = stub_issuer_and_verifier();
        let (mut macaroon, _, _) = issuer
            .challenge("tok-1", 1000, "read article", Vec::new())
            .expect("challenge");
        // A holder narrows the macaroon to a sub-agent before sharing.
        macaroon
            .attenuate("audience=sub-agent-42")
            .expect("attenuate");
        let authz = format!("L402 {}:{}", macaroon.serialize(), hex::encode(preimage));
        verifier
            .verify(&authz, |c| {
                // Operator predicate: any audience caveat is OK in this test.
                c.starts_with("audience=")
            })
            .expect("verify after attenuate");
    }

    #[test]
    fn missing_scheme_returns_specific_error() {
        let (_, verifier, _) = stub_issuer_and_verifier();
        match verifier.verify("Bearer not-l402", |_| true) {
            Err(L402Error::MissingScheme) => {}
            other => panic!("expected MissingScheme, got {other:?}"),
        }
    }

    #[test]
    fn malformed_authorization_returns_specific_error() {
        let (_, verifier, _) = stub_issuer_and_verifier();
        match verifier.verify("L402 macaroon-but-no-colon", |_| true) {
            Err(L402Error::MalformedAuthorization) => {}
            other => panic!("expected MalformedAuthorization, got {other:?}"),
        }
    }

    #[test]
    fn tampered_macaroon_returns_signature_mismatch() {
        let (issuer, verifier, preimage) = stub_issuer_and_verifier();
        let (mut macaroon, _, _) = issuer
            .challenge("tok-1", 1000, "read article", Vec::new())
            .expect("challenge");
        // Attacker drops the payment_hash caveat without re-signing.
        macaroon.caveats.clear();
        let authz = format!("L402 {}:{}", macaroon.serialize(), hex::encode(preimage));
        match verifier.verify(&authz, |_| true) {
            Err(L402Error::SignatureMismatch) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn operator_caveat_unsatisfied_returns_named_error() {
        let (issuer, verifier, preimage) = stub_issuer_and_verifier();
        let (macaroon, _, _) = issuer
            .challenge("tok-1", 1000, "read article", vec!["scope=read".into()])
            .expect("challenge");
        let authz = format!("L402 {}:{}", macaroon.serialize(), hex::encode(preimage));
        match verifier.verify(&authz, |c| c != "scope=read") {
            Err(L402Error::CaveatNotSatisfied(c)) => assert_eq!(c, "scope=read"),
            other => panic!("expected CaveatNotSatisfied, got {other:?}"),
        }
    }
}
