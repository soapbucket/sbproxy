//! WOR-807: macaroon bearer credentials (Birgisson et al. 2014).
//!
//! Macaroons are HMAC-chained bearer credentials that support
//! delegation through *attenuation*: any holder can mint a narrower
//! macaroon by appending a caveat and extending the HMAC chain. The
//! verifier recomputes the chain from the root key and confirms every
//! caveat against operator-supplied predicates. Aperture's L402 spec
//! (`crate::l402`) uses macaroons as the bearer half of its Lightning
//! 402 flow; this module is the pure protocol primitive.
//!
//! # Wire shape
//!
//! ```text
//! macaroon ::= identifier || location || caveats* || signature
//!   identifier : byte string the issuer assigns to bind the macaroon
//!                to issued state (typically a token id).
//!   location   : the verifier's URL or label so a holder can find the
//!                right verifier when multiple macaroons mix.
//!   caveats    : list of byte strings; each one further restricts the
//!                authority the macaroon confers.
//!   signature  : 32-byte HMAC-SHA256 chain over (identifier, caveats...).
//! ```
//!
//! The signature is computed as:
//!
//! ```text
//!   sig_0     = HMAC(root_key, identifier)
//!   sig_{i+1} = HMAC(sig_i, caveat_i)
//! ```
//!
//! so any holder who knows `sig_i` can extend the chain with a new
//! caveat without knowing the root key. The verifier replays the same
//! computation; if the result matches the macaroon's `signature` it
//! has not been forged and every caveat in the list was added by
//! someone holding the root key or an earlier intermediate signature.
//!
//! # Serialisation
//!
//! [`Macaroon::serialize`] produces a base64url-no-pad-encoded JSON
//! body. The JSON shape is intentionally simple; this module is a
//! self-contained protocol primitive, not a libmacaroons-binary-format
//! mirror. A future drop-in compatibility layer for the Aperture wire
//! format slots in alongside without touching the verifier.
//!
//! # Caveats
//!
//! Caveats are opaque byte strings on the wire. The
//! [`crate::l402`] layer parses them as `key=value` strings (e.g.
//! `payment_hash=abc123`, `valid_until=1700000000`). The verifier
//! takes a closure that decides whether a caveat is satisfied at
//! verify-time so the protocol layer does not have to teach this
//! module any L402 semantics.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A macaroon. Built via [`Macaroon::mint`] then extended via
/// [`Macaroon::attenuate`]. The signature is recomputed on every
/// attenuation so the holder never has to re-supply the root key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Macaroon {
    /// Identifier the issuer assigns; typically the token id bound to
    /// the Lightning invoice on the L402 mint path.
    pub identifier: String,
    /// Verifier location label so a holder mixing macaroons from
    /// multiple verifiers can pick the right one. Free-form, but
    /// conventionally a URL or hostname.
    pub location: String,
    /// First-party caveats added by the issuer or any subsequent
    /// holder via [`Macaroon::attenuate`]. Each entry is matched by
    /// the verifier closure passed to
    /// [`Macaroon::verify`].
    pub caveats: Vec<String>,
    /// HMAC-SHA256 chain over `(identifier, caveats...)`. The
    /// verifier recomputes this from the root key + the wire data.
    /// Hex-encoded so the serialised form is human-readable.
    pub signature: String,
}

impl Macaroon {
    /// Mint a new macaroon from a root key, identifier, location, and
    /// initial caveat set. The caveats are applied in declaration
    /// order so the resulting signature chain matches what the
    /// verifier will compute.
    pub fn mint(
        root_key: &[u8],
        identifier: impl Into<String>,
        location: impl Into<String>,
        caveats: Vec<String>,
    ) -> Self {
        let identifier = identifier.into();
        let mut chain = hmac_round(root_key, identifier.as_bytes());
        for c in &caveats {
            chain = hmac_round(&chain, c.as_bytes());
        }
        Self {
            identifier,
            location: location.into(),
            caveats,
            signature: hex::encode(chain),
        }
    }

    /// Attenuate the macaroon by appending a new first-party caveat
    /// and extending the signature chain. Does not require the root
    /// key, only the current signature.
    ///
    /// Returns an error if the current signature is not the
    /// canonical 32-byte HMAC output (i.e. the macaroon was crafted
    /// with junk in `signature`).
    pub fn attenuate(&mut self, caveat: impl Into<String>) -> Result<(), MacaroonError> {
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| MacaroonError::MalformedSignature("not hex".into()))?;
        if sig_bytes.len() != 32 {
            return Err(MacaroonError::MalformedSignature(format!(
                "expected 32 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let caveat = caveat.into();
        let new_sig = hmac_round(&sig_bytes, caveat.as_bytes());
        self.caveats.push(caveat);
        self.signature = hex::encode(new_sig);
        Ok(())
    }

    /// Verify the macaroon's signature chain against the root key and
    /// then check every caveat with the supplied predicate. The
    /// predicate returns the caveat verdict; the verifier short-
    /// circuits on the first unsatisfied caveat.
    ///
    /// The two failure modes are deliberately distinct so the caller
    /// can log "tampered macaroon" vs "valid but unsatisfied" cleanly.
    pub fn verify(
        &self,
        root_key: &[u8],
        mut caveat_satisfied: impl FnMut(&str) -> bool,
    ) -> Result<(), MacaroonError> {
        let mut chain = hmac_round(root_key, self.identifier.as_bytes());
        for c in &self.caveats {
            chain = hmac_round(&chain, c.as_bytes());
        }
        let expected = hex::encode(chain);
        if !constant_time_eq(expected.as_bytes(), self.signature.as_bytes()) {
            return Err(MacaroonError::SignatureMismatch);
        }
        for c in &self.caveats {
            if !caveat_satisfied(c) {
                return Err(MacaroonError::CaveatNotSatisfied(c.clone()));
            }
        }
        Ok(())
    }

    /// Serialise to a base64url-no-pad-encoded JSON body. Designed
    /// for the L402 wire shape where the macaroon is embedded in the
    /// `WWW-Authenticate` / `Authorization` header as a single token.
    pub fn serialize(&self) -> String {
        let json = serde_json::to_vec(self).expect("macaroon always serialises");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    /// Parse a macaroon from a base64url-no-pad-encoded JSON body.
    pub fn deserialize(token: &str) -> Result<Self, MacaroonError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.trim())
            .map_err(|e| MacaroonError::Decode(format!("base64: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| MacaroonError::Decode(format!("json: {e}")))
    }
}

/// Errors the macaroon primitive can produce. Distinct variants so
/// the L402 wrapper can map each to the right WWW-Authenticate error
/// code.
#[derive(Debug, Clone)]
pub enum MacaroonError {
    /// The signature chain did not match the recomputed value, so the
    /// macaroon was forged or corrupted.
    SignatureMismatch,
    /// A caveat was syntactically present but the predicate returned
    /// `false` for it; the macaroon is authentic but no longer
    /// authoritative for the current request.
    CaveatNotSatisfied(String),
    /// The signature stored on the macaroon is not 32-byte hex.
    /// Surfaces only when an attenuation call sees junk; the verifier
    /// path treats it the same as `SignatureMismatch` and only this
    /// variant is returned from [`Macaroon::attenuate`].
    MalformedSignature(String),
    /// A serialised macaroon failed base64 or JSON decode.
    Decode(String),
}

impl std::fmt::Display for MacaroonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureMismatch => write!(f, "macaroon signature mismatch"),
            Self::CaveatNotSatisfied(c) => write!(f, "macaroon caveat not satisfied: {c:?}"),
            Self::MalformedSignature(d) => write!(f, "macaroon signature malformed: {d}"),
            Self::Decode(d) => write!(f, "macaroon decode failed: {d}"),
        }
    }
}

impl std::error::Error for MacaroonError {}

fn hmac_round(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Constant-time byte slice equality. Local copy so this module
/// does not pull in a fresh `subtle` dep just for one byte compare;
/// `sbproxy-middleware` already lives below the HMAC layer so the
/// subtle behaviour matters.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &[u8] = b"unit-test-root-key-32-bytes-long!";

    #[test]
    fn mint_and_verify_round_trips() {
        let m = Macaroon::mint(
            ROOT,
            "tok-1",
            "https://verifier.example.com/",
            vec!["scope=read".into(), "valid_until=99999999999".into()],
        );
        assert_eq!(m.identifier, "tok-1");
        assert_eq!(m.caveats.len(), 2);
        assert_eq!(m.signature.len(), 64);
        m.verify(ROOT, |_| true).expect("verify");
    }

    #[test]
    fn attenuation_extends_chain_without_root_key() {
        let mut m = Macaroon::mint(ROOT, "tok-1", "x", vec!["scope=read".into()]);
        let sig_before = m.signature.clone();
        m.attenuate("audience=alice").expect("attenuate");
        assert_eq!(m.caveats, vec!["scope=read", "audience=alice"]);
        assert_ne!(m.signature, sig_before);
        // The verifier still validates because the chain was extended
        // correctly from the prior signature.
        m.verify(ROOT, |_| true).expect("verify after attenuate");
    }

    #[test]
    fn tampered_caveat_breaks_verification() {
        let mut m = Macaroon::mint(ROOT, "tok-1", "x", vec!["scope=read".into()]);
        m.caveats[0] = "scope=admin".into();
        match m.verify(ROOT, |_| true) {
            Err(MacaroonError::SignatureMismatch) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn appended_caveat_without_chain_extension_breaks_verification() {
        // Attacker copies the macaroon and adds a caveat without
        // extending the signature chain. The verifier MUST reject.
        let mut m = Macaroon::mint(ROOT, "tok-1", "x", vec!["scope=read".into()]);
        m.caveats.push("audience=anyone".into()); // signature untouched
        match m.verify(ROOT, |_| true) {
            Err(MacaroonError::SignatureMismatch) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unsatisfied_caveat_returns_named_error() {
        let m = Macaroon::mint(ROOT, "tok-1", "x", vec!["scope=read".into()]);
        match m.verify(ROOT, |c| c != "scope=read") {
            Err(MacaroonError::CaveatNotSatisfied(c)) => assert_eq!(c, "scope=read"),
            other => panic!("expected CaveatNotSatisfied, got {other:?}"),
        }
    }

    #[test]
    fn serialise_round_trips() {
        let m = Macaroon::mint(
            ROOT,
            "tok-1",
            "https://verifier.example.com/",
            vec!["a=1".into(), "b=2".into()],
        );
        let wire = m.serialize();
        let parsed = Macaroon::deserialize(&wire).expect("parse");
        assert_eq!(parsed, m);
        parsed
            .verify(ROOT, |_| true)
            .expect("verify after round-trip");
    }

    #[test]
    fn deserialize_rejects_garbage() {
        match Macaroon::deserialize("not base64 ::::") {
            Err(MacaroonError::Decode(_)) => {}
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn wrong_root_key_does_not_verify() {
        let m = Macaroon::mint(ROOT, "tok-1", "x", vec!["scope=read".into()]);
        match m.verify(b"other-root-key", |_| true) {
            Err(MacaroonError::SignatureMismatch) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn attenuation_rejects_malformed_signature() {
        let mut m = Macaroon::mint(ROOT, "tok-1", "x", vec!["a=1".into()]);
        m.signature = "not hex!!".into();
        match m.attenuate("b=2") {
            Err(MacaroonError::MalformedSignature(_)) => {}
            other => panic!("expected MalformedSignature, got {other:?}"),
        }
    }
}
