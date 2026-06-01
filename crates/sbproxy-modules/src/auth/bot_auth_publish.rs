//! WOR-805 AC#4: publish SBproxy's own Web Bot Auth JWKS directory
//! and Signature Agent Card.
//!
//! The complementary side of the `bot_auth_directory` module: that
//! module FETCHES other agents' directories; this module BUILDS the
//! directory SBproxy serves at
//! `/.well-known/http-message-signatures-directory` so other Web Bot
//! Auth verifiers (Cloudflare, AWS WAF, third-party origins) can
//! discover the keys SBproxy signs outbound requests with.
//!
//! The published surface is two documents:
//!
//! 1. **Directory JWKS** (`application/http-message-signatures-directory+json`).
//!    JWKS-shaped per RFC 7517 plus the Web Bot Auth IETF draft's
//!    extensions: `key_ops: ["sign"]`, `tag: "web-bot-auth"`. Each
//!    key carries a `kid`, a `crv: "Ed25519"`, and the public-key
//!    bytes as `x` (base64url, unpadded).
//! 2. **Signature Agent Card**. The draft's discovery document at a
//!    well-known path (operator-configured) telling verifiers who
//!    this agent is, what scopes it covers, and where to find the
//!    directory.
//!
//! Both documents are pure-function builds: the operator supplies
//! the keypairs + identity at config time, this module composes the
//! JSON. The HTTP handlers that mount them at well-known paths
//! land in `sbproxy-core` in a follow-up; this PR is the
//! shape-validation surface.
//!
//! Self-signature on the directory body (RFC 9421 message signature
//! over the JSON response) is the third concern. The pure
//! signature math is already in `sbproxy-middleware::signatures`;
//! integrating it requires the HTTP response headers, so it lands
//! with the handler wiring.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// One Ed25519 public key, in the JWK shape the directory JWKS
/// publishes. The private side never crosses this boundary; the
/// operator-side signer holds it.
///
/// Fields that are constant for this module (`kty`, `crv`, `tag`)
/// are owned `String`s so the struct round-trips cleanly through
/// `serde` Deserialize; the constructor sets them to the canonical
/// values [`KTY_OKP`], [`CRV_ED25519`], [`TAG_WEB_BOT_AUTH`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryKey {
    /// JWK key type. Always [`KTY_OKP`] for keys built here.
    pub kty: String,
    /// Curve. Always [`CRV_ED25519`] for keys built here.
    pub crv: String,
    /// Public-key bytes (32 bytes), base64url-no-pad encoded per
    /// RFC 7518 §6.1.
    pub x: String,
    /// Key identifier. Caller-supplied; should be stable across
    /// rotations of unrelated keys so an old `keyid` reference in a
    /// signed request still resolves.
    pub kid: String,
    /// Allowed key operations. Web Bot Auth verifiers want
    /// `["sign"]`; we never publish a verify-only public key here.
    pub key_ops: Vec<String>,
    /// Tag the Web Bot Auth IETF draft uses to distinguish a
    /// directory-served key from a generic JWK. Always
    /// [`TAG_WEB_BOT_AUTH`] for keys built here.
    pub tag: String,
}

/// Canonical JWK `kty` value for Ed25519 published keys.
pub const KTY_OKP: &str = "OKP";

/// Canonical JWK `crv` value for Ed25519 published keys.
pub const CRV_ED25519: &str = "Ed25519";

/// Canonical Web Bot Auth `tag` value the draft pins for
/// directory-served signing keys.
pub const TAG_WEB_BOT_AUTH: &str = "web-bot-auth";

impl DirectoryKey {
    /// Build a directory-shaped JWK from an Ed25519 public key.
    ///
    /// `public_key_bytes` MUST be the 32-byte raw public key. The
    /// caller is responsible for keeping the private side outside
    /// this module.
    pub fn from_ed25519(public_key_bytes: &[u8; 32], kid: impl Into<String>) -> Self {
        Self {
            kty: KTY_OKP.to_string(),
            crv: CRV_ED25519.to_string(),
            x: URL_SAFE_NO_PAD.encode(public_key_bytes),
            kid: kid.into(),
            key_ops: vec!["sign".to_string()],
            tag: TAG_WEB_BOT_AUTH.to_string(),
        }
    }
}

/// The JWKS-shaped directory document. JSON-encodes as
/// `{"keys": [...]}` matching what the Web Bot Auth IETF draft and
/// generic JWKS consumers expect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryDocument {
    /// Published keys. One entry per active Ed25519 signing key. A
    /// rotation publishes both the outgoing and incoming key
    /// simultaneously so signed requests verify across the cutover
    /// window.
    pub keys: Vec<DirectoryKey>,
}

impl DirectoryDocument {
    /// Build a directory document from a list of (public key, kid)
    /// pairs.
    pub fn build<I, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = ([u8; 32], K)>,
        K: Into<String>,
    {
        Self {
            keys: entries
                .into_iter()
                .map(|(pk, kid)| DirectoryKey::from_ed25519(&pk, kid))
                .collect(),
        }
    }

    /// JSON-encode the document to a `String` ready to ship in the
    /// HTTP response body. Stable byte representation across calls
    /// because the field order is fixed by the struct definition.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("DirectoryDocument always serialises")
    }
}

/// SBproxy's Signature Agent Card. Per the Web Bot Auth IETF draft
/// the card is a discovery document at a well-known path naming
/// the agent, the directory URL, and a description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureAgentCard {
    /// Operator-facing display name. Free text, intended for the
    /// "who is signing this request?" UX in a verifier's audit log.
    pub name: String,
    /// URL of the directory JWKS the card points at. Operators
    /// usually mount the directory at the operator's own origin;
    /// the card may sit on a different host (vendor docs site, for
    /// example), so the URL is operator-supplied rather than
    /// derived.
    pub directory_url: String,
    /// Optional description. Verifiers display it next to the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional operator contact URL (mailto:, https://, etc.) so a
    /// verifier that wants to report misuse has a person to reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_url: Option<String>,
}

impl SignatureAgentCard {
    /// Build a card from minimal config. The two optional fields
    /// are set via the builder methods.
    pub fn new(name: impl Into<String>, directory_url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            directory_url: directory_url.into(),
            description: None,
            contact_url: None,
        }
    }

    /// Builder: attach a description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Builder: attach a contact URL.
    pub fn with_contact_url(mut self, url: impl Into<String>) -> Self {
        self.contact_url = Some(url.into());
        self
    }

    /// JSON-encode to a body-ready `String`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("SignatureAgentCard always serialises")
    }
}

/// Self-sign a directory or agent-card HTTP response body per
/// RFC 9421 over `("content-digest")` with `tag="web-bot-auth"`.
///
/// Returns the three response headers a Web Bot Auth verifier needs
/// to confirm the body came from the holder of the published key:
/// `Content-Digest`, `Signature-Input`, and `Signature`. The covered
/// component set is intentionally minimal — only `content-digest` —
/// so the helper works equally well for the JWKS directory and the
/// agent card without depending on response-side derived components
/// (`@status` is not yet supported by the shared signature-base
/// builder, which is request-oriented).
///
/// `seed` is the 32-byte raw Ed25519 secret seed (the private half
/// of the keypair whose public half the directory advertises).
/// `key_id` MUST match the `kid` on the published JWK so a verifier
/// looking up `Signature-Input`'s `keyid=` finds the right key.
///
/// Failures fall into two categories: malformed input (the body is
/// empty, or the operator-supplied seed is the wrong length) and
/// internal signer errors (essentially impossible given how the
/// inputs are validated up front; surfaced as `String` so the
/// caller can log them without pulling in the signer's error
/// type).
pub fn sign_directory_response(
    seed: &[u8; 32],
    key_id: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, String> {
    use sbproxy_middleware::signatures::SignatureAlgorithm;
    use sbproxy_middleware::signatures_egress::{MessageSigner, SignerConfig};

    if body.is_empty() {
        // RFC 9421 §2.1 forbids covering a component that is not
        // present on the message; the signer would silently drop
        // `content-digest` from the covered set and emit a
        // signature with zero covered components. Refuse instead.
        return Err("sign_directory_response: empty body".to_string());
    }
    if key_id.is_empty() {
        return Err("sign_directory_response: empty key_id".to_string());
    }

    let signer = MessageSigner::new(SignerConfig {
        key_id: key_id.to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        secret: seed.to_vec(),
        covered_components: vec!["content-digest".to_string()],
    })
    .map_err(|e| format!("sign_directory_response: signer init: {e}"))?
    .with_web_bot_auth_profile("web-bot-auth", 60);

    // The signature base for a response covering only `content-digest`
    // depends solely on the body bytes; building the signer's request
    // shape with a placeholder URI is harmless because no @-prefixed
    // derived component is in the covered set.
    let req = http::Request::builder()
        .method("GET")
        .uri("https://signed-body.invalid/")
        .body(bytes::Bytes::copy_from_slice(body))
        .map_err(|e| format!("sign_directory_response: build req: {e}"))?;

    let signed = signer
        .sign_request(req)
        .map_err(|e| format!("sign_directory_response: sign: {e}"))?;

    let mut out: Vec<(String, String)> = Vec::with_capacity(3);
    for name in ["content-digest", "signature-input", "signature"] {
        if let Some(v) = signed.headers().get(name).and_then(|v| v.to_str().ok()) {
            out.push((name.to_string(), v.to_string()));
        } else {
            return Err(format!("sign_directory_response: signer omitted {name}"));
        }
    }
    Ok(out)
}

/// Validate that an operator-supplied directory URL is acceptable
/// for publishing. Web Bot Auth verifiers MUST refuse plaintext
/// directories; the publish side enforces the same invariant so an
/// operator does not silently ship a misconfigured directory_url
/// in the card.
pub fn validate_directory_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("directory_url cannot be empty".to_string());
    }
    if !url.starts_with("https://") {
        return Err(format!(
            "directory_url must be https:// (got {url:?}; plaintext directories are rejected by every Web Bot Auth verifier)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pk() -> [u8; 32] {
        // Deterministic key; the bytes don't have to verify, this
        // module never signs.
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        k
    }

    #[test]
    fn directory_key_carries_required_fields() {
        let key = DirectoryKey::from_ed25519(&sample_pk(), "key-2026-05-31");
        assert_eq!(key.kty, "OKP");
        assert_eq!(key.crv, "Ed25519");
        assert_eq!(key.kid, "key-2026-05-31");
        assert_eq!(key.key_ops, vec!["sign".to_string()]);
        assert_eq!(key.tag, "web-bot-auth");
        // `x` is the base64url-no-pad encoding of the 32-byte key.
        let decoded = URL_SAFE_NO_PAD.decode(&key.x).unwrap();
        assert_eq!(decoded, sample_pk());
    }

    #[test]
    fn directory_document_serialises_to_expected_shape() {
        let doc = DirectoryDocument::build(vec![(sample_pk(), "key-A"), (sample_pk(), "key-B")]);
        let json = doc.to_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["keys"].is_array());
        assert_eq!(v["keys"].as_array().unwrap().len(), 2);
        assert_eq!(v["keys"][0]["kid"], "key-A");
        assert_eq!(v["keys"][1]["kid"], "key-B");
        assert_eq!(v["keys"][0]["kty"], "OKP");
        assert_eq!(v["keys"][0]["crv"], "Ed25519");
        assert_eq!(v["keys"][0]["tag"], "web-bot-auth");
    }

    #[test]
    fn directory_document_round_trips_through_serde() {
        let doc = DirectoryDocument::build(vec![(sample_pk(), "kid-1")]);
        let json = doc.to_json();
        let parsed: DirectoryDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn empty_directory_is_legal() {
        let doc = DirectoryDocument::build(Vec::<([u8; 32], String)>::new());
        let json = doc.to_json();
        assert!(json.contains("\"keys\":[]"));
    }

    #[test]
    fn signature_agent_card_minimal_shape() {
        let card = SignatureAgentCard::new(
            "sbproxy",
            "https://example.com/.well-known/http-message-signatures-directory",
        );
        let v: serde_json::Value = serde_json::from_str(&card.to_json()).unwrap();
        assert_eq!(v["name"], "sbproxy");
        assert_eq!(
            v["directory_url"],
            "https://example.com/.well-known/http-message-signatures-directory"
        );
        assert!(v.get("description").is_none());
        assert!(v.get("contact_url").is_none());
    }

    #[test]
    fn signature_agent_card_builder_attaches_optionals() {
        let card = SignatureAgentCard::new("sbproxy", "https://example.com/dir")
            .with_description("AI gateway")
            .with_contact_url("mailto:abuse@example.com");
        let v: serde_json::Value = serde_json::from_str(&card.to_json()).unwrap();
        assert_eq!(v["description"], "AI gateway");
        assert_eq!(v["contact_url"], "mailto:abuse@example.com");
    }

    #[test]
    fn validate_directory_url_accepts_https() {
        assert!(validate_directory_url("https://example.com/.well-known/...").is_ok());
    }

    #[test]
    fn validate_directory_url_rejects_plaintext() {
        let err = validate_directory_url("http://example.com/.well-known/...").unwrap_err();
        assert!(err.contains("https"));
    }

    #[test]
    fn validate_directory_url_rejects_empty() {
        assert!(validate_directory_url("").is_err());
    }

    fn sample_seed() -> [u8; 32] {
        // Deterministic seed so the test does not rely on entropy.
        // The matching public key falls out of ed25519-dalek; tests
        // below derive it on the fly rather than hard-coding it.
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(3);
        }
        k
    }

    #[test]
    fn sign_directory_response_emits_three_headers() {
        let headers =
            sign_directory_response(&sample_seed(), "kid-1", b"{\"keys\":[]}").expect("sign");
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["content-digest", "signature-input", "signature"]
        );
        let by_name: std::collections::HashMap<_, _> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        // sha-256=:...: per RFC 9530 §3
        assert!(by_name["content-digest"].starts_with("sha-256=:"));
        // Signature-Input advertises the Web Bot Auth tag and the
        // operator-configured kid.
        assert!(by_name["signature-input"].contains("tag=\"web-bot-auth\""));
        assert!(by_name["signature-input"].contains("keyid=\"kid-1\""));
        assert!(by_name["signature-input"].contains("\"content-digest\""));
        // RFC 9421 dictionary entry with the canonical sig1 label.
        assert!(by_name["signature"].starts_with("sig1=:"));
    }

    #[test]
    fn sign_directory_response_round_trips_through_verifier() {
        use ed25519_dalek::SigningKey;
        use sbproxy_middleware::signatures::{
            MessageSignatureConfig, MessageSignatureVerifier, SignatureAlgorithm, VerifyVerdict,
        };

        let seed = sample_seed();
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let body = b"{\"keys\":[{\"kid\":\"kid-1\"}]}";
        let headers = sign_directory_response(&seed, "kid-1", body).expect("sign");

        // Reassemble the signed response as a `Request<Bytes>` so the
        // existing inbound verifier can check it. The verifier covers
        // only header-based components, so `content-digest` + the
        // round-trip works out of the box.
        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://signed-body.invalid/")
            .body(bytes::Bytes::copy_from_slice(body))
            .unwrap();
        for (name, value) in &headers {
            req.headers_mut().insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }

        let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "kid-1".to_string(),
            key: hex::encode(verifying_key.to_bytes()),
            required_components: vec!["content-digest".to_string()],
            clock_skew_seconds: 30,
        })
        .expect("verifier");
        match verifier.verify_request(&req) {
            VerifyVerdict::Ok { .. } => {}
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn sign_directory_response_rejects_empty_body() {
        let err = sign_directory_response(&sample_seed(), "kid-1", b"").unwrap_err();
        assert!(err.contains("empty body"), "got: {err}");
    }

    #[test]
    fn sign_directory_response_rejects_empty_key_id() {
        let err = sign_directory_response(&sample_seed(), "", b"x").unwrap_err();
        assert!(err.contains("empty key_id"), "got: {err}");
    }
}
