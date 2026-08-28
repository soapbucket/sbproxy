//! RFC 8705 §3 mTLS certificate-bound access tokens.
//!
//! RFC 8705 specifies two ways to sender-constrain an OAuth access
//! token using a client X.509 certificate that the TLS terminator
//! observed during the request handshake:
//!
//!   * §3 "Mutual-TLS Client Certificate-Bound Access Tokens" wires
//!     the SHA-256 thumbprint of the DER-encoded client certificate
//!     into the access token via a `cnf` claim with member
//!     `x5t#S256`.
//!   * §3.2 declares that protected resources MUST validate the
//!     binding on every request by recomputing the thumbprint from
//!     the connection-time client cert and comparing it to the value
//!     inside the token.
//!
//! This module ships the broker-side primitives both sides of the
//! flow need:
//!
//!   * [`client_cert_thumbprint`] - base64url-no-pad SHA-256 of the
//!     DER-encoded client certificate. The exact `x5t#S256` value
//!     RFC 8705 §3.1 demands.
//!   * [`inject_cnf_x5t_s256`] - mirror of `token::inject_cnf_jkt`
//!     for the mTLS path. Decorates the upstream's wrapper response
//!     by freshly re-signing a JWT with `cnf.x5t#S256`; opaque tokens
//!     and missing broker signing keys fail closed.
//!
//! Production request handling accepts only [`VerifiedClientCertificate`]
//! inserted by the host from its verified TLS connection. Raw XFCC
//! parsing exists under `cfg(test)` solely as parser regression coverage;
//! an arbitrary inbound forwarded header is never an identity signal.

#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
use axum::http::HeaderMap;
use base64::Engine;
use sha2::{Digest, Sha256};

/// HTTP header carrying the forwarded client certificate. The header
/// name follows the Envoy + Istio convention so deployers can put a
/// TLS-terminating proxy in front of the broker without inventing a
/// bespoke channel. RFC 8705 itself is silent on the in-process hand-
/// off; the IETF has documented the same XFCC shape in
/// `draft-ietf-httpapi-client-cert-field` so it is the safest
/// portable choice.
#[cfg(test)]
const CLIENT_CERT_HEADER: &str = "x-forwarded-client-cert";

/// Certificate identity established by the TLS stack or by a caller
/// that already enforced its configured trusted-proxy boundary.
#[derive(Clone, Debug)]
pub struct VerifiedClientCertificate {
    /// RFC 8705 `x5t#S256` of the verified leaf certificate.
    pub x5t_s256: String,
}

/// Compute the RFC 8705 §3.1 `x5t#S256` thumbprint over a DER-encoded
/// X.509 certificate: base64url-no-pad of SHA-256(DER).
///
/// `der` is the binary certificate, not PEM and not base64. Callers
/// holding a PEM-shaped cert must strip the `-----BEGIN/END
/// CERTIFICATE-----` armor and base64-decode the body first.
pub fn client_cert_thumbprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Pull a DER-encoded client certificate out of the inbound request.
///
/// Returns `Some(der_bytes)` when the request carries an
/// `x-forwarded-client-cert` header in one of the two on-the-wire
/// shapes the wider ecosystem uses:
///
///   * **Envoy XFCC**: `By=...;Hash=...;Cert="<URL-encoded PEM>";...`
///     Multiple semicolon-delimited key=value pairs per certificate,
///     comma-delimited certificates. We read the first cert's `Cert`
///     value, URL-decode it, then strip the PEM armor and base64-
///     decode the body.
///   * **Raw base64 DER**: the header is just the standard or
///     URL-safe base64 representation of the DER. Used by simpler
///     terminators (NGINX `$ssl_client_raw_cert` after manual base64
///     encoding) and by our own tests.
///
/// Returns `None` when the header is absent, empty, or unparseable.
/// The caller decides whether absence is fatal; for introspection-
/// time verification absence on a `cnf.x5t#S256`-carrying token is
/// fatal, but a token with no `cnf.x5t#S256` (typical bearer client)
/// does not need a cert at all.
#[cfg(test)]
fn extract_client_cert_der(headers: &HeaderMap) -> Option<Vec<u8>> {
    let raw = headers
        .get(CLIENT_CERT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;

    // Try Envoy XFCC first. The signal is the presence of `Cert=` or
    // `Chain=` keys. Both carry a URL-encoded PEM.
    if raw.contains("Cert=") || raw.contains("Chain=") {
        return parse_xfcc_cert(raw);
    }

    // Fallback: raw base64 DER. Accept both URL-safe and standard
    // alphabets, with or without padding, so callers that only know
    // one encoding still work.
    decode_base64_loose(raw)
}

/// Inject `cnf.x5t#S256` into the upstream's JSON token response.
///
/// Mirrors [`crate::token::inject_cnf_jkt`] for the mTLS path:
///
///   * **JWT access_token + no broker signing key:** fail closed.
///     Resource servers consult the signed `cnf` claim, and the broker
///     cannot create one without a signing key.
///   * **JWT access_token + broker signing key:** re-issue the token
///     with a signed `cnf.x5t#S256` claim and fresh broker timestamps.
///   * **Opaque access_token or malformed/non-object body:** fail
///     closed because this provider verifies signed JWT claims.
pub fn inject_cnf_x5t_s256(
    body: &bytes::Bytes,
    cert_der: &[u8],
    broker_signing_key: Option<&crate::config::JwkKey>,
    broker_issuer: &str,
) -> Result<bytes::Bytes, MtlsBindingError> {
    inject_cnf_x5t_s256_thumbprint(
        body,
        &client_cert_thumbprint(cert_der),
        broker_signing_key,
        broker_issuer,
    )
}

/// Re-issue a JWT access token with a signed RFC 8705 certificate
/// thumbprint derived from verified connection identity.
pub fn inject_cnf_x5t_s256_thumbprint(
    body: &bytes::Bytes,
    thumbprint: &str,
    broker_signing_key: Option<&crate::config::JwkKey>,
    broker_issuer: &str,
) -> Result<bytes::Bytes, MtlsBindingError> {
    let body_is_secret_reference = std::str::from_utf8(body)
        .ok()
        .is_some_and(sbproxy_vault::looks_like_secret_reference_uri);
    if body_is_secret_reference {
        return Err(MtlsBindingError::PayloadInvalid(
            "upstream token response is a secret reference".to_string(),
        ));
    }
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| MtlsBindingError::PayloadInvalid(format!("upstream body: {e}")))?;
    let obj = value.as_object_mut().ok_or_else(|| {
        MtlsBindingError::PayloadInvalid(
            "upstream token response must be a JSON object".to_string(),
        )
    })?;
    let access_token = obj
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let token_is_jwt = access_token
        .as_deref()
        .map(|t| t.split('.').count() == 3)
        .unwrap_or(false);
    if !token_is_jwt {
        return Err(MtlsBindingError::PayloadInvalid(
            "mTLS binding requires a JWT access token".to_string(),
        ));
    }
    let signing_key = broker_signing_key.ok_or_else(|| {
        MtlsBindingError::PayloadInvalid(
            "mTLS binding requires a configured broker signing key".to_string(),
        )
    })?;
    let access_token = access_token.ok_or_else(|| {
        MtlsBindingError::PayloadInvalid("upstream response missing access_token".to_string())
    })?;
    let mut cnf_map = signed_cnf_from_token(&access_token)?;
    cnf_map.insert(
        "x5t#S256".to_string(),
        serde_json::Value::String(thumbprint.to_string()),
    );
    let mut mutations = serde_json::Map::new();
    mutations.insert("cnf".to_string(), serde_json::Value::Object(cnf_map));
    let resigned =
        crate::at_jwt::resign_at_jwt(&access_token, signing_key, broker_issuer, &mutations)
            .map_err(|e| MtlsBindingError::PayloadInvalid(e.to_string()))?;
    obj.insert(
        "access_token".to_string(),
        serde_json::Value::String(resigned),
    );
    obj.remove("cnf");
    let serialized = serde_json::to_vec(&value)
        .map_err(|e| MtlsBindingError::PayloadInvalid(format!("serialize body: {e}")))?;
    Ok(bytes::Bytes::from(serialized))
}

pub(crate) fn signed_cnf_from_token(
    token: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, MtlsBindingError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| MtlsBindingError::PayloadInvalid("access token is not a JWT".to_string()))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| MtlsBindingError::PayloadInvalid(format!("JWT payload decode failed: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| MtlsBindingError::PayloadInvalid(format!("JWT payload invalid: {e}")))?;
    match claims.get("cnf") {
        None => Ok(serde_json::Map::new()),
        Some(serde_json::Value::Object(map)) => Ok(map.clone()),
        Some(_) => Err(MtlsBindingError::PayloadInvalid(
            "upstream cnf claim is not a JSON object".to_string(),
        )),
    }
}

/// Verify an inbound token whose claim set carries `cnf.x5t#S256`.
///
/// `claims` is the JSON object the introspection endpoint resolved
/// for the token (whether by upstream introspection or by local
/// RFC 9068 JWT decode). `headers` is the live request's header map
/// so we can pull the client cert off the wire.
///
/// Returns:
///
///   * `Ok(true)` when no `cnf.x5t#S256` is present (back-compat for
///     non-mTLS bearer tokens; the caller is expected to fall back
///     to whatever bearer policy applies).
///   * `Ok(true)` when `cnf.x5t#S256` matches the live request's
///     client cert thumbprint.
///   * `Err(MtlsBindingError::MissingClientCert)` when the token
///     carries `cnf.x5t#S256` but the request has no client cert.
///   * `Err(MtlsBindingError::ThumbprintMismatch)` when the
///     thumbprints disagree.
///   * `Err(MtlsBindingError::PayloadInvalid)` when the claim is
///     shaped unexpectedly (e.g. not a string).
///
/// Mapping to RFC 8705 §3 wire behavior: every `Err` here is an
/// `invalid_token` rejection at the HTTP layer.
#[cfg(test)]
fn verify_cnf_x5t_s256(
    claims: &serde_json::Value,
    headers: &HeaderMap,
) -> Result<bool, MtlsBindingError> {
    let actual = extract_client_cert_der(headers).map(|der| client_cert_thumbprint(&der));
    verify_cnf_x5t_s256_thumbprint(claims, actual.as_deref())
}

/// Verify a signed `cnf.x5t#S256` claim against certificate identity
/// already established by the host TLS stack.
pub(crate) fn verify_cnf_x5t_s256_thumbprint(
    claims: &serde_json::Value,
    verified_thumbprint: Option<&str>,
) -> Result<bool, MtlsBindingError> {
    let Some(expected) = claims.get("cnf").and_then(|c| c.get("x5t#S256")) else {
        // Back-compat: no binding => not our concern.
        return Ok(true);
    };
    let expected = expected.as_str().ok_or_else(|| {
        MtlsBindingError::PayloadInvalid("cnf.x5t#S256 must be a JSON string".to_string())
    })?;
    let actual = verified_thumbprint.ok_or(MtlsBindingError::MissingClientCert)?;
    // Constant-time compare to avoid leaking the per-byte position
    // of a mismatch via timing. The thumbprints are public values
    // but the comparison cadence is cheap insurance.
    if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        return Err(MtlsBindingError::ThumbprintMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(true)
}

// --- Errors ---

/// Failure modes for the mTLS binding flow. Every variant maps to
/// `invalid_token` (or `invalid_request` for payload shape errors)
/// at the HTTP layer.
#[derive(Debug, thiserror::Error)]
pub enum MtlsBindingError {
    /// Token advertised `cnf.x5t#S256` but the request carried no
    /// usable client certificate (header absent, empty, or
    /// unparseable).
    #[error("token carries cnf.x5t#S256 but request has no client certificate")]
    MissingClientCert,
    /// Thumbprints did not agree. RFC 8705 §3 specifies
    /// `invalid_token`.
    #[error(
        "client cert thumbprint mismatch: token expected {expected}, request presented {actual}"
    )]
    ThumbprintMismatch {
        /// The `cnf.x5t#S256` thumbprint carried on the token.
        expected: String,
        /// The thumbprint computed from the request's actual client
        /// certificate.
        actual: String,
    },
    /// The token claim payload was shaped in a way we could not
    /// process (e.g. cnf.x5t#S256 was not a string, upstream body
    /// was not JSON, cnf existed but was not an object).
    #[error("payload invalid: {0}")]
    PayloadInvalid(String),
}

// --- XFCC parsing ---

/// Parse an Envoy-style XFCC header value. We accept the first
/// `Cert=` (the leaf cert as URL-encoded PEM). Multi-cert headers
/// (multiple comma-separated entries) are treated as a chain and we
/// take the leaf at position 0.
#[cfg(test)]
fn parse_xfcc_cert(raw: &str) -> Option<Vec<u8>> {
    // Each comma-separated section is one cert in the chain.
    let leaf = raw.split(',').next()?;
    let kvs = split_xfcc_kvs(leaf);
    // Prefer Cert= (leaf only); fall back to Chain= (full chain in a
    // single value, but the leaf is still the first PEM block).
    let value = kvs
        .get("Cert")
        .cloned()
        .or_else(|| kvs.get("Chain").cloned())?;
    let pem = url_decode(&value)?;
    pem_to_der(&pem)
}

/// Split one XFCC element into its `Key=Value` pairs. Values may be
/// quoted with double quotes; embedded `;` inside quoted strings is
/// part of the value.
#[cfg(test)]
fn split_xfcc_kvs(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut chars = s.chars().peekable();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_value = false;
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        if !in_value {
            if c == '=' {
                in_value = true;
                // Skip optional opening quote.
                if let Some('"') = chars.peek() {
                    in_quotes = true;
                    chars.next();
                }
            } else {
                key.push(c);
            }
            continue;
        }
        if in_quotes {
            if c == '"' {
                in_quotes = false;
                continue;
            }
            value.push(c);
        } else if c == ';' {
            out.insert(key.trim().to_string(), value.clone());
            key.clear();
            value.clear();
            in_value = false;
        } else {
            value.push(c);
        }
    }
    if !key.is_empty() {
        out.insert(key.trim().to_string(), value);
    }
    out
}

/// Minimal URL-decode for `%xx` triplets. Envoy URL-encodes the PEM
/// because it contains characters (`\n`, `=`, `;`, ` `, `+`, `/`)
/// that would otherwise collide with the XFCC delimiter syntax.
#[cfg(test)]
fn url_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_value(bytes[i + 1])?;
            let lo = hex_value(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

/// Strip PEM armor and base64-decode the body. Accepts the first
/// `-----BEGIN CERTIFICATE-----` block; tolerates trailing chain
/// blocks but ignores them (only the leaf matters for thumbprint).
#[cfg(test)]
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find(END)?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// Tolerant base64 decoder that accepts either the URL-safe or
/// standard alphabet, with or without padding. Used for the bare-DER
/// header shape.
#[cfg(test)]
fn decode_base64_loose(s: &str) -> Option<Vec<u8>> {
    // Strip newlines / whitespace so callers that pass a multi-line
    // base64 blob still work.
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // Try the URL-safe alphabet first because XFCC-adjacent
    // terminators (Istio, Linkerd) tend to prefer it. Fall back to
    // standard. Both NO_PAD variants accept padded input too via
    // engine config below.
    let candidates = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::STANDARD,
    ];
    for engine in &candidates {
        if let Ok(bytes) = engine.decode(&cleaned) {
            return Some(bytes);
        }
    }
    None
}

/// Constant-time byte slice equality. We compare base64-encoded
/// thumbprints rather than raw digests so the lengths line up
/// already; if they do not, return false without leaking the cause.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // A short DER-shaped byte string that exercises the hashing path
    // without dragging a real X.509 fixture in. RFC 8705 §3.1 hashes
    // the raw DER without interpretation, so a synthetic blob is a
    // valid unit-test input.
    const FIXTURE_DER: &[u8] = b"\x30\x82\x01\x23test-cert-der-bytes";

    fn fixture_thumbprint() -> String {
        client_cert_thumbprint(FIXTURE_DER)
    }

    fn base64_xfcc_header(der: &[u8]) -> HeaderMap {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der);
        let mut h = HeaderMap::new();
        h.insert(CLIENT_CERT_HEADER, HeaderValue::from_str(&b64).unwrap());
        h
    }

    #[test]
    fn thumbprint_is_base64url_no_pad_of_sha256() {
        let tp = client_cert_thumbprint(FIXTURE_DER);
        // RFC 7515 base64url-no-pad does not include '=' or '+' or '/'.
        assert!(!tp.contains('='));
        assert!(!tp.contains('+'));
        assert!(!tp.contains('/'));
        // SHA-256 base64url is exactly 43 chars (256 bits => 32
        // bytes => 43 chars without padding).
        assert_eq!(tp.len(), 43);
        // Stable across calls.
        assert_eq!(tp, client_cert_thumbprint(FIXTURE_DER));
        // Different input => different output.
        assert_ne!(tp, client_cert_thumbprint(b"other-bytes"));
    }

    #[test]
    fn extract_client_cert_returns_none_when_header_absent() {
        let h = HeaderMap::new();
        assert!(extract_client_cert_der(&h).is_none());
    }

    #[test]
    fn extract_client_cert_returns_none_when_header_empty() {
        let mut h = HeaderMap::new();
        h.insert(CLIENT_CERT_HEADER, HeaderValue::from_static(""));
        assert!(extract_client_cert_der(&h).is_none());
    }

    #[test]
    fn extract_client_cert_handles_url_safe_base64() {
        let h = base64_xfcc_header(FIXTURE_DER);
        let der = extract_client_cert_der(&h).expect("decoded");
        assert_eq!(der, FIXTURE_DER);
    }

    #[test]
    fn extract_client_cert_handles_standard_base64_with_padding() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(FIXTURE_DER);
        let mut h = HeaderMap::new();
        h.insert(CLIENT_CERT_HEADER, HeaderValue::from_str(&b64).unwrap());
        let der = extract_client_cert_der(&h).expect("decoded");
        assert_eq!(der, FIXTURE_DER);
    }

    #[test]
    fn extract_client_cert_handles_envoy_xfcc_with_pem() {
        // Build a synthetic PEM around our DER then URL-encode it the
        // way Envoy does.
        let body = base64::engine::general_purpose::STANDARD.encode(FIXTURE_DER);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
        let url_encoded: String = pem
            .chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                _ => format!("%{:02X}", c as u8),
            })
            .collect();
        let xfcc = format!(
            "By=spiffe://example/leaf;Hash=abcd;Subject=\"CN=leaf\";Cert=\"{url_encoded}\""
        );
        let mut h = HeaderMap::new();
        h.insert(CLIENT_CERT_HEADER, HeaderValue::from_str(&xfcc).unwrap());
        let der = extract_client_cert_der(&h).expect("xfcc decoded");
        assert_eq!(der, FIXTURE_DER);
    }

    #[test]
    fn inject_cnf_x5t_s256_refuses_opaque_token_without_signed_claims() {
        let body = bytes::Bytes::from(
            r#"{"access_token":"opaque-1","token_type":"Bearer","expires_in":3600}"#,
        );
        let err =
            inject_cnf_x5t_s256(&body, FIXTURE_DER, None, "https://broker.example").unwrap_err();
        assert!(err.to_string().contains("JWT"));
    }

    #[test]
    fn inject_cnf_x5t_s256_refuses_jwt_when_broker_cannot_resign() {
        let body = bytes::Bytes::from(
            r#"{"access_token":"hdr.payload.sig","token_type":"Bearer","expires_in":3600}"#,
        );
        let err =
            inject_cnf_x5t_s256(&body, FIXTURE_DER, None, "https://broker.example").unwrap_err();
        assert!(err.to_string().contains("signing key"));
    }

    #[test]
    fn inject_cnf_x5t_s256_resigns_jwt_with_signed_thumbprint() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "https://upstream.example",
                "sub": "user-1",
                "aud": "https://mcp.example",
                "exp": 4102444800_i64,
                "iat": 1700000000_i64,
                "jti": "old-jti",
                "client_id": "client-1",
                "cnf": {"jkt": "existing-jkt"}
            }))
            .unwrap(),
        );
        let body = bytes::Bytes::from(
            serde_json::json!({
                "access_token": format!("{header}.{payload}.upstream-signature"),
                "token_type": "Bearer",
                "expires_in": 3600
            })
            .to_string(),
        );
        let key = crate::config::JwkKey::Pem {
            pem: include_str!("../../sbproxy-modules/src/auth/dpop_test_ec_p256.pem").to_string(),
            alg: "ES256".to_string(),
            kid: Some("broker-key".to_string()),
            public_jwk: None,
        };

        let rewritten =
            inject_cnf_x5t_s256(&body, FIXTURE_DER, Some(&key), "https://broker.example").unwrap();
        let wrapper: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        let token = wrapper["access_token"].as_str().unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(claims["iss"], "https://broker.example");
        assert_eq!(claims["cnf"]["x5t#S256"], fixture_thumbprint());
        assert_eq!(claims["cnf"]["jkt"], "existing-jkt");
        assert_ne!(token.split('.').nth(2), Some("upstream-signature"));
    }

    #[test]
    fn inject_cnf_x5t_s256_rejects_non_object_body() {
        let body = bytes::Bytes::from(r#"["not","an","object"]"#);
        let error = inject_cnf_x5t_s256(&body, FIXTURE_DER, None, "https://broker.example")
            .expect_err("a bound token response must be an object");
        assert!(error.to_string().contains("JSON object"));
    }

    #[test]
    fn inject_cnf_x5t_s256_rejects_non_object_cnf() {
        let body = bytes::Bytes::from(r#"{"access_token":"opaque","cnf":"oops"}"#);
        let err =
            inject_cnf_x5t_s256(&body, FIXTURE_DER, None, "https://broker.example").unwrap_err();
        assert!(matches!(err, MtlsBindingError::PayloadInvalid(_)));
    }

    #[test]
    fn verify_cnf_x5t_s256_accepts_matching_cert() {
        let claims = serde_json::json!({
            "active": true,
            "cnf": {"x5t#S256": fixture_thumbprint()},
        });
        let h = base64_xfcc_header(FIXTURE_DER);
        assert!(verify_cnf_x5t_s256(&claims, &h).unwrap());
    }

    #[test]
    fn verify_cnf_x5t_s256_rejects_mismatched_cert() {
        let claims = serde_json::json!({
            "active": true,
            "cnf": {"x5t#S256": fixture_thumbprint()},
        });
        let h = base64_xfcc_header(b"different-cert-bytes");
        let err = verify_cnf_x5t_s256(&claims, &h).unwrap_err();
        assert!(matches!(err, MtlsBindingError::ThumbprintMismatch { .. }));
    }

    #[test]
    fn verify_cnf_x5t_s256_rejects_missing_cert() {
        let claims = serde_json::json!({
            "active": true,
            "cnf": {"x5t#S256": fixture_thumbprint()},
        });
        let h = HeaderMap::new();
        let err = verify_cnf_x5t_s256(&claims, &h).unwrap_err();
        assert!(matches!(err, MtlsBindingError::MissingClientCert));
    }

    #[test]
    fn verify_cnf_x5t_s256_back_compat_for_unbound_tokens() {
        // Token without cnf.x5t#S256 is treated as a bearer token;
        // we return Ok(true) so the caller can fall back to bearer
        // policy.
        let claims = serde_json::json!({"active": true});
        let h = HeaderMap::new();
        assert!(verify_cnf_x5t_s256(&claims, &h).unwrap());
    }

    #[test]
    fn verify_cnf_x5t_s256_rejects_non_string_thumbprint() {
        let claims = serde_json::json!({
            "active": true,
            "cnf": {"x5t#S256": 1234},
        });
        let h = base64_xfcc_header(FIXTURE_DER);
        let err = verify_cnf_x5t_s256(&claims, &h).unwrap_err();
        assert!(matches!(err, MtlsBindingError::PayloadInvalid(_)));
    }

    #[test]
    fn constant_time_eq_handles_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }
}
