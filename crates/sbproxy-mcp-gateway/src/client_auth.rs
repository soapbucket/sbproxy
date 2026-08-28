// Client-authentication detection and verification for the /token
// handler.
//
// Per RFC 6749 §2.3 the client may authenticate with a HTTP Basic
// header (`client_secret_basic`), a form-encoded `client_id` /
// `client_secret` pair (`client_secret_post`), an HMAC-signed JWT in
// `client_assertion` (`client_secret_jwt`, RFC 7523 §2.2), or an
// asymmetric JWT in `client_assertion` (`private_key_jwt`, RFC 7523
// §2.2). Public clients using PKCE authenticate with no credentials at
// all (`none`).
//
// 4B.2 detects the method from the request shape and then validates
// the credential. The actual upstream token call lives in `token.rs`.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;

// --- Method enum ---

/// One of the five OAuth client-authentication methods supported by
/// the broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// HTTP Basic header carrying `base64(client_id:client_secret)`.
    ClientSecretBasic,
    /// `client_id` and `client_secret` in the form body.
    ClientSecretPost,
    /// HMAC-signed JWT in `client_assertion` (HS256 keyed off the
    /// shared secret).
    ClientSecretJwt,
    /// Asymmetric JWT in `client_assertion` (verified against a
    /// pre-registered JWK).
    PrivateKeyJwt,
    /// No client authentication. PKCE-only public clients.
    None,
}

impl ClientAuthMethod {
    /// Returns the canonical OAuth name string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::None => "none",
        }
    }
}

/// Distinguishes the two JWT-bearing methods on the wire.
const JWT_BEARER_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// --- Detection ---

/// Detects which client-authentication method the request carries.
/// Returns the detected method and the extracted client_id (when
/// available pre-validation). The returned client_id is informational
/// only; callers must still verify the credential.
pub fn detect_method(
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<(ClientAuthMethod, Option<String>)> {
    // 1) HTTP Basic wins if present.
    if let Some((cid, _secret)) = parse_basic_authorization(headers)? {
        if form
            .get("client_id")
            .is_some_and(|form_client_id| form_client_id != &cid)
        {
            return Err(anyhow!(
                "form client_id does not match the HTTP Basic principal"
            ));
        }
        return Ok((ClientAuthMethod::ClientSecretBasic, Some(cid)));
    }

    // 2) JWT-based assertion.
    if let Some(assertion_type) = form.get("client_assertion_type") {
        if assertion_type != JWT_BEARER_ASSERTION_TYPE {
            return Err(anyhow!(
                "unsupported client_assertion_type {assertion_type:?}"
            ));
        }
        let assertion = form
            .get("client_assertion")
            .ok_or_else(|| anyhow!("client_assertion missing"))?;
        // Read the header alg to decide which JWT method this is.
        let header = decode_header(assertion)
            .map_err(|e| anyhow!("client_assertion header decode failed: {e}"))?;
        let method = match header.alg {
            jsonwebtoken::Algorithm::HS256
            | jsonwebtoken::Algorithm::HS384
            | jsonwebtoken::Algorithm::HS512 => ClientAuthMethod::ClientSecretJwt,
            jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::RS384
            | jsonwebtoken::Algorithm::RS512
            | jsonwebtoken::Algorithm::ES256
            | jsonwebtoken::Algorithm::ES384
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::PS384
            | jsonwebtoken::Algorithm::PS512 => ClientAuthMethod::PrivateKeyJwt,
            other => return Err(anyhow!("unsupported client_assertion alg {other:?}")),
        };
        // Peek the `iss` / `sub` claim for the client_id.
        let claims = peek_unverified_claims(assertion).ok();
        let cid = claims.and_then(|c| c.client_id());
        return Ok((method, cid));
    }

    // 3) Form-body credentials.
    if let (Some(cid), Some(_)) = (form.get("client_id"), form.get("client_secret")) {
        return Ok((ClientAuthMethod::ClientSecretPost, Some(cid.clone())));
    }

    // 4) Public client: only client_id in form, no secret, no assertion.
    if let Some(cid) = form.get("client_id") {
        return Ok((ClientAuthMethod::None, Some(cid.clone())));
    }

    Err(anyhow!("no client authentication material on request"))
}

// --- Verification ---

/// Verify a `client_secret_basic` credential against a known secret.
/// Returns the validated `client_id` on success.
pub fn verify_basic(headers: &HeaderMap, expected_secret: &str) -> Result<String> {
    let (cid, secret) = parse_basic_authorization(headers)?
        .ok_or_else(|| anyhow!("missing authorization header"))?;
    if !constant_time_eq(secret.as_bytes(), expected_secret.as_bytes()) {
        return Err(anyhow!("client_secret mismatch"));
    }
    Ok(cid)
}

/// Verify a `client_secret_post` credential.
pub fn verify_post(form: &HashMap<String, String>, expected_secret: &str) -> Result<String> {
    let cid = form
        .get("client_id")
        .ok_or_else(|| anyhow!("client_id missing in form"))?;
    let secret = form
        .get("client_secret")
        .ok_or_else(|| anyhow!("client_secret missing in form"))?;
    if !constant_time_eq(secret.as_bytes(), expected_secret.as_bytes()) {
        return Err(anyhow!("client_secret mismatch"));
    }
    Ok(cid.clone())
}

/// Verify a `client_secret_jwt` assertion (HS256 only) using the
/// shared secret. Returns the `sub` (client_id) on success.
pub fn verify_secret_jwt(
    form: &HashMap<String, String>,
    shared_secret: &str,
    expected_audience: &str,
) -> Result<String> {
    let assertion = form
        .get("client_assertion")
        .ok_or_else(|| anyhow!("client_assertion missing"))?;
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[expected_audience]);
    let key = DecodingKey::from_secret(shared_secret.as_bytes());
    let token = decode::<JwtBearerClaims>(assertion, &key, &validation)
        .map_err(|e| anyhow!("client_secret_jwt verify failed: {e}"))?;
    Ok(token.claims.sub)
}

/// Verify a `private_key_jwt` assertion using a pre-registered JWK.
/// Returns the `sub` on success.
pub fn verify_private_key_jwt(
    form: &HashMap<String, String>,
    jwk_json: &serde_json::Value,
    expected_audience: &str,
) -> Result<String> {
    let assertion = form
        .get("client_assertion")
        .ok_or_else(|| anyhow!("client_assertion missing"))?;
    let header = decode_header(assertion)
        .map_err(|e| anyhow!("client_assertion header decode failed: {e}"))?;
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_json.clone())
        .map_err(|e| anyhow!("registered jwk is not a valid Jwk: {e}"))?;
    let key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| anyhow!("failed to build decoding key from jwk: {e}"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[expected_audience]);
    let token = decode::<JwtBearerClaims>(assertion, &key, &validation)
        .map_err(|e| anyhow!("private_key_jwt verify failed: {e}"))?;
    Ok(token.claims.sub)
}

/// Returns Ok if `method` is in `accepted`, Err otherwise. Uses the
/// canonical OAuth name for matching.
pub fn ensure_method_accepted(method: ClientAuthMethod, accepted: &[String]) -> Result<()> {
    if accepted.iter().any(|m| m == method.as_str()) {
        Ok(())
    } else {
        Err(anyhow!(
            "client auth method {} is not in accepted_client_auth_methods",
            method.as_str()
        ))
    }
}

// --- Internals ---

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JwtBearerClaims {
    /// `sub` MUST equal the client_id per RFC 7523 §3.2.
    sub: String,
    /// `iss` MUST equal the client_id per RFC 7523 §3.1. We do not
    /// enforce iss==sub here; that is the caller's job.
    #[serde(default)]
    iss: Option<String>,
    /// Audience as a single string or a JSON array. `jsonwebtoken`
    /// enforces this via `Validation::set_audience`; the field is
    /// kept here for completeness of the claims model.
    #[serde(default)]
    aud: Option<serde_json::Value>,
    /// Expiry. Validated by `jsonwebtoken`.
    #[serde(default)]
    exp: Option<i64>,
    /// Issued-at. Held for downstream forensic logging.
    #[serde(default)]
    iat: Option<i64>,
    /// JWT ID. Held for replay protection in 4B.3.
    #[serde(default)]
    jti: Option<String>,
}

impl JwtBearerClaims {
    fn client_id(&self) -> Option<String> {
        self.iss
            .clone()
            .or_else(|| Some(self.sub.clone()))
            .filter(|s| !s.is_empty())
    }
}

fn parse_basic(b64: &str) -> Result<(String, String)> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("basic auth not base64: {e}"))?;
    let s = String::from_utf8(bytes).map_err(|e| anyhow!("basic auth not utf-8: {e}"))?;
    let mut parts = s.splitn(2, ':');
    let cid = parts
        .next()
        .ok_or_else(|| anyhow!("basic auth missing client_id"))?
        .to_string();
    let secret = parts.next().unwrap_or("").to_string();
    Ok((cid, secret))
}

fn parse_basic_authorization(headers: &HeaderMap) -> Result<Option<(String, String)>> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(anyhow!("duplicate authorization headers are ambiguous"));
    }
    let value = value
        .to_str()
        .map_err(|_| anyhow!("authorization header is not valid utf-8"))?;
    let (scheme, credential) = value
        .split_once(' ')
        .ok_or_else(|| anyhow!("authorization header has no credential"))?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(anyhow!("unsupported authorization scheme"));
    }
    parse_basic(credential.trim()).map(Some)
}

fn peek_unverified_claims(jwt: &str) -> Result<JwtBearerClaims> {
    // Manually decode the payload segment without verification. This
    // is only used to read the iss/sub for logging or detection. The
    // actual verification path uses `decode` with proper validation.
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or_else(|| anyhow!("jwt malformed"))?;
    let payload = parts.next().ok_or_else(|| anyhow!("jwt missing payload"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| anyhow!("jwt payload not base64url: {e}"))?;
    let claims: JwtBearerClaims = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("jwt payload not valid claims json: {e}"))?;
    Ok(claims)
}

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

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    fn empty_form() -> HashMap<String, String> {
        HashMap::new()
    }

    fn basic_header(cid: &str, secret: &str) -> HeaderMap {
        let raw = format!("{cid}:{secret}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        headers
    }

    #[test]
    fn detect_basic_method() {
        let headers = basic_header("cli", "secret");
        let (method, cid) = detect_method(&headers, &empty_form()).unwrap();
        assert_eq!(method, ClientAuthMethod::ClientSecretBasic);
        assert_eq!(cid.as_deref(), Some("cli"));
    }

    #[test]
    fn detect_basic_scheme_is_case_insensitive() {
        let mut headers = basic_header("cli", "secret");
        let value = headers
            .get(axum::http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .replacen("Basic", "bAsIc", 1);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        assert_eq!(
            detect_method(&headers, &empty_form()).unwrap(),
            (ClientAuthMethod::ClientSecretBasic, Some("cli".to_string()))
        );
    }

    #[test]
    fn duplicate_authorization_headers_are_rejected() {
        let mut headers = basic_header("cli", "secret");
        headers.append(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic YXR0YWNrZXI6c2VjcmV0"),
        );
        assert!(detect_method(&headers, &empty_form())
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[test]
    fn basic_principal_cannot_be_overridden_by_form_client_id() {
        let headers = basic_header("cli", "secret");
        let mut form = empty_form();
        form.insert("client_id".to_string(), "spoofed".to_string());
        assert!(detect_method(&headers, &form).is_err());
    }

    #[test]
    fn detect_post_method() {
        let mut form = HashMap::new();
        form.insert("client_id".to_string(), "cli".to_string());
        form.insert("client_secret".to_string(), "shh".to_string());
        let (method, cid) = detect_method(&HeaderMap::new(), &form).unwrap();
        assert_eq!(method, ClientAuthMethod::ClientSecretPost);
        assert_eq!(cid.as_deref(), Some("cli"));
    }

    #[test]
    fn detect_none_method() {
        let mut form = HashMap::new();
        form.insert("client_id".to_string(), "public".to_string());
        let (method, cid) = detect_method(&HeaderMap::new(), &form).unwrap();
        assert_eq!(method, ClientAuthMethod::None);
        assert_eq!(cid.as_deref(), Some("public"));
    }

    #[test]
    fn detect_no_credentials_errors() {
        let result = detect_method(&HeaderMap::new(), &empty_form());
        assert!(result.is_err());
    }

    #[test]
    fn verify_basic_happy_path() {
        let headers = basic_header("cli", "secret");
        let cid = verify_basic(&headers, "secret").unwrap();
        assert_eq!(cid, "cli");
    }

    #[test]
    fn verify_basic_wrong_secret_rejected() {
        let headers = basic_header("cli", "wrong");
        let err = verify_basic(&headers, "secret").unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn verify_post_happy_path() {
        let mut form = HashMap::new();
        form.insert("client_id".to_string(), "cli".to_string());
        form.insert("client_secret".to_string(), "secret".to_string());
        let cid = verify_post(&form, "secret").unwrap();
        assert_eq!(cid, "cli");
    }

    #[test]
    fn verify_post_wrong_secret_rejected() {
        let mut form = HashMap::new();
        form.insert("client_id".to_string(), "cli".to_string());
        form.insert("client_secret".to_string(), "wrong".to_string());
        assert!(verify_post(&form, "secret").is_err());
    }

    #[test]
    fn verify_secret_jwt_happy_path() {
        let secret = "shared-secret-bytes-shared-secret-bytes";
        let claims = json!({
            "iss": "cli",
            "sub": "cli",
            "aud": "https://broker/token",
            "exp": (chrono_now() + 60),
            "iat": chrono_now(),
            "jti": "jti-1"
        });
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let mut form = HashMap::new();
        form.insert(
            "client_assertion_type".to_string(),
            JWT_BEARER_ASSERTION_TYPE.to_string(),
        );
        form.insert("client_assertion".to_string(), token);
        let cid = verify_secret_jwt(&form, secret, "https://broker/token").unwrap();
        assert_eq!(cid, "cli");
    }

    #[test]
    fn verify_secret_jwt_wrong_audience_rejected() {
        let secret = "shared-secret-bytes-shared-secret-bytes";
        let claims = json!({
            "iss": "cli",
            "sub": "cli",
            "aud": "https://wrong/aud",
            "exp": (chrono_now() + 60),
            "iat": chrono_now(),
        });
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let mut form = HashMap::new();
        form.insert("client_assertion".to_string(), token);
        assert!(verify_secret_jwt(&form, secret, "https://broker/token").is_err());
    }

    #[test]
    fn ensure_method_accepted_happy() {
        let accepted = vec!["client_secret_basic".to_string(), "none".to_string()];
        assert!(ensure_method_accepted(ClientAuthMethod::ClientSecretBasic, &accepted).is_ok());
        assert!(ensure_method_accepted(ClientAuthMethod::None, &accepted).is_ok());
    }

    #[test]
    fn ensure_method_accepted_rejects_unlisted() {
        let accepted = vec!["client_secret_basic".to_string()];
        assert!(ensure_method_accepted(ClientAuthMethod::None, &accepted).is_err());
        assert!(ensure_method_accepted(ClientAuthMethod::ClientSecretJwt, &accepted).is_err());
    }

    #[test]
    fn detect_jwt_assertion_picks_secret_jwt_for_hs256() {
        let secret = "shared-secret-bytes-shared-secret-bytes";
        let claims = json!({"iss": "cli", "sub": "cli"});
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let mut form = HashMap::new();
        form.insert(
            "client_assertion_type".to_string(),
            JWT_BEARER_ASSERTION_TYPE.to_string(),
        );
        form.insert("client_assertion".to_string(), token);
        let (method, cid) = detect_method(&HeaderMap::new(), &form).unwrap();
        assert_eq!(method, ClientAuthMethod::ClientSecretJwt);
        assert_eq!(cid.as_deref(), Some("cli"));
    }

    #[test]
    fn parse_basic_handles_password_with_colon() {
        let raw = "cli:has:colons";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let (cid, secret) = parse_basic(&encoded).unwrap();
        assert_eq!(cid, "cli");
        assert_eq!(secret, "has:colons");
    }

    #[test]
    fn constant_time_eq_handles_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    // Helper: avoid pulling chrono. Use std::time and seconds-since-epoch.
    fn chrono_now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // Suppress unused-fields warning on the test-only claims. The
    // fields are used implicitly through serde validation by
    // jsonwebtoken.
    #[test]
    fn jwt_claims_unused_fields_present() {
        let c = JwtBearerClaims {
            sub: "x".to_string(),
            iss: Some("x".to_string()),
            aud: Some(json!("a")),
            exp: Some(1),
            iat: Some(0),
            jti: Some("j".to_string()),
        };
        assert_eq!(c.client_id().as_deref(), Some("x"));
        assert!(c.aud.is_some());
        assert_eq!(c.exp, Some(1));
        assert_eq!(c.iat, Some(0));
        assert!(c.jti.is_some());
    }
}
