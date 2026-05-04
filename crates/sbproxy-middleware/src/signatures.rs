//! RFC 9421 HTTP Message Signatures.
//!
//! Implements the verification path for the most common subset of
//! [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html): the request
//! verification flow with HMAC-SHA256 and Ed25519 algorithms over the
//! standard derived components (`@method`, `@target-uri`, `@authority`,
//! `@scheme`, `@path`, `@query`) and arbitrary HTTP header references.
//! Signing the response and the heavier algorithms (RSA-PSS-SHA512,
//! ECDSA-P256, ECDSA-P384) are explicit non-goals for this initial
//! implementation; the verification API is shaped so they can be
//! added without breaking callers.
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
//! - Derived components: `@method`, `@target-uri`, `@authority`,
//!   `@scheme`, `@path`, `@query`.
//! - Arbitrary HTTP header references (case-insensitive name match;
//!   multi-value headers joined with `, ` per RFC 9421 §2.1).
//! - `created` and `expires` parameter enforcement when present.

use std::collections::HashMap;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
}

impl SignatureAlgorithm {
    /// Match an algorithm against the wire-format `alg` parameter
    /// from the `Signature-Input` header (RFC 9421 §6.2.2).
    pub fn matches_wire(&self, value: &str) -> bool {
        matches!(
            (*self, value),
            (SignatureAlgorithm::HmacSha256, "hmac-sha256")
                | (SignatureAlgorithm::Ed25519, "ed25519")
        )
    }

    /// Whether this algorithm setting pins verification to a single
    /// concrete algorithm.
    ///
    /// Today both variants are concrete, so this always returns
    /// `true`. The function exists so that the alg-required check in
    /// [`MessageSignatureVerifier::verify_request`] remains correct
    /// if a future variant ever represents "any supported algorithm".
    pub fn is_pinned(&self) -> bool {
        match self {
            SignatureAlgorithm::HmacSha256 | SignatureAlgorithm::Ed25519 => true,
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
    pub key: String,
    /// Optional list of components every accepted signature must
    /// cover. Verification rejects requests whose `Signature-Input`
    /// covers a strict subset.
    #[serde(default)]
    pub required_components: Vec<String>,
    /// Optional clock skew tolerance (seconds) for `created` /
    /// `expires` parameters. `created` may be at most this far in the
    /// future; `expires` at least this far in the past. Defaults to
    /// 30s.
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
    /// Decoded shared secret bytes (HMAC) or raw public key bytes
    /// (Ed25519). Decoded once at construction so the verify path
    /// never re-parses the configured key string.
    key_bytes: Vec<u8>,
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
    /// Build a verifier, validating and decoding the key material.
    pub fn new(config: MessageSignatureConfig) -> anyhow::Result<Self> {
        let key_bytes = match config.algorithm {
            SignatureAlgorithm::HmacSha256 => {
                // HMAC keys can be any byte sequence. Accept the
                // configured value as-is; most operators set a
                // base64 or hex string.
                decode_secret(&config.key)
            }
            SignatureAlgorithm::Ed25519 => {
                let bytes = decode_public_key(&config.key)?;
                if bytes.len() != 32 {
                    anyhow::bail!("ed25519 public key must be 32 bytes, got {}", bytes.len());
                }
                bytes
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
    pub fn verify_request(&self, req: &http::Request<bytes::Bytes>) -> VerifyVerdict {
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
        let base = match build_signature_base(req, input) {
            Ok(b) => b,
            Err(e) => {
                return VerifyVerdict::Failed {
                    reason: format!("signature base failed: {e}"),
                }
            }
        };

        // Crypto.
        let ok = match self.config.algorithm {
            SignatureAlgorithm::HmacSha256 => {
                let mut mac = match HmacSha256::new_from_slice(&self.key_bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        return VerifyVerdict::Failed {
                            reason: "invalid hmac key".to_string(),
                        }
                    }
                };
                mac.update(base.as_bytes());
                mac.verify_slice(raw_sig).is_ok()
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
                        return VerifyVerdict::Failed {
                            reason: "invalid ed25519 public key".to_string(),
                        }
                    }
                };
                let sig_arr: [u8; 64] = match raw_sig.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return VerifyVerdict::Failed {
                            reason: format!(
                                "ed25519 signature must be 64 bytes, got {}",
                                raw_sig.len()
                            ),
                        }
                    }
                };
                let signature = Signature::from_bytes(&sig_arr);
                key.verify(base.as_bytes(), &signature).is_ok()
            }
        };

        if ok {
            VerifyVerdict::Ok {
                signature_label: label,
            }
        } else {
            VerifyVerdict::Failed {
                reason: "cryptographic verification failed".to_string(),
            }
        }
    }
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

/// Build the canonical signature base for an inbound request.
///
/// Mirrors RFC 9421 §2 byte-for-byte for the components we support;
/// unsupported component types are surfaced as errors so the verifier
/// can fail closed rather than silently signing a different base than
/// the signer did.
pub fn build_signature_base(
    req: &http::Request<bytes::Bytes>,
    input: &SignatureInputEntry,
) -> anyhow::Result<String> {
    let mut out = String::new();
    for component in &input.components {
        let value = canonical_component_value(req, component)?;
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
) -> anyhow::Result<String> {
    if let Some(rest) = name.strip_prefix('@') {
        return derived_component(req, rest);
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

fn derived_component(req: &http::Request<bytes::Bytes>, name: &str) -> anyhow::Result<String> {
    let uri: &Uri = req.uri();
    Ok(match name {
        "method" => req.method().as_str().to_string(),
        "target-uri" => match uri.path_and_query() {
            Some(pq) => pq.as_str().to_string(),
            None => uri.path().to_string(),
        },
        "authority" => uri
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| header_str(req.headers(), "host").map(String::from))
            .unwrap_or_default(),
        "scheme" => uri.scheme_str().map(|s| s.to_string()).unwrap_or_else(|| {
            if uri.host().is_some() {
                "https".to_string()
            } else {
                "http".to_string()
            }
        }),
        "path" => uri.path().to_string(),
        "query" => match uri.query() {
            Some(q) if !q.is_empty() => format!("?{}", q),
            _ => "?".to_string(),
        },
        "request-target" => match uri.path_and_query() {
            Some(pq) => format!("{} {}", req.method().as_str(), pq.as_str()),
            None => format!("{} {}", req.method().as_str(), uri.path()),
        },
        other => anyhow::bail!("unsupported derived component: @{}", other),
    })
}

fn check_freshness(input: &SignatureInputEntry, skew: u64) -> Option<String> {
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => return Some("system clock before epoch".to_string()),
    };
    let skew = skew as i64;
    if let Some(created) = input.params.created {
        if created > now + skew {
            return Some(format!(
                "signature created in future: {} > {}",
                created, now
            ));
        }
    }
    if let Some(expires) = input.params.expires {
        if expires + skew < now {
            return Some(format!("signature expired: {} < {}", expires, now));
        }
    }
    None
}

// --- Helpers for key decoding ---

fn decode_secret(value: &str) -> Vec<u8> {
    // Try hex first (most common machine-generated form), then
    // base64 (also common), then fall through to raw UTF-8 bytes.
    if let Ok(bytes) = hex::decode(value) {
        return bytes;
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(value) {
        return bytes;
    }
    value.as_bytes().to_vec()
}

fn decode_public_key(value: &str) -> anyhow::Result<Vec<u8>> {
    if let Ok(bytes) = hex::decode(value) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(value) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value) {
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
        let expected = "\"@method\": POST\n\
            \"@target-uri\": /api/items?x=1\n\
            \"host\": api.example.com\n\
            \"@signature-params\": (\"@method\" \"@target-uri\" \"host\");created=1700000000;keyid=\"k1\"";
        assert_eq!(base, expected);
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

        let raw_input = r#"sig1=("@method" "@target-uri" "host");created=1700000000;keyid="test-key";alg="hmac-sha256""#;
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

        let raw_input =
            r#"sig1=("@method" "host");created=1700000000;keyid="test-key";alg="hmac-sha256""#;
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

        let raw_input =
            r#"sig1=("@method" "@path" "host");created=1700000000;keyid="test-key";alg="ed25519""#;
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
}
