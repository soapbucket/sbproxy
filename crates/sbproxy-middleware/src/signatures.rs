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
}
