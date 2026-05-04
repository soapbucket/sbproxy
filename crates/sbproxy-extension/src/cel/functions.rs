//! Custom CEL functions for sbproxy.
//!
//! Extends the standard CEL built-in functions with proxy-specific utilities
//! for IP matching, hashing, encoding, and time operations.

use std::sync::Arc;

use cel::extractors::This;
use cel::objects::Value;
use cel::ExecutionError;

// --- Registration ---

/// Register all custom sbproxy functions on a CEL context.
pub fn register_all(ctx: &mut cel::Context<'_>) {
    ctx.add_function("ip_in_cidr", cel_ip_in_cidr);
    ctx.add_function("uuid_v4", cel_uuid_v4);
    ctx.add_function("now", cel_now);
    ctx.add_function("sha256", cel_sha256);
    ctx.add_function("base64_encode", cel_base64_encode);
    ctx.add_function("base64_decode", cel_base64_decode);
    ctx.add_function("regex_match", cel_regex_match);
    ctx.add_function("toLowerCase", cel_to_lower_case);
    ctx.add_function("toUpperCase", cel_to_upper_case);
    ctx.add_function("trim", cel_trim);
    ctx.add_function("split", cel_split);
    ctx.add_function("flag_enabled", cel_flag_enabled);
    ctx.add_function("tls_fingerprint_matches", cel_tls_fingerprint_matches);
}

// --- TLS fingerprint catalogue lookup (Wave 5 / G5.3) ---

/// Trait the binary implements to expose the vendored TLS-fingerprint
/// catalogue to CEL evaluation. Lives in this crate so the extension
/// surface does not need a hard dep on `sbproxy-security`. The
/// `sbproxy` binary registers an adapter that delegates to
/// `sbproxy_security::TlsFingerprintCatalog::matches`.
pub trait TlsFingerprintMatcher: Send + Sync {
    /// Return `true` when `ja4` matches the catalog entry for
    /// `agent_class_id`. Per A5.1: `true` is also the conservative
    /// answer for an uncatalogued class.
    fn matches(&self, ja4: &str, agent_class_id: &str) -> bool;
}

/// Default matcher used when no operator override is registered.
/// Returns `true` unconditionally so policies that gate on
/// `tls_fingerprint_matches` continue to evaluate sensibly even
/// before the binary has wired the real catalogue.
struct PassThroughMatcher;

impl TlsFingerprintMatcher for PassThroughMatcher {
    fn matches(&self, _ja4: &str, _agent_class_id: &str) -> bool {
        true
    }
}

static TLS_MATCHER: once_cell::sync::Lazy<
    parking_lot::RwLock<std::sync::Arc<dyn TlsFingerprintMatcher>>,
> = once_cell::sync::Lazy::new(|| {
    parking_lot::RwLock::new(std::sync::Arc::new(PassThroughMatcher))
});

/// Install the process-wide TLS-fingerprint matcher. The previous
/// matcher is dropped when this returns. Idempotent across hot
/// reloads.
pub fn set_tls_fingerprint_matcher(matcher: std::sync::Arc<dyn TlsFingerprintMatcher>) {
    *TLS_MATCHER.write() = matcher;
}

/// CEL function `tls_fingerprint_matches(ja4, agent_class_id)` per
/// A5.1. Returns true when `ja4` is a known fingerprint for the
/// catalogued agent class, or when the catalogue has no entry for
/// the agent class (conservative).
fn cel_tls_fingerprint_matches(
    ja4: Arc<String>,
    agent_class_id: Arc<String>,
) -> Result<bool, ExecutionError> {
    let matcher = TLS_MATCHER.read().clone();
    Ok(matcher.matches(&ja4, &agent_class_id))
}

// --- Feature flags ---

/// Resolve a feature flag against the global flag store.
///
/// Usage in CEL: `flag_enabled("new-ui", jwt.claims.sub)`. The function
/// reads the live process-wide [`crate::flags::FlagStore`] populated
/// by the embedding binary at startup. Unknown flags evaluate `false`.
fn cel_flag_enabled(name: Arc<String>, key: Arc<String>) -> Result<bool, ExecutionError> {
    let store = crate::flags::global_store();
    Ok(store.enabled(&name, &key, None))
}

// --- IP Functions ---

/// Check if an IP address is within a CIDR range.
///
/// Usage in CEL: `ip_in_cidr("192.168.1.1", "192.168.1.0/24")`
fn cel_ip_in_cidr(ip: Arc<String>, cidr: Arc<String>) -> Result<bool, ExecutionError> {
    Ok(ip_in_cidr(&ip, &cidr))
}

/// Pure Rust implementation of IP-in-CIDR check.
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    use std::net::IpAddr;
    let ip: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let network: ipnetwork::IpNetwork = match cidr.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    network.contains(ip)
}

// --- UUID ---

/// Generate a UUID v4 string.
///
/// Usage in CEL: `uuid_v4()`
fn cel_uuid_v4() -> String {
    uuid_v4()
}

/// Generate a random UUID v4 as a string.
pub fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

// --- Time ---

/// Get the current UTC timestamp as an ISO 8601 string.
///
/// Usage in CEL: `now()`
fn cel_now() -> String {
    now_rfc3339()
}

/// Current UTC time formatted as an RFC 3339 string.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// --- Hashing ---

/// Compute the SHA-256 hash of a string, returned as hex.
///
/// Usage in CEL: `sha256("hello")`
fn cel_sha256(input: Arc<String>) -> String {
    sha256_hex(&input)
}

/// Compute the SHA-256 hash of `input` and return it as a lowercase hex string.
pub fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

// --- Encoding ---

/// Base64 encode a string.
///
/// Usage in CEL: `base64_encode("hello")`
fn cel_base64_encode(input: Arc<String>) -> String {
    base64_encode(&input)
}

/// Encode `input` as a standard base64 string.
pub fn base64_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}

/// Base64 decode a string.
///
/// Usage in CEL: `base64_decode("aGVsbG8=")`
fn cel_base64_decode(input: Arc<String>) -> Result<Value, ExecutionError> {
    match base64_decode(&input) {
        Ok(s) => Ok(Value::String(Arc::new(s))),
        Err(e) => Err(ExecutionError::function_error("base64_decode", e)),
    }
}

/// Decode a standard base64 string back into UTF-8 text.
pub fn base64_decode(input: &str) -> Result<String, anyhow::Error> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(input)?;
    Ok(String::from_utf8(bytes)?)
}

// --- Regex ---

/// Test if a string matches a regex pattern.
///
/// Usage in CEL: `regex_match("hello123", "^[a-z]+[0-9]+$")`
fn cel_regex_match(input: Arc<String>, pattern: Arc<String>) -> bool {
    regex_match(&input, &pattern)
}

/// Test whether `input` matches the given regex `pattern`. Returns false if the
/// pattern fails to compile.
pub fn regex_match(input: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(input))
        .unwrap_or(false)
}

// --- String Functions ---

/// Convert a string to lowercase.
///
/// Usage in CEL: `"Hello".toLowerCase()`
fn cel_to_lower_case(This(this): This<Arc<String>>) -> String {
    this.to_lowercase()
}

/// Convert a string to uppercase.
///
/// Usage in CEL: `"Hello".toUpperCase()`
fn cel_to_upper_case(This(this): This<Arc<String>>) -> String {
    this.to_uppercase()
}

/// Trim whitespace from both ends of a string.
///
/// Usage in CEL: `"  hello  ".trim()`
fn cel_trim(This(this): This<Arc<String>>) -> String {
    this.trim().to_string()
}

/// Split a string by a delimiter, returning a list.
///
/// Usage in CEL: `"a,b,c".split(",")`
fn cel_split(This(this): This<Arc<String>>, delimiter: Arc<String>) -> Arc<Vec<Value>> {
    Arc::new(
        this.split(delimiter.as_str())
            .map(|s| Value::String(Arc::new(s.to_string())))
            .collect(),
    )
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cel::{CelContext, CelEngine, CelValue};

    // --- Unit tests for pure functions ---

    #[test]
    fn test_ip_in_cidr_v4_match() {
        assert!(ip_in_cidr("192.168.1.50", "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_in_cidr_v4_no_match() {
        assert!(!ip_in_cidr("10.0.0.1", "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_in_cidr_v6() {
        assert!(ip_in_cidr("::1", "::1/128"));
        assert!(!ip_in_cidr("::2", "::1/128"));
    }

    #[test]
    fn test_ip_in_cidr_invalid_ip() {
        assert!(!ip_in_cidr("not-an-ip", "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_in_cidr_invalid_cidr() {
        assert!(!ip_in_cidr("192.168.1.1", "not-a-cidr"));
    }

    #[test]
    fn test_uuid_v4_format() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_uuid_v4_uniqueness() {
        let a = uuid_v4();
        let b = uuid_v4();
        assert_ne!(a, b);
    }

    #[test]
    fn test_now_rfc3339() {
        let ts = now_rfc3339();
        assert!(ts.contains('T'));
        assert!(ts.contains('+') || ts.ends_with('Z'));
    }

    #[test]
    fn test_sha256_known_value() {
        let hash = sha256_hex("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_base64_roundtrip() {
        let encoded = base64_encode("hello world");
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(base64_decode("!!!not-valid!!!").is_err());
    }

    #[test]
    fn test_regex_match_simple() {
        assert!(regex_match("hello123", r"^[a-z]+\d+$"));
        assert!(!regex_match("123hello", r"^[a-z]+\d+$"));
    }

    #[test]
    fn test_regex_match_invalid_pattern() {
        assert!(!regex_match("anything", "[invalid"));
    }

    // --- CEL integration tests for custom functions ---

    #[test]
    fn test_cel_ip_in_cidr() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        assert!(engine
            .eval_bool_source(r#"ip_in_cidr("192.168.1.50", "192.168.1.0/24")"#, &ctx)
            .unwrap());
        assert!(!engine
            .eval_bool_source(r#"ip_in_cidr("10.0.0.1", "192.168.1.0/24")"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_cel_sha256() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine.eval_source(r#"sha256("hello")"#, &ctx).unwrap();
        match result {
            CelValue::String(s) => {
                assert_eq!(
                    s,
                    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                );
            }
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_base64_encode() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine
            .eval_source(r#"base64_encode("hello")"#, &ctx)
            .unwrap();
        match result {
            CelValue::String(s) => assert_eq!(s, "aGVsbG8="),
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_base64_decode() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine
            .eval_source(r#"base64_decode("aGVsbG8=")"#, &ctx)
            .unwrap();
        match result {
            CelValue::String(s) => assert_eq!(s, "hello"),
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_regex_match() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        // In CEL strings, backslash is an escape character, so we need \\d for \d
        assert!(engine
            .eval_bool_source(r#"regex_match("test123", "^[a-z]+\\d+$")"#, &ctx)
            .unwrap());
    }

    #[test]
    fn test_cel_uuid_v4() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine.eval_source("uuid_v4()", &ctx).unwrap();
        match result {
            CelValue::String(s) => {
                assert_eq!(s.len(), 36);
            }
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_now() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine.eval_source("now()", &ctx).unwrap();
        match result {
            CelValue::String(s) => {
                assert!(s.contains('T'), "Timestamp should contain T: {}", s);
            }
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_to_lower_case() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine
            .eval_source(r#""HELLO World".toLowerCase()"#, &ctx)
            .unwrap();
        match result {
            CelValue::String(s) => assert_eq!(s, "hello world"),
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_to_upper_case() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine
            .eval_source(r#""hello".toUpperCase()"#, &ctx)
            .unwrap();
        match result {
            CelValue::String(s) => assert_eq!(s, "HELLO"),
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_trim() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine.eval_source(r#""  hello  ".trim()"#, &ctx).unwrap();
        match result {
            CelValue::String(s) => assert_eq!(s, "hello"),
            other => panic!("Expected String, got {:?}", other),
        }
    }

    #[test]
    fn test_cel_split() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine
            .eval_source(r#"size("a,b,c".split(","))"#, &ctx)
            .unwrap();
        match result {
            CelValue::Int(n) => assert_eq!(n, 3),
            other => panic!("Expected Int(3), got {:?}", other),
        }
    }

    #[test]
    fn test_cel_ip_check_with_request_context() {
        let engine = CelEngine::new();
        let mut ctx = CelContext::new();
        let mut connection = std::collections::HashMap::new();
        connection.insert(
            "remote_ip".to_string(),
            CelValue::String("10.0.0.50".to_string()),
        );
        ctx.set("connection", CelValue::Map(connection));

        assert!(engine
            .eval_bool_source(r#"ip_in_cidr(connection.remote_ip, "10.0.0.0/8")"#, &ctx,)
            .unwrap());
    }
}
