//! Exposed credentials policy.
//!
//! Detects exposed credentials in inbound requests. The OSS
//! implementation ships the **static** provider: operators supply a
//! list of leaked passwords (or SHA-1 hashes thereof) and the policy
//! hashes inbound credentials with SHA-1 before checking the set in
//! constant time.

use base64::Engine as _;
use serde::Deserialize;

/// Outcome of an exposed-credentials check on an inbound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposedCredsResult {
    /// No credentials extracted, or the extracted credentials were
    /// not on the configured exposure list.
    Clean,
    /// Credentials matched the list. The policy's `action` decides
    /// whether to tag the upstream request or block it.
    Hit {
        /// Short reason string emitted as the value of the
        /// `Exposed-Credential-Check` header (`leaked-password` for
        /// the static-list provider).
        reason: &'static str,
    },
}

/// What to do when a request carries an exposed credential.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExposedCredsAction {
    /// Forward the request, but stamp the `Exposed-Credential-Check`
    /// header so the upstream can react (force a step-up auth, page
    /// the SecOps team, etc.). Default.
    #[default]
    Tag,
    /// Reject the request with `403 Forbidden`. Use this once the
    /// upstream is confident the list represents real exposures.
    Block,
}

/// Detects exposed credentials in inbound requests.
///
/// Today the OSS implementation ships the **static** provider:
/// operators supply a list of leaked passwords (or SHA-1 hashes
/// thereof) and the policy hashes inbound credentials with SHA-1
/// before checking the set in constant time. Hash-only lists keep
/// the configured material from leaking through error messages or
/// process dumps.
///
/// Credentials are extracted from `Authorization: Basic <b64>`. The
/// HIBP k-anonymity provider lives behind a separate enterprise
/// adapter (TBD) so the OSS data plane has no outbound dependency.
#[derive(Debug, Clone, Deserialize)]
pub struct ExposedCredsPolicy {
    /// Source of the exposure list. Today only `static` is recognised
    /// in OSS; enterprise extends this with `hibp`.
    #[serde(default = "default_exposed_creds_provider")]
    pub provider: String,
    /// Action to take on a match. Default is `tag`.
    #[serde(default)]
    pub action: ExposedCredsAction,
    /// Header name stamped on the upstream request when `action: tag`.
    /// Default `exposed-credential-check`.
    #[serde(default = "default_exposed_creds_header")]
    pub header: String,
    /// Inline plaintext passwords. Hashed at compile time; the source
    /// strings are not retained on the policy.
    #[serde(default)]
    pub passwords: Vec<String>,
    /// Inline SHA-1 hex hashes (uppercase, the HIBP convention).
    /// Useful when distributing pre-hashed exposure lists without
    /// shipping plaintext passwords through the config.
    #[serde(default)]
    pub sha1_hashes: Vec<String>,
    /// File path containing one SHA-1 hex hash per line. Lines
    /// starting with `#` are ignored. Loaded once at config compile.
    #[serde(default)]
    pub sha1_file: Option<String>,
    /// Compiled lookup set (hex SHA-1, uppercase). Built by
    /// [`Self::from_config`] and not deserialised directly.
    #[serde(skip)]
    hash_set: std::collections::HashSet<String>,
}

fn default_exposed_creds_provider() -> String {
    "static".to_string()
}

fn default_exposed_creds_header() -> String {
    "exposed-credential-check".to_string()
}

impl ExposedCredsPolicy {
    /// Build a policy from a JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if policy.provider != "static" {
            anyhow::bail!(
                "exposed_credentials provider {:?} not recognised in OSS; only `static` is supported (HIBP lives in the enterprise build)",
                policy.provider
            );
        }
        let mut hash_set = std::collections::HashSet::new();
        for password in policy.passwords.drain(..) {
            hash_set.insert(sha1_hex_upper(password.as_bytes()));
        }
        for h in policy.sha1_hashes.drain(..) {
            hash_set.insert(h.trim().to_ascii_uppercase());
        }
        if let Some(path) = policy.sha1_file.as_deref() {
            let body = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read sha1_file {}: {}", path, e))?;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                hash_set.insert(line.to_ascii_uppercase());
            }
        }
        if hash_set.is_empty() {
            anyhow::bail!(
                "exposed_credentials requires a non-empty list (passwords, sha1_hashes, or sha1_file)"
            );
        }
        policy.hash_set = hash_set;
        Ok(policy)
    }

    /// Inspect the request headers for exposed credentials. Today this
    /// recognises `Authorization: Basic <base64(user:password)>`.
    pub fn check(&self, headers: &http::HeaderMap) -> ExposedCredsResult {
        let Some(password) = extract_basic_auth_password(headers) else {
            return ExposedCredsResult::Clean;
        };
        let hash = sha1_hex_upper(password.as_bytes());
        if self.hash_set.contains(&hash) {
            ExposedCredsResult::Hit {
                reason: "leaked-password",
            }
        } else {
            ExposedCredsResult::Clean
        }
    }

    /// Header name to stamp on the upstream request when tagging.
    pub fn header_name(&self) -> &str {
        &self.header
    }

    /// Configured action.
    pub fn action(&self) -> ExposedCredsAction {
        self.action
    }
}

/// Extract the password segment of an `Authorization: Basic` header.
fn extract_basic_auth_password(headers: &http::HeaderMap) -> Option<String> {
    let raw = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))?;
    let raw = raw.to_str().ok()?;
    let token = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?
        .trim();
    if token.is_empty() {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (_user, password) = decoded.split_once(':')?;
    if password.is_empty() {
        None
    } else {
        Some(password.to_string())
    }
}

fn sha1_hex_upper(bytes: &[u8]) -> String {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, bytes);
    let mut out = String::with_capacity(40);
    for b in d.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02X}", b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_auth_header(user: &str, password: &str) -> http::HeaderMap {
        let raw = format!("{}:{}", user, password);
        let token = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Basic {token}").parse().unwrap());
        headers
    }

    #[test]
    fn known_password_is_flagged() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let result = policy.check(&basic_auth_header("alice", "password123"));
        assert!(matches!(result, ExposedCredsResult::Hit { .. }));
    }

    #[test]
    fn unknown_password_passes() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let result = policy.check(&basic_auth_header("alice", "this-is-fine"));
        assert_eq!(result, ExposedCredsResult::Clean);
    }

    #[test]
    fn no_basic_auth_is_clean() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let result = policy.check(&http::HeaderMap::new());
        assert_eq!(result, ExposedCredsResult::Clean);
    }

    #[test]
    fn bearer_token_does_not_match_basic_auth_path() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer password123".parse().unwrap());
        assert_eq!(policy.check(&headers), ExposedCredsResult::Clean);
    }

    #[test]
    fn sha1_hashes_match_lowercase_or_uppercase() {
        // "password" -> SHA1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "sha1_hashes": ["5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"],
        }))
        .unwrap();
        let result = policy.check(&basic_auth_header("alice", "password"));
        assert!(matches!(result, ExposedCredsResult::Hit { .. }));
    }

    #[test]
    fn empty_list_is_rejected_at_config_time() {
        let err = ExposedCredsPolicy::from_config(serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("non-empty list"));
    }

    #[test]
    fn unrecognised_provider_rejected() {
        let err = ExposedCredsPolicy::from_config(serde_json::json!({
            "provider": "hibp",
            "passwords": ["password"],
        }))
        .unwrap_err();
        assert!(err.to_string().contains("hibp"));
    }

    #[test]
    fn block_action_round_trips() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password"],
            "action": "block",
        }))
        .unwrap();
        assert_eq!(policy.action(), ExposedCredsAction::Block);
    }
}
