//! MCP server-level runtime state vs per-tool-call auth challenges.
//!
//! "This federated server needs authentication" and "this in-flight
//! tool call is blocked on a step-up" are different facts. A scope
//! escalation on one call must not mark the whole server unusable.
//! Shared OAuth challenge shape follows the Agent Host Protocol MCP
//! guide (reason, requiredScopes from `WWW-Authenticate`, optional
//! oauthClient, description).

use serde::Serialize;

/// Discriminated runtime state of one federated MCP server.
///
/// Distinct from the operator's enable/disable intent: a disabled
/// server is not in the federation at all, and a configured server
/// stays `intent: enabled` while this enum moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub(crate) enum ServerRuntimeState {
    /// Probe has not yet classified the upstream.
    Starting,
    /// Last classifiable contact succeeded without an auth challenge.
    Ready,
    /// Last classifiable contact was a server-level auth challenge.
    #[serde(rename = "authRequired")]
    AuthRequired {
        /// Why the challenge was issued.
        challenge: OAuthChallenge,
    },
    /// Last contact failed in a way that is not an auth challenge.
    Error {
        /// Short, non-secret classification.
        reason: String,
    },
    /// The federation is no longer probing this server.
    #[allow(dead_code)] // documented GET /admin/mcp-runtime state; no production writer yet
    Stopped,
}

/// Why an OAuth challenge was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AuthChallengeReason {
    /// No credentials, or a first-contact 401.
    Required,
    /// The presented token is no longer valid.
    Expired,
    /// The presented token lacks a scope the call needs.
    InsufficientScope,
}

/// One OAuth challenge, shared by server-level and per-call state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthChallenge {
    /// Why the challenge was issued.
    pub reason: AuthChallengeReason,
    /// Scopes parsed from `WWW-Authenticate: Bearer scope="..."`.
    /// Authoritative for the next authorization request. Not inferred
    /// from `scopes_supported` in metadata.
    pub required_scopes: Vec<String>,
    /// Optional pre-registered client. A secret present means
    /// confidential; absent means public (PKCE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_client: Option<OAuthClientHint>,
    /// The OAuth `error_description`, for humans. Never a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Optional client hint so a caller can skip dynamic client registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthClientHint {
    /// Client id.
    pub client_id: String,
    /// True when a client secret is configured (confidential client).
    pub confidential: bool,
}

/// Status of one in-flight tool call's auth posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub(crate) enum ToolCallAuthStatus {
    /// The call is in flight and not blocked on auth.
    Running,
    /// The call is blocked on a step-up challenge. The server that
    /// owns the tool stays serving other calls.
    #[serde(rename = "authRequired")]
    AuthRequired {
        /// Server that owns the tool. Not the whole federation.
        server: String,
        /// Tool that triggered the challenge.
        tool: String,
        /// Challenge for this call only.
        challenge: OAuthChallenge,
    },
}

/// Parse `WWW-Authenticate: Bearer ...` into an [`OAuthChallenge`].
///
/// `requiredScopes` come only from the `scope=` parameter. Metadata
/// `scopes_supported` is ignored here. A missing or unparseable header
/// still yields `reason: required` with an empty scope list.
pub(crate) fn parse_bearer_challenge(header: Option<&str>) -> OAuthChallenge {
    let Some(header) = header.map(str::trim).filter(|h| !h.is_empty()) else {
        return OAuthChallenge {
            reason: AuthChallengeReason::Required,
            required_scopes: Vec::new(),
            oauth_client: None,
            description: None,
        };
    };
    let params = bearer_params(header);
    let error = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("error"))
        .map(|(_, v)| v.as_str());
    let reason = match error {
        Some("insufficient_scope") => AuthChallengeReason::InsufficientScope,
        Some("invalid_token") => AuthChallengeReason::Expired,
        _ => AuthChallengeReason::Required,
    };
    let required_scopes = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("scope"))
        .map(|(_, v)| {
            v.split_whitespace()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let description = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("error_description"))
        .map(|(_, v)| v.clone());
    OAuthChallenge {
        reason,
        required_scopes,
        oauth_client: None,
        description,
    }
}

fn bearer_params(header: &str) -> Vec<(String, String)> {
    let rest = header
        .strip_prefix("Bearer")
        .or_else(|| header.strip_prefix("bearer"))
        .unwrap_or(header)
        .trim();
    let mut out = Vec::new();
    for part in rest.split(',') {
        let part = part.trim();
        let Some((key, raw)) = part.split_once('=') else {
            continue;
        };
        let value = raw.trim().trim_matches('"');
        out.push((key.trim().to_string(), value.to_string()));
    }
    out
}

/// Whether a successful result is allowed for this call status.
///
/// Success is valid only from [`ToolCallAuthStatus::Running`]. A
/// failed or cancelled result completes either state.
pub(crate) fn success_is_valid(status: &ToolCallAuthStatus) -> bool {
    matches!(status, ToolCallAuthStatus::Running)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_header_is_reason_required_with_no_scopes() {
        let challenge = parse_bearer_challenge(None);
        assert_eq!(challenge.reason, AuthChallengeReason::Required);
        assert!(challenge.required_scopes.is_empty());
    }

    #[test]
    fn required_scopes_come_from_the_challenge_header_not_metadata() {
        let challenge = parse_bearer_challenge(Some(
            r#"Bearer realm="mcp", scope="tools:read tools:write", error="insufficient_scope""#,
        ));
        assert_eq!(challenge.reason, AuthChallengeReason::InsufficientScope);
        assert_eq!(
            challenge.required_scopes,
            vec!["tools:read".to_string(), "tools:write".to_string()]
        );
    }

    #[test]
    fn expired_tokens_map_to_expired() {
        let challenge = parse_bearer_challenge(Some(
            r#"Bearer error="invalid_token", error_description="token expired""#,
        ));
        assert_eq!(challenge.reason, AuthChallengeReason::Expired);
        assert_eq!(challenge.description.as_deref(), Some("token expired"));
    }

    #[test]
    fn a_bare_401_is_required() {
        let challenge = parse_bearer_challenge(Some("Bearer realm=\"mcp\""));
        assert_eq!(challenge.reason, AuthChallengeReason::Required);
        assert!(challenge.required_scopes.is_empty());
    }

    #[test]
    fn success_is_rejected_on_an_auth_required_call() {
        let running = ToolCallAuthStatus::Running;
        let blocked = ToolCallAuthStatus::AuthRequired {
            server: "gh".into(),
            tool: "search".into(),
            challenge: parse_bearer_challenge(Some(
                r#"Bearer error="insufficient_scope", scope="repo""#,
            )),
        };
        assert!(success_is_valid(&running));
        assert!(!success_is_valid(&blocked));
    }

    #[test]
    fn stopped_serializes_as_stopped() {
        let value = serde_json::to_value(ServerRuntimeState::Stopped).expect("serializes");
        assert_eq!(value["state"], "stopped");
    }
}
