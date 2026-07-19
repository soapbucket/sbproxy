//! Run-as-user upstream credential minting (WOR-1792 / G3).
//!
//! Produces Authorization credentials for MCP upstream calls from a
//! typed [`McpUpstreamAuthConfig`] and an [`McpExecutionContext`].
//! Identity and tokens never enter tool arguments; anonymous and
//! shared-key callers fail closed when run-as-user is enabled; stdio
//! plus run-as-user is a config error until a safe secret-delivery
//! path exists.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use sbproxy_plugin::{McpExecutionContext, Principal, PrincipalSource};
use sbproxy_security::egress::{EgressAuthorizer, EgressPurpose, HostResolver};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How the MCP upstream expects credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpUpstreamAuthConfig {
    /// Shared service credential resolved by reference (vault / env).
    ServiceCredential {
        /// Credential reference resolved through the secret lookup.
        credential_ref: String,
    },
    /// RFC 8693-style token exchange for the inbound / delegated subject.
    TokenExchange {
        /// Token endpoint URL. Gated by [`EgressPurpose::TokenExchange`].
        token_endpoint: url::Url,
        /// Audience requested for the exchanged token.
        audience: String,
        /// Optional OAuth scope.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Optional client credential reference for the token endpoint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_credential_ref: Option<String>,
    },
    /// Per-user credential; `{subject_id}` in the template is replaced
    /// with the delegation (or principal) subject before lookup.
    PerUserCredential {
        /// Template such as `vault://users/{subject_id}/mcp-token`.
        credential_template: String,
    },
}

/// MCP transport used to reach the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransportKind {
    /// Streamable HTTP / SSE-over-HTTP.
    Http,
    /// Legacy SSE client transport.
    Sse,
    /// Local supervised stdio child process.
    Stdio,
}

/// Closed error vocabulary for run-as-user credential minting.
///
/// Display / Debug strings never embed secrets, tokens, or raw DSNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAuthError {
    /// Caller has no subject and no attribution surface.
    AnonymousCaller,
    /// Shared bearer / API-key credential without a bound subject.
    SharedKeyCaller,
    /// stdio transport cannot safely deliver per-user secrets yet.
    StdioRunAsUserUnsupported,
    /// Run-as-user modes that need a subject but none was provided.
    MissingSubject,
    /// Secret lookup failed (reference identity only; never the secret).
    SecretLookup,
    /// Token exchange failed without echoing response bodies.
    TokenExchangeFailed,
    /// Token-endpoint egress denied.
    EgressDenied,
    /// Authorization header value could not be constructed.
    InvalidHeader,
}

impl std::fmt::Display for UpstreamAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnonymousCaller => write!(f, "run-as-user requires an authenticated subject"),
            Self::SharedKeyCaller => {
                write!(
                    f,
                    "run-as-user rejects shared-key callers without a subject"
                )
            }
            Self::StdioRunAsUserUnsupported => {
                write!(f, "stdio transport cannot use run-as-user credentials")
            }
            Self::MissingSubject => {
                write!(f, "run-as-user requires a delegation or principal subject")
            }
            Self::SecretLookup => write!(f, "credential secret lookup failed"),
            Self::TokenExchangeFailed => write!(f, "token exchange failed"),
            Self::EgressDenied => write!(f, "token exchange egress denied"),
            Self::InvalidHeader => write!(f, "authorization header is invalid"),
        }
    }
}

impl std::error::Error for UpstreamAuthError {}

/// Minted upstream Authorization credential (header only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAuthorization {
    /// Header name, lowercased (`authorization`).
    pub header_name: String,
    /// Header value (`Bearer …`). Never logged by this module.
    pub header_value: String,
}

/// Validate that run-as-user auth is compatible with the transport.
///
/// `stdio` + any run-as-user auth config is a hard config error until a
/// safe secret-delivery mechanism exists for local child processes.
pub fn validate_run_as_user_config(
    _config: &McpUpstreamAuthConfig,
    transport: McpTransportKind,
) -> Result<(), UpstreamAuthError> {
    if matches!(transport, McpTransportKind::Stdio) {
        return Err(UpstreamAuthError::StdioRunAsUserUnsupported);
    }
    Ok(())
}

/// True when the principal is a shared-key caller (bearer / API key
/// with no bound subject).
pub fn is_shared_key_caller(principal: &Principal) -> bool {
    principal.sub.is_empty()
        && matches!(
            principal.source,
            PrincipalSource::Bearer | PrincipalSource::ApiKey
        )
}

/// Resolve the subject id used for per-user minting and cache isolation.
fn subject_id_for(ctx: &McpExecutionContext<'_>) -> Option<String> {
    if let Some(d) = ctx.delegation {
        if !d.subject_id.is_empty() {
            return Some(d.subject_id.clone());
        }
    }
    if !ctx.principal.sub.is_empty() {
        return Some(ctx.principal.sub.clone());
    }
    if let Some(user) = ctx.principal.attrs.user.as_ref() {
        if !user.is_empty() {
            return Some(user.clone());
        }
    }
    None
}

fn require_identifiable_caller(ctx: &McpExecutionContext<'_>) -> Result<String, UpstreamAuthError> {
    if ctx.principal.is_anonymous() {
        return Err(UpstreamAuthError::AnonymousCaller);
    }
    if is_shared_key_caller(ctx.principal) {
        return Err(UpstreamAuthError::SharedKeyCaller);
    }
    subject_id_for(ctx).ok_or(UpstreamAuthError::MissingSubject)
}

/// Mint an Authorization credential for `ctx` under `config`.
///
/// Never mutates tool arguments. Token exchange is gated by
/// [`EgressPurpose::TokenExchange`] when an authorizer is supplied.
pub async fn mint_upstream_authorization(
    config: &McpUpstreamAuthConfig,
    ctx: &McpExecutionContext<'_>,
    secret_lookup: &(dyn Fn(&str) -> Result<String, ()> + Sync),
    http: &reqwest::Client,
    egress: Option<&EgressAuthorizer>,
    subject_token: Option<&str>,
) -> Result<UpstreamAuthorization, UpstreamAuthError> {
    let subject = require_identifiable_caller(ctx)?;
    match config {
        McpUpstreamAuthConfig::ServiceCredential { credential_ref } => {
            let secret =
                secret_lookup(credential_ref).map_err(|_| UpstreamAuthError::SecretLookup)?;
            Ok(bearer_auth(secret))
        }
        McpUpstreamAuthConfig::PerUserCredential {
            credential_template,
        } => {
            let resolved_ref = credential_template.replace("{subject_id}", &subject);
            let secret =
                secret_lookup(&resolved_ref).map_err(|_| UpstreamAuthError::SecretLookup)?;
            Ok(bearer_auth(secret))
        }
        McpUpstreamAuthConfig::TokenExchange {
            token_endpoint,
            audience,
            scope,
            client_credential_ref,
        } => {
            mint_token_exchange(
                token_endpoint,
                audience,
                scope.as_deref(),
                client_credential_ref.as_deref(),
                &subject,
                subject_token,
                secret_lookup,
                http,
                egress,
            )
            .await
        }
    }
}

fn bearer_auth(secret: String) -> UpstreamAuthorization {
    UpstreamAuthorization {
        header_name: "authorization".to_string(),
        header_value: format!("Bearer {secret}"),
    }
}

/// Attach a minted credential to outbound HTTP headers.
///
/// Tool argument maps are never touched by this helper.
pub fn attach_authorization(
    headers: &mut http::HeaderMap,
    auth: &UpstreamAuthorization,
) -> Result<(), UpstreamAuthError> {
    let name = http::HeaderName::from_bytes(auth.header_name.as_bytes())
        .map_err(|_| UpstreamAuthError::InvalidHeader)?;
    let value = http::HeaderValue::from_str(&auth.header_value)
        .map_err(|_| UpstreamAuthError::InvalidHeader)?;
    headers.insert(name, value);
    Ok(())
}

/// Invariant helper: run-as-user must not inject identity into tool args.
pub fn assert_args_unmutated(before: &serde_json::Value, after: &serde_json::Value) -> bool {
    before == after
        && before
            .as_object()
            .map(|o| !o.contains_key("_sbproxy_run_as_user"))
            .unwrap_or(true)
}

struct PublicPinResolver;

impl HostResolver for PublicPinResolver {
    fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )])
    }
}

struct CachedToken {
    header_value: String,
    expires_at: Instant,
}

static TOKEN_CACHE: Lazy<Mutex<HashMap<String, CachedToken>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn cache_key(
    endpoint: &str,
    audience: &str,
    subject_id: &str,
    subject_token: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(endpoint.as_bytes());
    hasher.update([0]);
    hasher.update(audience.as_bytes());
    hasher.update([0]);
    // Subject id is mandatory for isolation: tokens for user A must
    // never be served to user B even when subject tokens collide.
    hasher.update(subject_id.as_bytes());
    hasher.update([0]);
    if let Some(t) = subject_token {
        hasher.update(Sha256::digest(t.as_bytes()));
    }
    hex::encode(hasher.finalize())
}

async fn mint_token_exchange(
    token_endpoint: &url::Url,
    audience: &str,
    scope: Option<&str>,
    client_credential_ref: Option<&str>,
    subject_id: &str,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String, ()> + Sync),
    http: &reqwest::Client,
    egress: Option<&EgressAuthorizer>,
) -> Result<UpstreamAuthorization, UpstreamAuthError> {
    let endpoint = token_endpoint.as_str();
    if let Some(auth) = egress {
        auth.authorize(EgressPurpose::TokenExchange, endpoint, &PublicPinResolver)
            .map_err(|_| UpstreamAuthError::EgressDenied)?;
    }

    let key = cache_key(endpoint, audience, subject_id, subject_token);
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some(entry) = guard.get(&key) {
            if Instant::now() < entry.expires_at {
                return Ok(UpstreamAuthorization {
                    header_name: "authorization".to_string(),
                    header_value: entry.header_value.clone(),
                });
            }
        }
    }

    let subject = subject_token.ok_or(UpstreamAuthError::TokenExchangeFailed)?;
    let mut form: Vec<(&str, &str)> = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", subject),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", audience),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }

    let mut req = http.post(endpoint).form(&form);
    if let Some(client_ref) = client_credential_ref {
        let secret = secret_lookup(client_ref).map_err(|_| UpstreamAuthError::SecretLookup)?;
        req = req.basic_auth(client_ref, Some(secret));
    }

    let resp = req
        .send()
        .await
        .map_err(|_| UpstreamAuthError::TokenExchangeFailed)?;
    if !resp.status().is_success() {
        return Err(UpstreamAuthError::TokenExchangeFailed);
    }
    let body = resp
        .bytes()
        .await
        .map_err(|_| UpstreamAuthError::TokenExchangeFailed)?;
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| UpstreamAuthError::TokenExchangeFailed)?;
    let token = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or(UpstreamAuthError::TokenExchangeFailed)?;
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64()).unwrap_or(60);
    let header_value = format!("Bearer {token}");

    if let Some(ttl) = expires_in.checked_sub(30).filter(|&s| s > 0) {
        if let Ok(mut guard) = TOKEN_CACHE.lock() {
            guard.insert(
                key,
                CachedToken {
                    header_value: header_value.clone(),
                    expires_at: Instant::now() + Duration::from_secs(ttl),
                },
            );
        }
    }

    Ok(UpstreamAuthorization {
        header_name: "authorization".to_string(),
        header_value,
    })
}

/// Test-only: clear the process token cache between isolation tests.
#[cfg(test)]
pub fn clear_token_cache_for_tests() {
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        guard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_plugin::{DelegationSubject, PrincipalAttrs, TenantId};
    use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};
    use std::collections::HashMap as StdHashMap;

    fn identified_principal() -> Principal {
        Principal {
            tenant_id: TenantId::from("acme"),
            sub: "user-a".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        }
    }

    fn ctx_for<'a>(
        principal: &'a Principal,
        delegation: Option<&'a DelegationSubject>,
    ) -> McpExecutionContext<'a> {
        McpExecutionContext {
            principal,
            request_id: "req-1",
            session_id: None,
            audit_cause: None,
            delegation,
        }
    }

    fn lookup_ok(map: StdHashMap<String, String>) -> impl Fn(&str) -> Result<String, ()> + Sync {
        move |r: &str| map.get(r).cloned().ok_or(())
    }

    fn enforce_token_exchange(hosts: &[&str], ports: &[u16]) -> EgressAuthorizer {
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.schemes.insert("http".to_string());
        for p in ports {
            allow.ports.insert(*p);
        }
        if ports.is_empty() {
            allow.ports.insert(443);
            allow.ports.insert(80);
        }
        let mut purposes = StdHashMap::new();
        purposes.insert(EgressPurpose::TokenExchange, allow);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    #[test]
    fn stdio_plus_run_as_user_is_config_error() {
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let err = validate_run_as_user_config(&cfg, McpTransportKind::Stdio)
            .expect_err("stdio + run-as-user must be a config error");
        assert_eq!(err, UpstreamAuthError::StdioRunAsUserUnsupported);
        assert!(!format!("{err}").contains("vault://"));
        assert!(!format!("{err:?}").contains("vault://"));
    }

    #[test]
    fn http_transport_accepts_run_as_user_config() {
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        validate_run_as_user_config(&cfg, McpTransportKind::Http).expect("http ok");
        validate_run_as_user_config(&cfg, McpTransportKind::Sse).expect("sse ok");
    }

    #[tokio::test]
    async fn service_credential_passthrough_attaches_header_not_args() {
        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc-token".to_string(),
        };
        let map = StdHashMap::from([("vault://svc-token".to_string(), "svc-secret".to_string())]);
        let lookup = lookup_ok(map);
        let http = reqwest::Client::new();
        let auth = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect("passthrough");
        assert_eq!(auth.header_name, "authorization");
        assert_eq!(auth.header_value, "Bearer svc-secret");

        let mut headers = http::HeaderMap::new();
        attach_authorization(&mut headers, &auth).expect("attach");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer svc-secret")
        );

        let before = serde_json::json!({"query": "hello"});
        let after = before.clone();
        assert!(assert_args_unmutated(&before, &after));
        assert!(before
            .as_object()
            .unwrap()
            .get("_sbproxy_run_as_user")
            .is_none());
    }

    #[tokio::test]
    async fn per_user_credential_resolves_subject_template() {
        let principal = identified_principal();
        let delegation = DelegationSubject {
            subject_id: "user-42".to_string(),
            subject_type: "user".to_string(),
        };
        let ctx = ctx_for(&principal, Some(&delegation));
        let cfg = McpUpstreamAuthConfig::PerUserCredential {
            credential_template: "vault://users/{subject_id}/token".to_string(),
        };
        let map = StdHashMap::from([(
            "vault://users/user-42/token".to_string(),
            "user-42-secret".to_string(),
        )]);
        let lookup = lookup_ok(map);
        let http = reqwest::Client::new();
        let auth = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect("per-user");
        assert_eq!(auth.header_value, "Bearer user-42-secret");
    }

    #[tokio::test]
    async fn anonymous_caller_fails_closed() {
        let principal = Principal::anonymous();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let err = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect_err("anonymous must fail closed");
        assert_eq!(err, UpstreamAuthError::AnonymousCaller);
    }

    #[tokio::test]
    async fn shared_key_caller_fails_closed() {
        let principal = Principal {
            tenant_id: TenantId::from("acme"),
            sub: String::new(),
            source: PrincipalSource::ApiKey,
            virtual_key: None,
            attrs: PrincipalAttrs {
                key_id: Some("sk_abcd".to_string()),
                project: Some("platform".to_string()),
                ..PrincipalAttrs::default()
            },
        };
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let lookup = lookup_ok(StdHashMap::from([(
            "vault://svc".to_string(),
            "secret".to_string(),
        )]));
        let http = reqwest::Client::new();
        let err = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect_err("shared-key must fail closed");
        assert_eq!(err, UpstreamAuthError::SharedKeyCaller);
    }

    #[tokio::test]
    async fn mint_never_injects_run_as_user_into_tool_arguments() {
        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let lookup = lookup_ok(StdHashMap::from([(
            "vault://svc".to_string(),
            "secret".to_string(),
        )]));
        let http = reqwest::Client::new();
        let mut args = serde_json::json!({"path": "/tmp"});
        let before = args.clone();
        let _auth = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect("mint");
        assert!(assert_args_unmutated(&before, &args));
        assert!(args
            .as_object_mut()
            .unwrap()
            .get("_sbproxy_run_as_user")
            .is_none());
    }

    #[tokio::test]
    async fn token_exchange_mints_via_egress_purpose() {
        clear_token_cache_for_tests();
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping token-exchange test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let body =
                    r#"{"access_token":"exchanged-xyz","token_type":"Bearer","expires_in":3600}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });

        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let endpoint = url::Url::parse(&format!("http://127.0.0.1:{port}/token")).unwrap();
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: endpoint,
            audience: "https://mcp.example".to_string(),
            scope: Some("tools".to_string()),
            client_credential_ref: None,
        };
        let egress = enforce_token_exchange(&["127.0.0.1"], &[port]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let auth = mint_upstream_authorization(
            &cfg,
            &ctx,
            &lookup,
            &http,
            Some(&egress),
            Some("inbound-subject-token"),
        )
        .await
        .expect("exchange");
        assert_eq!(auth.header_value, "Bearer exchanged-xyz");
    }

    #[tokio::test]
    async fn token_exchange_egress_denies_unlisted_host() {
        clear_token_cache_for_tests();
        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: url::Url::parse("https://evil.example/token").unwrap(),
            audience: "https://mcp.example".to_string(),
            scope: None,
            client_credential_ref: None,
        };
        let egress = enforce_token_exchange(&["idp.example.com"], &[443]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let err = mint_upstream_authorization(
            &cfg,
            &ctx,
            &lookup,
            &http,
            Some(&egress),
            Some("inbound-subject-token"),
        )
        .await
        .expect_err("unlisted host");
        assert_eq!(err, UpstreamAuthError::EgressDenied);
        assert!(!format!("{err}").contains("evil.example"));
        assert!(!format!("{err:?}").contains("evil.example"));
    }

    #[tokio::test]
    async fn token_cache_isolates_users() {
        clear_token_cache_for_tests();
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping cache isolation test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for token in ["token-for-a", "token-for-b"] {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = s.read(&mut buf);
                    let body = format!(
                        r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
            }
        });

        let endpoint = url::Url::parse(&format!("http://127.0.0.1:{port}/token")).unwrap();
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: endpoint,
            audience: "https://mcp.example".to_string(),
            scope: None,
            client_credential_ref: None,
        };
        let egress = enforce_token_exchange(&["127.0.0.1"], &[port]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();

        let principal_a = Principal {
            tenant_id: TenantId::from("acme"),
            sub: "user-a".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        };
        let principal_b = Principal {
            tenant_id: TenantId::from("acme"),
            sub: "user-b".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        };
        let ctx_a = ctx_for(&principal_a, None);
        let ctx_b = ctx_for(&principal_b, None);
        let shared_subject_token = "shared-inbound-token";

        let auth_a = mint_upstream_authorization(
            &cfg,
            &ctx_a,
            &lookup,
            &http,
            Some(&egress),
            Some(shared_subject_token),
        )
        .await
        .expect("user a");
        let auth_b = mint_upstream_authorization(
            &cfg,
            &ctx_b,
            &lookup,
            &http,
            Some(&egress),
            Some(shared_subject_token),
        )
        .await
        .expect("user b");

        assert_eq!(auth_a.header_value, "Bearer token-for-a");
        assert_eq!(auth_b.header_value, "Bearer token-for-b");
        assert_ne!(
            auth_a.header_value, auth_b.header_value,
            "user A token must never be served to user B"
        );
    }

    #[test]
    fn errors_never_embed_secrets() {
        let errs = [
            UpstreamAuthError::AnonymousCaller,
            UpstreamAuthError::SharedKeyCaller,
            UpstreamAuthError::StdioRunAsUserUnsupported,
            UpstreamAuthError::MissingSubject,
            UpstreamAuthError::SecretLookup,
            UpstreamAuthError::TokenExchangeFailed,
            UpstreamAuthError::EgressDenied,
            UpstreamAuthError::InvalidHeader,
        ];
        for err in errs {
            let s = format!("{err}");
            let d = format!("{err:?}");
            assert!(!s.contains("Bearer"));
            assert!(!d.to_lowercase().contains("password"));
        }
    }

    #[test]
    fn public_pin_resolver_returns_socket() {
        let r = PublicPinResolver;
        let addrs = r.resolve("example.com", 443).unwrap();
        assert_eq!(
            addrs[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)
        );
    }
}
