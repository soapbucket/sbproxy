//! Transport-agnostic request dispatch for HTTP/3.
//!
//! Provides a dispatch function that processes requests through the proxy pipeline
//! without depending on Pingora's Session type. Used by the H3 listener.

use std::net::IpAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::{debug, error, warn};

use crate::reload;
use sbproxy_modules::{Action, Auth};
use sbproxy_tls::challenges::ACME_CHALLENGE_PREFIX;
use sbproxy_tls::h3_listener::HttpResponse;

// --- Public dispatch API ---

/// Dispatch an HTTP/3 request through the proxy pipeline.
///
/// This is a simplified version of the full Pingora pipeline dispatch.
/// It handles:
/// - Health check endpoint (/health)
/// - ACME challenge interception
/// - Hostname-based origin lookup
/// - Auth checks (API key, basic auth, bearer, JWT)
/// - Non-proxy actions (redirect, static, echo, mock, beacon, noop)
/// - Proxy action (upstream forwarding via reqwest)
pub async fn dispatch_h3_request(
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
    body: Option<Bytes>,
    _client_ip: IpAddr,
) -> Result<HttpResponse> {
    let path = uri.path();

    // --- 1. Health check ---
    if path == "/health" {
        debug!("H3 health check");
        return Ok(json_response(200, r#"{"status":"ok"}"#));
    }

    // --- 2. ACME HTTP-01 challenge interception ---
    if path.starts_with(ACME_CHALLENGE_PREFIX) {
        return handle_acme_challenge(path);
    }

    // --- 3. Origin lookup ---
    let hostname = extract_hostname(&headers, &uri);
    let pipeline = reload::current_pipeline();

    let origin_idx = match pipeline.resolve_origin(&hostname) {
        Some(idx) => idx,
        None => {
            debug!(hostname = %hostname, "H3: no origin found for hostname");
            return Ok(text_response(404, "Not Found"));
        }
    };

    // --- 4. Auth check ---
    if let Some(auth) = pipeline.auths.get(origin_idx).and_then(|a| a.as_ref()) {
        let authorized = check_auth(auth, &headers, &uri);
        if !authorized {
            debug!(hostname = %hostname, "H3: auth failed");
            let mut resp = text_response(401, "Unauthorized");
            resp.headers
                .push(("WWW-Authenticate".to_string(), "Bearer".to_string()));
            let alt_svc = reload::alt_svc_value();
            if !alt_svc.is_empty() {
                resp.headers
                    .push(("Alt-Svc".to_string(), alt_svc.as_str().to_string()));
            }
            return Ok(resp);
        }
    }

    // --- 5. Action dispatch ---
    let action = match pipeline.actions.get(origin_idx) {
        Some(a) => a,
        None => {
            warn!(hostname = %hostname, origin_idx, "H3: no action at index (pipeline mismatch)");
            return Ok(text_response(500, "Internal Server Error"));
        }
    };

    let mut resp = dispatch_action(action, &method, &uri, &headers, body).await?;

    // --- 6. Add Alt-Svc header ---
    let alt_svc = reload::alt_svc_value();
    if !alt_svc.is_empty() {
        resp.headers
            .push(("Alt-Svc".to_string(), alt_svc.as_str().to_string()));
    }

    Ok(resp)
}

// --- ACME challenge handler ---

fn handle_acme_challenge(path: &str) -> Result<HttpResponse> {
    let token = path.strip_prefix(ACME_CHALLENGE_PREFIX).unwrap_or_default();

    if let Some(store) = reload::challenge_store() {
        if let Some(key_auth) = store.get(token) {
            debug!(token = %token, "H3: serving ACME challenge response");
            return Ok(HttpResponse {
                status: 200,
                headers: vec![(
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                )],
                body: Some(Bytes::from(key_auth)),
            });
        }
    }

    debug!(token = %token, "H3: ACME challenge token not found");
    Ok(text_response(404, "challenge not found"))
}

// --- Auth checking ---

/// Returns true if the request passes the configured auth check, false otherwise.
fn check_auth(auth: &Auth, headers: &http::HeaderMap, uri: &http::Uri) -> bool {
    let query = uri.query();
    match auth {
        Auth::ApiKey(api_key) => api_key.check_request(headers, query),
        Auth::BasicAuth(basic) => basic.check_request(headers),
        Auth::Bearer(bearer) => bearer.check_request(headers),
        Auth::Jwt(jwt) => jwt.check_request(headers),
        Auth::Digest(digest) => {
            // For H3, we cannot do the challenge-response flow in a single request.
            // Check if Authorization header is present and valid; reject otherwise.
            digest.check_request(headers, "GET")
        }
        Auth::ForwardAuth(fa) => {
            // Forward auth requires an async subrequest. The H3 dispatch path is
            // synchronous at this point in the pipeline, so we cannot perform the
            // upstream auth call here without a wider refactor. Fail closed: deny
            // the request rather than silently bypassing the configured auth.
            let path = uri.path();
            error!(
                forward_auth_url = %fa.url,
                request_path = %path,
                "H3: forward_auth is not yet wired into the H3 dispatch path; denying request to fail closed. \
                 Configure an HTTP/1.1 or HTTP/2 listener for origins that depend on forward_auth."
            );
            false
        }
        Auth::BotAuth(_) => {
            // Web Bot Auth verification needs the full request shape
            // (method, target-uri, headers) to reconstruct the
            // signature base. The H3 dispatch path does not yet plumb
            // that through; fail closed so unsigned crawlers can't
            // sneak in via H3.
            warn!("H3: bot_auth not yet supported in H3 dispatch; denying request");
            false
        }
        Auth::Cap(_) => {
            // CAP needs the request host + path + agent_id binding.
            // The H3 dispatch path does not yet plumb the resolver
            // chain through; fail closed for symmetry with bot_auth.
            warn!("H3: cap not yet supported in H3 dispatch; denying request");
            false
        }
        Auth::Noop => true,
        Auth::Plugin(_) => {
            // Plugin auth not supported in H3 dispatch; fail closed for safety.
            warn!("H3: plugin auth not supported in H3 dispatch; denying request");
            false
        }
    }
}

// --- Action dispatch ---

async fn dispatch_action(
    action: &Action,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Option<Bytes>,
) -> Result<HttpResponse> {
    match action {
        // --- Redirect ---
        Action::Redirect(r) => {
            let location = if r.preserve_query {
                if let Some(q) = uri.query() {
                    format!("{}?{}", r.url, q)
                } else {
                    r.url.clone()
                }
            } else {
                r.url.clone()
            };
            Ok(HttpResponse {
                status: r.status,
                headers: vec![("Location".to_string(), location)],
                body: None,
            })
        }

        // --- Static ---
        Action::Static(s) => {
            let mut resp_headers = Vec::new();
            if let Some(ref ct) = s.content_type {
                resp_headers.push(("Content-Type".to_string(), ct.clone()));
            }
            for (k, v) in &s.headers {
                resp_headers.push((k.clone(), v.clone()));
            }
            let body = if s.body.is_empty() {
                None
            } else {
                Some(Bytes::from(s.body.clone()))
            };
            Ok(HttpResponse {
                status: s.status,
                headers: resp_headers,
                body,
            })
        }

        // --- Echo ---
        Action::Echo(_) => {
            // Build a JSON object containing the request method, path, headers, and body.
            let mut echo_headers = serde_json::Map::new();
            for (name, value) in headers.iter() {
                if let Ok(v) = value.to_str() {
                    echo_headers.insert(
                        name.as_str().to_string(),
                        serde_json::Value::String(v.to_string()),
                    );
                }
            }
            let body_str = body
                .as_ref()
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| serde_json::Value::String(s.to_string()))
                .unwrap_or(serde_json::Value::Null);

            let echo_obj = serde_json::json!({
                "method": method.as_str(),
                "path": uri.path(),
                "query": uri.query(),
                "headers": echo_headers,
                "body": body_str,
            });
            let echo_body = serde_json::to_string(&echo_obj).context("echo serialization")?;
            Ok(json_response(200, &echo_body))
        }

        // --- Mock ---
        Action::Mock(m) => {
            if let Some(delay_ms) = m.delay_ms {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            let mut resp_headers =
                vec![("Content-Type".to_string(), "application/json".to_string())];
            for (k, v) in &m.headers {
                resp_headers.push((k.clone(), v.clone()));
            }
            let body_str = serde_json::to_string(&m.body).context("mock serialization")?;
            Ok(HttpResponse {
                status: m.status,
                headers: resp_headers,
                body: Some(Bytes::from(body_str)),
            })
        }

        // --- Beacon ---
        Action::Beacon(_) => Ok(HttpResponse {
            status: 204,
            headers: vec![],
            body: None,
        }),

        // --- Noop ---
        Action::Noop => Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: None,
        }),

        // --- Proxy ---
        Action::Proxy(p) => proxy_upstream(p, method, uri, headers, body).await,

        // --- Unsupported actions ---
        Action::LoadBalancer(_) => {
            warn!("H3: load_balancer action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("load_balancer")))
        }
        Action::AiProxy(_) => {
            warn!("H3: ai_proxy action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("ai_proxy")))
        }
        Action::WebSocket(_) => {
            warn!("H3: websocket action not supported over HTTP/3");
            Ok(text_response(501, &h3_unsupported_message("websocket")))
        }
        Action::Grpc(_) => {
            warn!("H3: grpc action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("grpc")))
        }
        Action::GraphQL(_) => {
            warn!("H3: graphql action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("graphql")))
        }
        Action::Storage(_) => {
            warn!("H3: storage action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("storage")))
        }
        Action::A2a(_) => {
            warn!("H3: a2a action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("a2a")))
        }
        Action::Mcp(_) => {
            warn!("H3: mcp action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("mcp")))
        }
        Action::Plugin(_) => {
            warn!("H3: plugin action not supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("plugin")))
        }
    }
}

/// Build the standard 501 body for action types that the H3 dispatch path
/// does not yet route through. Operators that hit this should fall back to
/// an HTTP/1.1 or HTTP/2 listener for the affected origin.
fn h3_unsupported_message(action_type: &str) -> String {
    format!(
        "Action type {action_type} is not supported over HTTP/3 in this build. \
         Configure HTTP/1.1 or HTTP/2 listener for this origin."
    )
}

// --- Upstream proxy via reqwest ---

async fn proxy_upstream(
    action: &sbproxy_modules::ProxyAction,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Option<Bytes>,
) -> Result<HttpResponse> {
    // Build upstream URL: upstream base + path + query.
    let upstream_base = action.url.trim_end_matches('/');
    let path = uri.path();
    let upstream_url = if let Some(query) = uri.query() {
        format!("{}{}?{}", upstream_base, path, query)
    } else {
        format!("{}{}", upstream_base, path)
    };

    debug!(upstream = %upstream_url, method = %method, "H3: proxying to upstream");

    // Build reqwest client (no-redirect to preserve semantics).
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building reqwest client")?;

    // Convert http::Method to reqwest::Method.
    let req_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).context("converting method")?;

    let mut req_builder = client.request(req_method, &upstream_url);

    // Forward headers (skip hop-by-hop and H3 pseudo-headers).
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if should_forward_header(name_str) {
            if let Ok(v) = value.to_str() {
                req_builder = req_builder.header(name_str, v);
            }
        }
    }

    // Forward body if present.
    if let Some(b) = body {
        req_builder = req_builder.body(b);
    }

    let upstream_resp = req_builder
        .send()
        .await
        .with_context(|| format!("upstream request to {}", upstream_url))?;

    // Convert response.
    let resp_status = upstream_resp.status().as_u16();
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    for (name, value) in upstream_resp.headers().iter() {
        if let Ok(v) = value.to_str() {
            resp_headers.push((name.as_str().to_string(), v.to_string()));
        }
    }

    let resp_body = upstream_resp
        .bytes()
        .await
        .context("reading upstream body")?;
    let body_opt = if resp_body.is_empty() {
        None
    } else {
        Some(resp_body)
    };

    Ok(HttpResponse {
        status: resp_status,
        headers: resp_headers,
        body: body_opt,
    })
}

/// Returns false for headers that must not be forwarded to the upstream.
///
/// Skips HTTP/2+3 pseudo-headers (`:authority`, `:method`, `:path`, `:scheme`)
/// and common hop-by-hop headers that are connection-specific.
fn should_forward_header(name: &str) -> bool {
    // HTTP/2 and HTTP/3 pseudo-headers start with ':'.
    if name.starts_with(':') {
        return false;
    }
    // Standard hop-by-hop headers.
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
    .not()
}

// --- Hostname extraction ---

/// Extract the hostname from the `Host` header, falling back to the URI authority.
///
/// Strips any port suffix (e.g. `example.com:443` -> `example.com`).
fn extract_hostname(headers: &http::HeaderMap, uri: &http::Uri) -> String {
    // Prefer the :authority pseudo-header (H2/H3) which Pingora surfaces as
    // a normal header named ":authority". Fall back to Host, then URI authority.
    if let Some(auth) = headers
        .get(":authority")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
    {
        // Strip port from host if present.
        return strip_port(auth).to_string();
    }
    if let Some(auth) = uri.authority().map(|a| a.as_str()) {
        return strip_port(auth).to_string();
    }
    String::new()
}

/// Remove `:port` suffix from a host string.
fn strip_port(host: &str) -> &str {
    // IPv6 addresses look like [::1]:443 - strip after the closing bracket.
    if host.starts_with('[') {
        if let Some(bracket_end) = host.rfind(']') {
            return &host[..=bracket_end];
        }
    }
    // IPv4 / hostname: take everything before the last ':'.
    if let Some(colon_pos) = host.rfind(':') {
        // Only strip if what follows looks like a port number.
        let potential_port = &host[colon_pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            return &host[..colon_pos];
        }
    }
    host
}

// --- Response helpers ---

fn json_response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Some(Bytes::from(body.to_owned())),
    }
}

fn text_response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        body: Some(Bytes::from(body.to_owned())),
    }
}

// --- not() helper (std::ops::Not for bool) ---
trait BoolNot {
    fn not(self) -> bool;
}
impl BoolNot for bool {
    fn not(self) -> bool {
        !self
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Health check ---

    #[tokio::test]
    async fn health_check_returns_200() {
        let method = http::Method::GET;
        let uri: http::Uri = "/health".parse().unwrap();
        let headers = http::HeaderMap::new();

        let resp = dispatch_h3_request(method, uri, headers, None, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status, 200);
        let body = resp.body.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            body_str.contains("ok"),
            "body should contain ok: {body_str}"
        );
    }

    #[tokio::test]
    async fn health_check_content_type_is_json() {
        let method = http::Method::GET;
        let uri: http::Uri = "/health".parse().unwrap();
        let headers = http::HeaderMap::new();

        let resp = dispatch_h3_request(method, uri, headers, None, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        assert!(
            resp.headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v.contains("application/json")),
            "Content-Type should be application/json"
        );
    }

    // --- ACME challenge ---

    #[tokio::test]
    async fn acme_challenge_missing_token_returns_404() {
        let method = http::Method::GET;
        let uri: http::Uri = "/.well-known/acme-challenge/nonexistenttoken"
            .parse()
            .unwrap();
        let headers = http::HeaderMap::new();

        let resp = dispatch_h3_request(method, uri, headers, None, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        // No challenge store seeded, so we expect 404.
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn acme_challenge_with_store_returns_key_auth() {
        use sbproxy_tls::challenges::Http01ChallengeStore;

        let store = std::sync::Arc::new(Http01ChallengeStore::new());
        store.set("mytoken", "mytoken.thumbprint123");
        reload::set_challenge_store(std::sync::Arc::clone(&store));

        let method = http::Method::GET;
        let uri: http::Uri = "/.well-known/acme-challenge/mytoken".parse().unwrap();
        let headers = http::HeaderMap::new();

        let resp = dispatch_h3_request(method, uri, headers, None, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status, 200);
        let body = resp.body.unwrap();
        assert_eq!(body.as_ref(), b"mytoken.thumbprint123");
    }

    // --- strip_port ---

    #[test]
    fn strip_port_removes_port() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("localhost:8080"), "localhost");
    }

    #[test]
    fn strip_port_no_port_unchanged() {
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn strip_port_ipv6() {
        assert_eq!(strip_port("[::1]:443"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
    }

    // --- should_forward_header ---

    #[test]
    fn pseudo_headers_are_not_forwarded() {
        assert!(!should_forward_header(":authority"));
        assert!(!should_forward_header(":method"));
        assert!(!should_forward_header(":path"));
        assert!(!should_forward_header(":scheme"));
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        assert!(!should_forward_header("connection"));
        assert!(!should_forward_header("transfer-encoding"));
        assert!(!should_forward_header("upgrade"));
    }

    #[test]
    fn normal_headers_are_forwarded() {
        assert!(should_forward_header("content-type"));
        assert!(should_forward_header("authorization"));
        assert!(should_forward_header("x-custom-header"));
    }

    // --- No origin: returns 404 ---

    #[tokio::test]
    async fn unknown_hostname_returns_404() {
        let method = http::Method::GET;
        let uri: http::Uri = "/some/path".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("host", "completely-unknown-host.example".parse().unwrap());

        let resp = dispatch_h3_request(method, uri, headers, None, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status, 404);
    }

    // --- ForwardAuth fail-closed regression test ---
    //
    // Drives the synchronous `check_auth` helper directly so the assertion
    // does not race with other tests sharing the global pipeline.

    #[test]
    fn check_auth_forward_auth_fails_closed_over_h3() {
        use sbproxy_modules::auth::ForwardAuthProvider;

        let provider = ForwardAuthProvider {
            url: "http://127.0.0.1:1/auth".to_string(),
            method: None,
            headers_to_forward: Vec::new(),
            trust_headers: Vec::new(),
            success_status: None,
            timeout: None,
            host_override: None,
            disable_forwarded_host_header: false,
        };
        let auth = Auth::ForwardAuth(provider);

        let headers = http::HeaderMap::new();
        let uri: http::Uri = "/protected".parse().unwrap();

        let authorized = check_auth(&auth, &headers, &uri);

        assert!(
            !authorized,
            "forward_auth over H3 must fail closed (return false), not bypass auth"
        );
    }
}
