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
use sbproxy_plugin::ActionOutcome;
use sbproxy_tls::challenges::ACME_CHALLENGE_PREFIX;
use sbproxy_tls::h3_listener::HttpResponse;

pub(crate) fn unsupported_plugin_action_proxy_message() -> String {
    format!(
        "{}: plugin action cannot proxy without a configured upstream",
        sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE
    )
}

/// Status every transport answers a legacy
/// [`ActionOutcome::Responded`] with.
///
/// The variant says "I wrote a response through host state", and no
/// host state a linked `ActionHandler` can reach writes one: `handle`
/// receives the request and an opaque `&mut dyn Any`, never a session
/// or a response writer. The outcome therefore names a capability this
/// host does not implement, which is what 501 is for (RFC 9110
/// section 15.6.2). H3 already answered 501 here; H1/H2 treated the
/// outcome as handled and wrote nothing at all, so a client saw an
/// empty exchange and the access log had no status (WOR-2632).
pub(crate) const LEGACY_RESPONDED_STATUS: u16 = 501;

/// The single refusal body every transport sends for a legacy
/// [`ActionOutcome::Responded`], carrying the stable
/// [`sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE`] reason so an
/// operator can match on the code rather than the prose.
pub(crate) fn unsupported_plugin_action_responded_message() -> String {
    format!(
        "{}: plugin action returned the legacy `Responded` outcome, which carries no response \
         bytes; return `ActionOutcome::Response {{ status, headers, body }}` instead",
        sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE
    )
}

/// The `plugin_action_outcome` label every transport reports for a
/// legacy [`ActionOutcome::Responded`] refusal.
///
/// A closed value: one literal, never derived from anything a plugin
/// supplies, so the counter's cardinality is bounded by this file.
pub(crate) const LEGACY_RESPONDED_OUTCOME_LABEL: &str = "responded";

/// The typed decision record for a refused plugin action outcome.
///
/// Split out from the publisher so its shape is testable without a
/// process-wide event egress. Every field is either a constant from
/// this file or an identifier the gateway itself minted: no plugin
/// output, no request body, no header value reaches it.
pub(crate) fn unsupported_plugin_action_outcome_event_data(
    request_id: Option<&str>,
    outcome: &'static str,
) -> serde_json::Value {
    serde_json::json!({
        "action": "plugin",
        "plugin_action_outcome": outcome,
        "reason": sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE,
        "status": LEGACY_RESPONDED_STATUS,
        "request_id": request_id,
    })
}

/// Record a refused plugin action outcome on every axis an operator
/// reads, from one place both transports call.
///
/// WOR-2632's acceptance line asks telemetry to carry a defined HTTP
/// status *and* a plugin outcome. The status reaches the access log
/// through `RequestContext::response_status`; the outcome reached only
/// a `warn!`, and a log line that rotates is not a record of a
/// decision. It now also ticks `sbproxy_errors_total` under the stable
/// [`sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE`] reason and
/// publishes a `request_error` event, so the refusal is alertable in
/// Prometheus and present in the SIEM feed.
///
/// Both label values are closed: `error_type` is the reason constant
/// and `plugin_action_outcome` is
/// [`LEGACY_RESPONDED_OUTCOME_LABEL`], neither of them derived from
/// plugin output.
pub(crate) fn record_unsupported_plugin_action_outcome(
    hostname: &str,
    tenant_id: &str,
    request_id: Option<&str>,
    outcome: &'static str,
) {
    warn!(
        outcome,
        reason = sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE,
        status = LEGACY_RESPONDED_STATUS,
        "plugin action returned the legacy Responded outcome, which carries no response bytes"
    );
    sbproxy_observe::metrics::metrics()
        .errors_total
        .with_label_values(&[hostname, sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE])
        .inc();
    let event_type = sbproxy_observe::EventType::RequestError;
    if !sbproxy_observe::event_sink::wants_event(event_type) {
        return;
    }
    sbproxy_observe::event_sink::publish_proxy_event(event_type, || {
        sbproxy_observe::events::ProxyEvent::new(
            event_type,
            hostname.to_string(),
            tenant_id.to_string(),
            unsupported_plugin_action_outcome_event_data(request_id, outcome),
        )
    });
}

// --- Public dispatch API ---

/// Dispatch an HTTP/3 request through the proxy pipeline.
///
/// This is a simplified version of the full Pingora pipeline dispatch.
/// It handles:
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

    // --- 1. ACME HTTP-01 challenge interception ---
    if path.starts_with(ACME_CHALLENGE_PREFIX) {
        return handle_acme_challenge(path).await;
    }

    // --- 2. Origin lookup ---
    let hostname = extract_hostname(&headers, &uri);
    let pipeline = reload::current_pipeline();

    let resolved_origin = pipeline.resolve_origin(&hostname);
    if should_serve_unrouted_health(path, resolved_origin.is_some()) {
        debug!(hostname = %hostname, "H3 unrouted health fallback");
        return Ok(json_response(200, r#"{"status":"ok"}"#));
    }

    let origin_idx = match resolved_origin {
        Some(idx) => idx,
        None => {
            // WOR-1097: a request for an unrouted Host is rejected
            // before origin resolution, so it never reaches the access
            // log or any per-origin counter. Without this it is fully
            // invisible (misconfiguration, scanning, wrong DNS). Tenant
            // is unresolved here, so count it under a dedicated
            // unrouted-request series and log at warn (not debug) so it
            // surfaces in production.
            sbproxy_observe::metrics::record_unrouted_request("unknown_host");
            warn!(hostname = %hostname, status = 404, "H3: no origin found for hostname; request unrouted");
            return Ok(text_response(404, "Not Found"));
        }
    };

    // --- 3. Auth check ---
    if let Some(auth) = pipeline.auths.get(origin_idx).and_then(|a| a.as_ref()) {
        let authorized = check_auth(
            auth,
            &headers,
            &uri,
            &method,
            body.as_deref().unwrap_or(&[]),
        )
        .await;
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

    // --- 4. Action dispatch ---
    let action = match pipeline.actions.get(origin_idx) {
        Some(a) => a,
        None => {
            warn!(hostname = %hostname, origin_idx, "H3: no action at index (pipeline mismatch)");
            return Ok(text_response(500, "Internal Server Error"));
        }
    };

    let mut resp = dispatch_action(action, &method, &uri, &headers, body).await?;

    // --- 5. Add Alt-Svc header ---
    let alt_svc = reload::alt_svc_value();
    if !alt_svc.is_empty() {
        resp.headers
            .push(("Alt-Svc".to_string(), alt_svc.as_str().to_string()));
    }

    Ok(resp)
}

// --- ACME challenge handler ---

/// Async because the lookup reads through to the shared cert store when this
/// node is not the one that published the token, which is the common case
/// behind a load balancer (WOR-2310).
async fn handle_acme_challenge(path: &str) -> Result<HttpResponse> {
    let token = path.strip_prefix(ACME_CHALLENGE_PREFIX).unwrap_or_default();

    if let Some(store) = reload::challenge_store() {
        if let Some(key_auth) = store.get_async(token).await {
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

/// Complete the `content-digest` half of an RFC 9421 proof against the
/// bytes that actually arrived.
///
/// The H1/H2 path defers this to the request body filter, which has the
/// buffered body; the H3 dispatch holds the body already and has no such
/// filter behind it, so it finishes the proof inline. Returns `true`
/// when the signature covers no `content-digest` (there is nothing to
/// bind) and fails closed on a covered digest whose header is absent or
/// does not describe `body`.
///
/// `repr-digest` is accepted alongside `content-digest` to match
/// `trust_tier::verify_and_finalize_body_proof`, so the two paths cannot
/// disagree about what counts as a body proof.
fn signature_body_binding_holds(headers: &http::HeaderMap, body: &[u8]) -> bool {
    if !sbproxy_middleware::signatures::signature_input_covers_content_digest(headers) {
        return true;
    }
    headers
        .get("content-digest")
        .or_else(|| headers.get("repr-digest"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| sbproxy_middleware::digest::verify_content_digest(value, body))
}

/// Returns true if the request passes the configured auth check, false otherwise.
///
/// Async because JWT validation can refetch a rotated JWKS key set over
/// the network on an unknown `kid`; every other arm resolves without
/// awaiting.
async fn check_auth(
    auth: &Auth,
    headers: &http::HeaderMap,
    uri: &http::Uri,
    method: &http::Method,
    body: &[u8],
) -> bool {
    let query = uri.query();
    match auth {
        Auth::ApiKey(api_key) => api_key.check_request(headers, query),
        Auth::BasicAuth(basic) => basic.check_request(headers),
        Auth::Bearer(bearer) => bearer.check_request(headers),
        Auth::Jwt(jwt) => jwt.check_request(headers).await,
        Auth::Digest(digest) => {
            // For H3, we cannot do the challenge-response flow in a single request.
            // Check if Authorization header is present and valid; reject otherwise.
            // WOR-1163: validate against the request's real method. RFC 7616
            // digest binds the method into the A2 hash, so checking against a
            // hardcoded "GET" rejected every valid non-GET request.
            digest.check_request(headers, method.as_str())
        }
        Auth::Hmac(h) => {
            // RFC 9421 verification needs method + uri + headers, all of
            // which the H3 dispatch has, so it verifies for real here
            // rather than failing closed like the providers that need
            // wiring the H3 path lacks.
            //
            // Unlike the H1/H2 path, this one already holds the complete
            // body, and there is no request body filter downstream to
            // defer to. So both halves of the proof happen here:
            // `HmacAuth::verify` checks the covered components and
            // `signature_body_binding_holds` completes the
            // `content-digest` binding against the bytes that arrived.
            // Dropping the second half would make body coverage a no-op
            // on this path, which is worse than the empty-body compare
            // it replaced.
            let builder = http::Request::builder()
                .method(method.clone())
                .uri(uri.clone());
            match builder.body(bytes::Bytes::copy_from_slice(body)) {
                Ok(mut req) => {
                    *req.headers_mut() = headers.clone();
                    match h.verify(&req) {
                        sbproxy_modules::auth::HmacVerdict::Verified { .. } => {
                            if signature_body_binding_holds(headers, body) {
                                true
                            } else {
                                warn!(
                                    "H3: hmac_auth signature verified but its covered \
                                     content-digest does not describe the request body; denying"
                                );
                                false
                            }
                        }
                        verdict => {
                            debug!(?verdict, "H3: hmac_auth verification failed");
                            false
                        }
                    }
                }
                Err(_) => false,
            }
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
        Auth::Ldap(l) => {
            // WOR-2519: the directory bind needs only the request
            // headers, so it runs for real on the H3 path too. Every
            // non-allowed outcome (missing credentials, refused bind,
            // unreachable directory) maps to a denial here; the boolean
            // return cannot carry the 503-vs-401 split the H1/H2 path
            // reports, so H3 answers 401 for all of them, which still
            // fails closed.
            matches!(
                l.authenticate(headers).await,
                sbproxy_modules::auth::ldap::LdapBindOutcome::Allowed { .. }
            )
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
        // WOR-2667: the three providers ported from the enterprise
        // tree all verify from the request headers plus, for
        // `ext_authz`, the method and target, every one of which the
        // H3 dispatch holds. They run for real here rather than
        // failing closed like the providers that need wiring this path
        // lacks. The boolean return cannot carry the 503-vs-401 split
        // the H1/H2 path reports, so every non-allow answers a denial,
        // which still fails closed.
        Auth::ExtAuthz(provider) => {
            use sbproxy_modules::auth::ExtAuthzOutcome;
            let target = match uri.query() {
                Some(query) if !query.is_empty() => format!("{}?{}", uri.path(), query),
                _ => uri.path().to_string(),
            };
            matches!(
                provider.authorize(method.as_str(), &target, headers).await,
                ExtAuthzOutcome::Allowed { .. } | ExtAuthzOutcome::FailedOpen
            )
        }
        Auth::OauthIntrospection(provider) => {
            use sbproxy_modules::auth::IntrospectionOutcome;
            matches!(
                provider.authenticate(headers).await,
                IntrospectionOutcome::Active { .. }
            )
        }
        Auth::Kya(verifier) => {
            use sbproxy_modules::auth::KyaVerdict;
            // The same resolution the dispatch used to route the
            // request. Reading `Host` alone yields `""` when the request
            // carries its authority on the URI rather than in a header,
            // which is the H2/H3 shape, and an empty audience fails
            // every token minted for this gateway with
            // `audience_mismatch`: the same token succeeds over
            // HTTP/1.1, and the operator sees a rising `invalid` count
            // and goes looking at the issuer.
            let hostname = extract_hostname(headers, uri);
            match verifier.verify(headers, &hostname).await {
                KyaVerdict::Verified(_) => true,
                KyaVerdict::DirectoryUnavailable => verifier.fail_open,
                _ => false,
            }
        }
        Auth::Noop => true,
        Auth::Oidc(_) => {
            // WOR-892 PR1 step 2/3: OIDC requires the H1 / H2 request
            // pipeline for the auth-code redirect + cookie round-trip.
            // H3 dispatch denies until the wiring lands.
            warn!("H3: oidc auth not supported in H3 dispatch; denying request");
            false
        }
        Auth::Plugin(_) => {
            // Plugin auth not supported in H3 dispatch; fail closed for safety.
            warn!("H3: plugin auth not supported in H3 dispatch; denying request");
            false
        }
        Auth::AnyOf(providers) => {
            // WOR-2517: OR composition. First success wins; a slot the
            // H3 path cannot evaluate (forward_auth is refused at
            // compile, bot_auth / cap / oidc / plugin fail closed
            // above) simply loses its slot and the next provider gets
            // its turn. Boxed because async recursion needs a pinned
            // future.
            for provider in providers {
                if Box::pin(check_auth(provider, headers, uri, method, body)).await {
                    return true;
                }
            }
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
            // gRPC mandates HTTP/2 end-to-end, and the REST <-> gRPC
            // transcoding and gRPC-Web bridging paths are driven from the
            // HTTP/1.1 and HTTP/2 request flow, so none of the gRPC modes
            // are served over the HTTP/3 listener.
            warn!("H3: grpc action (and its transcoding / gRPC-Web modes) not supported in H3 dispatch");
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
        Action::AbTest(_) => {
            warn!("H3: abtest action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("abtest")))
        }
        Action::HttpsProxy(_) => {
            warn!("H3: https_proxy action not yet supported in H3 dispatch");
            Ok(text_response(501, &h3_unsupported_message("https_proxy")))
        }
        Action::Plugin(handler) => {
            let mut request = http::Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .body(body.unwrap_or_default())
                .context("building plugin action request")?;
            *request.headers_mut() = headers.clone();
            let outcome = handler
                .handler()
                .handle(&mut request, &mut ())
                .await
                .with_context(|| {
                    format!(
                        "plugin action {:?} failed",
                        handler.handler().handler_type()
                    )
                })?;
            if matches!(&outcome, ActionOutcome::Responded) {
                // H3 has no `RequestContext`, so the record is stamped
                // with the request's own Host and the default tenant.
                // The alternative is a refusal that appears on one
                // transport's counter and not the other's, which is the
                // per-transport divergence this ticket is about.
                record_unsupported_plugin_action_outcome(
                    &extract_hostname(headers, uri),
                    sbproxy_observe::decision::DEFAULT_TENANT,
                    None,
                    LEGACY_RESPONDED_OUTCOME_LABEL,
                );
            }
            plugin_action_outcome_response(outcome)
        }
    }
}

/// Map an [`ActionOutcome`] onto the response a transport sends.
///
/// Shared so every variant has one answer rather than one per
/// transport: `Response` is validated and sent, `Proxy` is a
/// configuration error the host cannot satisfy, and the legacy
/// `Responded` is the refusal described on
/// [`LEGACY_RESPONDED_STATUS`] (WOR-2632). The H1/H2 path in
/// `server::action_dispatch` writes through the session rather than
/// returning an [`HttpResponse`], so it consumes the same status and
/// message constants instead of calling this directly.
pub(crate) fn plugin_action_outcome_response(outcome: ActionOutcome) -> Result<HttpResponse> {
    match outcome {
        ActionOutcome::Response {
            status,
            headers,
            body,
        } => validate_plugin_action_response(status, headers, body),
        ActionOutcome::Proxy => Err(anyhow::anyhow!(unsupported_plugin_action_proxy_message())),
        // WOR-2632: the same `application/json` `{"error": ...}` body
        // H1/H2 sends through `send_error`, built from the same helper,
        // so "behavior is transport-independent" covers the body shape
        // and the content type and not only the status and the reason.
        // Pure on purpose: the log line, the counter and the typed event
        // belong to the caller, which is the half that knows the
        // hostname and the tenant.
        ActionOutcome::Responded => Ok(json_response(
            LEGACY_RESPONDED_STATUS,
            &crate::server::error_json_body(&unsupported_plugin_action_responded_message()),
        )),
    }
}

const MAX_PLUGIN_ACTION_RESPONSE_HEADERS: usize = 64;
const MAX_PLUGIN_ACTION_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

pub(crate) fn validate_plugin_action_response(
    status: u16,
    mut headers: Vec<(String, String)>,
    body: Bytes,
) -> Result<HttpResponse> {
    // A dynamic action's return value ends dispatch, so an informational
    // status or a body under a bodyless status has to be caught here
    // rather than at the transport, which would already be committed to
    // whatever framing the status implied (WOR-2274).
    sbproxy_extension::bundle::validate_extension_response(status, body.len())?;
    if headers.len() > MAX_PLUGIN_ACTION_RESPONSE_HEADERS {
        anyhow::bail!(
            "plugin action response has {} headers; maximum is {}",
            headers.len(),
            MAX_PLUGIN_ACTION_RESPONSE_HEADERS
        );
    }
    for (name, value) in &headers {
        http::HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid plugin action response header name {name:?}"))?;
        http::HeaderValue::from_str(value)
            .with_context(|| format!("invalid plugin action response header {name:?}"))?;
    }
    let connection_fields: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    headers.retain(|(name, _)| {
        !is_transport_owned_or_hop_by_hop_response_header(name)
            && !connection_fields
                .iter()
                .any(|connection_name| connection_name.eq_ignore_ascii_case(name))
    });
    if body.len() > MAX_PLUGIN_ACTION_RESPONSE_BODY_BYTES {
        anyhow::bail!(
            "plugin action response body exceeds 1 MiB (1048576 bytes): {} bytes",
            body.len()
        );
    }
    Ok(HttpResponse {
        status,
        headers,
        body: Some(body),
    })
}

fn is_transport_owned_or_hop_by_hop_response_header(name: &str) -> bool {
    [
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|blocked| name.eq_ignore_ascii_case(blocked))
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

/// Process-wide client for H3 upstream proxying, built once. Reusing it
/// across requests preserves connection pooling, and the bounded request
/// timeout stops a hung upstream from hanging the H3 request forever
/// (WOR-1147 / WOR-1160). No-redirect mirrors the proxy's pass-through
/// semantics. Per-upstream TLS/SSRF config threading is a follow-up; the
/// upstream URL here is operator-configured, not client-controlled.
fn h3_upstream_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("building shared H3 upstream client")
    })
}

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

    // WOR-1147 / WOR-1160: reuse one process-wide client across H3
    // requests instead of building a fresh one per call. Building per
    // request discarded connection pooling and, with no timeout, let a
    // hung upstream hang the request forever. The shared client carries a
    // bounded request timeout (no-redirect to preserve proxy semantics).
    let client = h3_upstream_client();

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

    // WOR-75: time the outbound call (regardless of success) and
    // stamp the result onto `sbproxy_outbound_request_duration_seconds`
    // along with the active trace exemplar. The host label is the
    // upstream URL's host so dashboards can split slow upstreams
    // from fast ones; `status` is the upstream status code or the
    // sentinel `"error"` when the call failed before a status was
    // available.
    let outbound_started = std::time::Instant::now();
    let outbound_host = uri.host().unwrap_or("").to_string();
    let outbound_method = method.as_str().to_string();
    let send_result = req_builder
        .send()
        .await
        .with_context(|| format!("upstream request to {}", upstream_url));
    let upstream_resp = match send_result {
        Ok(r) => r,
        Err(e) => {
            sbproxy_observe::metrics::record_outbound_request_duration(
                &outbound_host,
                &outbound_method,
                "error",
                outbound_started.elapsed().as_secs_f64(),
            );
            return Err(e);
        }
    };

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
    sbproxy_observe::metrics::record_outbound_request_duration(
        &outbound_host,
        &outbound_method,
        resp_status.to_string().as_str(),
        outbound_started.elapsed().as_secs_f64(),
    );
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
///
/// `pub(crate)` since WOR-2667: the `kya` audience check compares the
/// token's `aud` claim against the request's host, and a second copy of
/// the IPv6 bracket handling here is a second place for it to be wrong.
pub(crate) fn strip_port(host: &str) -> &str {
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

/// Preserve the legacy data-plane liveness probe only when routing has no
/// configured owner for the request. A matched origin must receive its own
/// `/health` request like any other path.
pub(crate) fn should_serve_unrouted_health(path: &str, has_origin: bool) -> bool {
    path == "/health" && !has_origin
}

#[cfg(test)]
pub(crate) fn javascript_proxy_action_fixture() -> (tempfile::TempDir, Action) {
    let directory = tempfile::TempDir::new().expect("temporary JavaScript bundle directory");
    let bundle = directory.path().join("guest-proxy-action");
    std::fs::create_dir_all(&bundle).expect("create JavaScript bundle directory");
    std::fs::write(
        bundle.join("entry.js"),
        r#"export function run() {
            return { version: "sbproxy-envelope/v1", outcome: "proxy" };
        }"#,
    )
    .expect("write JavaScript bundle entry");
    std::fs::write(
        bundle.join("bundle.yaml"),
        r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: guest-proxy-action
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: guest_proxy_action
    export: run
"#,
    )
    .expect("write JavaScript bundle manifest");
    let config = sbproxy_config::ExtensionBundlesConfig {
        bundles_dir: Some(directory.path().display().to_string()),
        sources: Vec::new(),
        grants: Default::default(),
    };
    let registry = sbproxy_extension::bundle::DynamicBundleRegistry::load(
        &config,
        directory.path(),
        &std::collections::BTreeSet::new(),
    )
    .expect("load JavaScript bundle");
    let action = sbproxy_modules::compile_action_with_registry(
        &serde_json::json!({"type": "guest_proxy_action"}),
        registry.as_ref(),
    )
    .expect("compile JavaScript bundle action");
    (directory, action)
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
    use std::future::Future;
    use std::pin::Pin;

    use sbproxy_plugin::{ActionHandler, ActionOutcome, PluginResult};

    use super::*;

    /// WOR-2667 re-review N4. The M4 fix is a one-line call swap with
    /// no test, and the arm it fixed cannot be driven from here: it
    /// needs a live issuer, `check_auth` is private, and this build
    /// refuses `http3.enabled: true`. What is testable is the
    /// resolution the arm now uses, which is the whole content of the
    /// fix. On the H2/H3 shape there is no `Host` header and the
    /// authority arrives on the URI, so `headers.get(HOST)` yielded
    /// `""`, and an empty audience fails every token minted for this
    /// gateway with `audience_mismatch`.
    #[test]
    fn the_kya_audience_hostname_survives_an_absent_host_header() {
        let authority_only = http::HeaderMap::new();
        let absolute: http::Uri = "https://gateway.example.com:8443/v1/chat"
            .parse()
            .expect("absolute uri");
        assert!(
            authority_only.get(http::header::HOST).is_none(),
            "this is the shape the old code read, and it is absent"
        );
        assert_eq!(
            extract_hostname(&authority_only, &absolute),
            "gateway.example.com",
            "the audience check has to see the routed name, not the empty string"
        );

        // The H1 shape still resolves the way it always did.
        let mut h1 = http::HeaderMap::new();
        h1.insert(
            http::header::HOST,
            http::HeaderValue::from_static("gateway.example.com:8443"),
        );
        let path_only: http::Uri = "/v1/chat".parse().expect("path-only uri");
        assert_eq!(extract_hostname(&h1, &path_only), "gateway.example.com");

        // And both resolve to the same name, which is the point: the
        // kya arm reads what the dispatch routed on, so one protocol
        // cannot refuse a token the other accepts.
        assert_eq!(
            extract_hostname(&authority_only, &absolute),
            extract_hostname(&h1, &path_only)
        );
    }

    struct OutcomeAction(ActionOutcome);

    impl ActionHandler for OutcomeAction {
        fn handler_type(&self) -> &str {
            "plugin_action_fixture"
        }

        fn handle(
            &self,
            _req: &mut http::Request<Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = PluginResult<ActionOutcome>> + Send + '_>> {
            let outcome = self.0.clone();
            Box::pin(async move { Ok(outcome) })
        }
    }

    fn plugin_action_response(status: u16, headers: Vec<(String, String)>, body: Bytes) -> Action {
        Action::Plugin(sbproxy_modules::PluginAction::linked(Box::new(
            OutcomeAction(ActionOutcome::Response {
                status,
                headers,
                body,
            }),
        )))
    }

    async fn dispatch_plugin_action(action: &Action) -> Result<HttpResponse> {
        dispatch_action(
            action,
            &http::Method::POST,
            &"/jobs".parse().expect("fixture URI"),
            &http::HeaderMap::new(),
            Some(Bytes::from_static(b"payload")),
        )
        .await
    }

    #[tokio::test]
    async fn h3_refuses_abtest_and_https_proxy_actions_with_documented_501() {
        let abtest = Action::AbTest(
            sbproxy_modules::action::AbTestAction::from_config(serde_json::json!({
                "type": "abtest",
                "variants": [{"name": "only", "url": "https://only.example.test", "weight": 1}],
            }))
            .expect("valid A/B fixture"),
        );
        let https_proxy = Action::HttpsProxy(
            sbproxy_modules::action::HttpsProxyAction::from_config(serde_json::json!({
                "type": "https_proxy",
                "allowed_hosts": ["api.example.test"],
            }))
            .expect("valid HTTPS relay fixture"),
        );

        for action in [&abtest, &https_proxy] {
            let response = dispatch_action(
                action,
                &http::Method::GET,
                &"/".parse().expect("fixture URI"),
                &http::HeaderMap::new(),
                None,
            )
            .await
            .expect("H3 refusal response");
            assert_eq!(response.status, 501);
            assert!(
                String::from_utf8_lossy(response.body.as_deref().unwrap_or_default())
                    .contains("not supported over HTTP/3"),
                "H3 refusal must explain the action is unavailable"
            );
        }
    }

    #[tokio::test]
    async fn plugin_action_h3_dispatches_structured_response() {
        let action = plugin_action_response(
            202,
            vec![("content-type".into(), "text/plain".into())],
            Bytes::from_static(b"queued"),
        );

        let response = dispatch_plugin_action(&action)
            .await
            .expect("valid plugin response");

        assert_eq!(response.status, 202);
        assert_eq!(
            response.headers,
            vec![("content-type".to_string(), "text/plain".to_string())]
        );
        assert_eq!(response.body.as_deref(), Some(&b"queued"[..]));
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_proxy_without_an_upstream() {
        let action = Action::Plugin(sbproxy_modules::PluginAction::linked(Box::new(
            OutcomeAction(ActionOutcome::Proxy),
        )));

        let error = match dispatch_plugin_action(&action).await {
            Ok(_) => panic!("a plugin action cannot continue without an upstream"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("unsupported_action_outcome"),
            "error: {error:#}"
        );
    }

    #[tokio::test]
    async fn javascript_action_h3_rejects_proxy_without_an_upstream() {
        let (_directory, action) = javascript_proxy_action_fixture();

        let error = match dispatch_plugin_action(&action).await {
            Ok(_) => panic!("a JavaScript action cannot continue without an upstream"),
            Err(error) => error,
        };

        assert!(
            format!("{error:#}").contains("unsupported_action_outcome"),
            "error: {error:#}"
        );
    }

    #[tokio::test]
    async fn plugin_action_h3_strips_transport_owned_and_hop_by_hop_headers() {
        let action = plugin_action_response(
            200,
            vec![
                ("content-length".into(), "999".into()),
                ("x-safe-first".into(), "one".into()),
                ("connection".into(), "x-plugin-hop".into()),
                ("x-plugin-hop".into(), "remove-me".into()),
                ("keep-alive".into(), "timeout=5".into()),
                ("proxy-authenticate".into(), "Basic".into()),
                ("proxy-authorization".into(), "Basic secret".into()),
                ("proxy-connection".into(), "keep-alive".into()),
                ("transfer-encoding".into(), "chunked".into()),
                ("te".into(), "trailers".into()),
                ("trailer".into(), "x-checksum".into()),
                ("upgrade".into(), "websocket".into()),
                ("content-type".into(), "text/plain".into()),
                ("x-safe-last".into(), "two".into()),
            ],
            Bytes::from_static(b"actual"),
        );

        let response = dispatch_plugin_action(&action)
            .await
            .expect("valid plugin response");

        assert_eq!(
            response.headers,
            vec![
                ("x-safe-first".to_string(), "one".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-safe-last".to_string(), "two".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_status_below_100() {
        let action = plugin_action_response(99, Vec::new(), Bytes::new());

        let error = dispatch_plugin_action(&action)
            .await
            .err()
            .expect("status below 100 must be rejected");

        assert!(error.to_string().contains("status"), "error: {error:#}");
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_informational_status() {
        // A 1xx is not a final response, but dispatch has already been
        // torn down by the time the outcome arrives, so the client would
        // wait forever for a final status that never comes (WOR-2274).
        for status in [100, 101, 103] {
            let action = plugin_action_response(status, Vec::new(), Bytes::new());

            let error = dispatch_plugin_action(&action)
                .await
                .err()
                .unwrap_or_else(|| panic!("status {status} must be rejected"));

            assert!(
                error.to_string().contains("informational"),
                "status {status} error: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_a_body_under_a_bodyless_status() {
        for status in [204, 304] {
            let action = plugin_action_response(status, Vec::new(), Bytes::from_static(b"nope"));

            let error = dispatch_plugin_action(&action)
                .await
                .err()
                .unwrap_or_else(|| panic!("status {status} with a body must be rejected"));

            assert!(
                error.to_string().contains("forbids a response body"),
                "status {status} error: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn plugin_action_h3_allows_a_bodyless_status_with_no_body() {
        let action = plugin_action_response(204, Vec::new(), Bytes::new());

        let response = dispatch_plugin_action(&action)
            .await
            .expect("204 with an empty body is well formed");

        assert_eq!(response.status, 204);
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_crlf_header_value() {
        let action = plugin_action_response(
            200,
            vec![("x-safe".into(), "ok\r\nx-injected: bad".into())],
            Bytes::new(),
        );

        let error = dispatch_plugin_action(&action)
            .await
            .err()
            .expect("CR/LF header values must be rejected");

        assert!(error.to_string().contains("header"), "error: {error:#}");
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_more_than_64_headers() {
        let headers = (0..65)
            .map(|index| (format!("x-fixture-{index}"), "value".to_string()))
            .collect();
        let action = plugin_action_response(200, headers, Bytes::new());

        let error = dispatch_plugin_action(&action)
            .await
            .err()
            .expect("header count must be bounded");

        assert!(error.to_string().contains("64"), "error: {error:#}");
    }

    #[tokio::test]
    async fn plugin_action_h3_rejects_body_above_one_mib() {
        let action =
            plugin_action_response(200, Vec::new(), Bytes::from(vec![b'x'; 1024 * 1024 + 1]));

        let error = dispatch_plugin_action(&action)
            .await
            .err()
            .expect("response body must be bounded");

        assert!(
            error.to_string().contains("1048576") || error.to_string().contains("1 MiB"),
            "error: {error:#}"
        );
    }

    // --- Data-plane route ownership ---

    #[tokio::test]
    async fn unrouted_health_keeps_the_compatibility_probe() {
        let method = http::Method::GET;
        let uri: http::Uri = "/health".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "host",
            "completely-unknown-health-host.example".parse().unwrap(),
        );

        let resp = dispatch_h3_request(method, uri, headers, None, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status, 200);
    }

    #[test]
    fn a_configured_origin_owns_its_health_path() {
        assert!(!should_serve_unrouted_health("/health", true));
        assert!(should_serve_unrouted_health("/health", false));
        assert!(!should_serve_unrouted_health("/healthz", false));
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
    async fn acme_challenge_is_served_by_a_node_that_did_not_publish_it() {
        // The load balancer decides which replica the CA's validation GET
        // lands on, and it is almost never the replica that won the issuance
        // lease. The serving node here never called `set`; it answers only
        // because the token was published through the shared cert store.
        use sbproxy_platform::{KVStore, MemoryKVStore};
        use sbproxy_tls::challenges::Http01ChallengeStore;

        let shared: std::sync::Arc<dyn KVStore> = std::sync::Arc::new(MemoryKVStore::new(0));
        let issuing_node = Http01ChallengeStore::with_store(std::sync::Arc::clone(&shared));
        issuing_node
            .set("mytoken", "mytoken.thumbprint123", None)
            .unwrap();

        let serving_node = std::sync::Arc::new(Http01ChallengeStore::with_store(shared));
        reload::set_challenge_store(serving_node);

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
    // Drives the `check_auth` helper directly so the assertion
    // does not race with other tests sharing the global pipeline.

    #[tokio::test]
    async fn check_auth_forward_auth_fails_closed_over_h3() {
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

        let authorized = check_auth(&auth, &headers, &uri, &http::Method::GET, b"").await;

        assert!(
            !authorized,
            "forward_auth over H3 must fail closed (return false), not bypass auth"
        );
    }

    // --- hmac_auth body binding over H3 ---
    //
    // The H1/H2 path defers the `content-digest` half of the proof to
    // the request body filter. This path has no filter behind it and
    // already holds the body, so it has to finish the proof itself. If
    // it does not, routing `hmac_auth` through the deferring verifier
    // turns body coverage into a no-op here.

    /// Sign `POST /v1/transfer` over method, target-uri, and
    /// content-digest, returning the header set a client would send.
    fn h3_signed_headers(secret_hex: &str, key_id: &str, digest: &str) -> http::HeaderMap {
        use base64::Engine as _;
        use hmac::{KeyInit as _, Mac as _};
        use sha2::Sha256;
        type HmacSha256 = hmac::Hmac<Sha256>;

        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let raw_input = format!(
            "sig1=(\"@method\" \"@target-uri\" \"content-digest\");created={created};\
             keyid=\"{key_id}\";alg=\"hmac-sha256\""
        )
        .replace("\n", "")
        .replace("             ", "");
        let entry = sbproxy_middleware::signatures::parse_signature_input(&raw_input)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        let req = http::Request::builder()
            .method("POST")
            .uri("/v1/transfer")
            .header("content-digest", digest)
            .body(bytes::Bytes::new())
            .unwrap();
        let base = sbproxy_middleware::signatures::build_signature_base(&req, &entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        mac.update(base.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        let mut headers = http::HeaderMap::new();
        headers.insert("signature-input", raw_input.parse().unwrap());
        headers.insert("signature", format!("sig1=:{sig}:").parse().unwrap());
        headers.insert("content-digest", digest.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn h3_hmac_auth_binds_a_covered_digest_to_the_body_it_received() {
        const SIGNED_BODY: &[u8] = br#"{"to":"acct-1091","amount":"25.00"}"#;
        const SUBSTITUTED_BODY: &[u8] = br#"{"to":"acct-9999","amount":"250000.00"}"#;

        let secret_hex = "00112233445566778899aabbccddeeff";
        let key_id = "svc-billing";
        let auth = sbproxy_modules::compile::compile_auth(&serde_json::json!({
            "type": "hmac_auth",
            "keys": [{"key_id": key_id, "secret": secret_hex}],
        }))
        .expect("hmac provider compiles");

        let digest = sbproxy_middleware::digest::compute_content_digest(
            sbproxy_middleware::digest::Algorithm::Sha256,
            SIGNED_BODY,
        );
        let headers = h3_signed_headers(secret_hex, key_id, &digest);
        let uri: http::Uri = "/v1/transfer".parse().unwrap();
        let method = http::Method::POST;

        assert!(
            check_auth(&auth, &headers, &uri, &method, SIGNED_BODY).await,
            "the body the signature covered must be admitted"
        );
        assert!(
            !check_auth(&auth, &headers, &uri, &method, SUBSTITUTED_BODY).await,
            "H3 holds the body and has no filter behind it, so a substituted body \
             must be refused here or the covered digest means nothing"
        );
    }

    // --- WOR-2517: auth composition over H3 ---

    #[tokio::test]
    async fn check_auth_any_of_accepts_either_credential_over_h3() {
        let auth = sbproxy_modules::compile::compile_auth(&serde_json::json!([
            {"type": "api_key", "api_keys": ["h3-key"], "header_name": "X-Api-Key"},
            {"type": "bearer", "tokens": ["h3-token"]},
        ]))
        .expect("two-provider auth list must compile");
        let uri: http::Uri = "/protected".parse().unwrap();

        let mut with_key = http::HeaderMap::new();
        with_key.insert("x-api-key", "h3-key".parse().unwrap());
        assert!(
            check_auth(&auth, &with_key, &uri, &http::Method::GET, b"").await,
            "the first provider's credential must be accepted"
        );

        let mut with_token = http::HeaderMap::new();
        with_token.insert("authorization", "Bearer h3-token".parse().unwrap());
        assert!(
            check_auth(&auth, &with_token, &uri, &http::Method::GET, b"").await,
            "the second provider's credential must be accepted"
        );

        let empty = http::HeaderMap::new();
        assert!(
            !check_auth(&auth, &empty, &uri, &http::Method::GET, b"").await,
            "a request neither provider accepts must be denied"
        );
    }

    /// WOR-2632: every public `ActionOutcome` has to end in a complete
    /// response. `Responded` carries no bytes and no writer, so the
    /// deterministic answer is the shared 501 refusal rather than a
    /// half-written exchange.
    #[test]
    fn every_action_outcome_yields_a_defined_transport_response() {
        let structured = plugin_action_outcome_response(ActionOutcome::Response {
            status: 202,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body: Bytes::from_static(b"queued"),
        })
        .expect("a structured response is sent as authored");
        assert_eq!(structured.status, 202);
        assert_eq!(structured.body.as_deref(), Some(&b"queued"[..]));

        let responded = plugin_action_outcome_response(ActionOutcome::Responded)
            .expect("the legacy outcome is a defined refusal, not an error");
        assert_eq!(responded.status, LEGACY_RESPONDED_STATUS);
        assert!(
            responded.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("content-type") && value == "application/json"
            }),
            "H3 answers the same media type H1/H2's send_error does: {:?}",
            responded.headers
        );
        let body = String::from_utf8(responded.body.expect("the refusal carries a body").to_vec())
            .expect("refusal body is UTF-8");
        assert_eq!(
            body,
            crate::server::error_json_body(&unsupported_plugin_action_responded_message()),
            "both transports build the refusal body from one helper"
        );
        assert!(
            body.contains(sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE),
            "the refusal names the stable plugin-outcome reason: {body}"
        );

        let Err(proxied) = plugin_action_outcome_response(ActionOutcome::Proxy) else {
            panic!("the plugin action has no upstream to proxy to");
        };
        assert!(
            proxied
                .to_string()
                .contains(sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE),
            "the proxy refusal keeps its own stable reason: {proxied}"
        );
    }

    /// WOR-2632: the typed record the SIEM feed receives for a refused
    /// plugin outcome.
    ///
    /// Rubric: a refusal whose only record is a log line is a refusal
    /// nobody can alert on or reconstruct. This pins the field names an
    /// operator writes a detection against, and pins that nothing a
    /// plugin authored reaches the payload.
    #[test]
    fn the_refused_plugin_outcome_event_names_the_outcome_the_reason_and_the_status() {
        let data = unsupported_plugin_action_outcome_event_data(
            Some("req-1234"),
            LEGACY_RESPONDED_OUTCOME_LABEL,
        );

        assert_eq!(data["action"], "plugin");
        assert_eq!(data["plugin_action_outcome"], "responded");
        assert_eq!(
            data["reason"],
            sbproxy_plugin::UNSUPPORTED_ACTION_OUTCOME_CODE
        );
        assert_eq!(data["status"], LEGACY_RESPONDED_STATUS);
        assert_eq!(data["request_id"], "req-1234");

        // Every value is a constant from this file or an identifier the
        // gateway minted. A payload that grew a plugin-supplied field
        // would be a disclosure decision, not a formatting one.
        let object = data.as_object().expect("the payload is an object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "action",
                "plugin_action_outcome",
                "reason",
                "status",
                "request_id"
            ]
        );
    }
}
