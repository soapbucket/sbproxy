//! Outbound callback, webhook, and request/response mirror dispatch.
//!
//! Extracted from `server.rs` (WOR-629). Behavior-preserving move:
//! `use super::*` re-imports the parent module's private items and
//! `use` aliases, so the moved code needs no rewiring.

use super::*;

// --- Callback firing ---

/// Lazily-initialized HTTP client for firing callbacks. Builder
/// failure here means a malformed default TLS root store or a
/// system-level resource starvation; both are unrecoverable for the
/// callback path, so we surface the failure via panic rather than
/// silently dropping to a `Client::default()` (which has no timeout).
/// Reads from `proxy.http_client_timeouts.callback_client_secs`
/// (default 10s) on first use.
pub(super) static CALLBACK_CLIENT: std::sync::OnceLock<reqwest::Client> =
    std::sync::OnceLock::new();

pub(super) fn callback_client() -> &'static reqwest::Client {
    CALLBACK_CLIENT.get_or_init(|| {
        let secs = reload::current_pipeline()
            .config
            .server
            .http_client_timeouts
            .callback_client_secs;
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(secs))
            .build()
            .expect("callback reqwest::Client build must succeed")
    })
}

/// Fire a fire-and-forget shadow copy of an inbound request at a
/// mirror URL. The response is read and discarded; errors are logged
/// at debug level. Body data is NOT mirrored in this initial cut
/// (the inbound body is consumed by Pingora to forward to the primary
/// upstream); only method, path/query, and headers are sent. This is
/// sufficient for safe rollouts of new backends and for replay-style
/// shadowing of read endpoints. Body mirroring requires teeing the
/// inbound body and is a follow-on.
/// Fire a pending mirror with whatever body has been buffered. The
/// `mirror_pending` slot is taken from `ctx` so the mirror only ever
/// fires once. Bodies that exceed the configured cap are dropped (we
/// fire the mirror without a body rather than skip it entirely).
///
/// WOR-168: when the slot is unexpectedly empty (which the request
/// body filter call sites previously matched via `as_ref` /
/// `as_mut` before `take().unwrap()`), bump the
/// `sbproxy_mirror_state_drift_total` counter and warn rather than
/// panicking the worker. The graceful no-op return is the behaviour
/// pinned by `fire_pending_mirror_no_panic_when_slot_empty` below.
pub(super) fn fire_pending_mirror(ctx: &mut crate::context::RequestContext) {
    let params = match ctx.mirror_pending.take() {
        Some(p) => p,
        None => return,
    };
    let body = ctx.request_body_buf.take().map(|buf| buf.freeze());
    let body_for_mirror = body.filter(|b| b.len() <= params.max_body_bytes);
    tokio::spawn(async move {
        fire_request_mirror(
            params.url,
            params.timeout,
            params.method,
            params.path_and_query,
            params.headers,
            params.request_id,
            body_for_mirror,
        )
        .await;
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn fire_request_mirror(
    mirror_url: String,
    timeout: std::time::Duration,
    method: String,
    path_and_query: String,
    headers: http::HeaderMap,
    request_id: String,
    body: Option<bytes::Bytes>,
) {
    // Compose the full URL: mirror base + the original path + query.
    // Trim trailing slash on the base so we don't double up.
    let full_url = {
        let base = mirror_url.trim_end_matches('/');
        if path_and_query.starts_with('/') {
            format!("{base}{path_and_query}")
        } else {
            format!("{base}/{path_and_query}")
        }
    };

    let client = callback_client();
    let method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => return,
        },
    };

    let mut req = client.request(method, &full_url).timeout(timeout);
    // Forward most headers, but skip hop-by-hop and ones reqwest will
    // recompute (Host gets rewritten by reqwest from the URL; Content-
    // Length is no longer accurate without the body).
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if matches!(
            n,
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "upgrade"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            req = req.header(n, v);
        }
    }
    req = req
        .header("x-sbproxy-mirror", "1")
        .header("x-sbproxy-request-id", request_id.as_str())
        .header("x-sbproxy-instance", crate::identity::instance_id());
    if let Some(b) = body {
        req = req.body(b);
    }

    match req.send().await {
        Ok(resp) => {
            debug!(url = %full_url, status = %resp.status(), "mirror sent");
            // Drain the body so the connection can be returned to the pool.
            let _ = resp.bytes().await;
        }
        Err(e) => {
            debug!(url = %full_url, error = %e, "mirror delivery failed");
        }
    }
}

/// HMAC-SHA256 sign a payload with a shared secret. Returns the
/// `v1=<hex>` value used in `X-Sbproxy-Signature`. Surfaces an error
/// rather than panicking when the HMAC primitive cannot accept the
/// provided key bytes.
pub(super) fn sign_webhook(secret: &str, body: &[u8], timestamp: i64) -> anyhow::Result<String> {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("webhook hmac init failed: {e}"))?;
    // GitHub-style: include timestamp in the signed material so old
    // signatures cannot be replayed past the receiver's tolerance window.
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    Ok(format!("v1={}", hex::encode(bytes)))
}

/// Build the standard webhook envelope shared by `on_request` and
/// `on_response`. Receivers can correlate the pair via `request.id`.
pub(super) fn webhook_envelope(
    event: &str,
    request_id: &str,
    config_revision: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut base = serde_json::json!({
        "event": event,
        "proxy": {
            "instance_id": crate::identity::instance_id(),
            "version": crate::identity::version(),
            "config_revision": config_revision,
        },
        "request": {
            "id": request_id,
            "received_at": chrono::Utc::now().to_rfc3339(),
        },
    });
    if let (serde_json::Value::Object(ref mut base_map), serde_json::Value::Object(extra_map)) =
        (&mut base, extra)
    {
        for (k, v) in extra_map {
            base_map.insert(k, v);
        }
    }
    base
}

/// Prefix that marks headers on a callback response as injection
/// directives. The callback responds with `X-Inject-Foo: bar`; the
/// proxy strips the prefix and adds `Foo: bar` to either the upstream
/// request (`on_request` enrichment) or the client-facing response
/// (`on_response` enrichment).
pub(super) const CALLBACK_INJECT_PREFIX: &str = "x-inject-";

/// Read the `enrich` flag from a callback config object. Defaults to
/// `false` so existing audit-only callbacks keep their fire-and-forget
/// semantics. Accepts either `enrich: true` or `mode: "enrich"`.
pub(super) fn callback_is_enrich(cb_val: &serde_json::Value) -> bool {
    if let Some(b) = cb_val.get("enrich").and_then(|v| v.as_bool()) {
        return b;
    }
    matches!(
        cb_val.get("mode").and_then(|v| v.as_str()),
        Some(m) if m.eq_ignore_ascii_case("enrich")
    )
}

/// Extract injection directives from a callback response. Any header
/// whose name starts with `X-Inject-` is converted into a
/// `(unprefixed_name, value)` pair. Returns an empty vec when the
/// callback does not include any injection headers.
pub(super) fn extract_inject_headers(
    resp_headers: &reqwest::header::HeaderMap,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in resp_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if let Some(stripped) = lower.strip_prefix(CALLBACK_INJECT_PREFIX) {
            if stripped.is_empty() {
                continue;
            }
            if let Ok(v) = value.to_str() {
                out.push((stripped.to_string(), v.to_string()));
            }
        }
    }
    out
}

/// Fire on_request callbacks for an origin. Audit-mode callbacks are
/// dispatched through [`WEBHOOK_TASKS`] (fire-and-forget, drained on
/// shutdown). Enrichment callbacks (`enrich: true`) are awaited inline
/// and any `X-Inject-*` response headers are returned for injection
/// into the upstream request.
#[allow(clippy::too_many_arguments)]
pub(super) async fn fire_on_request_callbacks(
    callbacks: &[serde_json::Value],
    method: &str,
    path: &str,
    hostname: &str,
    client_ip: Option<String>,
    request_id: &str,
    config_revision: &str,
    headers: &http::HeaderMap,
) -> Vec<(String, String)> {
    let mut inject: Vec<(String, String)> = Vec::new();

    for cb_val in callbacks {
        let url = match cb_val.get("url").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };
        let cb_method = cb_val
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();
        let secret = cb_val
            .get("secret")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let mut header_map = serde_json::Map::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                header_map.insert(name.to_string(), serde_json::Value::String(v.to_string()));
            }
        }
        let payload = webhook_envelope(
            "on_request",
            request_id,
            config_revision,
            serde_json::json!({
                "origin": { "name": hostname },
                "method": method,
                "path": path,
                "host": hostname,
                "client_ip": client_ip,
                "headers": header_map,
            }),
        );

        let timeout_secs = cb_val.get("timeout").and_then(|v| v.as_u64()).unwrap_or(5);
        let request_id_owned = request_id.to_string();
        let config_revision_owned = config_revision.to_string();

        if callback_is_enrich(cb_val) {
            let injected = send_webhook_collect_inject(
                &url,
                &cb_method,
                &payload,
                secret.as_deref(),
                "on_request",
                &request_id_owned,
                &config_revision_owned,
                timeout_secs,
            )
            .await;
            inject.extend(injected);
        } else {
            WEBHOOK_TASKS.spawn(async move {
                send_webhook(
                    &url,
                    &cb_method,
                    &payload,
                    secret.as_deref(),
                    "on_request",
                    &request_id_owned,
                    &config_revision_owned,
                    timeout_secs,
                )
                .await;
            });
        }
    }

    inject
}

/// Fire on_response callbacks for an origin. Audit-mode callbacks are
/// dispatched through [`WEBHOOK_TASKS`] (fire-and-forget, drained on
/// shutdown). Enrichment callbacks (`enrich: true`) are awaited inline
/// and any `X-Inject-*` response headers are returned for injection
/// into the client-facing response.
#[allow(clippy::too_many_arguments)]
pub(super) async fn fire_on_response_callbacks(
    callbacks: &[serde_json::Value],
    status: u16,
    hostname: &str,
    path: &str,
    request_id: &str,
    config_revision: &str,
    duration_ms: Option<u64>,
) -> Vec<(String, String)> {
    let mut inject: Vec<(String, String)> = Vec::new();

    for cb_val in callbacks {
        let url = match cb_val.get("url").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };
        let cb_method = cb_val
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();
        let secret = cb_val
            .get("secret")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let payload = webhook_envelope(
            "on_response",
            request_id,
            config_revision,
            serde_json::json!({
                "origin": { "name": hostname },
                "status": status,
                "host": hostname,
                "path": path,
                "duration_ms": duration_ms,
            }),
        );

        let timeout_secs = cb_val.get("timeout").and_then(|v| v.as_u64()).unwrap_or(5);
        let request_id_owned = request_id.to_string();
        let config_revision_owned = config_revision.to_string();

        if callback_is_enrich(cb_val) {
            let injected = send_webhook_collect_inject(
                &url,
                &cb_method,
                &payload,
                secret.as_deref(),
                "on_response",
                &request_id_owned,
                &config_revision_owned,
                timeout_secs,
            )
            .await;
            inject.extend(injected);
        } else {
            WEBHOOK_TASKS.spawn(async move {
                send_webhook(
                    &url,
                    &cb_method,
                    &payload,
                    secret.as_deref(),
                    "on_response",
                    &request_id_owned,
                    &config_revision_owned,
                    timeout_secs,
                )
                .await;
            });
        }
    }

    inject
}

/// Build the outbound webhook request with the standard envelope,
/// identifying headers, and optional HMAC signature. Returns `None`
/// when payload serialization fails so callers can short-circuit.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_webhook_request(
    url: &str,
    method: &str,
    payload: &serde_json::Value,
    secret: Option<&str>,
    event: &str,
    request_id: &str,
    config_revision: &str,
    timeout_secs: u64,
) -> Option<reqwest::RequestBuilder> {
    let client = callback_client();
    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "webhook payload serialize failed");
            return None;
        }
    };
    let timestamp = chrono::Utc::now().timestamp();

    let mut req = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url).body(body.clone()),
        _ => client.post(url).body(body.clone()),
    };
    req = req
        .header("content-type", "application/json")
        .header(
            "user-agent",
            format!("sbproxy/{}", crate::identity::version()),
        )
        .header("x-sbproxy-event", event)
        .header("x-sbproxy-instance", crate::identity::instance_id())
        .header("x-sbproxy-request-id", request_id)
        .header("x-sbproxy-config-revision", config_revision)
        .header("x-sbproxy-timestamp", timestamp.to_string());
    if let Some(s) = secret {
        match sign_webhook(s, &body, timestamp) {
            Ok(sig) => {
                req = req.header("x-sbproxy-signature", sig);
            }
            Err(e) => {
                warn!(url = %url, event = %event, error = %e, "webhook signing failed; sending without signature");
            }
        }
    }
    Some(req.timeout(std::time::Duration::from_secs(timeout_secs)))
}

/// Send a webhook in audit mode. Errors are logged and dropped; the
/// response body is discarded.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_webhook(
    url: &str,
    method: &str,
    payload: &serde_json::Value,
    secret: Option<&str>,
    event: &str,
    request_id: &str,
    config_revision: &str,
    timeout_secs: u64,
) {
    let Some(req) = build_webhook_request(
        url,
        method,
        payload,
        secret,
        event,
        request_id,
        config_revision,
        timeout_secs,
    ) else {
        return;
    };
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            debug!(url = %url, event = %event, "webhook sent");
        }
        Ok(resp) => {
            warn!(url = %url, event = %event, status = %resp.status(), "webhook non-success");
        }
        Err(e) => {
            warn!(url = %url, event = %event, error = %e, "webhook delivery failed");
        }
    }
}

/// Send a webhook in enrichment mode. Awaits the response, harvests
/// any `X-Inject-*` response headers, and returns them as
/// `(unprefixed_name, value)` pairs. A timed-out, non-success, or
/// failed callback returns an empty vec so the request still flows.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_webhook_collect_inject(
    url: &str,
    method: &str,
    payload: &serde_json::Value,
    secret: Option<&str>,
    event: &str,
    request_id: &str,
    config_revision: &str,
    timeout_secs: u64,
) -> Vec<(String, String)> {
    let Some(req) = build_webhook_request(
        url,
        method,
        payload,
        secret,
        event,
        request_id,
        config_revision,
        timeout_secs,
    ) else {
        return Vec::new();
    };
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let injected = extract_inject_headers(resp.headers());
            debug!(
                url = %url,
                event = %event,
                injected = injected.len(),
                "enrichment webhook returned"
            );
            injected
        }
        Ok(resp) => {
            warn!(url = %url, event = %event, status = %resp.status(), "enrichment webhook non-success");
            Vec::new()
        }
        Err(e) => {
            warn!(url = %url, event = %event, error = %e, "enrichment webhook delivery failed");
            Vec::new()
        }
    }
}
