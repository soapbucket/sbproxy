//! Host-mediated outbound HTTP for bundle hooks granted `net:outbound`.
//!
//! The guest never gets a socket. It calls a synchronous host function
//! with a JSON request and receives a JSON envelope back; the host
//! authorizes the destination against the hook's granted allowlist
//! through the shared egress authorizer, pins resolution (the address
//! the guard checked is the address dialed), runs the call inside the
//! invocation's remaining wall-clock budget, and caps the response
//! body at the sandbox buffer limit. Every property is enforced
//! host-side; a guest cannot weaken any of them.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use base64::Engine as _;
use sbproxy_config::OutboundDestination;
use sbproxy_security::egress::{
    CachedSystemResolver, EgressAuthorizer, EgressConfig, EgressPurpose, PurposeAllowlist,
};

/// One-thread runtime driving bundle fetches. The JS worker threads
/// have no tokio reactor of their own (they are plain OS threads
/// blocking on a channel), so the synchronous host function drives the
/// async client here. Process-lifetime, like the key plane's runtime,
/// so a fetch never pays runtime construction.
///
/// `None` when the runtime could not be built, which fails the fetch
/// closed (a refused call) rather than ending the process: a bundle
/// hook must never be able to panic the proxy, and a runtime that will
/// not build is a host resource condition the guest cannot be trusted
/// to have caused or to recover from.
fn fetch_runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("sbproxy-bundle-fetch")
                .build()
                .ok()
        })
        .as_ref()
}

/// Compiled outbound capability for one hook: its granted destinations
/// as a purpose allowlist, plus the shared resolver.
pub(super) struct BundleOutbound {
    authorizer: EgressAuthorizer,
    resolver: CachedSystemResolver,
    /// Response body cap, from the manifest sandbox's buffer limit.
    max_response_bytes: usize,
}

impl std::fmt::Debug for BundleOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleOutbound")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl BundleOutbound {
    /// Build from the hook's parsed destinations. Load validation has
    /// already proven every declared destination is operator-granted,
    /// so this set is both the declared and the effective one.
    pub(super) fn new(
        destinations: &[OutboundDestination],
        max_response_bytes: usize,
    ) -> Arc<Self> {
        let mut hosts = HashSet::new();
        let mut schemes = HashSet::new();
        let mut ports = HashSet::new();
        for destination in destinations {
            hosts.insert(destination.host.clone());
            schemes.insert(destination.scheme.clone());
            ports.insert(destination.port);
        }
        // The private-address refusal exists to stop a DNS answer from
        // steering a granted public hostname into private space. A
        // grant whose every host is a literal address (or localhost)
        // involves no lookup an attacker can influence, and the
        // operator typed the address; refusing it would only forbid
        // the legitimate internal-service case. Mixed grants keep the
        // strict posture, because one allowlist carries one flag.
        let every_host_is_literal = hosts
            .iter()
            .all(|host| host == "localhost" || host.parse::<std::net::IpAddr>().is_ok());
        let mut config = EgressConfig::default();
        config.purposes.insert(
            EgressPurpose::BundleHook,
            PurposeAllowlist {
                hosts,
                schemes,
                ports,
                allow_private: every_host_is_literal,
            },
        );
        Arc::new(Self {
            authorizer: EgressAuthorizer::new(config),
            resolver: CachedSystemResolver,
            max_response_bytes,
        })
    }

    /// Serve one guest fetch. Never panics and never returns guest
    /// prose from the host: the reply is always a JSON envelope,
    /// either `{"status", "headers", "body_base64"}` or `{"error"}`
    /// with a bounded reason label, so a refusal is inspectable
    /// without being exploitable.
    pub(super) fn fetch(&self, request_json: &str, deadline: Instant) -> String {
        match self.fetch_inner(request_json, deadline) {
            Ok(reply) => reply,
            Err(reason) => serde_json::json!({ "error": reason }).to_string(),
        }
    }

    fn fetch_inner(&self, request_json: &str, deadline: Instant) -> Result<String, String> {
        let request: serde_json::Value =
            serde_json::from_str(request_json).map_err(|_| "request_not_json".to_owned())?;
        let url = request
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "request_missing_url".to_owned())?;
        let method = request
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| "request_method_invalid".to_owned())?;
        let body = match request
            .get("body_base64")
            .and_then(serde_json::Value::as_str)
        {
            Some(encoded) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| "request_body_not_base64".to_owned())?,
            ),
            None => None,
        };

        let destination = self
            .authorizer
            .authorize(EgressPurpose::BundleHook, url, &self.resolver)
            .map_err(|denied| format!("egress_denied:{denied:?}"))?;
        let addrs = self
            .authorizer
            .verify_dial_addrs(&destination, &self.resolver)
            .map_err(|denied| format!("egress_denied:{denied:?}"))?;
        let host = destination
            .url
            .host_str()
            .ok_or_else(|| "egress_denied:MissingHost".to_owned())?
            .to_owned();

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "budget_exhausted".to_owned())?;
        let runtime = fetch_runtime().ok_or_else(|| "fetch_runtime_unavailable".to_owned())?;

        let max_bytes = self.max_response_bytes;
        let url = destination.url.clone();
        let headers: Vec<(String, String)> = request
            .get("headers")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        let pair = entry.as_array()?;
                        Some((
                            pair.first()?.as_str()?.to_owned(),
                            pair.get(1)?.as_str()?.to_owned(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();

        runtime.block_on(async move {
            // One deadline bounds the whole call, connect through the
            // last byte, so a slow-trickle upstream cannot hold the
            // worker past the hook's budget by resetting a per-chunk
            // timer. `timeout_at` on a single instant is that bound; the
            // client-level timeouts are the fast-path backstop.
            let overall = tokio::time::Instant::now() + remaining;
            // The pinned addresses are the whole point: the client
            // resolves the checked host to the verified set and never
            // performs its own lookup, so a rebinding DNS answer
            // between check and connect changes nothing. No redirects:
            // a redirect is a new destination that was never granted.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(remaining)
                .timeout(remaining)
                .resolve_to_addrs(&host, &addrs)
                .build()
                .map_err(|_| "client_build_failed".to_owned())?;
            let mut outgoing = client.request(method, url);
            for (name, value) in headers {
                outgoing = outgoing.header(name, value);
            }
            if let Some(body) = body {
                outgoing = outgoing.body(body);
            }
            let response = tokio::time::timeout_at(overall, outgoing.send())
                .await
                .map_err(|_| "budget_exhausted".to_owned())?
                .map_err(|_| "request_failed".to_owned())?;
            let status = response.status().as_u16();
            let reply_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let mut collected: Vec<u8> = Vec::new();
            let mut stream = response;
            loop {
                let chunk = tokio::time::timeout_at(overall, stream.chunk())
                    .await
                    .map_err(|_| "budget_exhausted".to_owned())?
                    .map_err(|_| "request_failed".to_owned())?;
                let Some(chunk) = chunk else { break };
                if collected.len().saturating_add(chunk.len()) > max_bytes {
                    return Err("response_over_buffer_cap".to_owned());
                }
                collected.extend_from_slice(&chunk);
            }
            Ok(serde_json::json!({
                "status": status,
                "headers": reply_headers,
                "body_base64": base64::engine::general_purpose::STANDARD.encode(&collected),
            })
            .to_string())
        })
    }
}
