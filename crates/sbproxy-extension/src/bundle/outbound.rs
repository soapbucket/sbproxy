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
    CachedSystemResolver, EgressAuthorizer, EgressConfig, EgressDenied, EgressPurpose,
    PurposeAllowlist,
};

/// Count and log one refusal on the shared egress family, then return
/// the guest-facing reason string. Free-standing so a refusal can be
/// recorded from inside the deadline-bounded async block, which owns
/// only the bundle name rather than a `&self`.
fn refuse_for(bundle: &str, denied: EgressDenied) -> String {
    sbproxy_security::egress::record_egress_refused(
        EgressPurpose::BundleHook,
        denied,
        "__bundle__",
        bundle,
    );
    format!("egress_denied:{denied:?}")
}

/// Multi-worker runtime driving bundle fetches. The JS worker threads
/// have no tokio reactor of their own (they are plain OS threads
/// blocking on a channel), so the synchronous host function drives the
/// async client here. It is multi-threaded on purpose: a
/// current-thread runtime polls one future at a time, so concurrent
/// `block_on` calls from separate JS workers would serialize, turning
/// N parallel fetches into a sum rather than a max. Two worker threads
/// let the (at most four) JS workers' fetches make progress at once
/// without spawning a thread per hook. Process-lifetime, so a fetch
/// never pays runtime construction.
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
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("sbproxy-bundle-fetch")
                .build()
                .ok()
        })
        .as_ref()
}

/// Compiled outbound capability for one hook: its granted destinations
/// and the shared resolver.
pub(super) struct BundleOutbound {
    authorizer: EgressAuthorizer,
    resolver: CachedSystemResolver,
    /// The exact granted `(scheme, host, port)` tuples. The egress
    /// authorizer matches a request against three independent sets, so
    /// on its own a hook granted two destinations would authorize
    /// their cross product (host A's IP over host B's port). This set
    /// is the precise gate: a request is refused unless its canonical
    /// tuple is a member, checked before the authorizer runs.
    granted: HashSet<OutboundDestination>,
    /// Bundle name, for the egress-refused metric's origin label.
    bundle: String,
    /// Response body cap, from the manifest sandbox's buffer limit.
    max_response_bytes: usize,
}

impl std::fmt::Debug for BundleOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleOutbound")
            .field("bundle", &self.bundle)
            .field("granted", &self.granted.len())
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl BundleOutbound {
    /// Build from the hook's parsed destinations. Load validation has
    /// already proven every declared destination is operator-granted,
    /// so this set is both the declared and the effective one.
    pub(super) fn new(
        bundle: &str,
        destinations: &[OutboundDestination],
        max_response_bytes: usize,
    ) -> Arc<Self> {
        let granted: HashSet<OutboundDestination> = destinations.iter().cloned().collect();
        let mut hosts = HashSet::new();
        let mut schemes = HashSet::new();
        let mut ports = HashSet::new();
        for destination in &granted {
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
        // strict posture, because one allowlist carries one flag. The
        // exact-tuple gate above already refuses a cross-product
        // request, so this flag only relaxes the private-IP check for
        // the literal destinations the operator actually named.
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
            granted,
            bundle: bundle.to_owned(),
            max_response_bytes,
        })
    }

    /// Refuse a request whose canonical destination is not one the
    /// operator granted, before the authorizer's independent-set match
    /// could admit a cross-product tuple. Counts and logs the refusal
    /// on the shared egress family so an operator sees a bundle probing
    /// outside its grant.
    fn admit_destination(&self, url: &url::Url) -> Result<(), String> {
        let scheme = url.scheme();
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Err(self.refuse(EgressDenied::MissingHost));
        };
        let requested = OutboundDestination {
            scheme: scheme.to_owned(),
            host: host.to_ascii_lowercase(),
            port,
        };
        if self.granted.contains(&requested) {
            return Ok(());
        }
        // Not one of the exact tuples the operator granted. UnlistedHost
        // is the closest closed-set reason (the request named a
        // destination the allowlist does not carry); it keeps the metric
        // vocabulary bounded rather than inventing a bundle-only label.
        Err(self.refuse(EgressDenied::UnlistedHost))
    }

    fn refuse(&self, denied: EgressDenied) -> String {
        refuse_for(&self.bundle, denied)
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

        let parsed = url::Url::parse(url).map_err(|_| self.refuse(EgressDenied::InvalidUrl))?;
        // The precise gate: exactly one granted tuple, not the cross
        // product of the component sets the authorizer matches against.
        self.admit_destination(&parsed)?;

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "budget_exhausted".to_owned())?;
        let runtime = fetch_runtime().ok_or_else(|| "fetch_runtime_unavailable".to_owned())?;

        let max_bytes = self.max_response_bytes;
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

        // Authorization resolves DNS through a blocking syscall
        // (`getaddrinfo`), which has no timeout of its own and would
        // otherwise pin the worker past the budget if the granted
        // host's DNS hangs. Run it, and the whole fetch, under one
        // deadline: the authorize/verify pair goes on a blocking pool
        // thread bounded by `timeout_at`, so a hung resolver fails the
        // call at the deadline rather than holding the JS worker
        // indefinitely. The authorizer and resolver are cheap to clone
        // into the task (a small config map and a unit handle over a
        // process-wide cache).
        let authorizer = self.authorizer.clone();
        let resolver = self.resolver;
        let url = url.to_owned();
        let bundle = self.bundle.clone();
        runtime.block_on(async move {
            let overall = tokio::time::Instant::now() + remaining;
            let (destination, addrs) = tokio::time::timeout_at(
                overall,
                tokio::task::spawn_blocking(move || {
                    let destination =
                        authorizer.authorize(EgressPurpose::BundleHook, &url, &resolver)?;
                    let addrs = authorizer.verify_dial_addrs(&destination, &resolver)?;
                    Ok::<_, EgressDenied>((destination, addrs))
                }),
            )
            .await
            .map_err(|_| "budget_exhausted".to_owned())?
            .map_err(|_| "request_failed".to_owned())?
            .map_err(|denied| refuse_for(&bundle, denied))?;
            let host = destination
                .url
                .host_str()
                .ok_or_else(|| refuse_for(&bundle, EgressDenied::MissingHost))?
                .to_owned();
            let url = destination.url.clone();
            // One deadline bounds the whole call, connect through the
            // last byte, so a slow-trickle upstream cannot hold the
            // worker past the hook's budget by resetting a per-chunk
            // timer. `timeout_at` on a single instant is that bound; the
            // client-level timeouts are the fast-path backstop.
            //
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
            // Reply headers count against the same buffer cap as the
            // body, so a granted-but-hostile upstream cannot hand the
            // guest an unbounded header set the body cap would miss.
            let mut header_budget = max_bytes;
            let mut reply_headers: Vec<(String, String)> = Vec::new();
            for (name, value) in response.headers() {
                let Ok(value) = value.to_str() else { continue };
                let cost = name.as_str().len().saturating_add(value.len());
                header_budget = match header_budget.checked_sub(cost) {
                    Some(remaining) => remaining,
                    None => return Err("response_over_buffer_cap".to_owned()),
                };
                reply_headers.push((name.as_str().to_owned(), value.to_owned()));
            }
            // The body shares the one buffer cap with the headers: the
            // ceiling here is what the headers left, not a fresh
            // `max_bytes`, so headers plus body together never exceed
            // one `sandbox.max_buffer_bytes`.
            let body_budget = header_budget;
            let mut collected: Vec<u8> = Vec::new();
            let mut stream = response;
            loop {
                let chunk = tokio::time::timeout_at(overall, stream.chunk())
                    .await
                    .map_err(|_| "budget_exhausted".to_owned())?
                    .map_err(|_| "request_failed".to_owned())?;
                let Some(chunk) = chunk else { break };
                if collected.len().saturating_add(chunk.len()) > body_budget {
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
