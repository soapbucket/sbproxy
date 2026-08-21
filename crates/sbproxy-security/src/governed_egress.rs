//! One bounded redirect loop for outbound calls that carry a credential.
//!
//! [`crate::egress`] states the contract: the pin set an authorization
//! produced must reach the connector, and a governed client must never
//! auto-follow a redirect. Stating it was not enough. Five call sites
//! asked the authorizer whether a destination was allowed, threw the
//! answer away, and handed the URL to a client that resolved the host
//! again and followed whatever `Location` came back. Each had its own
//! near-copy of the same loop, and each got a different subset of the
//! contract right.
//!
//! So the loop lives here once. [`GovernedEgress::send`] authorizes the
//! destination, pins the dial to the addresses that authorization
//! resolved, and re-authorizes every hop after it (scheme, host, port,
//! fresh DNS answer, and private-address class) before any second
//! connect, dialing only that hop's own pin set. It bounds the chain at
//! [`crate::egress::MAX_REDIRECT_HOPS`], the bytes it reads from any
//! response at the caller's ceiling, and the whole call at one
//! [`GovernedEgress::timeout`] rather than one per hop.
//!
//! # Two of the five are converted
//!
//! Say which, because a reader who takes this page as an inventory of
//! governed paths would be wrong about three of them. Converted: the
//! MCP run-as-user token exchange (`sbproxy_extension::mcp::auth`) and
//! the `events:` webhook sink (`sbproxy_observe::event_sink`), the two
//! that carry a credential a redirect can steal outright, which is why
//! they went first.
//!
//! Still carrying their own [`crate::egress::evaluate_hop`] loop, each
//! with its own subset of the contract: the AI provider dispatch
//! (`sbproxy_ai::client::send_governed`), the usage-sink webhook
//! (`sbproxy_ai::usage_sink::send_sink_post`, which authorizes and then
//! discards
//! [`crate::egress::AuthorizedDestination::pinned_addrs`], so the
//! rebinding window between its check and its connect is still open),
//! and the model-artifact download
//! (`sbproxy_model_host::artifact::http::follow_governed`). Converting
//! them is WOR-2612's remaining work, not something this page should
//! read as already done.
//!
//! # The cross-origin credential rule
//!
//! A hop that changes scheme, host, or port leaves the origin the
//! operator wrote down, so nothing on the request that proves who the
//! caller is may ride along. The two kinds of credential need different
//! remedies, and this loop applies both:
//!
//! Headers are stripped. `authorization`, `proxy-authorization`, and
//! `cookie` always, plus every name the caller declares sensitive.
//! reqwest strips the first three on its own and leaves custom names
//! alone, which is exactly the gap: `X-Sbproxy-Signature` and
//! `x-api-key` are on nobody's built-in list.
//!
//! A body is refused. There is no stripping a body that *is* the
//! credential: an RFC 8693 exchange carries the caller's subject token
//! as a form field, and a signed event batch is the thing the signature
//! covers. Forwarding it hands the credential to a host nobody
//! approved; stripping it sends an empty request the next hop cannot
//! serve and the caller never asked for. So a request with a body does
//! not make a cross-origin hop at all. It is refused with
//! [`EgressDenied::RedirectToUnlistedHost`], the same closed reason a
//! hop off the allowlist gets, because it is the same fact about the
//! chain: the destination is not one the operator named.
//!
//! That rule holds whether or not an authorizer is armed, which is the
//! half [`evaluate_hop`] alone does not give a caller. With an
//! authorizer attached, `evaluate_hop` treats the allowlist as the
//! authority and permits a hop to any other allowlisted host; correct
//! for an artifact download that is meant to land on a CDN, wrong for a
//! request whose body is a bearer token.
//!
//! # What an operator sees on a refusal
//!
//! One closed [`EgressDenied`] label, on all four surfaces at once:
//! the `sbproxy::egress` warn line, the
//! `sbproxy_egress_refused_total{purpose,reason,tenant,origin}` counter,
//! the `GET /api/egress` inventory row, and the typed `egress_refused`
//! event when an `events:` sink is configured. No surface ever carries
//! URL text: the counter's `origin` label is a configuration-scoped
//! name the caller supplies (a sink name or an origin id), and the
//! inventory stores host, port, and scheme rather than the URL.

use std::net::SocketAddr;
use std::time::Duration;

use url::Url;

use crate::egress::{
    evaluate_hop, is_cross_origin, record_egress_refused, record_egress_seen, resolve_redirect_url,
    EgressAuthorizer, EgressDenied, EgressPurpose, EgressSightingStatus, HostResolver, RedirectHop,
    RedirectRule,
};

/// Header names dropped from every cross-origin replay whatever the
/// caller declares. Lowercase, because header-map keys compare
/// case-insensitively and writing them any other way invites a caller
/// to add `Authorization` to its own list and think it did something.
const ALWAYS_SENSITIVE_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

/// Why a governed call did not produce a response.
///
/// Closed set, and every variant is a label rather than a message: the
/// callers turn these into metric label values, so a variant that
/// embedded a host, a URL, or a resolver diagnostic would be an
/// unbounded series set and a config leak at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedEgressError {
    /// Egress authorization refused the destination or one of its hops.
    /// Already counted, logged, stamped into the inventory, and
    /// published to the typed event feed before this is returned.
    Denied(EgressDenied),
    /// The pinned client would not build. Fails closed: a governed dial
    /// never falls back to a re-resolving client, because that silently
    /// gives back the pin defense the caller asked for.
    ClientBuild,
    /// Connect, TLS, timeout, or reset.
    Transport,
    /// The response body passed the caller's ceiling.
    ResponseTooLarge,
    /// A redirect arrived for a request that cannot be replayed, which
    /// for reqwest means a streaming body it cannot clone. Refused
    /// rather than returned as the 3xx it was, so a caller cannot read
    /// "not a success status" as "the endpoint declined".
    NotReplayable,
}

impl GovernedEgressError {
    /// Stable, bounded label for metrics and structured logs.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Denied(_) => "egress_denied",
            Self::ClientBuild => "client_build_failed",
            Self::Transport => "transport_error",
            Self::ResponseTooLarge => "response_too_large",
            Self::NotReplayable => "not_replayable",
        }
    }
}

/// The final response of a governed call, with its body already read
/// under the caller's ceiling.
#[derive(Debug, Clone)]
pub struct GovernedResponse {
    /// Status of the last response in the chain, which is by
    /// construction not a redirect the loop was willing to follow.
    pub status: u16,
    /// Response body, never longer than
    /// [`GovernedEgress::max_response_bytes`].
    pub body: Vec<u8>,
}

/// One governed outbound call's whole policy.
///
/// Plain public fields rather than a builder: every field is a decision
/// the call site has to make on purpose, and a builder with defaults
/// would let a new consumer inherit an ungated tenant label or an
/// unbounded body read by saying nothing.
pub struct GovernedEgress<'a> {
    /// Purpose whose allowlist gates this call and whose label every
    /// refusal is counted under.
    pub purpose: EgressPurpose,
    /// The purpose's compiled allowlist, or `None` for the legacy
    /// ungated contract, where the destination is stamped
    /// [`EgressSightingStatus::Ungated`] and every cross-origin hop is
    /// refused because no allowlist exists to approve one.
    pub authorizer: Option<&'a EgressAuthorizer>,
    /// Resolver every authorization and pin verification runs through.
    /// Production passes [`crate::egress::CachedSystemResolver`]; a test
    /// passes a fixture so it can make the two answers disagree.
    pub resolver: &'a dyn HostResolver,
    /// Configuration-scoped attribution for the metric, the log line,
    /// and the inventory row: a sink name, provider name, or origin id.
    /// Never a URL, request id, or trace id.
    pub origin: &'a str,
    /// Tenant a refusal is attributed to, or `"unset"` where the
    /// surrounding code genuinely has none.
    pub tenant: &'a str,
    /// Header names, lowercase, dropped on a cross-origin hop on top of
    /// `authorization`, `proxy-authorization`, and `cookie`, which this
    /// loop always drops. A provider-specific key header or a request
    /// signature goes here.
    pub sensitive_headers: &'a [&'a str],
    /// Ceiling on the bytes read from any response body in the chain.
    pub max_response_bytes: usize,
    /// Client used for a hop with no pin set, which is only ever an
    /// ungated purpose. Also the seam for a caller that pinned the dial
    /// itself through another guard (the SSRF guard's
    /// [`crate::ssrf::validate_url_resolved`], say) and hands in the
    /// client it built from that answer.
    ///
    /// It must be built with `redirect(Policy::none())`. A client with a
    /// redirect policy of its own follows the hop before this loop can
    /// refuse it, which is the whole defect this type exists to close.
    /// The loop cannot set a policy on a client it did not build, so it
    /// checks instead: a response whose final URL is at a different
    /// origin than the request's is refused rather than returned. That
    /// catches the mistake, and catching it is not the same as
    /// preventing it, since the request has already gone out by then.
    pub no_redirect_client: &'a reqwest::Client,
    /// Budget for the **whole** call, redirects included, not for each
    /// hop.
    ///
    /// [`Self::send`] turns this into one deadline at entry and runs
    /// every await under what is left of it, so a chain of hops cannot
    /// cost more than a caller that made no hops at all. Each pinned
    /// client this loop builds also carries it as a per-request
    /// timeout, which is a subordinate bound: reqwest restarts that one
    /// on every `execute`, which is exactly why the outer deadline
    /// exists. The `no_redirect_client`'s own timeout is left alone and
    /// is likewise subordinate.
    ///
    /// It used to be per hop, and the arithmetic was the bug: ten
    /// same-origin redirects that each stalled just under a five-second
    /// timeout held the events webhook's single delivery thread for
    /// most of a minute, and everything published behind it in that
    /// window was dropped as `queue_full` (WOR-2612).
    pub timeout: Duration,
}

impl GovernedEgress<'_> {
    /// Issue `request`, following only hops that re-authorize.
    ///
    /// The destination is authorized and pinned before the first
    /// connect; every redirect after it is re-authorized and dialed on
    /// its own pin set; the chain is bounded at
    /// [`crate::egress::MAX_REDIRECT_HOPS`] and the body at
    /// [`Self::max_response_bytes`]. A refusal is reported on all four
    /// operator surfaces before it is returned; see the module docs.
    ///
    /// The whole call, every hop of it, runs inside one
    /// [`Self::timeout`]. See that field for why it is not per hop.
    pub async fn send(
        &self,
        mut request: reqwest::Request,
    ) -> Result<GovernedResponse, GovernedEgressError> {
        // One deadline for the chain, taken before the first
        // authorization so the DNS this loop does on the caller's
        // behalf is inside the budget rather than beside it.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut client = self.authorize_destination(request.url())?;
        let mut hop = 0usize;
        loop {
            // Clone before the move into `execute`: a redirect needs the
            // request back, and reqwest consumes it.
            let replay = request.try_clone();
            let from = request.url().clone();
            let response = tokio::time::timeout_at(
                deadline,
                client
                    .as_ref()
                    .unwrap_or(self.no_redirect_client)
                    .execute(request),
            )
            .await
            // A chain that outlives its budget and a connect that never
            // answered are the same fact from the caller's side, and
            // there is no reason label that separates them without
            // telling an attacker which one they produced.
            .map_err(|_| GovernedEgressError::Transport)?
            .map_err(|_| GovernedEgressError::Transport)?;
            // A client this loop did not build could carry a redirect
            // policy of its own and follow a hop before the loop ever
            // saw the `Location`. reqwest reports the URL it finally
            // landed on, so an origin that moved says exactly that
            // happened. The request is already gone by then and nothing
            // here can recall it; what this refuses is handing the
            // caller a body from an origin nothing authorized, and
            // putting the refusal where an operator will see it.
            if is_cross_origin(&from, response.url()) {
                return Err(self.refuse(
                    response.url().as_str(),
                    EgressDenied::RedirectToUnlistedHost,
                ));
            }
            if !response.status().is_redirection() {
                return self.read_capped_by(deadline, response).await;
            }
            let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
            else {
                // A redirect naming no next hop is the end of the chain,
                // not a hop to authorize. Hand the caller what it got;
                // a 3xx is not a success to any consumer of this loop.
                return self.read_capped_by(deadline, response).await;
            };
            let Some(mut replay) = replay else {
                return Err(GovernedEgressError::NotReplayable);
            };
            // The credential rule runs before authorization on purpose,
            // so a hop this request may never make is never stamped
            // `allowed` in the inventory on its way to being refused.
            if replay.body().is_some() {
                if let Some(target) = cross_origin_target(&from, &location) {
                    return Err(self.refuse(target.as_str(), EgressDenied::RedirectToUnlistedHost));
                }
            }
            hop += 1;
            let next = evaluate_hop(
                self.authorizer,
                self.purpose,
                &from,
                &location,
                hop,
                RedirectRule::SameOriginOnly,
                self.resolver,
                self.origin,
            )
            .map_err(|denied| {
                // `evaluate_hop` already stamped the inventory row; this
                // adds the counter, the warn line, and the typed event.
                record_egress_refused(self.purpose, denied, self.tenant, self.origin);
                GovernedEgressError::Denied(denied)
            })?;
            if next.strip_credentials {
                self.strip_sensitive(replay.headers_mut());
            }
            client = self.pin_hop(&next)?;
            *replay.url_mut() = next.url;
            request = replay;
        }
    }

    /// Authorize the configured destination and build the client that
    /// dials it.
    ///
    /// With an authorizer armed, the returned client is pinned to the
    /// exact addresses [`EgressAuthorizer::verify_dial_addrs`] just
    /// confirmed, so the connector cannot resolve the host a second
    /// time and an answer that rebinds between the check and the
    /// connect changes nothing. `None` means the purpose is ungated and
    /// [`Self::no_redirect_client`] is what dials.
    fn authorize_destination(
        &self,
        url: &Url,
    ) -> Result<Option<reqwest::Client>, GovernedEgressError> {
        let Some(authorizer) = self.authorizer else {
            record_egress_seen(
                self.purpose,
                url.as_str(),
                self.origin,
                EgressSightingStatus::Ungated,
                None,
            );
            return Ok(None);
        };
        let verified = authorizer
            .authorize(self.purpose, url.as_str(), self.resolver)
            .and_then(|destination| {
                let addrs = authorizer.verify_dial_addrs(&destination, self.resolver)?;
                Ok((destination, addrs))
            });
        let (destination, addrs) = match verified {
            Ok(pair) => pair,
            Err(denied) => return Err(self.refuse(url.as_str(), denied)),
        };
        record_egress_seen(
            self.purpose,
            url.as_str(),
            self.origin,
            EgressSightingStatus::Allowed,
            None,
        );
        let Some(host) = destination.url.host_str() else {
            return Err(self.refuse(url.as_str(), EgressDenied::MissingHost));
        };
        self.pinned_client(host, &addrs).map(Some)
    }

    /// Build the client for one re-authorized hop, or `None` when the
    /// hop carries no pins because no authorizer resolved it.
    fn pin_hop(&self, hop: &RedirectHop) -> Result<Option<reqwest::Client>, GovernedEgressError> {
        if hop.pinned_addrs.is_empty() {
            return Ok(None);
        }
        let Some(host) = hop.url.host_str() else {
            return Err(self.refuse(hop.url.as_str(), EgressDenied::MissingHost));
        };
        self.pinned_client(host, &hop.pinned_addrs).map(Some)
    }

    /// A client that dials `addrs` and nothing else.
    ///
    /// `resolve_to_addrs` overrides only the address the connector
    /// dials: the URL keeps its host, so the `Host` header and the TLS
    /// SNI stay the ones the authorizer checked and certificate
    /// verification still runs against the real name.
    fn pinned_client(
        &self,
        host: &str,
        addrs: &[SocketAddr],
    ) -> Result<reqwest::Client, GovernedEgressError> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout)
            .resolve_to_addrs(host, addrs)
            .build()
            .map_err(|_| GovernedEgressError::ClientBuild)
    }

    /// Drop every credential-bearing header before a cross-origin replay.
    fn strip_sensitive(&self, headers: &mut reqwest::header::HeaderMap) {
        for name in ALWAYS_SENSITIVE_HEADERS {
            headers.remove(name);
        }
        for name in self.sensitive_headers {
            headers.remove(*name);
        }
    }

    /// `read_capped` under what is left of the chain's budget.
    ///
    /// The body read is the last await in the call and it is the one a
    /// wedged peer holds open most cheaply: it can trickle bytes under
    /// the ceiling indefinitely, and every chunk arriving keeps a
    /// per-request timeout from ever firing. Bounding it by the same
    /// deadline as the hops is what makes [`Self::timeout`] a statement
    /// about the whole call rather than about its fastest part.
    async fn read_capped_by(
        &self,
        deadline: tokio::time::Instant,
        response: reqwest::Response,
    ) -> Result<GovernedResponse, GovernedEgressError> {
        match tokio::time::timeout_at(deadline, self.read_capped(response)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(GovernedEgressError::Transport),
        }
    }

    /// Read a response body under [`Self::max_response_bytes`].
    ///
    /// Chunk by chunk, checking the ceiling before each extend rather
    /// than after: `bytes()` buffers whatever the peer sends, so a
    /// hostile or misconfigured collector could otherwise answer a
    /// small POST with an allocation bounded by nothing.
    async fn read_capped(
        &self,
        mut response: reqwest::Response,
    ) -> Result<GovernedResponse, GovernedEgressError> {
        let status = response.status().as_u16();
        let mut body: Vec<u8> = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|_| GovernedEgressError::Transport)?;
            let Some(chunk) = chunk else { break };
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(GovernedEgressError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(GovernedResponse { status, body })
    }

    /// Report one refusal on every operator surface, then hand back the
    /// typed error. See the module docs for what those four surfaces
    /// are and why the reason is an [`EgressDenied`] variant.
    fn refuse(&self, url: &str, denied: EgressDenied) -> GovernedEgressError {
        record_egress_seen(
            self.purpose,
            url,
            self.origin,
            EgressSightingStatus::Denied,
            Some(denied),
        );
        record_egress_refused(self.purpose, denied, self.tenant, self.origin);
        GovernedEgressError::Denied(denied)
    }
}

/// The absolute next hop, when this `Location` leaves the origin the
/// request was authorized for.
///
/// A `Location` that will not resolve returns `None` and falls through
/// to [`evaluate_hop`], which owns the [`EgressDenied::InvalidUrl`]
/// refusal, so the two can never disagree about a malformed value.
fn cross_origin_target(from: &Url, location: &str) -> Option<Url> {
    let next = resolve_redirect_url(from, location).ok()?;
    is_cross_origin(from, &next).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{EgressConfig, PurposeAllowlist};
    use std::collections::{HashMap, HashSet};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A resolver that hands out a different answer on each call for the
    /// same host, so a test can make authorize time and dial time
    /// disagree the way a rebinding DNS server does.
    struct SequenceResolver {
        answers: Mutex<Vec<Vec<SocketAddr>>>,
        calls: AtomicUsize,
    }

    impl SequenceResolver {
        fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl HostResolver for SequenceResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, ()> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            let answers = self.answers.lock().map_err(|_| ())?;
            answers
                .get(index)
                .or_else(|| answers.last())
                .cloned()
                .ok_or(())
        }
    }

    /// Resolves every host to loopback on the port it was asked about,
    /// so two fixtures that differ only by port still get pin sets that
    /// match the fixture their URL names.
    struct LoopbackResolver;

    impl HostResolver for LoopbackResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        }
    }

    fn allow(hosts: &[&str], ports: &[u16]) -> EgressAuthorizer {
        let mut allowlist = PurposeAllowlist {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            schemes: HashSet::from(["http".to_string(), "https".to_string()]),
            ports: ports.iter().copied().collect(),
            allow_private: true,
        };
        allowlist.ports.insert(80);
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::TokenExchange, allowlist);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    /// One-shot loopback fixture. The flag latches once something
    /// connects, and the string keeps whatever the request carried so a
    /// test can prove a credential did or did not travel.
    fn fixture(response: String) -> Option<(SocketAddr, Arc<AtomicBool>, Arc<Mutex<String>>)> {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let hit = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(String::new()));
        let hit_writer = Arc::clone(&hit);
        let seen_writer = Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                hit_writer.store(true, Ordering::SeqCst);
                let mut scratch = [0u8; 8192];
                let read = stream.read(&mut scratch).unwrap_or(0);
                if let Ok(mut guard) = seen_writer.lock() {
                    *guard = String::from_utf8_lossy(&scratch[..read]).to_string();
                }
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Some((addr, hit, seen))
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// WOR-2620: the pin set is the dial set. Authorization resolves the
    /// endpoint to listener A, the dial-time re-resolve answers listener
    /// B, and the call must be refused rather than reaching B.
    #[tokio::test]
    async fn a_rebound_answer_is_refused_before_any_connect() {
        let Some((allowed, allowed_hit, _)) = fixture(ok_response("{}")) else {
            return;
        };
        let Some((rebound, rebound_hit, _)) = fixture(ok_response("{}")) else {
            return;
        };
        let resolver = SequenceResolver::new(vec![vec![allowed], vec![rebound]]);
        let authorizer = allow(&["idp.test"], &[allowed.port()]);
        let unpinned = reqwest::Client::new();
        let governed = GovernedEgress {
            purpose: EgressPurpose::TokenExchange,
            authorizer: Some(&authorizer),
            resolver: &resolver,
            origin: "idp.test",
            tenant: "acme",
            sensitive_headers: &[],
            max_response_bytes: 4096,
            no_redirect_client: &unpinned,
            timeout: Duration::from_secs(5),
        };
        let request = unpinned
            .post(format!("http://idp.test:{}/token", allowed.port()))
            .body("subject_token=user-secret")
            .build()
            .expect("request builds");

        let err = governed
            .send(request)
            .await
            .expect_err("a rebound answer must be refused");
        assert_eq!(
            err,
            GovernedEgressError::Denied(EgressDenied::DnsPinMismatch)
        );
        assert!(
            !rebound_hit.load(Ordering::SeqCst),
            "the rebound address must never be dialed"
        );
        assert!(
            !allowed_hit.load(Ordering::SeqCst),
            "nothing is dialed once the pin check fails"
        );
    }

    /// WOR-2612 / WOR-2620: a cross-origin hop for a request with a body
    /// is refused, and the body never reaches the redirect target.
    #[tokio::test]
    async fn a_cross_origin_hop_never_replays_the_body() {
        let Some((sink, sink_hit, sink_seen)) = fixture(ok_response("{}")) else {
            return;
        };
        let Some((idp, idp_hit, _)) = fixture(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{}/token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            sink.port()
        )) else {
            return;
        };
        // Both ports on the allowlist: this is the case `evaluate_hop`
        // on its own would follow, because with an authorizer armed it
        // treats the allowlist as the authority for a cross-origin hop.
        let authorizer = allow(&["127.0.0.1"], &[idp.port(), sink.port()]);
        let resolver = LoopbackResolver;
        let unpinned = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client builds");
        let governed = GovernedEgress {
            purpose: EgressPurpose::TokenExchange,
            authorizer: Some(&authorizer),
            resolver: &resolver,
            origin: "idp.test",
            tenant: "acme",
            sensitive_headers: &[],
            max_response_bytes: 4096,
            no_redirect_client: &unpinned,
            timeout: Duration::from_secs(5),
        };
        let request = unpinned
            .post(format!("http://127.0.0.1:{}/token", idp.port()))
            .body("subject_token=user-secret")
            .build()
            .expect("request builds");

        let err = governed
            .send(request)
            .await
            .expect_err("a cross-origin hop carrying a body must be refused");
        assert_eq!(
            err,
            GovernedEgressError::Denied(EgressDenied::RedirectToUnlistedHost)
        );
        assert!(idp_hit.load(Ordering::SeqCst), "the endpoint answered");
        assert!(
            !sink_hit.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
        assert!(
            !sink_seen
                .lock()
                .expect("fixture lock")
                .contains("user-secret"),
            "the subject token must never leave the authorized origin"
        );
    }

    /// The other half of the credential rule: a hop with nothing to
    /// refuse still loses every credential header on the way across.
    #[tokio::test]
    async fn a_cross_origin_hop_strips_declared_sensitive_headers() {
        let Some((sink, sink_hit, sink_seen)) = fixture(ok_response("{}")) else {
            return;
        };
        let Some((origin, _, _)) = fixture(format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            sink.port()
        )) else {
            return;
        };
        let authorizer = allow(&["127.0.0.1"], &[origin.port(), sink.port()]);
        let resolver = LoopbackResolver;
        let unpinned = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client builds");
        let governed = GovernedEgress {
            purpose: EgressPurpose::TokenExchange,
            authorizer: Some(&authorizer),
            resolver: &resolver,
            origin: "collector",
            tenant: "acme",
            sensitive_headers: &["x-sbproxy-signature"],
            max_response_bytes: 4096,
            no_redirect_client: &unpinned,
            timeout: Duration::from_secs(5),
        };
        // No body, so the hop is followed rather than refused, and the
        // stripping is what has to hold.
        let request = unpinned
            .get(format!("http://127.0.0.1:{}/start", origin.port()))
            .header("authorization", "Bearer origin-secret")
            .header("x-sbproxy-signature", "v1=deadbeef")
            .build()
            .expect("request builds");

        let _ = governed.send(request).await;
        assert!(sink_hit.load(Ordering::SeqCst), "the hop was followed");
        let seen = sink_seen.lock().expect("fixture lock").clone();
        assert!(
            !seen.to_lowercase().contains("origin-secret"),
            "authorization must not survive a cross-origin hop, saw: {seen}"
        );
        assert!(
            !seen.to_lowercase().contains("deadbeef"),
            "a declared sensitive header must not survive either, saw: {seen}"
        );
    }

    /// A caller that hands in a client with a redirect policy of its own
    /// does not get a governed answer out of it.
    ///
    /// The loop cannot set a policy on a client it did not build, so the
    /// hop has already happened by the time it can say anything. What it
    /// refuses is returning the body: reqwest reports the URL it landed
    /// on, and an origin that moved is proof the chain went somewhere
    /// nothing authorized.
    #[tokio::test]
    async fn a_client_that_followed_a_hop_itself_is_refused() {
        let Some((sink, sink_hit, _)) = fixture(ok_response("{}")) else {
            return;
        };
        let Some((origin, _, _)) = fixture(format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            sink.port()
        )) else {
            return;
        };
        // Deliberately wrong: reqwest's default is `Policy::limited(10)`.
        let follows = reqwest::Client::new();
        let governed = GovernedEgress {
            purpose: EgressPurpose::TokenExchange,
            authorizer: None,
            resolver: &LoopbackResolver,
            origin: "collector",
            tenant: "acme",
            sensitive_headers: &[],
            max_response_bytes: 4096,
            no_redirect_client: &follows,
            timeout: Duration::from_secs(5),
        };
        let request = follows
            .get(format!("http://127.0.0.1:{}/start", origin.port()))
            .build()
            .expect("request builds");

        let err = governed
            .send(request)
            .await
            .expect_err("a hop the loop never authorized must not produce a response");
        assert_eq!(
            err,
            GovernedEgressError::Denied(EgressDenied::RedirectToUnlistedHost)
        );
        assert!(
            sink_hit.load(Ordering::SeqCst),
            "the client did follow the hop; this check catches it rather than preventing it"
        );
    }

    /// The response-body ceiling is checked before the allocation, not
    /// after it.
    #[tokio::test]
    async fn an_oversized_response_body_is_refused() {
        let payload = "x".repeat(4096);
        let Some((endpoint, _, _)) = fixture(ok_response(&payload)) else {
            return;
        };
        let authorizer = allow(&["127.0.0.1"], &[endpoint.port()]);
        let resolver = LoopbackResolver;
        let unpinned = reqwest::Client::new();
        let governed = GovernedEgress {
            purpose: EgressPurpose::TokenExchange,
            authorizer: Some(&authorizer),
            resolver: &resolver,
            origin: "idp.test",
            tenant: "acme",
            sensitive_headers: &[],
            max_response_bytes: 64,
            no_redirect_client: &unpinned,
            timeout: Duration::from_secs(5),
        };
        let request = unpinned
            .get(format!("http://127.0.0.1:{}/token", endpoint.port()))
            .build()
            .expect("request builds");

        let err = governed
            .send(request)
            .await
            .expect_err("a body past the ceiling must be refused");
        assert_eq!(err, GovernedEgressError::ResponseTooLarge);
    }

    /// WOR-2612: `timeout` bounds the whole chain, not each hop.
    ///
    /// The fixture stalls `HOP_STALL` before answering every request
    /// with a same-origin `302`, and the budget is two stalls. Under a
    /// per-hop timeout no hop ever exceeds its own deadline, so all ten
    /// get through and the call ends `Denied(TooManyRedirects)` after
    /// ten stalls, with ten requests served. Under one budget for the
    /// chain the second or third hop runs out of it and the call ends
    /// `Transport`.
    ///
    /// Both assertions are on the shape of the outcome rather than on a
    /// wall clock, and they lean the safe way: a slow machine can only
    /// spend the budget sooner, which serves fewer requests and reaches
    /// the same `Transport`. It cannot turn the fixed behavior into the
    /// broken one.
    #[tokio::test]
    async fn one_budget_covers_the_whole_redirect_chain() {
        const HOP_STALL: Duration = Duration::from_millis(300);

        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(endpoint) = listener.local_addr() else {
            return;
        };
        let served = Arc::new(AtomicUsize::new(0));
        let served_side = Arc::clone(&served);
        let done = Arc::new(AtomicBool::new(false));
        let done_side = Arc::clone(&done);
        let fixture = std::thread::spawn(move || {
            // One more than the hop bound, so a chain that is not being
            // cut short still runs out of fixture rather than looping.
            for _ in 0..(crate::egress::MAX_REDIRECT_HOPS + 2) {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                if done_side.load(Ordering::SeqCst) {
                    break;
                }
                served_side.fetch_add(1, Ordering::SeqCst);
                let mut scratch = [0u8; 8192];
                let _ = stream.read(&mut scratch);
                std::thread::sleep(HOP_STALL);
                let _ = stream.write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /hop\r\nContent-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                );
                let _ = stream.flush();
            }
        });

        let authorizer = allow(&["127.0.0.1"], &[endpoint.port()]);
        let resolver = LoopbackResolver;
        let unpinned = reqwest::Client::new();
        let governed = GovernedEgress {
            purpose: EgressPurpose::TokenExchange,
            authorizer: Some(&authorizer),
            resolver: &resolver,
            origin: "idp.test",
            tenant: "acme",
            sensitive_headers: &[],
            max_response_bytes: 4096,
            no_redirect_client: &unpinned,
            timeout: HOP_STALL * 2,
        };
        let request = unpinned
            .get(format!("http://127.0.0.1:{}/hop", endpoint.port()))
            .build()
            .expect("request builds");

        let err = governed
            .send(request)
            .await
            .expect_err("a chain that outlives the budget must not return a response");
        assert_eq!(
            err,
            GovernedEgressError::Transport,
            "the call ended on the hop bound instead of the budget, so each hop \
             restarted the deadline"
        );
        let hops = served.load(Ordering::SeqCst);
        assert!(
            hops <= 4,
            "one budget of {HOP_STALL:?} x2 cannot pay for {hops} hops of {HOP_STALL:?} each"
        );

        done.store(true, Ordering::SeqCst);
        drop(std::net::TcpStream::connect(endpoint));
        let _ = fixture.join();
    }

    #[test]
    fn every_error_label_is_a_closed_token() {
        let labels = [
            GovernedEgressError::Denied(EgressDenied::UnlistedHost).as_label(),
            GovernedEgressError::ClientBuild.as_label(),
            GovernedEgressError::Transport.as_label(),
            GovernedEgressError::ResponseTooLarge.as_label(),
            GovernedEgressError::NotReplayable.as_label(),
        ];
        for label in labels {
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "label {label} is not a bounded metric token"
            );
        }
        // One label for every `Denied` reason, so a counter cannot grow
        // a series per denial variant on this axis.
        assert_eq!(
            GovernedEgressError::Denied(EgressDenied::DnsPinMismatch).as_label(),
            GovernedEgressError::Denied(EgressDenied::UnlistedHost).as_label()
        );
    }
}
