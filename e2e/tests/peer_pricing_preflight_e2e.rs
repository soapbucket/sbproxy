// SPDX-License-Identifier: BUSL-1.1
//! WOR-188: outbound peer-pricing pre-flight, end-to-end.
//!
//! Exercises the [`PeerPricingPreflightPolicy`] against a real local
//! HTTP fixture peer. Three behaviours are pinned here:
//!
//! 1. **Over budget -> structured 402.** A peer publishes a priced
//!    route well above the operator's per-request cap; the policy
//!    must short-circuit with [`PreflightDecision::Block`] whose body
//!    carries `route_pattern`, `price_micros`, `currency`, and
//!    `shape`.
//! 2. **Under budget -> pass-through.** The same peer publishes a
//!    cheap route that fits the operator's cap; the policy returns
//!    [`PreflightDecision::Allow`] with the matched route attached.
//! 3. **No second GET within TTL.** Hitting the policy repeatedly for
//!    the same peer must reuse the cached manifest, not re-probe.
//!
//! The test does not depend on the proxy binary: the policy is the
//! integration unit and is driven directly against a peer fixture
//! served by a one-shot `axum` app. This keeps the e2e fast while
//! still exercising real socket I/O, real HTTP framing, and the same
//! fetcher contract production wiring will use.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use sbproxy_modules::policy::peer_pricing_preflight::{
    BlockReason, FetchResult, ManifestFetcher, OnNoManifest, PeerPricingPreflightConfig,
    PeerPricingPreflightPolicy, PreflightDecision,
};

/// Fixture manifest the peer publishes at `/llms.txt`. Mirrors the
/// renderer output for an `ai_crawl_control` config with two
/// markdown / html tiers and one expensive json tier so the test can
/// hit "cheap tier passes, expensive tier blocks" with one fixture.
const FIXTURE_MANIFEST: &str = "# sitename: peer.example\n\
# version: 7\n\
# payment: pay-per-request\n\
# shapes: html,markdown,json\n\
\n\
# peer.example\n\
\n\
## Priced routes\n\
\n\
- `/articles/*` - agent `*`, shape `html`, price 0.005000 USD\n\
- `/articles/*` - agent `*`, shape `markdown`, price 0.002000 USD\n\
- `/data/*` - agent `*`, shape `json`, price 0.050000 USD\n";

/// Adapter that drives the fetcher trait off a `reqwest::blocking`
/// client. Lives inside the test so the production wiring (a future
/// PR) is free to choose its own client and connect-timeout policy.
struct ReqwestFetcher {
    base_url: String,
    calls: Arc<AtomicUsize>,
    client: reqwest::blocking::Client,
}

impl ReqwestFetcher {
    fn new(base_url: String) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");
        (
            Self {
                base_url,
                calls: calls.clone(),
                client,
            },
            calls,
        )
    }
}

impl ManifestFetcher for ReqwestFetcher {
    fn fetch(&self, _peer_host: &str) -> FetchResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let url = format!("{}/llms.txt", self.base_url);
        let resp = match self.client.get(&url).send() {
            Ok(r) => r,
            Err(_) => return FetchResult::NotPublished,
        };
        if !resp.status().is_success() {
            return FetchResult::NotPublished;
        }
        match resp.bytes() {
            Ok(b) => FetchResult::Ok(b.to_vec()),
            Err(_) => FetchResult::NotPublished,
        }
    }
}

/// Spin up a one-shot peer that serves `FIXTURE_MANIFEST` at
/// `/llms.txt`. Returns the bound base URL plus a shutdown signal so
/// the test drops the server cleanly after the assertions land.
fn start_fixture_peer() -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = Router::new().route(
        "/llms.txt",
        get(|| async {
            (
                [("content-type", "text/plain; charset=utf-8")],
                FIXTURE_MANIFEST,
            )
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr: SocketAddr = listener.local_addr().expect("local addr");

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    // The fixture runs on its own tokio runtime so the test stays
    // synchronous. Server shutdown is driven by `tx`.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    std::thread::spawn(move || {
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("from_std");
            let server = axum::serve(listener, app.into_make_service());
            tokio::select! {
                _ = server => {}
                _ = rx => {}
            }
        });
    });

    // Spin briefly until the listener accepts a TCP connect; the
    // server is ready as soon as that succeeds.
    let base = format!("http://{}", addr);
    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (base, tx)
}

#[test]
fn over_budget_returns_structured_402_and_under_budget_passes() {
    let (base, _shutdown) = start_fixture_peer();
    let (fetcher, calls) = ReqwestFetcher::new(base);

    let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
        // 0.01 USD per call: blocks the 0.05 USD json route, allows
        // the markdown route at 0.002 USD.
        max_price_per_request: Some(0.01),
        daily_budget_micros: Some(10_000_000),
        cache_ttl: None,
        on_no_manifest: OnNoManifest::Allow,
    })
    .expect("policy");

    // Pass-through case: agent asks for markdown, peer offers it at
    // 2000 micros (well under the 10_000-micro cap).
    let pass = policy.evaluate(
        "peer.example",
        "/articles/intro",
        Some("text/markdown"),
        &fetcher,
    );
    match pass {
        PreflightDecision::Allow {
            matched_route: Some(route),
        } => {
            assert_eq!(route.route_pattern, "/articles/*");
            assert_eq!(route.price_micros, 2000);
            assert_eq!(route.currency, "USD");
        }
        other => panic!("expected Allow with route, got {other:?}"),
    }

    // Block case: agent asks for json, peer offers it at 50_000
    // micros, over the 10_000-micro cap.
    let block = policy.evaluate(
        "peer.example",
        "/data/users",
        Some("application/json"),
        &fetcher,
    );
    match block {
        PreflightDecision::Block { reason, body } => {
            assert_eq!(reason, BlockReason::OverPerRequestBudget);
            assert_eq!(body["error"], "peer_pricing_preflight");
            assert_eq!(body["reason"], "over_per_request_budget");
            assert_eq!(body["route_pattern"], "/data/*");
            assert_eq!(body["price_micros"], 50_000);
            assert_eq!(body["currency"], "USD");
            assert_eq!(body["shape"], "json");
            assert_eq!(body["max_price_per_request_micros"], 10_000);
        }
        other => panic!("expected Block, got {other:?}"),
    }

    // Cache contract: both calls share one peer fetch within the TTL.
    assert_eq!(calls.load(Ordering::SeqCst), 1, "expected one peer fetch");
}

#[test]
fn no_second_get_within_ttl() {
    let (base, _shutdown) = start_fixture_peer();
    let (fetcher, calls) = ReqwestFetcher::new(base);

    let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
        max_price_per_request: Some(0.01),
        daily_budget_micros: None,
        cache_ttl: None,
        on_no_manifest: OnNoManifest::Allow,
    })
    .expect("policy");

    for i in 0..10 {
        let _ = policy.evaluate(
            "peer.example",
            "/articles/x",
            Some("text/markdown"),
            &fetcher,
        );
        // Sanity: in-loop accounting should keep climbing.
        assert!(policy.spent_today_micros() >= 2000 * (i as u64 + 1));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "TTL must coalesce fetches");
}
