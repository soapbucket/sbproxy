//! Runnable CoMP marketplace bridge: serves a two-tier manifest, mints
//! a signed quote, redeems it into a bridged OLP license token, and
//! then serves `/.well-known/iab-comp/*`, `/admin/status`, and
//! `/metrics` so you can repeat the same flow yourself over HTTP.
//!
//! ```text
//! cargo run -p sbproxy-licensing --example standalone_marketplace
//! ```
//!
//! Then, in another terminal:
//!
//! ```text
//! curl -s http://127.0.0.1:8096/.well-known/iab-comp/manifest.json | jq
//! curl -s http://127.0.0.1:8096/admin/status | jq
//! curl -s http://127.0.0.1:8096/metrics | grep sbproxy_comp_marketplace
//! ```
//!
//! To drive a quote and redeem it yourself against the running demo,
//! see the buyer-side signing steps this file performs at startup;
//! the demo buyer key is fixed (`buyer-demo-1`) so a `curl` script can
//! reuse it without minting its own keypair.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

use sbproxy_licensing::comp::{
    CompAcceptance, CompAuthorization, CompBuyer, CompEndpoints, CompManifest, CompMarketplace,
    CompPaymentProof, CompPricing, CompPricingModel, CompPublisher, CompQuoteRequest, CompRateCaps,
    CompRedeemRequest, CompRequestedVolume, CompSignature, CompTier, InMemoryBuyerKeyRegistry,
    OlpBridgeSigner, COMP_VERSION,
};
use sbproxy_licensing::keys::{KeyManager, MasterKey};
use sbproxy_licensing::revocation::{InMemoryRevocation, Revocation};

const LISTEN_ADDR: &str = "127.0.0.1:8096";
const PUBLISHER_DOMAIN: &str = "publisher.example.com";
const BUYER_KID: &str = "buyer-demo-1";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // --- Signing keys ---
    //
    // A real deployment reads the master key from a secret store and
    // the OLP bridge seed from the same config value the origin's
    // `olp.signing_key` uses. Both are fixed bytes here for a
    // zero-setup demo; the comment on each explains what a production
    // value must be instead.
    let keys = KeyManager::new(MasterKey::new(vec![0xABu8; 32]).expect("32-byte master key"));
    keys.set_active("2026-demo-001").expect("derive comp key");

    let olp_bridge = Arc::new(OlpBridgeSigner::new(
        // Production: the SAME 32-byte seed as `origins.<host>.olp.signing_key`
        // on the origin this token will be presented to, so
        // `/.well-known/olp/introspect` there can verify it.
        [0xCDu8; 32],
        "olp-2026-demo-001",
        "https://publisher.example.com",
        "ai-input",
        3600,
    ));

    let buyer_signing = SigningKey::from_bytes(&[0xEFu8; 32]);
    let buyer_keys = Arc::new(InMemoryBuyerKeyRegistry::new());
    buyer_keys.insert(BUYER_KID, buyer_signing.verifying_key());

    let manifest = Arc::new(demo_manifest());
    let revocation: Arc<dyn Revocation> = Arc::new(InMemoryRevocation::new());
    let marketplace = Arc::new(CompMarketplace::new(
        keys.clone(),
        manifest,
        revocation,
        olp_bridge,
        buyer_keys,
    ));

    // --- Demonstrate quote -> redeem before the server even starts ---
    let quote_req = CompQuoteRequest {
        comp_version: COMP_VERSION.into(),
        buyer: CompBuyer {
            agent_id: "agent_demo_buyer".into(),
            organization: "Demo Buyer Inc.".into(),
        },
        tier_id: "tier_ai_inference".into(),
        requested_volume: CompRequestedVolume {
            model: CompPricingModel::PerRequest,
            expected_count: 10_000,
            duration_days: 30,
        },
        audience: PUBLISHER_DOMAIN.into(),
    };
    let quote = marketplace.quote(quote_req).expect("quote the demo tier");
    eprintln!(
        "quoted {} (${:.2}): quote_id={}",
        quote.tier_id,
        quote.pricing.amount_micros as f64 / 1_000_000.0,
        quote.quote_id
    );

    let mut redeem_req = CompRedeemRequest {
        comp_version: COMP_VERSION.into(),
        quote_id: quote.quote_id.clone(),
        buyer_signature: CompSignature {
            alg: "ed25519".into(),
            kid: BUYER_KID.into(),
            value: String::new(),
        },
        buyer_acceptance: CompAcceptance {
            accepted_quote_hash: "sha256:demo".into(),
            accepted_at: "2026-05-02T14:35:00Z".into(),
            buyer_legal_entity: "Demo Buyer Inc.".into(),
        },
        payment_proof: CompPaymentProof {
            rail: "x402".into(),
            txhash: Some("0xdemo".into()),
            chain: Some("base".into()),
            receipt_id: None,
        },
    };
    let mut for_sig = redeem_req.clone();
    for_sig.buyer_signature.value = String::new();
    let signing_input = serde_json::to_vec(&for_sig).expect("serialize redeem for signing");
    let sig = buyer_signing.sign(&signing_input);
    redeem_req.buyer_signature.value = B64URL.encode(sig.to_bytes());

    let redeemed = marketplace
        .redeem(redeem_req)
        .await
        .expect("redeem the demo quote");
    eprintln!(
        "redeemed: license_token (first 24 chars) = {}...  expires_in={}s",
        &redeemed.license_token[..24.min(redeemed.license_token.len())],
        redeemed.expires_in
    );

    let app: Router =
        sbproxy_licensing::router(marketplace, keys).route("/metrics", get(metrics_handler));

    let addr: SocketAddr = LISTEN_ADDR.parse().expect("static address parses");
    eprintln!("sbproxy-licensing CoMP marketplace demo");
    eprintln!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| panic!("serve: {e}"));
}

fn demo_manifest() -> CompManifest {
    CompManifest {
        comp_version: COMP_VERSION.into(),
        publisher: CompPublisher {
            name: "Example Publishing Co.".into(),
            domain: PUBLISHER_DOMAIN.into(),
            contact: "licensing@example.com".into(),
            verified_at: Some("2026-05-02T00:00:00Z".into()),
        },
        tiers: vec![
            CompTier {
                id: "tier_free_search".into(),
                name: "Free search indexing".into(),
                description: "Indexing for traditional search engines.".into(),
                license: "urn:rsl:search-index:default".into(),
                shape: "html".into(),
                pricing: CompPricing {
                    model: CompPricingModel::Free,
                    currency: "USD".into(),
                    amount: Some(0),
                    amount_micros: None,
                },
                authorization: CompAuthorization::Cap,
                rate_caps: Some(CompRateCaps {
                    max_rps: 1.0,
                    max_bytes_per_day: 1_073_741_824,
                }),
                route_glob: "/**".into(),
            },
            CompTier {
                id: "tier_ai_inference".into(),
                name: "AI inference".into(),
                description: "Per-request inference access.".into(),
                license: "urn:rsl:pay-per-inference:default".into(),
                shape: "json-envelope".into(),
                pricing: CompPricing {
                    model: CompPricingModel::PerRequest,
                    currency: "USD".into(),
                    amount: None,
                    amount_micros: Some(2500),
                },
                authorization: CompAuthorization::Olp,
                rate_caps: None,
                route_glob: "/api/v1/inference/**".into(),
            },
        ],
        endpoints: CompEndpoints {
            manifest: format!("https://{PUBLISHER_DOMAIN}/.well-known/iab-comp/manifest.json"),
            quote: format!("https://{PUBLISHER_DOMAIN}/.well-known/iab-comp/quote"),
            redeem: format!("https://{PUBLISHER_DOMAIN}/.well-known/iab-comp/redeem"),
        },
        robots_url: format!("https://{PUBLISHER_DOMAIN}/robots.txt"),
        llms_url: format!("https://{PUBLISHER_DOMAIN}/llms.txt"),
        rsl_url: format!("https://{PUBLISHER_DOMAIN}/licenses.xml"),
        generated_at: "2026-05-02T14:00:00Z".into(),
        manifest_hash: "sha256:demo-placeholder".into(),
    }
}

/// Render every registered Prometheus family, including this crate's
/// `sbproxy_comp_marketplace_*` families
/// (`dashboards/grafana/sbproxy-comp-marketplace.json` draws them from
/// an endpoint shaped exactly like this one).
async fn metrics_handler() -> String {
    use prometheus::Encoder;
    let families = prometheus::gather();
    let mut buf = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&families, &mut buf)
        .unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}
