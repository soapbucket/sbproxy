//! End-to-end integration tests for the CoMP router. Drives the
//! axum::Router through `tower::ServiceExt::oneshot` so the tests
//! exercise the real HTTP surface without binding a TCP listener.

use std::sync::Arc;

use axum::body::Body;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use sbproxy_licensing::comp::{
    comp_router, CompAcceptance, CompAuthorization, CompBuyer, CompEndpoints, CompManifest,
    CompMarketplace, CompPaymentProof, CompPricing, CompPricingModel, CompPublisher,
    CompQuoteRequest, CompQuoteResponse, CompRateCaps, CompRedeemRequest, CompRedeemResponse,
    CompRequestedVolume, CompSignature, CompTier, InMemoryBuyerKeyRegistry, OlpBridgeSigner,
    COMP_VERSION,
};
use sbproxy_licensing::keys::{KeyManager, MasterKey};
use sbproxy_licensing::revocation::InMemoryRevocation;

fn build_manifest() -> Arc<CompManifest> {
    Arc::new(CompManifest {
        comp_version: COMP_VERSION.into(),
        publisher: CompPublisher {
            name: "Example Publishing Co.".into(),
            domain: "api.example.com".into(),
            contact: "licensing@example.com".into(),
            verified_at: Some("2026-05-02T00:00:00Z".into()),
        },
        tiers: vec![
            CompTier {
                id: "tier_free_search".into(),
                name: "Free search".into(),
                description: "Free search indexing".into(),
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
                description: "Per-request inference".into(),
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
            manifest: "https://api.example.com/.well-known/iab-comp/manifest.json".into(),
            quote: "https://api.example.com/.well-known/iab-comp/quote".into(),
            redeem: "https://api.example.com/.well-known/iab-comp/redeem".into(),
        },
        robots_url: "https://api.example.com/robots.txt".into(),
        llms_url: "https://api.example.com/llms.txt".into(),
        rsl_url: "https://api.example.com/licenses.xml".into(),
        generated_at: "2026-05-02T14:00:00Z".into(),
        manifest_hash: "sha256:placeholder".into(),
    })
}

fn build_marketplace() -> (Arc<CompMarketplace>, SigningKey) {
    let mgr = KeyManager::new(MasterKey::new(vec![0x99u8; 32]).unwrap());
    mgr.set_active("2026-q2-001").unwrap();
    let bridge = Arc::new(OlpBridgeSigner::new(
        [0x88u8; 32],
        "olp-2026-q2-001",
        "https://api.example.com",
        "ai-input",
        3600,
    ));
    let revocation = Arc::new(InMemoryRevocation::new());
    let buyer_keys = Arc::new(InMemoryBuyerKeyRegistry::new());
    let buyer_signing = SigningKey::from_bytes(&[0x11u8; 32]);
    buyer_keys.insert("buyer-acme-001", buyer_signing.verifying_key());
    let mp = Arc::new(CompMarketplace::new(
        mgr,
        build_manifest(),
        revocation,
        bridge,
        buyer_keys,
    ));
    (mp, buyer_signing)
}

#[tokio::test]
async fn manifest_endpoint_returns_json_with_pinned_content_type() {
    let (mp, _) = build_marketplace();
    let app = comp_router(mp);
    let req = Request::get("/.well-known/iab-comp/manifest.json")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ct = res.headers().get(http::header::CONTENT_TYPE).unwrap();
    assert_eq!(ct.to_str().unwrap(), "application/iab-comp+json");
    let cache = res.headers().get(http::header::CACHE_CONTROL).unwrap();
    assert_eq!(cache.to_str().unwrap(), "public, max-age=300");
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let parsed: CompManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.comp_version, "1.0");
    assert_eq!(parsed.tiers.len(), 2);
}

#[tokio::test]
async fn quote_endpoint_returns_signed_quote() {
    let (mp, _) = build_marketplace();
    let app = comp_router(mp);
    let body = serde_json::to_vec(&CompQuoteRequest {
        comp_version: COMP_VERSION.into(),
        buyer: CompBuyer {
            agent_id: "agent_acme_001".into(),
            organization: "Acme AI Inc.".into(),
        },
        tier_id: "tier_ai_inference".into(),
        requested_volume: CompRequestedVolume {
            model: CompPricingModel::PerRequest,
            expected_count: 100_000,
            duration_days: 30,
        },
        audience: "api.example.com".into(),
    })
    .unwrap();
    let req = Request::post("/.well-known/iab-comp/quote")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ct = res.headers().get(http::header::CONTENT_TYPE).unwrap();
    assert_eq!(ct.to_str().unwrap(), "application/iab-comp-quote+json");
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let parsed: CompQuoteResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.tier_id, "tier_ai_inference");
    assert!(parsed.signature.kid.starts_with("comp-"));
    assert!(!parsed.signature.value.is_empty());
    assert_eq!(parsed.pricing.amount_micros, 2500u64 * 100_000);
}

#[tokio::test]
async fn redeem_endpoint_mints_bridged_olp_token() {
    let (mp, signer) = build_marketplace();
    let app = comp_router(mp.clone());

    // Drive a quote first so the redeem has a real quote_id.
    let quote_body = serde_json::to_vec(&CompQuoteRequest {
        comp_version: COMP_VERSION.into(),
        buyer: CompBuyer {
            agent_id: "agent_acme_001".into(),
            organization: "Acme AI Inc.".into(),
        },
        tier_id: "tier_ai_inference".into(),
        requested_volume: CompRequestedVolume {
            model: CompPricingModel::PerRequest,
            expected_count: 1_000,
            duration_days: 30,
        },
        audience: "api.example.com".into(),
    })
    .unwrap();
    let req = Request::post("/.well-known/iab-comp/quote")
        .header("content-type", "application/json")
        .body(Body::from(quote_body))
        .unwrap();
    let quote_res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(quote_res.status(), StatusCode::OK);
    let quote_bytes = quote_res.into_body().collect().await.unwrap().to_bytes();
    let quote: CompQuoteResponse = serde_json::from_slice(&quote_bytes).unwrap();

    // Build a redeem and sign it with the buyer key.
    let mut redeem = CompRedeemRequest {
        comp_version: COMP_VERSION.into(),
        quote_id: quote.quote_id,
        buyer_signature: CompSignature {
            alg: "ed25519".into(),
            kid: "buyer-acme-001".into(),
            value: String::new(),
        },
        buyer_acceptance: CompAcceptance {
            accepted_quote_hash: "sha256:placeholder".into(),
            accepted_at: "2026-05-02T14:35:00Z".into(),
            buyer_legal_entity: "Acme AI Inc.".into(),
        },
        payment_proof: CompPaymentProof {
            rail: "x402".into(),
            txhash: Some("0xdeadbeef".into()),
            chain: Some("base".into()),
            receipt_id: None,
        },
    };
    // Re-derive the canonical signing input by using the same shape
    // the marketplace uses: serialize with signature.value cleared.
    let mut for_sig = redeem.clone();
    for_sig.buyer_signature.value = String::new();
    let signing_input = serde_json::to_vec(&for_sig).unwrap();
    let sig = signer.sign(&signing_input);
    redeem.buyer_signature.value = B64URL.encode(sig.to_bytes());

    let body = serde_json::to_vec(&redeem).unwrap();
    let req = Request::post("/.well-known/iab-comp/redeem")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cache = res.headers().get(http::header::CACHE_CONTROL).unwrap();
    assert_eq!(cache.to_str().unwrap(), "no-store");
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let parsed: CompRedeemResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.license, "urn:rsl:pay-per-inference:default");
    assert_eq!(parsed.route_glob, "/api/v1/inference/**");
    assert_eq!(parsed.license_token.split('.').count(), 3);
    assert_eq!(parsed.expires_in, 3600);
}

#[tokio::test]
async fn redeem_endpoint_rejects_bad_signature_with_401() {
    let (mp, _signer) = build_marketplace();
    let app = comp_router(mp.clone());

    let quote_body = serde_json::to_vec(&CompQuoteRequest {
        comp_version: COMP_VERSION.into(),
        buyer: CompBuyer {
            agent_id: "agent_acme_001".into(),
            organization: "Acme AI Inc.".into(),
        },
        tier_id: "tier_ai_inference".into(),
        requested_volume: CompRequestedVolume {
            model: CompPricingModel::PerRequest,
            expected_count: 1,
            duration_days: 1,
        },
        audience: "api.example.com".into(),
    })
    .unwrap();
    let req = Request::post("/.well-known/iab-comp/quote")
        .header("content-type", "application/json")
        .body(Body::from(quote_body))
        .unwrap();
    let quote_res = app.clone().oneshot(req).await.unwrap();
    let quote_bytes = quote_res.into_body().collect().await.unwrap().to_bytes();
    let quote: CompQuoteResponse = serde_json::from_slice(&quote_bytes).unwrap();

    let redeem = CompRedeemRequest {
        comp_version: COMP_VERSION.into(),
        quote_id: quote.quote_id,
        buyer_signature: CompSignature {
            alg: "ed25519".into(),
            kid: "buyer-acme-001".into(),
            // Well-formed base64 but not a valid signature over
            // anything: the marketplace must reject it, not panic.
            value: B64URL.encode([0u8; 64]),
        },
        buyer_acceptance: CompAcceptance {
            accepted_quote_hash: "sha256:placeholder".into(),
            accepted_at: "2026-05-02T14:35:00Z".into(),
            buyer_legal_entity: "Acme AI Inc.".into(),
        },
        payment_proof: CompPaymentProof {
            rail: "x402".into(),
            txhash: Some("0xdeadbeef".into()),
            chain: Some("base".into()),
            receipt_id: None,
        },
    };
    let body = serde_json::to_vec(&redeem).unwrap();
    let req = Request::post("/.well-known/iab-comp/redeem")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
