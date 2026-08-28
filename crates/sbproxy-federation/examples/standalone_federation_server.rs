//! Runnable OpenID Federation entity: mints an ES256 keypair, serves
//! a self-signed Entity Configuration at
//! `/.well-known/openid-federation`, exposes `/admin/status` and
//! `/metrics`, and resolves a one-step trust chain against itself
//! before the server even starts accepting connections (a leaf that
//! is also its own trust anchor), so you can see the
//! [`sbproxy_federation::TrustChainResolver`] decision-event log line
//! and the matching counter tick without standing up a second
//! entity.
//!
//! ```text
//! cargo run -p sbproxy-federation --example standalone_federation_server
//! ```
//!
//! Then, in another terminal:
//!
//! ```text
//! curl -s http://127.0.0.1:8095/.well-known/openid-federation
//! curl -s http://127.0.0.1:8095/admin/status | jq
//! curl -s http://127.0.0.1:8095/metrics | grep sbproxy_federation
//! ```
//!
//! The well-known response is a compact JWS; decode its payload with
//! `cut -d. -f2 | base64 -d` (add `=` padding first) or `jq -R 'split(".")[1] | @base64d | fromjson'`
//! to read the claims.
//!
//! `FEDERATION_ENTITY_ID` overrides the entity URL this process
//! advertises as both `iss` and `sub` (default `http://127.0.0.1:8095`,
//! matching the bind address below so the demo is fully self
//! contained). OpenID Federation §9 REQUIRES this to be an `https://`
//! URL in production; [`sbproxy_federation::ReqwestFederationFetcher`]
//! enforces that on the CONSUMING side, but this example does not run
//! a fetcher against itself, so the plain-http default is left in
//! place for a zero-setup `cargo run`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use jsonwebtoken::Algorithm;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use sbproxy_federation::{
    router, EntityMetadata, FederationEntityMetadata, FederationKeySet, FederationServerConfig,
    SigningKeyConfig, TrustAnchor, TrustAnchorStore, TrustChainResolver, WellKnownIssuer,
};

const DEFAULT_ENTITY_ID: &str = "http://127.0.0.1:8095";
const LISTEN_ADDR: &str = "127.0.0.1:8095";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let entity_id =
        std::env::var("FEDERATION_ENTITY_ID").unwrap_or_else(|_| DEFAULT_ENTITY_ID.to_string());

    let (pem, jwk) = mint_es256_keypair("demo-key-1");
    let mut published_jwks = FederationKeySet::empty();
    published_jwks.push(jwk);

    let config = FederationServerConfig {
        entity_id: entity_id.clone(),
        signing_key: SigningKeyConfig {
            pem,
            algorithm: Algorithm::ES256,
            kid: "demo-key-1".to_string(),
        },
        published_jwks,
        metadata: EntityMetadata {
            federation_entity: Some(FederationEntityMetadata {
                organization_name: Some("sbproxy-federation demo entity".to_string()),
                contacts: vec!["security@example.com".to_string()],
                ..Default::default()
            }),
            other: Default::default(),
        },
        // No superiors: this entity is its own trust anchor for the
        // demo below. A leaf in a real federation lists its
        // immediate superiors' entity URLs here instead.
        authority_hints: vec![],
        trust_marks: vec![],
        metadata_policy: None,
        lifetime: Duration::from_secs(3600),
        refresh_margin: Duration::from_secs(360),
    };

    let issuer = Arc::new(WellKnownIssuer::new(config).expect("valid signing key"));

    // --- Demonstrate the trust-chain resolver against ourselves ---
    //
    // A single-step chain where the leaf's own entity id is also a
    // configured trust anchor is a valid OIDF mode (see
    // `trust_chain::tests::single_step_chain_with_self_anchor_resolves`).
    // This fires the same `TrustChainResolver::resolve` call path a
    // peer verifying this entity would use, so the decision-event log
    // line and the `sbproxy_federation_trust_chain_resolutions_total`
    // counter both tick before the first HTTP request ever arrives.
    let doc = issuer.current().expect("sign entity configuration");
    let anchors = TrustAnchorStore::from_anchors([TrustAnchor {
        entity_id: entity_id.clone(),
        jwks: issuer.config().published_jwks.clone(),
    }]);
    let resolver = TrustChainResolver::new(anchors, 5);
    match resolver.resolve(std::slice::from_ref(&doc.compact_jws)) {
        Ok(resolved) => {
            eprintln!(
                "self-resolved trust chain: leaf = anchor = {}",
                resolved.trust_anchor_id
            );
        }
        Err(err) => eprintln!("self-resolve failed (unexpected): {err}"),
    }

    let app: Router = router(issuer).route("/metrics", get(metrics_handler));

    let addr: SocketAddr = LISTEN_ADDR.parse().expect("static address parses");
    eprintln!("sbproxy-federation demo entity: {entity_id}");
    eprintln!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| panic!("serve: {e}"));
}

/// Mint a fresh ES256 keypair for the demo. Every run gets a new key;
/// a real deployment loads a persisted PEM instead so its published
/// `kid` stays stable across restarts.
fn mint_es256_keypair(kid: &str) -> (Vec<u8>, serde_json::Value) {
    use base64::Engine;
    let signing = SigningKey::random(&mut rand::thread_rng());
    let pem = signing
        .to_pkcs8_pem(Default::default())
        .expect("PKCS#8 encode");
    let verifying = signing.verifying_key();
    let point = verifying.to_encoded_point(false);
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        "kid": kid,
    });
    (pem.as_bytes().to_vec(), jwk)
}

/// Render every registered Prometheus family as the standard text
/// exposition format, including this crate's `sbproxy_federation_*`
/// families (`dashboards/grafana/sbproxy-federation.json` draws them
/// from an endpoint shaped exactly like this one).
async fn metrics_handler() -> String {
    use prometheus::Encoder;
    let families = prometheus::gather();
    let mut buf = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&families, &mut buf)
        .unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}
