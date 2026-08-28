// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-level CoMP marketplace reachability (WOR-2673).
//!
//! `sbproxy-licensing`'s own tests drive its axum router, and this
//! binary never mounts that router: it serves the three CoMP
//! well-known URLs from the Pingora request path instead. Nothing in
//! the library crate can prove that path exists, that
//! `origins.<host>.comp` reaches it, or that the buyer-key registry the
//! config declares is the one a redeem is checked against.
//!
//! This test boots the released binary from an `sb.yml`, walks the
//! whole buyer flow over the public listener (manifest, quote, redeem),
//! and then drives the two refusals that matter most: a buyer key this
//! publisher never onboarded, and a `quote_id` this publisher never
//! issued. Both must fail closed, and neither refusal may carry a
//! token.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

/// The buyer's Ed25519 seed. Fixed so the config below can name its
/// public half without the test generating and re-serializing one.
const BUYER_SEED: [u8; 32] = [0x5Au8; 32];

/// The origin's OLP signing seed, hex, exactly as `olp.signing_key`
/// takes it. The bridge signs the license token it returns with this,
/// which is the whole reason the token verifies against this same
/// origin's OLP surface.
const OLP_SEED_HEX: &str = "1122334455667788990011223344556677889900112233445566778899001122";

/// The CoMP quote-signing master key. Any value of 32 bytes or more;
/// HKDF expands it per rotation label.
const COMP_MASTER_KEY: &str = "comp-master-key-for-the-process-test-0123456789";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-comp-marketplace-process-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

/// One HTTP/1.1 request over a fresh connection. Returns the raw
/// response bytes, or `None` while the listener is not yet up.
fn request(port: u16, method: &str, path: &str, body: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: marketplace.test\r\nConnection: close\r\n");
    if let Some(body) = body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body).ok()?;
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    Some(response)
}

/// Split a raw response into its status line plus headers, and its body.
fn split(response: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(response).to_string();
    match text.split_once("\r\n\r\n") {
        Some((head, body)) => (head.to_string(), body.to_string()),
        None => (text, String::new()),
    }
}

fn start_proxy(root: &Path, config: &Path, port: u16) -> Child {
    let mut child = Command::new(binary())
        .arg("serve")
        .arg(config)
        .env_remove("SB_CONFIG_FILE")
        .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start sbproxy");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().expect("poll sbproxy").is_some() {
            let output = child.wait_with_output().expect("collect sbproxy output");
            panic!(
                "sbproxy exited before serving the CoMP manifest: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if request(port, "GET", "/.well-known/iab-comp/manifest.json", None).is_some() {
            return child;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed-out sbproxy");
            panic!(
                "sbproxy did not serve the CoMP manifest: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The current time as the RFC 3339 stamp a buyer puts in its
/// acceptance. The redeem path bounds how far this may sit from the
/// bridge's own clock, so a frozen date would fail for the wrong reason.
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the unix epoch")
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Serialize a redeem request and sign it the way an onboarded buyer's
/// client does: over the whole body with `buyer_signature.value`
/// cleared.
fn signed_redeem(
    quote: &sbproxy_licensing::comp::CompQuoteResponse,
    quote_id: &str,
    kid: &str,
    signer: &SigningKey,
) -> Vec<u8> {
    use sbproxy_licensing::comp::{
        quote_acceptance_hash, CompAcceptance, CompPaymentProof, CompRedeemRequest, CompSignature,
        COMP_VERSION,
    };
    let mut request = CompRedeemRequest {
        comp_version: COMP_VERSION.into(),
        quote_id: quote_id.to_string(),
        buyer_signature: CompSignature {
            alg: "ed25519".into(),
            kid: kid.into(),
            value: String::new(),
        },
        buyer_acceptance: CompAcceptance {
            accepted_quote_hash: quote_acceptance_hash(quote).expect("hash the quote"),
            accepted_at: rfc3339_now(),
            buyer_legal_entity: "Acme AI Inc.".into(),
        },
        payment_proof: CompPaymentProof {
            rail: "x402".into(),
            txhash: Some("0xdeadbeef".into()),
            chain: Some("base".into()),
            receipt_id: None,
        },
    };
    let signing_input = serde_json::to_vec(&request).expect("serialize for signing");
    let signature = signer.sign(&signing_input);
    request.buyer_signature.value =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
    serde_json::to_vec(&request).expect("serialize redeem")
}

#[test]
fn security_boundary_a_configured_origin_sells_licenses_and_refuses_the_rest() {
    let root = temp_dir();
    let buyer = SigningKey::from_bytes(&BUYER_SEED);
    let buyer_public =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buyer.verifying_key().to_bytes());
    let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral port");
    let port = reserved.local_addr().expect("reserved address").port();
    drop(reserved);
    let config = root.join("sb.yml");
    std::fs::write(
        &config,
        format!(
            r#"proxy:
  http_bind_port: {port}
  bind_address: 127.0.0.1
origins:
  "marketplace.test":
    action:
      type: static
      status_code: 418
      content_type: text/plain
      body: origin-fallback-must-not-answer
    olp:
      enabled: true
      signing_key: "{OLP_SEED_HEX}"
      key_id: process-test-olp-key
      issuer: https://marketplace.test
      default_scope: ai-input
      default_ttl_secs: 3600
    comp:
      enabled: true
      master_key: "{COMP_MASTER_KEY}"
      rotation_id: 2026-q3-001
      publisher:
        name: Example Publishing Co.
        contact: licensing@example.com
      tiers:
        - id: tier_ai_inference
          name: AI inference
          description: Per-request inference access.
          license: urn:rsl:pay-per-inference:default
          shape: json-envelope
          authorization: olp
          route_glob: "/api/v1/inference/**"
          pricing:
            model: per_request
            currency: USD
            amount_micros: 2500
      buyer_keys:
        - kid: buyer-acme-001
          public_key: "{buyer_public}"
"#
        ),
    )
    .expect("write process config");

    let mut child = start_proxy(&root, &config, port);

    // --- 1. The manifest, from the config block ---
    let raw = request(port, "GET", "/.well-known/iab-comp/manifest.json", None)
        .expect("manifest response");
    let (head, body) = split(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let lowered = head.to_ascii_lowercase();
    assert!(
        lowered.contains("content-type: application/iab-comp+json"),
        "{head}"
    );
    // Both headers come from the crate's own body rather than from a
    // second hand-rolled copy in the request path. A copy is what left
    // every federation metric family flat on this binary once already.
    assert!(lowered.contains("cache-control:"), "{head}");
    assert!(lowered.contains("x-comp-version: 1.0"), "{head}");
    let manifest: serde_json::Value = serde_json::from_str(&body).expect("manifest is JSON");
    assert_eq!(manifest["publisher"]["domain"], "marketplace.test");
    assert_eq!(manifest["publisher"]["name"], "Example Publishing Co.");
    assert_eq!(manifest["tiers"][0]["id"], "tier_ai_inference");
    assert_eq!(manifest["tiers"][0]["pricing"]["amount_micros"], 2500);
    assert_eq!(
        manifest["endpoints"]["redeem"],
        "https://marketplace.test/.well-known/iab-comp/redeem"
    );
    // Computed by the proxy over the manifest it publishes, not a
    // placeholder carried through from config.
    let hash = manifest["manifest_hash"]
        .as_str()
        .expect("manifest_hash is a string");
    assert!(hash.starts_with("sha256:"), "{hash}");
    assert_eq!(hash.len(), "sha256:".len() + 64, "{hash}");

    // --- 2. A quote ---
    let quote_body = serde_json::json!({
        "comp_version": "1.0",
        "buyer": { "agent_id": "agent_acme_001", "organization": "Acme AI Inc." },
        "tier_id": "tier_ai_inference",
        "requested_volume": {
            "model": "per_request", "expected_count": 1000, "duration_days": 30
        },
        "audience": "marketplace.test",
    })
    .to_string();
    let raw = request(
        port,
        "POST",
        "/.well-known/iab-comp/quote",
        Some(quote_body.as_bytes()),
    )
    .expect("quote response");
    let (head, body) = split(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "a signed price must not be cached: {head}"
    );
    let quote: sbproxy_licensing::comp::CompQuoteResponse =
        serde_json::from_str(&body).expect("quote is a CompQuoteResponse");
    assert_eq!(quote.tier_id, "tier_ai_inference");
    assert_eq!(quote.pricing.amount_micros, 2500 * 1000);
    assert!(
        quote.signature.kid.starts_with("comp-"),
        "quotes sign under this crate's own kid namespace: {}",
        quote.signature.kid
    );

    // --- 3. The redeem, and the token it mints ---
    let redeem = signed_redeem(&quote, &quote.quote_id, "buyer-acme-001", &buyer);
    let raw = request(port, "POST", "/.well-known/iab-comp/redeem", Some(&redeem))
        .expect("redeem response");
    let (head, body) = split(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "a license token must not be cached: {head}"
    );
    let redeemed: serde_json::Value = serde_json::from_str(&body).expect("redeem is JSON");
    assert_eq!(redeemed["token_type"], "Bearer");
    assert_eq!(redeemed["license"], "urn:rsl:pay-per-inference:default");
    assert_eq!(redeemed["route_glob"], "/api/v1/inference/**");
    let token = redeemed["license_token"]
        .as_str()
        .expect("a license token came back");
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3, "the token is a compact JWS: {token}");
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[0])
            .expect("the JWS header is base64url"),
    )
    .expect("the JWS header is JSON");
    // The token is minted under the origin's own OLP key id, which is
    // what makes it verifiable against this origin's OLP surface rather
    // than against a second issuer nobody configured.
    assert_eq!(header["kid"], "process-test-olp-key");
    assert_eq!(header["typ"], "olp-license+jws");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[1])
            .expect("the JWS payload is base64url"),
    )
    .expect("the JWS payload is JSON");
    assert_eq!(claims["iss"], "https://marketplace.test");
    assert_eq!(claims["aud"], "marketplace.test");
    assert_eq!(claims["license_urn"], "urn:rsl:pay-per-inference:default");

    // --- 4. Fails closed: a key this publisher never onboarded ---
    let stranger = SigningKey::from_bytes(&[0x7Bu8; 32]);
    let forged = signed_redeem(&quote, &quote.quote_id, "buyer-not-onboarded", &stranger);
    let (head, body) =
        split(&request(port, "POST", "/.well-known/iab-comp/redeem", Some(&forged)).expect("resp"));
    assert!(head.starts_with("HTTP/1.1 401"), "{head}\n{body}");
    assert!(body.contains("unknown_key"), "{body}");
    assert!(
        !body.contains("license_token"),
        "a refusal must not carry a token: {body}"
    );

    // --- 5. Fails closed: a quote_id this publisher never issued ---
    let fabricated = signed_redeem(
        &quote,
        "01JFABRICATEDQUOTEID000000",
        "buyer-acme-001",
        &buyer,
    );
    let (head, body) = split(
        &request(
            port,
            "POST",
            "/.well-known/iab-comp/redeem",
            Some(&fabricated),
        )
        .expect("resp"),
    );
    assert!(head.starts_with("HTTP/1.1 403"), "{head}\n{body}");
    assert!(body.contains("unknown_quote"), "{body}");
    assert!(
        !body.contains("license_token"),
        "a refusal must not carry a token: {body}"
    );

    // --- 6. Fails closed: a body this endpoint cannot read ---
    let (head, body) = split(
        &request(
            port,
            "POST",
            "/.well-known/iab-comp/quote",
            Some(b"{not json"),
        )
        .expect("resp"),
    );
    assert!(head.starts_with("HTTP/1.1 400"), "{head}\n{body}");
    assert!(body.contains("malformed"), "{body}");

    // --- 7. The method contract ---
    let (head, _) =
        split(&request(port, "GET", "/.well-known/iab-comp/redeem", None).expect("resp"));
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(root);
}
