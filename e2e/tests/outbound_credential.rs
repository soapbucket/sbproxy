//! Outbound credential resolver wiring (WOR-802 PR2).
//!
//! Verifies the proxy mints/resolves a per-upstream credential and
//! stamps it on the request it sends upstream, with no client-side
//! credential handling:
//! - two origins with `vault_secret` credentials send distinct headers
//!   to their respective upstreams (request to A gets cred A, B gets B);
//! - a `token_exchange` origin exchanges the inbound bearer at a token
//!   endpoint and forwards the minted token, not the inbound one.

use base64::Engine as _;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use sha2::Digest as _;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const DPOP_PRIVATE_KEY: &str =
    include_str!("../../crates/sbproxy-modules/src/auth/dpop_test_ec_p256.pem");

fn dpop_jwk() -> serde_json::Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4",
        "y": "bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc"
    })
}

fn dpop_jkt() -> &'static str {
    "IeJTwmoSPsFMO6w48KpbHar6spW4kZZ9UvgEXQ0hOwA"
}

fn proof_claims(proof: &str) -> serde_json::Value {
    let encoded = proof.split('.').nth(1).expect("proof claims");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("base64url proof claims");
    serde_json::from_slice(&decoded).expect("proof claims JSON")
}

fn raw_request_header(raw: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(raw).lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

const VAULT_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "a.localhost":
    action:
      type: proxy
      url: "UPSTREAM_A"
    outbound_credential:
      type: vault_secret
      secret: "secret-for-A"
      header: "x-api-key"
      scheme: ""
  "b.localhost":
    action:
      type: proxy
      url: "UPSTREAM_B"
    outbound_credential:
      type: vault_secret
      secret: "secret-for-B"
      header: "x-api-key"
      scheme: ""
"#;

#[test]
fn per_upstream_credentials_are_distinct() {
    let upstream_a = MockUpstream::start(json!({"ok": "a"})).expect("upstream a");
    let upstream_b = MockUpstream::start(json!({"ok": "b"})).expect("upstream b");
    let yaml = VAULT_CONFIG
        .replace("UPSTREAM_A", &upstream_a.base_url())
        .replace("UPSTREAM_B", &upstream_b.base_url());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let ra = proxy.get("/", "a.localhost").expect("call a");
    assert_eq!(ra.status, 200);
    let rb = proxy.get("/", "b.localhost").expect("call b");
    assert_eq!(rb.status, 200);

    let seen_a = upstream_a.captured();
    let seen_b = upstream_b.captured();
    assert!(!seen_a.is_empty() && !seen_b.is_empty());
    assert_eq!(
        seen_a[0].headers.get("x-api-key").map(String::as_str),
        Some("secret-for-A"),
        "upstream A must receive credential A; got {:?}",
        seen_a[0].headers.get("x-api-key")
    );
    assert_eq!(
        seen_b[0].headers.get("x-api-key").map(String::as_str),
        Some("secret-for-B"),
        "upstream B must receive credential B; got {:?}",
        seen_b[0].headers.get("x-api-key")
    );
}

fn jwt(claims: serde_json::Value) -> String {
    let b64 = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    format!(
        "{}.{}.sig",
        b64(&json!({"alg": "none", "typ": "JWT"})),
        b64(&claims)
    )
}

#[test]
fn token_exchange_mints_and_replaces_inbound_token() {
    // The token endpoint returns a minted access token; the app
    // upstream must receive that minted token, not the inbound bearer.
    let token_endpoint = MockUpstream::start(json!({
        "access_token": "minted-token-xyz",
        "token_type": "Bearer",
        "expires_in": 3600
    }))
    .expect("token endpoint");
    let app = MockUpstream::start(json!({"ok": true})).expect("app upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{app}"
    outbound_credential:
      type: token_exchange
      token_endpoint: "{token}"
      audience: "https://api.example.com"
      allowed_audiences: ["https://api.example.com"]
      subject_token_issuers: ["https://issuer"]
"#,
        app = app.base_url(),
        token = token_endpoint.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let subject = jwt(json!({"iss": "https://issuer", "sub": "user-1"}));
    let resp = proxy
        .get_with_headers(
            "/data",
            "api.localhost",
            &[("authorization", &format!("Bearer {subject}"))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let seen = app.captured();
    assert!(!seen.is_empty(), "app upstream should be called");
    assert_eq!(
        seen[0].headers.get("authorization").map(String::as_str),
        Some("Bearer minted-token-xyz"),
        "app upstream must receive the minted token, not the inbound one; got {:?}",
        seen[0].headers.get("authorization")
    );
    // The token endpoint was actually called to mint.
    assert!(
        !token_endpoint.captured().is_empty(),
        "token endpoint should be called for the exchange"
    );
}

#[test]
fn dpop_mints_fresh_bound_resource_proofs_and_retries_one_nonce_challenge() {
    let token_endpoint = MockUpstream::start(json!({
        "access_token": "dpop-bound-token",
        "token_type": "DPoP",
        "expires_in": 3600
    }))
    .expect("token endpoint");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("resource listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking resource listener");
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let server_captured = Arc::clone(&captured);
    let resource_server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut attempt = 0;
        while attempt < 2 && std::time::Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("resource accept: {error}"),
            };
            stream
                .set_nonblocking(false)
                .expect("blocking resource stream");
            let mut bytes = vec![0; 16 * 1024];
            let count = stream.read(&mut bytes).expect("read resource request");
            bytes.truncate(count);
            server_captured.lock().unwrap().push(bytes);
            let (status, headers, body) = if attempt == 0 {
                (
                    "401 Unauthorized",
                    "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"\r\nDPoP-Nonce: resource-nonce\r\n",
                    r#"{"error":"use_dpop_nonce"}"#,
                )
            } else {
                ("200 OK", "", r#"{"ok":true}"#)
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write resource response");
            attempt += 1;
        }
    });

    let mut key_file = tempfile::NamedTempFile::new().expect("DPoP key file");
    key_file
        .write_all(DPOP_PRIVATE_KEY.as_bytes())
        .expect("write DPoP key");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "dpop.localhost":
    action:
      type: proxy
      url: "http://127.0.0.1:{resource_port}/api"
    outbound_credential:
      type: client_credentials
      token_endpoint: "{token_endpoint}"
      client_id: "sbproxy"
      client_secret: "test-secret"
      dpop:
        key: "file:{key_path}"
        alg: ES256
        jwk: {jwk}
"#,
        resource_port = port,
        token_endpoint = token_endpoint.base_url(),
        key_path = key_file.path().display(),
        jwk = dpop_jwk(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start DPoP proxy");
    let response = proxy
        .get("/items/a%2Fb?debug=true", "dpop.localhost")
        .expect("DPoP resource call");
    assert_eq!(response.status, 200, "{}", proxy.stderr_contents());
    resource_server.join().expect("resource server");

    let token_requests = token_endpoint.captured();
    assert_eq!(token_requests.len(), 1);
    let token_proof = token_requests[0]
        .headers
        .get("dpop")
        .expect("token DPoP proof");
    let token_claims = proof_claims(token_proof);
    assert_eq!(token_claims["htm"], "POST");
    assert!(token_claims.get("ath").is_none());

    let requests = captured.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let proofs: Vec<_> = requests
        .iter()
        .map(|request| raw_request_header(request, "dpop").expect("resource DPoP proof"))
        .collect();
    assert_ne!(proofs[0], proofs[1]);
    for (attempt, proof) in proofs.iter().enumerate() {
        let expected_htu = "http://127.0.0.1/api/items/a%2Fb".to_string();
        let claims = proof_claims(proof);
        assert_eq!(claims["htm"], "GET");
        assert_eq!(claims["htu"], expected_htu);
        let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(b"dpop-bound-token"));
        assert_eq!(claims["ath"], expected_ath);
        if attempt == 0 {
            assert!(claims.get("nonce").is_none());
        } else {
            assert_eq!(claims["nonce"], "resource-nonce");
        }
        sbproxy_modules::auth::dpop::DpopVerifier::default()
            .verify(
                Some(proof),
                "GET",
                &expected_htu,
                dpop_jkt(),
                std::time::SystemTime::now(),
            )
            .expect("valid resource proof");
        assert_eq!(
            raw_request_header(&requests[attempt], "authorization").as_deref(),
            Some("DPoP dpop-bound-token")
        );
    }
}
