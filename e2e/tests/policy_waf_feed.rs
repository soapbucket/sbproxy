//! End-to-end coverage for the WAF rule-feed subscription.
//!
//! Spins up an in-process HTTP server that pretends to be the
//! enterprise rule-feed publisher, points the proxy at it, and asserts
//! the documented behaviour:
//!
//! 1. A request that matches a rule shipped in the bundle is blocked
//!    with 403.
//! 2. After the mock feed swaps in a bundle that drops the rule, the
//!    proxy hot-reloads it and the same request now passes with 200.
//! 3. When the mock feed serves a tampered signature, the proxy
//!    refuses to apply the new bundle and keeps serving the last-good
//!    corpus (so a rule the prior bundle blocked is still blocked).
//!
//! The protocol contract under test:
//! - `GET /waf/rules/<channel>` returns a JSON bundle.
//! - Header `X-SBProxy-Feed-Sig: <hex hmac-sha256>` over the raw body.
//! - `Authorization: Bearer <token>` carries the tenant identifier.
//! - Polling cadence is short here (`poll_interval: 1`) so the test
//!   does not have to wait for the production-default 60-second loop.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sbproxy_e2e::ProxyHarness;
use serde_json::json;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the hex-encoded HMAC-SHA256 of `body` under `key`. Matches
/// the helper in `sbproxy_modules::policy::waf::feed`.
fn sign(body: &[u8], key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, body);
    hex::encode(mac.finalize().into_bytes())
}

/// Settings the mock feed's request handler reads on every poll. Cloned
/// per request so the test thread can swap them mid-flight.
#[derive(Clone)]
struct FeedState {
    /// Bundle JSON body the next request will receive.
    body: Vec<u8>,
    /// Hex HMAC-SHA256 emitted in the `X-SBProxy-Feed-Sig` header.
    /// Tests can overwrite this to a wrong value to drive the
    /// signature-failure path.
    signature: String,
}

struct MockFeed {
    port: u16,
    state: Arc<Mutex<FeedState>>,
    shutdown: Arc<Mutex<bool>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl MockFeed {
    fn start(initial: FeedState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock feed");
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(initial));
        let shutdown = Arc::new(Mutex::new(false));

        let st = state.clone();
        let sh = shutdown.clone();
        // Match the harness's MockUpstream pattern: spawn a thread that
        // accepts forever and dispatches each connection to its own
        // worker.
        let join = std::thread::spawn(move || {
            for incoming in listener.incoming() {
                if *sh.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let st2 = st.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(stream, st2);
                });
            }
        });

        Self {
            port,
            state,
            shutdown,
            join: Some(join),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/waf/rules/test", self.port)
    }

    fn set_state(&self, new: FeedState) {
        *self.state.lock().unwrap() = new;
    }
}

impl Drop for MockFeed {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Poke the listener so accept() returns and the loop sees the flag.
        let _ = std::net::TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn handle_conn(
    mut stream: std::net::TcpStream,
    state: Arc<Mutex<FeedState>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf)?;
    // Snapshot the current state so a mid-write swap by the test
    // thread doesn't tear the response.
    let snap = state.lock().unwrap().clone();
    let mut resp = String::new();
    resp.push_str("HTTP/1.1 200 OK\r\n");
    resp.push_str("Content-Type: application/json\r\n");
    resp.push_str(&format!("X-SBProxy-Feed-Sig: {}\r\n", snap.signature));
    resp.push_str(&format!("Content-Length: {}\r\n", snap.body.len()));
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;
    stream.write_all(&snap.body)?;
    stream.flush()?;
    Ok(())
}

/// Build a signed bundle FeedState from a list of (id, pattern) rules.
fn bundle_with(rules: &[(&str, &str)], key: &[u8]) -> FeedState {
    let json_body = json!({
        "version": chrono_now_rfc3339(),
        "channel": "test",
        "rules": rules.iter().map(|(id, pat)| json!({
            "id": id,
            "paranoia": 1,
            "category": "test",
            "pattern": pat,
            "action": "block",
            "severity": "medium",
        })).collect::<Vec<_>>(),
    });
    let body = serde_json::to_vec(&json_body).unwrap();
    let signature = sign(&body, key);
    FeedState { body, signature }
}

/// Stand-in for `chrono::Utc::now().to_rfc3339()` that does not pull
/// chrono into the e2e dev-deps. Returns a coarse but well-formed
/// RFC-3339 string anchored to wall-clock seconds since the unix
/// epoch.
fn chrono_now_rfc3339() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 2026-01-01T00:00:00Z corresponds to 1767225600 unix seconds.
    // Producing a real calendar date without chrono is fiddly; cheat
    // by formatting offset-seconds as a synthetic but parseable
    // timestamp. The proxy only treats this as an opaque revision
    // marker once `max_age` is disabled.
    format!("1970-01-01T00:00:{:02}Z", secs % 60)
}

fn config(feed_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "waf.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        owasp_crs:
          enabled: false
        action_on_match: block
        test_mode: false
        fail_open: false
        feed:
          enabled: true
          transport: http
          url: "{url}"
          channel: test
          signature_key_env: SBPROXY_FEED_TEST_E2E_KEY
          poll_interval: 1
          max_age: 0
          fallback_to_static: true
"#,
        url = feed_url,
    )
}

/// Poll until the supplied predicate returns `true` or the deadline
/// elapses. The subscriber's first poll lands within ~`poll_interval`
/// seconds of startup; tests give it a generous margin so a slow CI
/// host does not flake.
fn wait_for<F: FnMut() -> bool>(mut f: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn feed_rule_blocks_then_drops_then_signature_tamper_keeps_last_good() {
    // --- Shared HMAC key. Used by the test to sign bundles and by the
    // proxy (via env var) to verify them. ---
    let key = b"e2e-test-shared-key";
    std::env::set_var("SBPROXY_FEED_TEST_E2E_KEY", "e2e-test-shared-key");

    // --- Mock feed serves a bundle that blocks `evil-token`. ---
    let initial = bundle_with(&[("E2E-001", "evil-token")], key);
    let feed = MockFeed::start(initial);
    let url = feed.url();

    // --- Proxy boots and pulls the bundle. The first poll lands
    //     within ~poll_interval seconds. ---
    let harness = ProxyHarness::start_with_yaml(&config(&url)).expect("start proxy");

    // --- Phase 1: rule from feed blocks the request. ---
    let blocked = wait_for(
        || {
            harness
                .get("/scan?q=evil-token", "waf.localhost")
                .map(|r| r.status == 403)
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    );
    assert!(
        blocked,
        "feed-loaded rule should have blocked the request within 10s"
    );

    // --- Phase 2: publisher drops the rule. The proxy must hot-load
    //     the new bundle and stop blocking. ---
    let empty = bundle_with(&[], key);
    feed.set_state(empty);
    let unblocked = wait_for(
        || {
            harness
                .get("/scan?q=evil-token", "waf.localhost")
                .map(|r| r.status == 200)
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    );
    assert!(
        unblocked,
        "after dropping the rule, the proxy should let the request through within 10s"
    );

    // --- Phase 3: re-publish the blocking rule, verify it sticks,
    //     then tamper with the signature header so the next poll
    //     fails verification. The proxy must keep serving the
    //     last-good corpus. ---
    let blocking_again = bundle_with(&[("E2E-001", "evil-token")], key);
    feed.set_state(blocking_again);
    let reblocked = wait_for(
        || {
            harness
                .get("/scan?q=evil-token", "waf.localhost")
                .map(|r| r.status == 403)
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    );
    assert!(reblocked, "republished rule should block again within 10s");

    // Tamper: keep the same body but emit a wrong signature.
    let tampered = {
        let mut bad = bundle_with(&[("E2E-002", "newer-payload")], key);
        bad.signature = "deadbeef".repeat(8); // 64 hex chars, valid shape, wrong MAC
        bad
    };
    feed.set_state(tampered);

    // Wait two poll cycles to give the proxy a chance to *attempt* the
    // bad fetch and reject it.
    std::thread::sleep(Duration::from_secs(3));

    // The original blocking rule must still be active (last-good held).
    let resp = harness
        .get("/scan?q=evil-token", "waf.localhost")
        .expect("get after tamper");
    assert_eq!(
        resp.status, 403,
        "after a signature tamper the proxy must continue serving the last-good bundle"
    );

    // The new (rejected) rule must NOT have taken effect, since the
    // tampered bundle was discarded.
    let resp = harness
        .get("/scan?q=newer-payload", "waf.localhost")
        .expect("get tampered payload");
    assert_eq!(
        resp.status, 200,
        "tampered bundle must not load; new rule should not take effect"
    );
}
