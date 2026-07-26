//! End-to-end drills for minted keys presented in an arbitrary inbound header.
//!
//! These exercise the real request path, which the unit tests cannot: the sweep
//! runs pre-auth, policies run before the upstream filter, and the strip and
//! credential injection happen in `upstream_request_filter`. Several of the
//! behaviours here fail *silently* when broken (a key that stops governing, a
//! secret that reaches an origin), so each one asserts on what the upstream
//! actually received rather than on a status code alone.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

/// Headers the stub upstream saw, lowercased.
#[derive(Debug, Default, Clone)]
struct SeenHeaders {
    headers: Vec<(String, String)>,
}

impl SeenHeaders {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

/// A one-shot upstream that records the request it was given and answers 200.
struct StubUpstream {
    port: u16,
    seen: mpsc::Receiver<SeenHeaders>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl StubUpstream {
    fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (tx, seen) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            // Serve until dropped so a retry lands on the same stub. The stop
            // flag is checked after every accept: `Drop` sets it and then makes
            // one throwaway connection purely to wake this blocking accept, and
            // without the check the loop would go straight back to accept and
            // the join would never return.
            while let Ok((mut stream, _)) = listener.accept() {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(seen) = read_headers(&mut stream) else {
                    continue;
                };
                let _ = tx.send(seen);
                let body = b"{\"ok\":true}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });
        Ok(Self {
            port,
            seen,
            stop,
            join: Some(join),
        })
    }

    fn next_request(&self) -> SeenHeaders {
        self.seen
            .recv_timeout(Duration::from_secs(10))
            .expect("the upstream received a request")
    }
}

impl Drop for StubUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the thread observes the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_headers(stream: &mut TcpStream) -> std::io::Result<SeenHeaders> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break offset;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut headers = Vec::new();
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(SeenHeaders { headers })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral listener")
        .local_addr()
        .expect("listener address")
        .port()
}

/// Config with the key sweep on and a plain proxy origin at the stub.
fn config(admin_port: u16, upstream_port: u16, extra_origin: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  key_management:
    enabled: true
    store:
      backend: embedded
      path: /tmp/sbproxy-e2e-inbound-key-{admin_port}.redb
    crypto:
      pepper: e2e-pepper-value-not-a-real-secret
      master_key: e2e-master-value-not-a-real-secret
    inbound:
      headers:
        - name: authorization
          scheme: "Bearer "
        - name: x-api-key
          scheme: ""
        - name: x-sb-api
          scheme: ""
      require: false

origins:
  tools.local:
    action:
      type: proxy
      url: http://127.0.0.1:{upstream_port}
{extra_origin}
"#
    )
}

fn mint(admin_port: u16, body: serde_json::Value) -> String {
    let response = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{admin_port}/admin/keys"))
        .basic_auth("admin", Some("secret"))
        .json(&body)
        .send()
        .expect("mint request");
    let status = response.status().as_u16();
    let text = response.text().unwrap_or_default();
    assert_eq!(status, 201, "mint refused: {text}");
    serde_json::from_str::<serde_json::Value>(&text)
        .unwrap_or_else(|e| panic!("mint response is json: {e}: {text}"))["token"]
        .as_str()
        .unwrap_or_else(|| panic!("mint response carries a token: {text}"))
        .to_string()
}

fn create_credential(admin_port: u16, body: serde_json::Value) -> u16 {
    reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{admin_port}/admin/credentials"))
        .basic_auth("admin", Some("secret"))
        .json(&body)
        .send()
        .expect("credential request")
        .status()
        .as_u16()
}

#[test]
fn the_key_header_is_consumed_and_never_reaches_the_upstream() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let token = mint(admin_port, serde_json::json!({"name": "sdk"}));

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &token)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert!(
        !seen.has("x-api-key"),
        "the proxy's own key must not reach the origin: {seen:?}"
    );
}

#[test]
fn a_sidecar_key_leaves_the_callers_own_credential_untouched() {
    // The governance-without-custody shape: the tool keeps sending its real
    // upstream secret and the minted key rides alongside.
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let token = mint(admin_port, serde_json::json!({"name": "sidecar"}));

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("authorization", "Bearer the-callers-own-upstream-secret")
        .header("x-sb-api", &token)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("authorization"),
        Some("Bearer the-callers-own-upstream-secret"),
        "a pass-through credential must survive untouched"
    );
    assert!(
        !seen.has("x-sb-api"),
        "the minted key is consumed: {seen:?}"
    );
}

#[test]
fn a_bound_credential_replaces_the_key_on_the_same_header() {
    // Substitution: the tool sends a minted key in the header it already uses,
    // and the origin sees its own real secret there instead.
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    assert_eq!(
        create_credential(
            admin_port,
            serde_json::json!({
                "id": "anthropic-prod",
                "secret": "the-real-upstream-secret",
                "header": "x-api-key",
                "scheme": ""
            })
        ),
        201
    );
    let token = mint(
        admin_port,
        serde_json::json!({"name": "bound", "credential_id": "anthropic-prod"}),
    );

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &token)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("x-api-key"),
        Some("the-real-upstream-secret"),
        "the bound credential replaces the minted key: {seen:?}"
    );
}

#[test]
fn two_conflicting_tokens_are_refused_rather_than_silently_resolved() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let first = mint(admin_port, serde_json::json!({"name": "a"}));
    let second = mint(admin_port, serde_json::json!({"name": "b"}));

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &first)
        .header("x-sb-api", &second)
        .send()
        .expect("proxied request");
    assert_eq!(
        response.status().as_u16(),
        400,
        "configuration order must not decide which key governs"
    );
}

#[test]
fn a_callers_own_provider_key_still_reaches_the_upstream() {
    // The parallel-operation guarantee. A tool presenting its real Anthropic
    // key must not collect a 401 from us just because key management is on.
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", "sk-ant-api03-not-one-of-ours")
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("x-api-key"),
        Some("sk-ant-api03-not-one-of-ours"),
        "a key that is not ours passes through untouched: {seen:?}"
    );
}

#[test]
fn an_unknown_minted_key_is_refused() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let unknown = format!("sbp_{}_{}", "f".repeat(16), "e".repeat(64));
    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", unknown)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 401);
}

#[test]
fn requiring_a_key_refuses_a_request_that_carries_none() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let yaml = config(admin_port, upstream.port, "")
        .replace("      require: false", "      require: true");
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 401);
}
