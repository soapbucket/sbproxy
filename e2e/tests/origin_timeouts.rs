//! Per-origin upstream timeouts (WOR-2311).
//!
//! Proves a configured `timeouts.read_ms` actually bounds the upstream
//! read. The stub upstream accepts the connection, reads the request,
//! and never writes a response, so the proxy's upstream read deadline
//! is the only thing that can end the exchange. With the built-in 30s
//! default the harness client would give up first (its own timeout is
//! 10s and `get` would return an error); with `read_ms: 500` the proxy
//! must surface an upstream-timeout error well inside that budget.

use sbproxy_e2e::ProxyHarness;
use std::io::Read;
use std::net::TcpListener;
use std::time::{Duration, Instant};

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "slow.localhost":
    action:
      type: proxy
      url: "UPSTREAM"
    timeouts:
      read_ms: 500
"#;

#[test]
fn configured_read_timeout_fires_before_the_default() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    let stall = std::thread::spawn(move || {
        // Accept one connection and read until the peer closes. No
        // response bytes are ever written, so the exchange ends only
        // when the proxy's read deadline fires and it drops the
        // connection, which also lets this thread exit.
        if let Ok((mut socket, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            while socket.read(&mut buf).map(|n| n > 0).unwrap_or(false) {}
        }
    });

    let yaml = CONFIG.replace("UPSTREAM", &format!("http://{addr}"));
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let started = Instant::now();
    let resp = proxy
        .get("/", "slow.localhost")
        .expect("read_ms: 500 should produce a fast upstream-timeout response; a client-side timeout here means the configured deadline was not applied");
    let elapsed = started.elapsed();

    assert!(
        resp.status >= 500,
        "expected an upstream-timeout error status, got {}",
        resp.status
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "read_ms: 500 should fail the request quickly; took {elapsed:?}"
    );

    drop(proxy);
    let _ = stall.join();
}
