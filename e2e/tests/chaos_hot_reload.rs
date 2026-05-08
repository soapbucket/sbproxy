//! Chaos test: rapid hot-reload under sustained traffic (WOR-28).
//!
//! The reload drain state machine has unit coverage in
//! `sbproxy-core::reload` and loom coverage in the same crate (PR #47).
//! Neither hammers the integrated story: a live proxy serving real
//! HTTP traffic while the operator reload path swaps the compiled
//! pipeline out from under it. This test covers that gap.
//!
//! Setup: three stable origins (`a.localhost`, `b.localhost`,
//! `c.localhost`), each returning a distinct static body. A pool of
//! N concurrent worker threads sends GETs against a randomly picked
//! stable origin in a tight loop. A reload thread mutates the
//! on-disk config and hits `POST /admin/reload` at ~1 reload/s,
//! cycling through three non-trivial change shapes: add an extra
//! origin (`d.localhost`), remove that extra origin again, and
//! attach a `request_limit` policy to one stable origin. Workers
//! never request the transient origin, so the reload churn is
//! invisible from the assertion side except as pipeline pressure.
//!
//! Assertions match the WOR-28 ticket: zero dropped connections (no
//! transport-layer errors), zero misrouted requests (a 200 response
//! from origin X must carry origin X's body), and zero unexpected
//! 5xx (the test config exposes no 5xx-emitting surface, so any 5xx
//! is a chaos artefact).
//!
//! Numbers are scaled down from the ticket's 5000 rps / 10
//! reloads-per-second / 60s budget to fit the CI runtime envelope:
//! 200 concurrent workers (instead of "5000 rps"), 10 reloads at 1/s
//! (instead of 10/s for 60s), and ~12s wall-clock (instead of 60s).
//! The ticket-shape numbers are documented here so a reviewer can
//! scale up locally by editing the constants below; the assertion
//! shapes stay identical.
//!
//! Gating: marked `#[ignore]` and run nightly via
//! `cargo test ... -- --ignored`. Mirrors the pattern used by
//! `licensing-conformance.yml`. Skipped on regular PR CI because
//! the wall-clock budget plus 200-thread fan-out is too expensive
//! for the per-PR e2e lane.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;

// --- Tunables ---
//
// Chosen to fit the per-test CI runtime budget (~30s incl. proxy
// boot + teardown). The ticket-shape numbers are noted alongside.

/// Concurrent in-flight worker threads. Ticket aspiration: 5000 rps.
const NUM_WORKERS: usize = 200;
/// Total wall-clock the workers run for. Ticket aspiration: 60s.
const TEST_DURATION: Duration = Duration::from_secs(12);
/// Number of reload events the reload thread fires across the run.
/// Ticket aspiration: 10/s for 60s = 600 total. We do 10 over ~10s.
const NUM_RELOADS: usize = 10;
/// Spacing between reloads. Ticket aspiration: 100ms (10/s).
const RELOAD_INTERVAL: Duration = Duration::from_millis(1000);

// --- Stable origin bodies. Workers verify response body matches
//     the origin they targeted, so misrouting is observable as a
//     body mismatch. ---

const HOST_A: &str = "a.localhost";
const HOST_B: &str = "b.localhost";
const HOST_C: &str = "c.localhost";

const BODY_A: &str = "chaos-origin-a-body";
const BODY_B: &str = "chaos-origin-b-body";
const BODY_C: &str = "chaos-origin-c-body";

fn pick_admin_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Base config: three stable origins, no policies.
fn config_base(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "{HOST_A}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_A}"
  "{HOST_B}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_B}"
  "{HOST_C}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_C}"
"#
    )
}

/// Variant: adds a transient `d.localhost` origin. Workers never
/// request `d.localhost` so the add is only visible as compiler /
/// router churn.
fn config_with_extra(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "{HOST_A}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_A}"
  "{HOST_B}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_B}"
  "{HOST_C}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_C}"
  "d.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "chaos-origin-d-body"
"#
    )
}

/// Variant: same three origins, but `a.localhost` now has a
/// `request_limit` policy attached. The request_limit limits do
/// not reject GETs without bodies, so workers continue to see 200s
/// with body BODY_A; the only effect is to force the compiler to
/// produce a different handler chain for that origin.
fn config_with_policy(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "{HOST_A}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_A}"
    policies:
      - type: request_limit
        max_body_size: 65536
        max_header_count: 64
        max_url_length: 4096
  "{HOST_B}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_B}"
  "{HOST_C}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{BODY_C}"
"#
    )
}

/// One worker thread's tally of observed conditions. Aggregated at
/// the end of the run for the assertion phase.
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    /// Transport-level failure: connect refused, connection reset,
    /// read timeout, etc. Any non-HTTP error counts.
    drops: AtomicU64,
    /// 200 OK with a body that does not match the targeted host.
    /// The hot-reload swap is only safe if the in-flight request
    /// keeps using its snapshot of the pipeline; misroutes here
    /// indicate the projection-cache skew window is observable
    /// under load.
    misrouted: AtomicU64,
    /// Any 5xx response. Test config has no 5xx-emitting surface,
    /// so any 5xx is treated as a chaos artefact.
    unexpected_5xx: AtomicU64,
}

/// Issue one GET against the proxy and update the counters with
/// the outcome. Never panics; transient errors fall into `drops`.
fn one_request(client: &reqwest::blocking::Client, base: &str, host: &str, ctrs: &Counters) {
    let url = format!("{}/", base);
    ctrs.requests.fetch_add(1, Ordering::Relaxed);
    let result = client.get(&url).header("host", host).send();
    let resp = match result {
        Ok(r) => r,
        Err(_) => {
            ctrs.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let status = resp.status().as_u16();
    if (500..600).contains(&status) {
        ctrs.unexpected_5xx.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if status != 200 {
        // 4xx is acceptable (router during a reload race may briefly
        // miss); the misrouting check only triggers on a successful
        // 200 whose body proves the wrong origin served the request.
        return;
    }
    let body = match resp.text() {
        Ok(b) => b,
        Err(_) => {
            ctrs.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let expected = match host {
        HOST_A => BODY_A,
        HOST_B => BODY_B,
        HOST_C => BODY_C,
        _ => return,
    };
    if body.trim() != expected {
        ctrs.misrouted.fetch_add(1, Ordering::Relaxed);
    }
}

/// Send the admin reload POST. Returns the HTTP status; transient
/// reload errors are reported back to the caller so the orchestrator
/// can flag them without aborting the whole run.
fn admin_reload(admin_port: u16, auth: &str) -> Option<u16> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .post(format!("http://127.0.0.1:{}/admin/reload", admin_port))
        .header("authorization", auth)
        .send()
        .ok()?;
    Some(resp.status().as_u16())
}

/// Tiny standard-alphabet base64 encoder. Keeps the test free of
/// extra deps; mirrors the helper in `admin_reload.rs`.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };
        out.push(ALPH[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPH[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(ALPH[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[test]
#[ignore = "chaos test (WOR-28); runs nightly via --ignored, too expensive for per-PR CI"]
fn chaos_hot_reload_under_sustained_load() {
    // --- Boot the proxy on the base config ---
    let admin_port = pick_admin_port();
    let proxy = ProxyHarness::start_with_yaml(&config_base(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(10)).expect("admin port to bind");

    // Sanity-check that all three stable origins are wired before
    // we start hammering them. If this fails the chaos run cannot
    // produce a meaningful assertion, so fail fast with a clear
    // error.
    for (host, body) in [(HOST_A, BODY_A), (HOST_B, BODY_B), (HOST_C, BODY_C)] {
        let r = proxy.get("/", host).expect("baseline GET");
        assert_eq!(r.status, 200, "baseline {host}: status");
        assert_eq!(r.text().unwrap().trim(), body, "baseline {host}: body");
    }

    let base_url = proxy.base_url();
    let auth = format!("Basic {}", base64_encode("admin:secret"));

    // --- Spawn workers ---
    let counters = Arc::new(Counters::default());
    let stop = Arc::new(AtomicBool::new(false));

    let mut worker_handles = Vec::with_capacity(NUM_WORKERS);
    for worker_idx in 0..NUM_WORKERS {
        let counters = counters.clone();
        let stop = stop.clone();
        let base_url = base_url.clone();
        let h = std::thread::spawn(move || {
            // Each worker owns its own client so connection pools
            // do not become a single shared bottleneck. A short
            // timeout keeps a stalled connection from hiding a
            // dropped request as "in flight forever".
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("build client");
            // Cycle hosts deterministically across the 3 stable
            // origins. Using the worker index + a per-iteration
            // counter avoids needing an RNG dep and still spreads
            // load across all three hosts evenly.
            let mut iter: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                let host = match (worker_idx as u64).wrapping_add(iter) % 3 {
                    0 => HOST_A,
                    1 => HOST_B,
                    _ => HOST_C,
                };
                one_request(&client, &base_url, host, &counters);
                iter = iter.wrapping_add(1);
            }
        });
        worker_handles.push(h);
    }

    // --- Spawn the reload thread ---
    let reload_failures = Arc::new(AtomicU64::new(0));
    let reload_handle = {
        let reload_failures = reload_failures.clone();
        let stop_reload = stop.clone();
        let auth = auth.clone();
        // Lift &ProxyHarness into a sendable surface by capturing
        // only the bits the reload thread needs (the on-disk path
        // mutator + the admin port). Doing so dodges sharing the
        // ProxyHarness across threads, which is awkward because the
        // child process handle is not Sync.
        let config_path = proxy.config_path().to_path_buf();
        std::thread::spawn(move || {
            for i in 0..NUM_RELOADS {
                if stop_reload.load(Ordering::Relaxed) {
                    break;
                }
                // Cycle through the three change shapes: add origin,
                // remove origin (back to base), attach a policy.
                let yaml = match i % 3 {
                    0 => config_with_extra(admin_port),
                    1 => config_base(admin_port),
                    _ => config_with_policy(admin_port),
                };
                if let Err(e) = std::fs::write(&config_path, yaml) {
                    eprintln!("reload {i}: rewrite_config failed: {e}");
                    reload_failures.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(RELOAD_INTERVAL);
                    continue;
                }
                match admin_reload(admin_port, &auth) {
                    Some(200) => {}
                    Some(s) => {
                        eprintln!("reload {i}: admin POST status {s}");
                        reload_failures.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        eprintln!("reload {i}: admin POST transport error");
                        reload_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                std::thread::sleep(RELOAD_INTERVAL);
            }
        })
    };

    // --- Let the load run for the test duration ---
    std::thread::sleep(TEST_DURATION);
    stop.store(true, Ordering::Relaxed);

    // Drain workers + reload thread.
    let _ = reload_handle.join();
    for (i, h) in worker_handles.into_iter().enumerate() {
        if let Err(e) = h.join() {
            panic!("worker {i} panicked: {e:?}");
        }
    }

    // --- Restore the base config so the harness drop is clean ---
    let _ = proxy.rewrite_config(&config_base(admin_port));
    let _ = admin_reload(admin_port, &auth);

    // --- Assertions ---
    let requests = counters.requests.load(Ordering::Relaxed);
    let drops = counters.drops.load(Ordering::Relaxed);
    let misrouted = counters.misrouted.load(Ordering::Relaxed);
    let unexpected_5xx = counters.unexpected_5xx.load(Ordering::Relaxed);
    let reload_fail = reload_failures.load(Ordering::Relaxed);

    eprintln!(
        "chaos_hot_reload: {requests} requests, {drops} drops, \
         {misrouted} misrouted, {unexpected_5xx} 5xx, {reload_fail} reload failures \
         over {:?} with {NUM_WORKERS} workers and {NUM_RELOADS} reloads",
        TEST_DURATION
    );

    // Floor on traffic volume: if the workers somehow never made it
    // off the ground (e.g. proxy crashed at startup, threads
    // deadlocked) the chaos assertion is meaningless. We do not
    // require a specific rps, just that "many" requests landed.
    assert!(
        requests > (NUM_WORKERS as u64),
        "expected each worker to send at least one request, got {requests} total"
    );

    // The three load-bearing assertions from the ticket.
    assert_eq!(drops, 0, "dropped connections during reload chaos: {drops}");
    assert_eq!(
        misrouted, 0,
        "misrouted requests during reload chaos: {misrouted} \
         (a 200 response with the wrong origin's body indicates the \
         pipeline arc-swap let an in-flight request observe a torn \
         configuration)"
    );
    assert_eq!(
        unexpected_5xx, 0,
        "unexpected 5xx during reload chaos: {unexpected_5xx} \
         (the test config exposes no 5xx-emitting surface, so any \
         5xx is a chaos artefact)"
    );

    // The reload thread itself is not part of the WOR-28 contract
    // but a high failure rate would invalidate the run (the chaos
    // assertion is only meaningful if reloads are actually firing).
    // Allow one transient failure; flag anything more.
    assert!(
        reload_fail <= 1,
        "too many admin /reload failures during chaos run: {reload_fail} of {NUM_RELOADS}"
    );

    // Belt-and-braces: confirm the proxy survived the chaos run by
    // hitting it once after teardown. A reload-induced crash would
    // surface as a transport error here.
    let post = Instant::now();
    let r = proxy.get("/", HOST_A).expect("post-chaos GET");
    assert_eq!(r.status, 200, "post-chaos GET status");
    assert_eq!(
        r.text().unwrap().trim(),
        BODY_A,
        "post-chaos GET body (the proxy must have a coherent config after the run)"
    );
    eprintln!(
        "chaos_hot_reload: post-run probe OK in {:?}",
        post.elapsed()
    );
}
