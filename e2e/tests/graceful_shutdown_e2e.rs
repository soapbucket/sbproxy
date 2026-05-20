//! WOR-636: SIGTERM graceful-shutdown integration test.
//!
//! Kubernetes (pod eviction / drain), `docker stop`, and systemd all
//! deliver SIGTERM and then wait `terminationGracePeriodSeconds`
//! before escalating to SIGKILL. SBproxy must acknowledge the signal,
//! drain in flight, and exit cleanly inside that window. This test
//! spawns the real binary, sends a real SIGTERM, and asserts a clean
//! exit (status 0) well within the configured grace budget.
//!
//! Unix-only: SIGTERM has no portable Windows analogue, and the
//! binary's signal path is `#[cfg(unix)]` SIGINT/SIGTERM handling.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sbproxy_e2e::proxy_binary_path;

/// Grab an ephemeral port by binding to `:0` and releasing it. There
/// is an inherent race between release and the proxy's rebind, but the
/// window is tiny on a loopback bind and the proxy is the only thing
/// racing for it here.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// Poll until the proxy accepts a TCP connection on `port`, or the
/// deadline expires.
fn wait_listening(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

#[test]
fn sigterm_drains_and_exits_cleanly_within_grace() {
    let bin = proxy_binary_path();
    assert!(
        bin.is_file(),
        "sbproxy binary missing at {}; run `cargo build -p sbproxy` first",
        bin.display()
    );

    let port = free_port();
    let cfg = format!(
        "proxy:\n  \
           http_bind_port: {port}\n\
         origins:\n  \
           \"shutdown.localhost\":\n    \
             action:\n      \
               type: proxy\n      \
               url: \"http://127.0.0.1:1\"\n"
    );
    let mut cfg_file = tempfile::NamedTempFile::new().expect("temp config");
    cfg_file.write_all(cfg.as_bytes()).expect("write config");
    cfg_file.flush().expect("flush config");

    // A short, explicit grace budget keeps the test deterministic
    // regardless of how Pingora paces an idle drain: with no in-flight
    // requests the server should exit far inside this window.
    let mut child = Command::new(&bin)
        .arg("--config")
        .arg(cfg_file.path())
        .env("SBPROXY_SHUTDOWN_GRACE_MS", "500")
        .env("SB_LOG_LEVEL", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sbproxy");

    assert!(
        wait_listening(port, Duration::from_secs(20)),
        "proxy did not start listening on 127.0.0.1:{port}"
    );

    // Deliver a real SIGTERM, exactly as kubelet / `docker stop` would.
    let kill = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("invoke kill -TERM");
    assert!(kill.success(), "kill -TERM did not succeed");

    // Assert a clean exit within a generous margin over the 500ms grace.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    panic!("sbproxy did not exit within 10s of SIGTERM (grace=500ms)");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };
    assert!(
        status.success(),
        "sbproxy must exit cleanly on SIGTERM, got {status:?}"
    );

    // The binary must make the shutdown visible in its logs (the
    // execution-phase logger emits `shutdown_*` tracing events). Read
    // whatever the child wrote; both pipes are at EOF now that it has
    // exited, so these reads cannot block.
    let mut out = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut out);
    }
    assert!(
        out.contains("shutdown"),
        "expected a shutdown log line on SIGTERM; captured output was:\n{out}"
    );
}
