// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-listener-startup-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

#[test]
fn a_configured_bind_address_reaches_the_listener() {
    // WOR-2199. The only test that can tell the difference between
    // formatting proxy.bind_address into a string and the listener
    // actually binding it. Occupy loopback specifically, configure
    // loopback specifically, and require the startup failure to name
    // it: a proxy still binding 0.0.0.0 would not collide with a
    // loopback-only holder on most hosts, and would start clean.
    let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy ephemeral loopback port");
    let port = occupied.local_addr().expect("occupied address").port();
    let root = temp_dir("bind-address");
    let config = root.join("sb.yml");
    std::fs::write(
        &config,
        format!(
            r#"proxy:
  http_bind_port: {port}
  bind_address: 127.0.0.1
origins:
  "listener.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
        ),
    )
    .expect("write bind-address config");

    let mut child = Command::new(binary())
        .arg("serve")
        .arg(&config)
        .env_remove("SB_CONFIG_FILE")
        .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start sbproxy");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll sbproxy") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("sbproxy did not exit after binding an occupied loopback port");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect sbproxy output");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!status.success(), "occupied listener must exit nonzero");
    assert!(
        stderr.contains(&format!("127.0.0.1:{port}")),
        "the failure must name the configured address, not 0.0.0.0: {stderr}"
    );
    drop(occupied);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn occupied_public_listener_fails_startup_with_address_and_cause() {
    let occupied = TcpListener::bind("0.0.0.0:0").expect("occupy ephemeral public port");
    let port = occupied.local_addr().expect("occupied address").port();
    let root = temp_dir("collision");
    let config = root.join("sb.yml");
    std::fs::write(
        &config,
        format!(
            r#"proxy:
  http_bind_port: {port}
origins:
  "listener.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
        ),
    )
    .expect("write collision config");

    let mut child = Command::new(binary())
        .arg("serve")
        .arg(&config)
        .env_remove("SB_CONFIG_FILE")
        .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start sbproxy");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll sbproxy") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed-out sbproxy");
            panic!(
                "listener collision left startup running; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect sbproxy output");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!status.success(), "occupied listener must exit nonzero");
    assert!(stderr.contains(&format!("0.0.0.0:{port}")), "{stderr}");
    assert!(
        stderr
            .to_ascii_lowercase()
            .contains("address already in use")
            || stderr.to_ascii_lowercase().contains("address in use"),
        "{stderr}"
    );

    drop(occupied);
    TcpListener::bind(("0.0.0.0", port))
        .expect("failed startup must not retain or leak the public listener");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
/// Whether the proxy is serving on `port`, not merely listening.
///
/// A prepared-but-unattended socket still completes a TCP handshake, so
/// `TcpStream::connect` returning `Ok` proves only that the port is
/// bound. One HTTP exchange proves the run loop is up, which is the
/// state the rest of this test depends on.
fn serves_ok(port: u16) -> bool {
    use std::io::{Read as _, Write as _};

    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: listener.test\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    // A short read is enough: the status line arrives first.
    let _ = stream.read_to_end(&mut response);
    response.starts_with(b"HTTP/1.1 200")
}

#[cfg(unix)]
#[test]
fn sigterm_cleanly_releases_a_prepared_public_listener() {
    let root = temp_dir("sigterm");
    let config = root.join("sb.yml");
    let log_path = root.join("sbproxy.log");

    // Acquire a free ephemeral port and start the proxy on it. The port is
    // reserved, its number read, and the reservation dropped so the child
    // can bind it, which leaves a TOCTOU window: under parallel test load
    // another process can take the port before the child binds, and the
    // child then exits with "address in use". That is a harness race, not a
    // shutdown bug, so it retries on a fresh port; any other early exit is
    // a real startup failure and fails immediately.
    let (mut child, port) = 'acquire: {
        for _ in 0..16 {
            let reservation =
                TcpListener::bind("0.0.0.0:0").expect("reserve ephemeral public port");
            let port = reservation.local_addr().expect("reserved address").port();
            drop(reservation);
            std::fs::write(
                &config,
                format!(
                    r#"proxy:
  http_bind_port: {port}
origins:
  "listener.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
                ),
            )
            .expect("write serve config");
            let stdout = std::fs::File::create(&log_path).expect("create serve log");
            let stderr = stdout.try_clone().expect("clone serve log");
            let mut child = Command::new(binary())
                .arg("serve")
                .arg(&config)
                .arg("--shutdown-grace-ms")
                .arg("0")
                .env_remove("SB_CONFIG_FILE")
                .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .expect("start sbproxy");
            let startup_deadline = Instant::now() + Duration::from_secs(15);
            let ready = loop {
                // Served, not merely connectable. sbproxy prepares its
                // public listener before Pingora's `Server::run` installs
                // the SIGTERM handler, and a bare `TcpStream::connect`
                // succeeds the moment the socket is listening because the
                // kernel completes the handshake into the backlog. Probing
                // that way declared the proxy ready while a SIGTERM would
                // still kill it by default disposition, and the test then
                // failed on `status.success()` with `signal: 15`. Waiting
                // for a response means the run loop is actually serving.
                if serves_ok(port) {
                    break true;
                }
                if let Some(status) = child.try_wait().expect("poll startup") {
                    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                    let stolen = {
                        let lower = log.to_ascii_lowercase();
                        lower.contains("address") && lower.contains("use")
                    };
                    assert!(
                        stolen,
                        "sbproxy exited before listener was ready: {status}; log={log}"
                    );
                    break false; // port was taken; retry on a fresh one
                }
                if Instant::now() >= startup_deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                    panic!("sbproxy did not accept on prepared listener; log={log}");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            if ready {
                break 'acquire (child, port);
            }
        }
        panic!("could not acquire a free public port for the proxy after 16 attempts");
    };

    let signal = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(signal.success(), "send SIGTERM to sbproxy");
    let shutdown_deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll shutdown") {
            break status;
        }
        if Instant::now() >= shutdown_deadline {
            let _ = child.kill();
            let _ = child.wait();
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("sbproxy ignored SIGTERM; log={log}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(status.success(), "SIGTERM exit was {status}; log={log}");
    // The child has exited, so the port is ours to reclaim. Retry briefly:
    // if the child cleanly released the listener the bind succeeds at once,
    // and the retry only absorbs another process transiently holding the
    // just-freed port. A child that failed to release keeps the port for
    // its whole (already-exited) lifetime, so this never masks that bug.
    let mut released = false;
    for _ in 0..20 {
        if TcpListener::bind(("0.0.0.0", port)).is_ok() {
            released = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        released,
        "clean shutdown must release the prepared public listener; log={log}"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// How long to hold the process inside the startup signal window.
///
/// Long enough that the signal, the exit, and the assertions all fit
/// inside it with room for a loaded CI machine, because the test's whole
/// claim rests on the child exiting *before* this elapses.
#[cfg(unix)]
const STARTUP_WINDOW_HOLD: Duration = Duration::from_secs(8);

#[cfg(unix)]
#[test]
fn sigterm_inside_the_startup_window_exits_cleanly_rather_than_by_signal() {
    // WOR-2452. The companion to
    // `sigterm_cleanly_releases_a_prepared_public_listener`, which waits
    // for the run loop before signalling and therefore only ever
    // exercises Pingora's handler. This one signals in the window
    // between the bind and `Server::run`, where the process used to have
    // a listening socket and the default signal disposition, and a
    // SIGTERM killed it outright as `signal: 15`.
    //
    // The window is a few milliseconds unaided, so the proxy widens it
    // on request. Without that hook the test would be a coin flip, and a
    // coin flip cannot distinguish "the guard handled it" from "the
    // signal arrived after the guard stopped mattering", which is the
    // only distinction the test is for.
    let root = temp_dir("sigterm-window");
    let config = root.join("sb.yml");
    let log_path = root.join("sbproxy.log");

    // Same reserve-read-release acquisition as the test above, and the
    // same reason: the reservation has to be dropped for the child to
    // bind, which leaves a window where another process can take the
    // port. "Address in use" is a harness race and retries; any other
    // early exit is a real failure.
    let (mut child, port) = 'acquire: {
        for _ in 0..16 {
            let reservation =
                TcpListener::bind("0.0.0.0:0").expect("reserve ephemeral public port");
            let port = reservation.local_addr().expect("reserved address").port();
            drop(reservation);
            std::fs::write(
                &config,
                format!(
                    r#"proxy:
  http_bind_port: {port}
origins:
  "listener.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
                ),
            )
            .expect("write serve config");
            let stdout = std::fs::File::create(&log_path).expect("create serve log");
            let stderr = stdout.try_clone().expect("clone serve log");
            let mut child = Command::new(binary())
                .arg("serve")
                .arg(&config)
                .arg("--shutdown-grace-ms")
                .arg("0")
                .env_remove("SB_CONFIG_FILE")
                .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
                .env(
                    "SBPROXY_TEST_STARTUP_SIGNAL_HOLD_MS",
                    STARTUP_WINDOW_HOLD.as_millis().to_string(),
                )
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .expect("start sbproxy");
            // Connectable, deliberately: this is the state the other
            // test skips past. The kernel completes the handshake into
            // the listen backlog as soon as the socket is bound, so a
            // successful connect here means the bind is done and the
            // hold has begun.
            let bound_deadline = Instant::now() + Duration::from_secs(15);
            let bound = loop {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    break true;
                }
                if let Some(status) = child.try_wait().expect("poll startup") {
                    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                    let stolen = {
                        let lower = log.to_ascii_lowercase();
                        lower.contains("address") && lower.contains("use")
                    };
                    assert!(
                        stolen,
                        "sbproxy exited before the listener was bound: {status}; log={log}"
                    );
                    break false; // port was taken; retry on a fresh one
                }
                if Instant::now() >= bound_deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                    panic!("sbproxy never bound the public listener; log={log}");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if bound {
                break 'acquire (child, port);
            }
        }
        panic!("could not acquire a free public port for the proxy after 16 attempts");
    };

    // The precondition the whole test rests on, asserted rather than
    // assumed. Bound but not serving is the window; if the hold were
    // ignored (hook renamed, parse changed, delay moved after `run`) the
    // proxy would already be answering here, the SIGTERM below would
    // land on Pingora's handler, and the test would pass while proving
    // nothing. This is also why the test does not import the variable
    // name from the library: it verifies the effect, not the spelling.
    let window_entered_at = Instant::now();
    assert!(
        !serves_ok(port),
        "the startup hold did not take effect: the proxy was already serving, so this test \
         would have signalled Pingora's handler instead of the startup window"
    );

    let signal = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(signal.success(), "send SIGTERM to sbproxy");

    let shutdown_deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll shutdown") {
            break status;
        }
        if Instant::now() >= shutdown_deadline {
            let _ = child.kill();
            let _ = child.wait();
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("sbproxy ignored SIGTERM inside the startup window; log={log}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let elapsed = window_entered_at.elapsed();
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();

    // The assertion the ticket is about. Before the guard this was
    // `signal: 15`, the default disposition killing a process that had a
    // bound socket and no handler.
    assert!(
        status.success(),
        "SIGTERM inside the startup window exited {status}; log={log}"
    );
    // Exiting is not enough: a process that slept out the hold, started
    // serving, and only then honoured the signal would also exit 0. The
    // guard has to be what answered, so the exit must beat the hold.
    assert!(
        elapsed < STARTUP_WINDOW_HOLD,
        "exit took {elapsed:?}, which is past the {STARTUP_WINDOW_HOLD:?} hold, so the run loop \
         had started and Pingora handled the signal; log={log}"
    );
    // And name the seam, so a future refactor that routes this through
    // some other path has to say so.
    assert!(
        log.contains("before the run loop started"),
        "the startup guard did not log the shutdown it handled; log={log}"
    );

    let mut released = false;
    for _ in 0..20 {
        if TcpListener::bind(("0.0.0.0", port)).is_ok() {
            released = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        released,
        "a startup-window shutdown must release the bound public listener; log={log}"
    );
    let _ = std::fs::remove_dir_all(root);
}
