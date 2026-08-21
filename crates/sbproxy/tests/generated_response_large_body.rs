// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! A response sbproxy writes itself must survive a large request body.
//!
//! WOR-2599. `type: mock`, `type: static`, and every policy denial answer
//! during the request phase, before the client's body has been read. The
//! socket then carries unread bytes when the session ends, and closing a
//! socket in that state makes the kernel send a TCP RST instead of a FIN.
//! An RST discards whatever the peer had buffered but not yet read, which
//! includes the response that was just written, so the client sees a reset
//! mid-response rather than the 200 it was sent.
//!
//! This only bites above a socket buffer's worth of body, which is why the
//! reported threshold was "roughly 70 KB": under that the whole exchange
//! completes before the close.
//!
//! These tests drive the real binary over a raw socket because nothing
//! below the wire can see the difference. A `reqwest`-level test would
//! report the same failure but could not distinguish a truncated body from
//! a reset connection, and an in-process `handle_action` test never reaches
//! the session teardown where the close happens.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A body past the loopback socket buffer, so the server's close and the
/// client's send overlap. Measured against the unfixed binary: a `type:
/// mock` origin answered 20 of 20 at 32 KiB and 0 of 20 at 70 KiB, 73 KiB,
/// 76 KiB, and 128 KiB.
const LARGE_MOCK_BODY_BYTES: usize = 128 * 1024;

/// The same measurement for `type: static`, which has always declared
/// `Content-Length` and so survives much further: 20 of 20 up to 512 KiB,
/// 16 of 20 at 1 MiB, 0 of 20 at 4 MiB. 4 MiB is the first size that
/// fails outright.
const LARGE_STATIC_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Repeat count per size. Both sizes above failed on every attempt on the
/// host these numbers came from, so one request would be enough there. The
/// repeats are for everywhere else: this is a race between the server's
/// close and the client's read, and the margin depends on socket buffer
/// sizes that differ per host and per kernel setting. The 1 MiB static row
/// above (16 of 20) is what the middle of that range looks like, and a
/// single-shot test sitting in that band would pass four times in five. A
/// dozen draws turns a defect that reproduces even a third of the time
/// into a sub-1% chance of a green run, and still costs well under a
/// second.
const REPEATS: usize = 12;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-generated-response-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

/// The outcome of one exchange, in the terms that matter here.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// A complete, correctly framed response arrived.
    Complete,
    /// The exchange died at the OS level, carrying the errno description.
    Reset(String),
    /// A response arrived but its body was short of what it declared.
    Truncated,
    /// A response arrived with an unexpected status line.
    Status(String),
}

/// One complete HTTP/1.1 POST exchange on a fresh connection.
///
/// Framing is honored the way a real client honors it: stop at
/// `Content-Length` when the response declares one, read to EOF when it
/// does not. That distinction is half the bug. A close-delimited response
/// gives the client no way to tell a finished body from a killed
/// connection, which is why the mock path failed at 70 KiB while the
/// static path, which does send `Content-Length`, survived to 512 KiB.
fn post(port: u16, host: &str, body: &[u8]) -> Outcome {
    let mut stream = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(e) => return Outcome::Reset(format!("connect: {e}")),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    if let Err(e) = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
    {
        return Outcome::Reset(format!("send: {e}"));
    }

    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    // Read at least the header block.
    let header_end = loop {
        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break idx + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Outcome::Reset("eof before response headers".to_string()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Outcome::Reset(format!("recv headers: {e}")),
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let status_line = headers.lines().next().unwrap_or_default().to_string();
    if !status_line.starts_with("HTTP/1.1 200") {
        return Outcome::Status(status_line);
    }
    let declared_len = headers
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| value.trim().parse::<usize>().ok());

    match declared_len {
        Some(len) => {
            while buf.len() - header_end < len {
                match stream.read(&mut chunk) {
                    Ok(0) => return Outcome::Truncated,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return Outcome::Reset(format!("recv body: {e}")),
                }
            }
        }
        None => loop {
            // Close-delimited: the only end-of-body signal is a clean EOF,
            // so a reset here is indistinguishable from a short body.
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Outcome::Reset(format!("recv body: {e}")),
            }
        },
    }

    if buf[header_end..].windows(8).any(|w| w == b"wor-2599") {
        Outcome::Complete
    } else {
        Outcome::Truncated
    }
}

/// Whether the proxy is serving, not merely listening.
fn serves(port: u16, host: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }
    if stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    // Any 2xx: the origins under test answer 200 and 204, and this only
    // has to prove the run loop is up rather than merely bound.
    response.starts_with(b"HTTP/1.1 2")
}

/// Start the proxy on a free ephemeral port.
///
/// Reserving a port, reading its number, and dropping the reservation so
/// the child can bind it leaves a TOCTOU window: under parallel test load
/// something else can take the port first and the child exits with
/// "address in use". That is a harness race and gets another port. Any
/// other early exit is a real startup failure and fails immediately with
/// the child's stderr, so a broken config cannot masquerade as sixteen
/// lost port races.
fn start_proxy(root: &Path, config_body: &dyn Fn(u16) -> String, host: &str) -> (Child, u16) {
    for _ in 0..16 {
        let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral port");
        let port = reserved.local_addr().expect("reserved address").port();
        drop(reserved);

        let config = root.join("sb.yml");
        std::fs::write(&config, config_body(port)).expect("write config");
        let mut child = Command::new(binary())
            .arg("serve")
            .arg(&config)
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
                let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                assert!(
                    stderr.contains("address already in use") || stderr.contains("address in use"),
                    "sbproxy exited during startup for a reason other than a lost port race: \
                     {stderr}"
                );
                break;
            }
            if serves(port, host) {
                return (child, port);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sbproxy did not start serving on port {port}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    panic!("could not acquire a free port for sbproxy after 16 attempts");
}

fn mock_config(port: u16) -> String {
    format!(
        r#"proxy:
  http_bind_port: {port}
origins:
  "mock.test":
    action:
      type: mock
      status: 200
      body:
        marker: "wor-2599"
"#
    )
}

fn mock_204_config(port: u16) -> String {
    format!(
        r#"proxy:
  http_bind_port: {port}
origins:
  "mock.test":
    action:
      type: mock
      status: 204
      body:
        marker: "wor-2599"
"#
    )
}

fn static_config(port: u16) -> String {
    format!(
        r#"proxy:
  http_bind_port: {port}
origins:
  "static.test":
    action:
      type: static
      status: 200
      content_type: application/json
      body: '{{"marker":"wor-2599"}}'
"#
    )
}

/// WOR-2599 as reported: a `type: mock` origin answered a 128 KiB POST
/// with a reset connection instead of its body.
///
/// This is the ticket's own repro and it is red against `main`, but it is
/// the framing half of the fix that carries it: with `Content-Length`
/// declared and the drain removed, 128 KiB is back inside the band
/// `type: static` already survived, and this passes. The drain is pinned
/// by `a_slowly_sent_body_is_read_to_the_end_rather_than_cut_off` and by
/// the two 4 MiB cases, all three of which stay red without it. Keep this
/// one anyway: it is the exact shape an operator reported, and a
/// regression in either half brings it back.
#[test]
fn mock_origin_answers_a_large_request_body() {
    let root = temp_dir("mock");
    let (mut child, port) = start_proxy(&root, &mock_config, "mock.test");

    let body = large_json_body();
    let mut failures = Vec::new();
    for attempt in 0..REPEATS {
        match post(port, "mock.test", &body) {
            Outcome::Complete => {}
            other => failures.push(format!("attempt {attempt}: {other:?}")),
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    let sent = body.len();
    assert!(
        failures.is_empty(),
        "a {sent}-byte POST to a type: mock origin must get its response back, \
         not a reset connection: {failures:#?}"
    );
}

/// Fetch one response over a `Connection: close` exchange and return the
/// raw bytes. Nothing here panics, so the caller can shut the proxy down
/// before it asserts.
fn fetch(port: u16, method: &str, host: &str) -> Result<Vec<u8>, String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    stream
        .write_all(
            format!("{method} / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .map_err(|e| format!("write: {e}"))?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    Ok(response)
}

/// Split a raw response into its lowercased header block and body length.
fn split_response(response: &[u8]) -> Result<(String, usize), String> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "response has no header block".to_string())?;
    let headers = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    Ok((headers, response.len() - (split + 4)))
}

/// A mock response must be self-delimiting. Without `Content-Length` the
/// body is close-delimited, and a client cannot then tell a complete body
/// from a connection that died mid-response. Every other generated-body
/// arm (`static`, `echo`, `beacon`) declares its length.
#[test]
fn mock_origin_declares_its_content_length() {
    let root = temp_dir("mock-framing");
    let (mut child, port) = start_proxy(&root, &mock_config, "mock.test");

    let fetched = fetch(port, "GET", "mock.test");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    let response = fetched.expect("fetch the mock response");
    let (headers, body_len) = split_response(&response).expect("parse the mock response");
    let declared = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok());

    // Declaring a length is the point, but declaring the wrong one is
    // worse than declaring none: the client would either truncate the
    // body or block waiting for bytes that are never coming.
    assert_eq!(
        declared,
        Some(body_len),
        "a mock response must declare its own body length so the body is not close-delimited: \
         {headers}"
    );
}

/// The drain itself, pinned without depending on a socket buffer size.
///
/// Every other test here needs a body big enough that the server's close
/// races the client's send, and where that threshold sits depends on the
/// host's socket buffers: on a box with large enough buffers a 4 MiB body
/// lands entirely in kernel memory, the write never blocks, and nothing
/// races. This one makes the overlap explicit instead of buying it with
/// volume. The client spends about a third of a second dribbling its body
/// out in chunks, which is far longer than the microseconds the mock arm
/// needs to answer, so the server is guaranteed to have responded and
/// moved on while the client is still writing.
///
/// Without the drain the session is torn down as soon as the response is
/// written, and the next chunk lands on a dead socket: `EPIPE`, or
/// `ECONNRESET` once the peer's RST arrives. With the drain the server
/// keeps reading until the body is done, and every chunk is accepted.
/// A body this small proves nothing on its own; the pacing is the test.
#[test]
fn a_slowly_sent_body_is_read_to_the_end_rather_than_cut_off() {
    let root = temp_dir("slow-body");
    let (mut child, port) = start_proxy(&root, &mock_config, "mock.test");

    const CHUNKS: usize = 16;
    const CHUNK_BYTES: usize = 16 * 1024;
    const PACE: Duration = Duration::from_millis(20);

    let outcome = (|| -> Result<(), String> {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

        let declared = CHUNKS * CHUNK_BYTES;
        let head = format!(
            "POST / HTTP/1.1\r\nHost: mock.test\r\nContent-Type: application/json\r\n\
             Content-Length: {declared}\r\n\r\n"
        );
        stream
            .write_all(head.as_bytes())
            .map_err(|e| format!("send headers: {e}"))?;

        let chunk = vec![b'x'; CHUNK_BYTES];
        for i in 0..CHUNKS {
            std::thread::sleep(PACE);
            stream
                .write_all(&chunk)
                .map_err(|e| format!("send chunk {i} of {CHUNKS}: {e}"))?;
        }
        Ok(())
    })();

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        outcome,
        Ok(()),
        "the server must keep reading a body that is still arriving after it answered, rather \
         than closing under the client mid-upload"
    );
}

/// The exception to the rule above. A 204 carries no body, Pingora writes
/// none, and RFC 9110 section 8.6 forbids `Content-Length` on one, so the
/// length that fixes the 200 case must not appear here. Mocking a
/// `DELETE -> 204` is ordinary, and `body` defaults to JSON `null` rather
/// than to nothing, so this is reachable without configuring a body.
#[test]
fn a_204_mock_declares_no_content_length() {
    let root = temp_dir("mock-204");
    let (mut child, port) = start_proxy(&root, &mock_204_config, "mock.test");

    let fetched = fetch(port, "DELETE", "mock.test");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    let response = fetched.expect("fetch the 204");
    let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(
        response.starts_with("http/1.1 204"),
        "expected the configured 204: {response}"
    );
    assert!(
        !response.contains("content-length:"),
        "a 204 must not declare a content length: {response}"
    );
}

/// The third generated-body arm. A beacon pixel is far too small to reach
/// the large-body race, but without a declared length its body is
/// close-delimited, so every tracking pixel costs a whole connection and
/// the client cannot tell a complete pixel from a killed connection.
#[test]
fn beacon_origin_declares_its_content_length() {
    let root = temp_dir("beacon");
    let config = |port: u16| {
        format!(
            r#"proxy:
  http_bind_port: {port}
origins:
  "beacon.test":
    action:
      type: beacon
"#
        )
    };
    let (mut child, port) = start_proxy(&root, &config, "beacon.test");

    let fetched = fetch(port, "GET", "beacon.test");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    let response = fetched.expect("fetch the beacon");
    let (headers, body_len) = split_response(&response).expect("parse the beacon response");
    let declared = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok());

    assert_eq!(
        declared,
        Some(body_len),
        "a beacon response must declare the pixel's length: {headers}"
    );
}

/// The same defect on the `type: static` path. It declares `Content-Length`
/// so it survives far longer, but the undrained body still resets the
/// connection once the client is still sending when the close lands.
#[test]
fn static_origin_answers_a_large_request_body() {
    let root = temp_dir("static");
    let (mut child, port) = start_proxy(&root, &static_config, "static.test");

    let body = vec![b'x'; LARGE_STATIC_BODY_BYTES];
    let mut failures = Vec::new();
    for attempt in 0..REPEATS {
        match post(port, "static.test", &body) {
            Outcome::Complete => {}
            other => failures.push(format!("attempt {attempt}: {other:?}")),
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        failures.is_empty(),
        "a {LARGE_STATIC_BODY_BYTES}-byte POST to a type: static origin must get its \
         response back, not a reset connection: {failures:#?}"
    );
}

/// The same defect on the error path, which is the one that bites in
/// production. `fail_to_proxy` answers 502 for an upstream that could not
/// be reached, and an upstream that was never reached never consumed the
/// request body either, so the connection closes with the client's upload
/// still queued. Measured on the unfixed binary: 15 of 15 attempts at
/// 4 MiB died with "broken pipe" while the client was still sending, and
/// the 502 the gateway had already written was never delivered.
#[test]
fn a_failed_upstream_still_delivers_its_error_for_a_large_request_body() {
    let root = temp_dir("dead-upstream");
    // A port nothing is listening on, so `upstream_peer` connects and is
    // refused before any of the body has gone anywhere.
    let dead = TcpListener::bind("127.0.0.1:0").expect("reserve a dead port");
    let dead_port = dead.local_addr().expect("dead address").port();
    drop(dead);

    let config = |port: u16| {
        format!(
            r#"proxy:
  http_bind_port: {port}
  extensions:
    upstream:
      allow_private_cidrs:
        - 127.0.0.0/8
origins:
  "mock.test":
    action:
      type: mock
      status: 200
      body:
        marker: "wor-2599"
  "dead.test":
    action:
      type: proxy
      url: http://127.0.0.1:{dead_port}
"#
        )
    };
    // The readiness probe needs an origin that answers, so the config
    // carries the mock origin purely to let `start_proxy` confirm the run
    // loop is up before the dead-upstream requests start.
    let (mut child, port) = start_proxy(&root, &config, "mock.test");

    let body = vec![b'x'; LARGE_STATIC_BODY_BYTES];
    let mut failures = Vec::new();
    for attempt in 0..REPEATS {
        match post(port, "dead.test", &body) {
            // 502 is the correct answer here. What matters is that it
            // arrives at all rather than being destroyed by the reset.
            Outcome::Status(line) if line.starts_with("HTTP/1.1 502") => {}
            Outcome::Complete => failures.push(format!(
                "attempt {attempt}: a dead upstream must not answer 200"
            )),
            other => failures.push(format!("attempt {attempt}: {other:?}")),
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        failures.is_empty(),
        "a {LARGE_STATIC_BODY_BYTES}-byte POST to a dead upstream must get the 502 back, \
         not a reset connection: {failures:#?}"
    );
}

/// A small body is the control. It fits inside a socket buffer, so the
/// exchange finishes before the close either way, and this must pass both
/// before and after the fix. If it ever fails, the harness is broken
/// rather than the drain.
#[test]
fn mock_origin_answers_a_small_request_body() {
    let root = temp_dir("mock-small");
    let (mut child, port) = start_proxy(&root, &mock_config, "mock.test");

    let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#.to_vec();
    let mut failures = Vec::new();
    for attempt in 0..REPEATS {
        match post(port, "mock.test", &body) {
            Outcome::Complete => {}
            other => failures.push(format!("attempt {attempt}: {other:?}")),
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        failures.is_empty(),
        "small-body control failed: {failures:#?}"
    );
}

fn large_json_body() -> Vec<u8> {
    let filler = "x".repeat(LARGE_MOCK_BODY_BYTES);
    format!(r#"{{"model":"local-demo","messages":[{{"role":"user","content":"{filler}"}}]}}"#)
        .into_bytes()
}
