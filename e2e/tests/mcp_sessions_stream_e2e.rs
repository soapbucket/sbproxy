//! MCP streamable HTTP sessions and the server-to-client stream.
//!
//! With `sessions.enabled` the gateway issues an `Mcp-Session-Id`
//! during `initialize`, requires it on every later request, answers
//! 404 for unknown or expired ids (the client's cue to
//! re-initialize), and ends a session on DELETE. Independently of
//! sessions, a GET with `Accept: text/event-stream` opens the
//! server-to-client stream, which pushes
//! `notifications/tools/list_changed` when the federated catalogue
//! actually changes. Notifications (id-less requests) answer 202.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

// --- Mock upstream whose catalogue can change between refreshes ---

struct MutableMcpUpstream {
    port: u16,
    grown: Arc<AtomicBool>,
    shutdown: Arc<Mutex<bool>>,
}

impl MutableMcpUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let grown = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Mutex::new(false));
        let grown_clone = grown.clone();
        let shutdown_clone = shutdown.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let grown = grown_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, &grown);
                });
            }
        });
        Self {
            port,
            grown,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    /// Grow the advertised catalogue; the next gateway refresh sees a
    /// changed contract and bumps the registry generation.
    fn grow(&self) {
        self.grown.store(true, Ordering::SeqCst);
    }
}

impl Drop for MutableMcpUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(stream: &mut TcpStream, grown: &AtomicBool) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut buf = [0u8; 4096];
    let mut total = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total.extend_from_slice(&buf[..n]);
        if let Some(idx) = find_double_crlf(&total) {
            let headers = &total[..idx];
            let len = parse_content_length(headers).unwrap_or(0);
            if total.len() >= idx + 4 + len {
                break;
            }
        }
    }
    let body_start = find_double_crlf(&total)
        .map(|i| i + 4)
        .unwrap_or(total.len());
    let body = &total[body_start..];
    let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let response_body = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": {"name": "mutable", "version": "1.0.0"}
            }
        }),
        "tools/list" => {
            let mut tools = vec![json!(
                {"name": "alpha", "description": "first tool", "inputSchema": {"type": "object"}}
            )];
            if grown.load(Ordering::SeqCst) {
                tools.push(json!(
                    {"name": "beta", "description": "late arrival", "inputSchema": {"type": "object"}}
                ));
            }
            json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}})
        }
        "resources/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"resources": []}}),
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "method not found"}
        }),
    };
    let body_bytes = serde_json::to_vec(&response_body).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&body_bytes)?;
    stream.flush()?;
    Ok(())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.split("\r\n") {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn sessions_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: gateway
        version: "1.0.0"
      refresh_interval: "1h"
      sessions:
        enabled: true
        ttl: "5m"
      federated_servers:
        - origin: "{upstream_url}"
          prefix: up
"#
    )
}

/// Full session lifecycle: issue on initialize, require on use,
/// DELETE to end, 404 after.
#[test]
fn session_lifecycle() {
    let upstream = MutableMcpUpstream::start();
    let harness = match ProxyHarness::start_with_yaml(&sessions_config(&upstream.url())) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping session_lifecycle: {e}");
            return;
        }
    };

    // initialize issues a session id.
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
    });
    let resp = harness
        .post_json("/", "mcp.localhost", &init, &[])
        .expect("initialize");
    assert_eq!(resp.status, 200);
    let session_id = resp
        .headers
        .get("mcp-session-id")
        .cloned()
        .expect("initialize must issue Mcp-Session-Id");
    assert!(!session_id.is_empty() && session_id.is_ascii());

    // A request without the header is a 400.
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &list, &[])
        .expect("send");
    assert_eq!(resp.status, 400, "missing session header must be a 400");

    // A bogus id is a 404 (re-initialize cue).
    let resp = harness
        .post_json(
            "/",
            "mcp.localhost",
            &list,
            &[("Mcp-Session-Id", "not-a-session")],
        )
        .expect("send");
    assert_eq!(resp.status, 404, "unknown session must be a 404");

    // The issued id works.
    let resp = harness
        .post_json(
            "/",
            "mcp.localhost",
            &list,
            &[("Mcp-Session-Id", session_id.as_str())],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    // Notifications answer 202 and also require the session.
    let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let resp = harness
        .post_json(
            "/",
            "mcp.localhost",
            &notif,
            &[("Mcp-Session-Id", session_id.as_str())],
        )
        .expect("send");
    assert_eq!(resp.status, 202, "notifications answer 202 Accepted");

    // DELETE ends the session; using it afterwards is a 404.
    let del = raw_request(
        harness.port(),
        &format!(
            "DELETE / HTTP/1.1\r\nHost: mcp.localhost\r\nMcp-Session-Id: {session_id}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(
        del.starts_with("HTTP/1.1 204"),
        "DELETE must end the session, got: {}",
        del.lines().next().unwrap_or("")
    );
    let resp = harness
        .post_json(
            "/",
            "mcp.localhost",
            &list,
            &[("Mcp-Session-Id", session_id.as_str())],
        )
        .expect("send");
    assert_eq!(resp.status, 404, "ended session must be a 404");
}

/// A sessionless gateway keeps answering 202 for notifications and
/// never demands a session header.
#[test]
fn stateless_gateway_answers_202_for_notifications() {
    let upstream = MutableMcpUpstream::start();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      refresh_interval: "1h"
      federated_servers:
        - origin: "{url}"
          prefix: up
"#,
        url = upstream.url()
    );
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping stateless_gateway_answers_202_for_notifications: {e}");
            return;
        }
    };
    let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let resp = harness
        .post_json("/", "mcp.localhost", &notif, &[])
        .expect("send");
    assert_eq!(resp.status, 202);
}

/// The server-to-client stream delivers tools/list_changed after the
/// upstream catalogue actually changes.
#[test]
fn stream_delivers_list_changed_on_catalogue_change() {
    let upstream = MutableMcpUpstream::start();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      refresh_interval: "1s"
      federated_servers:
        - origin: "{url}"
          prefix: up
"#,
        url = upstream.url()
    );
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping stream_delivers_list_changed_on_catalogue_change: {e}");
            return;
        }
    };

    // Prime the registry so the stream's baseline generation is set.
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &list, &[])
        .expect("prime");
    assert_eq!(resp.status, 200);

    // Open the stream, then change the upstream catalogue. The
    // background refresh (1s) picks it up and the stream must carry
    // the notification within a few polls.
    let mut stream = TcpStream::connect(("127.0.0.1", harness.port())).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: mcp.localhost\r\nAccept: text/event-stream\r\n\r\n",
        )
        .expect("send GET");

    upstream.grow();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut collected = String::new();
    let mut buf = [0u8; 2048];
    let saw_notification = loop {
        if Instant::now() > deadline {
            break false;
        }
        match stream.read(&mut buf) {
            Ok(0) => break false,
            Ok(n) => {
                collected.push_str(&String::from_utf8_lossy(&buf[..n]));
                if collected.contains("notifications/tools/list_changed") {
                    break true;
                }
            }
            // Read timeout between frames: keep waiting.
            Err(_) => continue,
        }
    };
    assert!(
        collected.contains("text/event-stream"),
        "stream response must be SSE, got: {collected}"
    );
    assert!(
        saw_notification,
        "stream must deliver tools/list_changed after a catalogue change; got: {collected}"
    );
}

/// Raw HTTP/1.1 exchange helper for methods the harness does not
/// wrap (DELETE).
fn raw_request(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).expect("write");
    let mut out = String::new();
    let mut buf = [0u8; 2048];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    out
}
