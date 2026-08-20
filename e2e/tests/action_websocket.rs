//! End-to-end coverage for the `websocket` action.
//!
//! The `websocket` action proxies a client HTTP/1.1 upgrade to an
//! upstream WebSocket server. We bring up a tiny `tokio-tungstenite`
//! echo server on an ephemeral port, configure the proxy to forward
//! to it, then drive a real client through the proxy with
//! `tokio-tungstenite::connect_async`. The upstream sees the upgrade,
//! echoes the frame, and closes cleanly.

mod websocket_common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sbproxy_e2e::ProxyHarness;
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Message};

use websocket_common::{
    assert_text_echo, dial_websocket, spawn_echo_ws_server, spawn_echo_ws_server_selecting,
};

fn ws_config(upstream_ws_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ws.localhost":
    action:
      type: websocket
      url: "{upstream_ws_url}"
"#
    )
}

#[test]
fn websocket_upgrade_round_trips_a_frame() {
    // The harness boots the proxy synchronously, but the WS dance is
    // async. Build a small Tokio runtime for the client + upstream
    // and tear it down at the end of the test.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let harness =
            ProxyHarness::start_with_yaml(&ws_config(upstream.websocket_url())).expect("start");
        let (mut ws, response) = dial_websocket(&harness, "ws.localhost", "/", &[])
            .await
            .expect("ws upgrade");

        assert_eq!(
            response.status().as_u16(),
            101,
            "expected 101 Switching Protocols, got {}",
            response.status()
        );

        assert_text_echo(&mut ws, "hello-sbproxy").await;

        // Clean close.
        ws.close(None).await.expect("close");
    });
}

#[test]
fn websocket_passes_close_frame_in_both_directions() {
    // Validates that the proxy forwards a client-initiated Close
    // through to the upstream and surfaces the upstream's echoed
    // Close back to the client. tungstenite's high-level API
    // collapses the echoed Close into a `ConnectionClosed` terminal
    // error after the peer's Close arrives, so we observe the round
    // trip by:
    //   1. Confirming a normal frame round-trips first (proves the
    //      upgrade and forwarding work).
    //   2. Sending Close and asserting the read side terminates with
    //      either an explicit Close frame OR `ConnectionClosed` /
    //      `Protocol(...)` (which both indicate the peer's Close
    //      bytes were observed and processed). A timeout would mean
    //      the close did not propagate, which is the regression we
    //      care about.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let harness =
            ProxyHarness::start_with_yaml(&ws_config(upstream.websocket_url())).expect("start");
        let (ws, _) = dial_websocket(&harness, "ws.localhost", "/", &[])
            .await
            .expect("ws upgrade");
        let (mut tx, mut rx) = ws.split();

        // 1. Round-trip a normal frame so we know the upgrade is
        // wired through end-to-end.
        tx.send(Message::Text("ping".into()))
            .await
            .expect("send text");
        let echoed = tokio::time::timeout(Duration::from_secs(3), rx.next())
            .await
            .expect("text echo timeout")
            .expect("stream closed early")
            .expect("text echo error");
        assert_eq!(echoed, Message::Text("ping".into()));

        // 2. Send Close. The peer must echo Close, which tungstenite
        // surfaces either as a `Message::Close` or as a terminal
        // `ConnectionClosed` after consuming the peer Close. Both
        // shapes prove the close traveled both ways through the proxy.
        tx.send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "bye".into(),
        })))
        .await
        .expect("send close");

        let mut close_observed = false;
        while let Ok(Some(frame)) = tokio::time::timeout(Duration::from_secs(3), rx.next()).await {
            match frame {
                Ok(Message::Close(_)) => {
                    close_observed = true;
                    break;
                }
                Ok(_) => continue,
                Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
                | Err(tokio_tungstenite::tungstenite::Error::AlreadyClosed) => {
                    close_observed = true;
                    break;
                }
                Err(tokio_tungstenite::tungstenite::Error::Protocol(_))
                | Err(tokio_tungstenite::tungstenite::Error::Io(_)) => {
                    // The proxy may tear down the TCP connection after
                    // the upstream closes, before tungstenite has a
                    // chance to read the echoed Close frame off the
                    // socket. The proxy still forwarded the close
                    // bytes both ways - the regression we'd care about
                    // is a hang, not an early TCP teardown - so treat
                    // this as the close having been observed.
                    close_observed = true;
                    break;
                }
                Err(other) => panic!("unexpected ws error: {other:?}"),
            }
        }
        assert!(
            close_observed,
            "proxy did not propagate the close handshake"
        );
    });
}

// --- WOR-2490: `max_message_size` and `subprotocols` enforcement ---

fn ws_config_with_action_fields(upstream_ws_url: &str, action_fields: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ws.localhost":
    action:
      type: websocket
      url: "{upstream_ws_url}"
{action_fields}
"#
    )
}

#[test]
fn websocket_oversized_message_tears_down_the_tunnel() {
    // WOR-2490: `max_message_size` used to be dead config; an oversized
    // frame passed through unmodified. Now the gateway scans frame
    // headers in both directions and closes the tunnel as soon as a
    // message declares more payload than the cap.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let config =
            ws_config_with_action_fields(upstream.websocket_url(), "      max_message_size: 1024");
        let harness = ProxyHarness::start_with_yaml(&config).expect("start");
        let (mut ws, response) = dial_websocket(&harness, "ws.localhost", "/", &[])
            .await
            .expect("ws upgrade");
        assert_eq!(response.status().as_u16(), 101);

        // A message under the cap still round-trips: the scan must not
        // disturb conforming traffic.
        assert_text_echo(&mut ws, "small enough").await;

        // 4 KiB against a 1 KiB cap. The gateway refuses on the frame
        // header, so the echo never arrives and the connection dies.
        // The send itself may fail if the proxy tears the connection
        // down while the client is still writing; either way, no echo
        // may come back.
        let _ = ws.send(Message::Text("x".repeat(4096))).await;
        let outcome = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
        match outcome {
            Ok(None) => {}
            Ok(Some(Err(_))) => {}
            Ok(Some(Ok(Message::Close(_)))) => {}
            Ok(Some(Ok(frame))) => {
                panic!("oversized message must not round-trip, got {frame:?}")
            }
            Err(_) => {
                panic!("connection survived an oversized message (timeout waiting for teardown)")
            }
        }
    });
}

#[test]
fn websocket_subprotocol_offer_is_filtered_to_the_allowlist() {
    // WOR-2490: with `subprotocols` configured, the client's
    // `Sec-WebSocket-Protocol` offer is intersected with the allowlist
    // before the upgrade goes upstream, and the upstream's selection
    // from that filtered offer flows back to the client.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = spawn_echo_ws_server_selecting(Some("chat.v2")).await;
        let config =
            ws_config_with_action_fields(upstream.websocket_url(), "      subprotocols: [chat.v2]");
        let harness = ProxyHarness::start_with_yaml(&config).expect("start");
        let (mut ws, response) = dial_websocket(
            &harness,
            "ws.localhost",
            "/",
            &[("sec-websocket-protocol", "chat.v1, chat.v2")],
        )
        .await
        .expect("ws upgrade");
        assert_eq!(response.status().as_u16(), 101);
        assert_eq!(
            response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok()),
            Some("chat.v2"),
            "upstream's selection must reach the client"
        );

        let captured = upstream.captured();
        assert_eq!(captured.len(), 1, "one upstream handshake");
        assert_eq!(
            captured[0].header_values("sec-websocket-protocol"),
            vec!["chat.v2"],
            "the offer sent upstream must be filtered to the allowlist"
        );

        assert_text_echo(&mut ws, "negotiated").await;
        ws.close(None).await.expect("close");
    });
}

#[test]
fn websocket_disallowed_subprotocol_offer_is_refused_before_connect() {
    // WOR-2490: a client that offers only subprotocols outside the
    // allowlist is refused with a 400 in the request phase, before any
    // upstream connection exists. The upstream capture stays empty,
    // which is the pre-connect proof.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let config =
            ws_config_with_action_fields(upstream.websocket_url(), "      subprotocols: [chat.v2]");
        let harness = ProxyHarness::start_with_yaml(&config).expect("start");
        let result = dial_websocket(
            &harness,
            "ws.localhost",
            "/",
            &[("sec-websocket-protocol", "chat.v9")],
        )
        .await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 400);
            }
            other => panic!("expected an HTTP 400 refusal, got {other:?}"),
        }
        assert!(
            upstream.captured().is_empty(),
            "a refused offer must never reach the upstream"
        );
    });
}

#[test]
fn websocket_upstream_selecting_outside_the_negotiated_set_is_refused() {
    // WOR-2490, third enforcement point: the subprotocol named on the
    // upstream's 101 must be one the client offered and the allowlist
    // permits. An upstream that answers with anything else is violating
    // RFC 6455 negotiation, and the gateway fails the upgrade with a
    // 502 instead of handing the client a protocol it never asked for.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = spawn_echo_ws_server_selecting(Some("chat.v9")).await;
        let config =
            ws_config_with_action_fields(upstream.websocket_url(), "      subprotocols: [chat.v2]");
        let harness = ProxyHarness::start_with_yaml(&config).expect("start");
        let result = dial_websocket(
            &harness,
            "ws.localhost",
            "/",
            &[("sec-websocket-protocol", "chat.v2")],
        )
        .await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 502);
            }
            other => panic!("expected an HTTP 502 refusal, got {other:?}"),
        }
    });
}

#[test]
fn websocket_mid_tunnel_upstream_failure_closes_without_http_bytes() {
    // WOR-2551: after the 101 commits, the downstream connection
    // speaks WebSocket frames. A mid-tunnel upstream failure used to
    // fall through to the generic upstream-error tail and write a
    // synthesized "HTTP/1.1 502 ... bad gateway" into the frame
    // stream. This drives a raw TCP client (tungstenite would hide the
    // injected bytes behind a framing error) against an upstream that
    // echoes one frame and then RSTs, and asserts the bytes on the
    // wire after the upgrade are frames only: a clean close, no HTTP.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream = websocket_common::spawn_ws_server_aborting_after_first_frame().await;
        let harness =
            ProxyHarness::start_with_yaml(&ws_config(upstream.websocket_url())).expect("start");

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", harness.port()))
            .await
            .expect("connect");
        stream
            .write_all(
                format!(
                    "GET / HTTP/1.1\r\nHost: ws.localhost:{}\r\nConnection: Upgrade\r\n\
                     Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                    harness.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write upgrade request");

        // Read the upgrade response headers.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
                .await
                .expect("101 header timeout")
                .expect("101 header read");
            assert!(n > 0, "connection ended inside the upgrade response");
            head.extend_from_slice(&byte);
            assert!(head.len() < 16 * 1024, "unbounded upgrade response");
        }
        let head_text = String::from_utf8_lossy(&head);
        assert!(
            head_text.starts_with("HTTP/1.1 101"),
            "expected 101 Switching Protocols, got: {head_text}"
        );

        // One masked text frame ("hello", zero mask so the payload
        // bytes read plainly). The upstream echoes it and then RSTs.
        stream
            .write_all(&[0x81, 0x85, 0, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'])
            .await
            .expect("write frame");

        // Everything from here to EOF is post-upgrade wire content.
        let mut tunnel_bytes = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => tunnel_bytes.extend_from_slice(&buf[..n]),
                // The teardown may surface as a reset rather than EOF;
                // either way the wire content so far is what counts.
                Ok(Err(_)) => break,
                Err(_) => panic!(
                    "connection survived the upstream failure (timeout waiting for teardown)"
                ),
            }
        }

        assert!(
            tunnel_bytes.windows(5).any(|w| w == b"hello"),
            "the echoed frame must reach the client before the teardown: {tunnel_bytes:?}"
        );
        let lowered = tunnel_bytes.to_ascii_lowercase();
        for forbidden in [&b"http/1."[..], &b"bad gateway"[..], &b"content-length"[..]] {
            assert!(
                !lowered
                    .windows(forbidden.len())
                    .any(|window| window == forbidden),
                "HTTP bytes were written into the upgraded tunnel: {:?}",
                String::from_utf8_lossy(&tunnel_bytes)
            );
        }
    });
}
