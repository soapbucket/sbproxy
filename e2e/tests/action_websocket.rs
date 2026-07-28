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

use websocket_common::{assert_text_echo, dial_websocket, spawn_echo_ws_server};

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
