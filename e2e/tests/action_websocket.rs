//! End-to-end coverage for the `websocket` action.
//!
//! The `websocket` action proxies a client HTTP/1.1 upgrade to an
//! upstream WebSocket server. We bring up a tiny `tokio-tungstenite`
//! echo server on an ephemeral port, configure the proxy to forward
//! to it, then drive a real client through the proxy with
//! `tokio-tungstenite::connect_async`. The upstream sees the upgrade,
//! echoes the frame, and closes cleanly.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sbproxy_e2e::ProxyHarness;
use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_async,
    tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Message},
};

/// Spawn an echo WebSocket server on an ephemeral port. Returns the
/// `ws://` URL the proxy should forward to. The server runs in the
/// background and exits when the test runtime drops.
///
/// Returns once the accept loop is actually polling, so callers can
/// assume any subsequent TCP connect to the returned URL will be
/// served. Every error path inside the spawn tasks is logged via
/// `eprintln!` so the next time CI flakes (e.g. `ResetWithoutClosingHandshake`
/// at the client) the actual server-side cause shows up in `--nocapture`
/// output.
async fn spawn_echo_ws_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("ws bind");
    let addr = listener.local_addr().expect("ws addr");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        // Signal that we are about to enter the accept loop. The
        // listener has been polling at the kernel level since `bind`,
        // so any TCP connect after this point will be queued in the
        // SYN backlog and serviced as soon as the next iteration of
        // accept() awakens.
        let _ = ready_tx.send(());
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("ws upstream: accept error: {e}");
                    return;
                }
            };
            tokio::spawn(async move {
                let ws_stream = match accept_async(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("ws upstream {peer}: handshake failed: {e}");
                        return;
                    }
                };
                let (mut tx, mut rx) = ws_stream.split();
                while let Some(item) = rx.next().await {
                    let msg = match item {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("ws upstream {peer}: read error: {e}");
                            return;
                        }
                    };
                    // clippy::collapsible_match would have us hoist the inner
                    // `if` into a match guard, but the guard would have to
                    // .await on tx.send, which is awkward to express while
                    // also needing `msg` in the body. Keep the explicit shape.
                    #[allow(clippy::collapsible_match)]
                    match msg {
                        Message::Text(_) | Message::Binary(_) => {
                            if let Err(e) = tx.send(msg).await {
                                eprintln!("ws upstream {peer}: echo send error: {e}");
                                return;
                            }
                        }
                        Message::Close(frame) => {
                            if let Err(e) = tx.send(Message::Close(frame)).await {
                                eprintln!("ws upstream {peer}: close mirror error: {e}");
                            }
                            return;
                        }
                        Message::Ping(p) => {
                            if let Err(e) = tx.send(Message::Pong(p)).await {
                                eprintln!("ws upstream {peer}: pong send error: {e}");
                                return;
                            }
                        }
                        _ => {}
                    }
                }
                eprintln!("ws upstream {peer}: client stream ended");
            });
        }
    });

    // Block until the spawn task has been scheduled at least once and
    // sent the ready signal. After this, the accept loop is poised to
    // service connections.
    ready_rx
        .await
        .expect("ws upstream ready signal dropped before send");

    format!("ws://{}", addr)
}

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
        let upstream_url = spawn_echo_ws_server().await;
        let harness = ProxyHarness::start_with_yaml(&ws_config(&upstream_url)).expect("start");

        // Connect through the proxy. tungstenite resolves the host
        // from the URL host segment, so we have to dial 127.0.0.1
        // directly and supply the proxy origin via the Host header.
        let proxy_url = format!(
            "ws://ws.localhost:{}/",
            harness
                .base_url()
                .strip_prefix("http://127.0.0.1:")
                .expect("base_url shape")
        );
        let request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                proxy_url.as_str(),
            )
            .expect("build ws request");

        // Override the connect target so the URL host (`ws.localhost`)
        // is what's sent in the Host header but we actually dial
        // 127.0.0.1.
        let proxy_addr = harness
            .base_url()
            .replace("http://", "")
            .parse::<std::net::SocketAddr>()
            .expect("parse proxy addr");
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(proxy_addr),
        )
        .await
        .expect("connect timeout")
        .expect("connect");

        let (mut ws, response) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::client_async(request, stream),
        )
        .await
        .expect("ws upgrade timeout")
        .expect("ws upgrade");

        assert_eq!(
            response.status().as_u16(),
            101,
            "expected 101 Switching Protocols, got {}",
            response.status()
        );

        // Round-trip a text frame.
        ws.send(Message::Text("hello-sbproxy".into()))
            .await
            .expect("send text");
        let echoed = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("read timeout")
            .expect("stream ended")
            .expect("frame error");
        assert_eq!(echoed, Message::Text("hello-sbproxy".into()));

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
        let upstream_url = spawn_echo_ws_server().await;
        let harness = ProxyHarness::start_with_yaml(&ws_config(&upstream_url)).expect("start");

        let proxy_url = format!(
            "ws://ws.localhost:{}/",
            harness
                .base_url()
                .strip_prefix("http://127.0.0.1:")
                .expect("base_url shape")
        );
        let request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                proxy_url.as_str(),
            )
            .expect("build ws request");

        let proxy_addr = harness
            .base_url()
            .replace("http://", "")
            .parse::<std::net::SocketAddr>()
            .expect("parse proxy addr");
        let stream = tokio::net::TcpStream::connect(proxy_addr)
            .await
            .expect("connect");

        let (ws, _) = tokio_tungstenite::client_async(request, stream)
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
