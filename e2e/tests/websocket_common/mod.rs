//! Shared WebSocket test server and client helpers.
//!
//! Each integration test compiles this module as a separate crate and uses a
//! different subset of the helpers.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sbproxy_e2e::ProxyHarness;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Request, Response},
        http::{HeaderName, HeaderValue},
        protocol::{frame::coding::CloseCode, CloseFrame, Message},
        Error as WebSocketError,
    },
    WebSocketStream,
};

/// The URI and headers observed by a completed upstream handshake.
#[derive(Clone, Debug)]
pub struct CapturedUpgrade {
    /// Origin-form or absolute request URI sent to the upstream.
    pub uri: String,
    headers: HashMap<String, Vec<String>>,
}

impl CapturedUpgrade {
    /// First value for a lowercased header name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    /// Every value for a lowercased header name.
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|values| values.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

/// Running echo server with a snapshot-based handshake capture.
pub struct EchoWebSocketServer {
    websocket_url: String,
    http_url: String,
    captured: Arc<Mutex<Vec<CapturedUpgrade>>>,
}

impl EchoWebSocketServer {
    /// `ws://` URL for a regular `websocket` action.
    pub fn websocket_url(&self) -> &str {
        &self.websocket_url
    }

    /// `http://` URL accepted by AI provider base-URL validation.
    pub fn http_url(&self) -> &str {
        &self.http_url
    }

    /// Snapshot the handshakes observed so far.
    pub fn captured(&self) -> Vec<CapturedUpgrade> {
        self.captured.lock().expect("capture mutex").clone()
    }
}

/// Concrete WebSocket stream returned by [`dial_websocket`].
pub type ClientWebSocket = WebSocketStream<TcpStream>;

/// Spawn a capture-enabled echo WebSocket server on an ephemeral port.
pub async fn spawn_echo_ws_server() -> EchoWebSocketServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("ws bind");
    let addr = listener.local_addr().expect("ws addr");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let task_captured = Arc::clone(&captured);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = ready_tx.send(());
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => {
                    eprintln!("ws upstream: accept error: {error}");
                    return;
                }
            };
            let connection_captured = Arc::clone(&task_captured);
            tokio::spawn(async move {
                // The Err type's size is tungstenite's ErrorResponse; the
                // callback signature is not ours to shrink.
                #[allow(clippy::result_large_err)]
                let callback = move |request: &Request, response: Response| {
                    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
                    for (name, value) in request.headers() {
                        headers
                            .entry(name.as_str().to_ascii_lowercase())
                            .or_default()
                            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
                    }
                    connection_captured
                        .lock()
                        .expect("capture mutex")
                        .push(CapturedUpgrade {
                            uri: request.uri().to_string(),
                            headers,
                        });
                    Ok(response)
                };
                let websocket = match accept_hdr_async(stream, callback).await {
                    Ok(websocket) => websocket,
                    Err(error) => {
                        eprintln!("ws upstream {peer}: handshake failed: {error}");
                        return;
                    }
                };
                let (mut tx, mut rx) = websocket.split();
                while let Some(item) = rx.next().await {
                    let message = match item {
                        Ok(message) => message,
                        Err(error) => {
                            eprintln!("ws upstream {peer}: read error: {error}");
                            return;
                        }
                    };
                    #[allow(clippy::collapsible_match)]
                    match message {
                        Message::Text(_) | Message::Binary(_) => {
                            if let Err(error) = tx.send(message).await {
                                eprintln!("ws upstream {peer}: echo send error: {error}");
                                return;
                            }
                        }
                        Message::Close(frame) => {
                            if let Err(error) = tx.send(Message::Close(frame)).await {
                                eprintln!("ws upstream {peer}: close mirror error: {error}");
                            }
                            return;
                        }
                        Message::Ping(payload) => {
                            if let Err(error) = tx.send(Message::Pong(payload)).await {
                                eprintln!("ws upstream {peer}: pong send error: {error}");
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

    ready_rx
        .await
        .expect("ws upstream ready signal dropped before send");
    EchoWebSocketServer {
        websocket_url: format!("ws://{addr}"),
        http_url: format!("http://{addr}"),
        captured,
    }
}

/// Dial a WebSocket origin through the proxy while connecting to loopback.
pub async fn dial_websocket(
    harness: &ProxyHarness,
    origin_host: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
) -> Result<
    (
        ClientWebSocket,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    WebSocketError,
> {
    let url = format!("ws://{origin_host}:{}{}", harness.port(), path_and_query);
    let mut request = url.into_client_request().expect("build ws request");
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("valid WebSocket header name");
        let value = HeaderValue::from_str(value).expect("valid WebSocket header value");
        request.headers_mut().append(name, value);
    }

    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", harness.port())),
    )
    .await
    .expect("connect timeout")
    .expect("connect");
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async(request, stream),
    )
    .await
    .expect("ws upgrade timeout")
}

/// Send a text frame and require the same frame back before the timeout.
pub async fn assert_text_echo(websocket: &mut ClientWebSocket, text: &str) {
    websocket
        .send(Message::Text(text.to_string()))
        .await
        .expect("send text");
    let echoed = tokio::time::timeout(Duration::from_secs(3), websocket.next())
        .await
        .expect("read timeout")
        .expect("stream ended")
        .expect("frame error");
    assert_eq!(echoed, Message::Text(text.to_string()));
}

/// Require a client-initiated close to terminate without hanging.
pub async fn assert_clean_close(websocket: &mut ClientWebSocket) {
    websocket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "done".into(),
        })))
        .await
        .expect("send close");

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match websocket.next().await {
                Some(Ok(Message::Close(_))) | None => return,
                Some(Ok(_)) => {}
                Some(Err(
                    WebSocketError::ConnectionClosed
                    | WebSocketError::AlreadyClosed
                    | WebSocketError::Protocol(_)
                    | WebSocketError::Io(_),
                )) => return,
                Some(Err(other)) => panic!("unexpected close error: {other:?}"),
            }
        }
    })
    .await
    .expect("close round-trip timeout");
}
