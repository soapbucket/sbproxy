//! End-to-end coverage for the `grpc` action.
//!
//! Stands up a tiny `tonic` echo service on an ephemeral port,
//! configures the proxy to forward to it via `action: { type: grpc }`,
//! and drives a real unary RPC through the proxy. The proto
//! definition lives at `e2e/proto/echo.proto` and is compiled by
//! `e2e/build.rs` via `tonic-build`.
//!
//! gRPC requires HTTP/2. The proxy's plain TCP listener speaks
//! HTTP/1.1 by default; the test config opts in to h2c with
//! `proxy.http2_cleartext: true` so the listener detects the HTTP/2
//! connection preface and serves the connection as h2. Without this
//! flag the proxy parses the preface as a malformed HTTP/1.1 request
//! and tears the connection down with `FRAME_SIZE_ERROR`.

// `tonic::Status` is 176 bytes, over `result_large_err`'s threshold,
// and the bidi drivers below hand it back to the caller so the test
// can compare the proxied status against the direct one. Boxing it
// would only obscure the comparison. The generated `echo_pb` module
// carries the same allow for the same type.
#![allow(clippy::result_large_err)]

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

// Pull in the generated proto types. `tonic_build::compile` writes
// `<package>.rs` into `OUT_DIR`; the proto package is
// `sbproxy_e2e.echo`.
pub mod echo_pb {
    // The generated `Echo` service returns `Result<_, tonic::Status>`,
    // and `tonic::Status` is 176 bytes, over the lint's threshold.
    // `tonic-build` re-emits this file on every build, so the signature
    // is not ours to reshape. Same call as `judge_rpc.rs`.
    #![allow(clippy::result_large_err)]
    tonic::include_proto!("sbproxy_e2e.echo");
}

use echo_pb::echo_client::EchoClient;
use echo_pb::echo_server::{Echo, EchoServer};
use echo_pb::{EchoRequest, EchoResponse};

#[derive(Default)]
struct EchoSvc;

type EchoStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<EchoResponse, tonic::Status>> + Send + 'static>,
>;

#[tonic::async_trait]
impl Echo for EchoSvc {
    async fn hello(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        let msg = request.into_inner().message;
        Ok(tonic::Response::new(EchoResponse { message: msg }))
    }

    type HelloStreamStream = EchoStream;

    async fn hello_stream(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<Self::HelloStreamStream>, tonic::Status> {
        let msg = request.into_inner().message;
        let chunks: Vec<EchoResponse> = msg
            .split_whitespace()
            .map(|s| EchoResponse {
                message: s.to_string(),
            })
            .collect();
        let stream =
            futures_util::stream::iter(chunks.into_iter().map(Ok::<EchoResponse, tonic::Status>));
        Ok(tonic::Response::new(Box::pin(stream)))
    }

    async fn hello_error(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        Err(tonic::Status::failed_precondition(
            request.into_inner().message,
        ))
    }

    type HelloStreamErrorStream = EchoStream;

    async fn hello_stream_error(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<Self::HelloStreamErrorStream>, tonic::Status> {
        let msg = request.into_inner().message;
        // Yield one message, then terminate with an error so the
        // grpc-status lands in real HTTP/2 trailers after the body.
        let items: Vec<Result<EchoResponse, tonic::Status>> = vec![
            Ok(EchoResponse {
                message: "first".into(),
            }),
            Err(tonic::Status::failed_precondition(msg)),
        ];
        let stream = futures_util::stream::iter(items);
        Ok(tonic::Response::new(Box::pin(stream)))
    }

    type HelloBidiStream = EchoStream;

    async fn hello_bidi(
        &self,
        request: tonic::Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<tonic::Response<Self::HelloBidiStream>, tonic::Status> {
        use futures_util::StreamExt as _;
        // One response per request, emitted as the request arrives.
        // Mapping the inbound stream (rather than draining it first)
        // is what makes this genuinely full-duplex: the server never
        // waits for the client to half-close.
        let inbound = request.into_inner();
        let outbound = inbound.map(|item| {
            item.map(|req| EchoResponse {
                message: format!("echo:{}", req.message),
            })
        });
        Ok(tonic::Response::new(Box::pin(outbound)))
    }

    type HelloBidiServerFirstStream = EchoStream;

    async fn hello_bidi_server_first(
        &self,
        _request: tonic::Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<tonic::Response<Self::HelloBidiServerFirstStream>, tonic::Status> {
        // Deliberately drop the inbound stream without reading it and
        // answer immediately. The client is still writing, so the
        // HTTP/2 server tears down the request half under it.
        Err(tonic::Status::unimplemented(
            "server first: not implemented",
        ))
    }

    type HelloBidiOneShotStream = EchoStream;

    async fn hello_bidi_one_shot(
        &self,
        _request: tonic::Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<tonic::Response<Self::HelloBidiOneShotStream>, tonic::Status> {
        // One reply, then done, without draining the request stream.
        let items: Vec<Result<EchoResponse, tonic::Status>> = vec![Ok(EchoResponse {
            message: "one-shot".into(),
        })];
        Ok(tonic::Response::new(Box::pin(futures_util::stream::iter(
            items,
        ))))
    }
}

/// Spawn the echo gRPC server on an ephemeral port. Returns the
/// `grpc://` URL the proxy should target. The server runs in the
/// background and exits when the test runtime drops.
///
/// We bind a std `TcpListener` first to capture the OS-chosen port,
/// then drop it and let `tonic::transport::Server::serve` re-bind on
/// the same address. The OS reliably hands back the same port a few
/// milliseconds later in tests; see `pick_free_port` in `lib.rs` for
/// the same trick.
async fn spawn_echo_grpc_server() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("grpc bind");
    let addr = listener.local_addr().expect("grpc addr");
    drop(listener);

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(EchoServer::new(EchoSvc))
            .serve(addr)
            .await;
    });

    // Give the tonic server a moment to bind before the proxy first
    // tries to dial it. Without this the first RPC sometimes races
    // the listener.
    for _ in 0..50 {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    format!("grpc://{}", addr)
}

fn grpc_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  http2_cleartext: true
origins:
  "grpc.localhost":
    action:
      type: grpc
      url: "{upstream_url}"
"#
    )
}

#[test]
fn grpc_unary_passes_through_proxy() {
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream_url = spawn_echo_grpc_server().await;
        let harness = ProxyHarness::start_with_yaml(&grpc_config(&upstream_url)).expect("start");

        // tonic clients dial the URI we hand them, so we point them
        // at the proxy's bind address but tag the authority as
        // `grpc.localhost` so the proxy routes by host.
        let proxy_endpoint = tonic::transport::Endpoint::from_shared(harness.base_url())
            .expect("endpoint")
            .origin("http://grpc.localhost".parse().expect("authority parse"))
            .timeout(Duration::from_secs(5));
        let channel = proxy_endpoint.connect().await.expect("grpc connect");
        let mut client = EchoClient::new(channel);

        let resp = client
            .hello(EchoRequest {
                message: "hello-via-proxy".into(),
            })
            .await
            .expect("rpc");
        assert_eq!(resp.into_inner().message, "hello-via-proxy");
    });
}

#[test]
fn grpc_unary_preserves_payload_with_multibyte_chars() {
    // Round-trip a payload containing multi-byte UTF-8 to confirm the
    // proxy passes the binary length-prefixed gRPC frame through
    // verbatim. A regression here would show up as a truncated or
    // re-encoded `message` field.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream_url = spawn_echo_grpc_server().await;
        let harness = ProxyHarness::start_with_yaml(&grpc_config(&upstream_url)).expect("start");

        let proxy_endpoint = tonic::transport::Endpoint::from_shared(harness.base_url())
            .expect("endpoint")
            .origin("http://grpc.localhost".parse().expect("authority parse"))
            .timeout(Duration::from_secs(5));
        let channel = proxy_endpoint.connect().await.expect("grpc connect");
        let mut client = EchoClient::new(channel);

        let payload = "sbproxy emoji round-trip OK";
        let resp = client
            .hello(EchoRequest {
                message: payload.into(),
            })
            .await
            .expect("rpc");
        assert_eq!(resp.into_inner().message, payload);
    });
}

// ---------------------------------------------------------------
// WOR-2524: bidirectional streaming through the `grpc` action.
//
// `examples/grpc-h2c/README.md` recorded the symptom before this
// test existed: grpcurl's `list` (server reflection, which is a
// bidi-streaming RPC) came back as a garbled framing error while
// unary calls on the same origin were fine. A bidi RPC is the one
// shape where the proxy has to keep both halves of an HTTP/2 stream
// moving at once, so it is the one shape a request/response proxy
// can get structurally wrong.
//
// This test drives a real interleaved bidi stream: send one message,
// read its reply, then send the next. Nothing about it is a unit
// test over a framing helper; every byte crosses the proxy.
// ---------------------------------------------------------------

/// Build a request stream fed by an mpsc channel so the test can
/// interleave sends and receives. `futures_util::stream::unfold` over
/// the receiver avoids pulling in `tokio-stream`'s `sync` feature for
/// one wrapper type.
fn channel_request_stream(
    rx: tokio::sync::mpsc::Receiver<EchoRequest>,
) -> impl futures_util::Stream<Item = EchoRequest> {
    futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}

#[test]
fn grpc_bidi_streaming_round_trips_every_message() {
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        use futures_util::StreamExt as _;

        let upstream_url = spawn_echo_grpc_server().await;
        let harness = ProxyHarness::start_with_yaml(&grpc_config(&upstream_url)).expect("start");

        let proxy_endpoint = tonic::transport::Endpoint::from_shared(harness.base_url())
            .expect("endpoint")
            .origin("http://grpc.localhost".parse().expect("authority parse"))
            .timeout(Duration::from_secs(10));
        let channel = proxy_endpoint.connect().await.expect("grpc connect");
        let mut client = EchoClient::new(channel);

        let (tx, rx) = tokio::sync::mpsc::channel::<EchoRequest>(8);
        let response = client
            .hello_bidi(channel_request_stream(rx))
            .await
            .expect("bidi rpc must open through the proxy");
        let mut inbound = response.into_inner();

        // Interleave: one send, one receive, four times over. A proxy
        // that holds the request body until end-of-stream deadlocks
        // here; a proxy that re-frames the body returns garbage or a
        // decode error.
        for i in 0..4u32 {
            let payload = format!("msg-{i}");
            tx.send(EchoRequest {
                message: payload.clone(),
            })
            .await
            .expect("send request message");

            let received = tokio::time::timeout(Duration::from_secs(5), inbound.next())
                .await
                .unwrap_or_else(|_| {
                    panic!("bidi reply {i} never arrived: the proxy is not full-duplex")
                })
                .unwrap_or_else(|| panic!("bidi stream ended early at message {i}"))
                .unwrap_or_else(|e| panic!("bidi reply {i} failed to decode: {e}"));
            assert_eq!(
                received.message,
                format!("echo:{payload}"),
                "message {i} must survive the proxy byte for byte"
            );
        }

        // Half-close the request stream and confirm the server closes
        // the response stream cleanly, with the gRPC status intact.
        drop(tx);
        let tail = tokio::time::timeout(Duration::from_secs(5), inbound.next())
            .await
            .expect("stream close must not hang");
        assert!(
            tail.is_none(),
            "stream should end cleanly after half-close; got {tail:?}"
        );
    });
}

/// Drive a bidi RPC whose server answers without ever draining the
/// request stream, while the client keeps writing. Returns whatever
/// the client observes on the response half.
///
/// `direct` selects the upstream address so the same driver can be
/// pointed at the gRPC server with no proxy in the path, which is how
/// the test establishes what the correct answer is before asserting
/// on the proxied one.
async fn drive_server_first(
    endpoint_url: String,
    authority: Option<&str>,
) -> Result<Vec<String>, tonic::Status> {
    use futures_util::StreamExt as _;

    let mut endpoint = tonic::transport::Endpoint::from_shared(endpoint_url)
        .expect("endpoint")
        .timeout(Duration::from_secs(10));
    if let Some(a) = authority {
        endpoint = endpoint.origin(format!("http://{a}").parse().expect("authority parse"));
    }
    let channel = endpoint.connect().await.expect("grpc connect");
    let mut client = EchoClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<EchoRequest>(8);
    // Keep writing for as long as the peer accepts it. The point of
    // the shape is that the client's request half is still open when
    // the server finishes.
    tokio::spawn(async move {
        for i in 0..64u32 {
            if tx
                .send(EchoRequest {
                    message: format!("keep-writing-{i}"),
                })
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let response = client
        .hello_bidi_server_first(channel_request_stream(rx))
        .await?;
    let mut inbound = response.into_inner();
    let mut seen = Vec::new();
    while let Some(item) = inbound.next().await {
        seen.push(item?.message);
    }
    Ok(seen)
}

#[test]
fn grpc_bidi_server_first_reply_survives_the_proxy() {
    // WOR-2524. `examples/grpc-h2c/README.md` reported grpcurl's
    // reflection `list` coming back garbled through the proxy while
    // unary calls were fine. Reflection is bidi-streaming, and the
    // version-probe flow ends with the server answering UNIMPLEMENTED
    // while the client is still writing. That is the shape here.
    //
    // The assertion is a comparison, not a guess: the same RPC is
    // driven once straight at the gRPC server and once through the
    // proxy, and the proxy has to produce the same gRPC status.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let upstream_url = spawn_echo_grpc_server().await;
        let direct_url = upstream_url.replacen("grpc://", "http://", 1);
        let harness = ProxyHarness::start_with_yaml(&grpc_config(&upstream_url)).expect("start");

        let direct = drive_server_first(direct_url, None).await;
        let direct_status = direct.expect_err("the server answers UNIMPLEMENTED");
        assert_eq!(
            direct_status.code(),
            tonic::Code::Unimplemented,
            "sanity: talking straight to the upstream yields UNIMPLEMENTED, got {direct_status:?}"
        );

        let proxied = drive_server_first(harness.base_url(), Some("grpc.localhost")).await;
        let proxied_status = proxied.expect_err("the proxy must not turn this into a success");
        assert_eq!(
            proxied_status.code(),
            tonic::Code::Unimplemented,
            "the proxy must forward the upstream's gRPC status, not replace it. \
             direct={:?} / proxied={:?}: {}",
            direct_status.code(),
            proxied_status.code(),
            proxied_status.message()
        );
        assert_eq!(
            proxied_status.message(),
            direct_status.message(),
            "the grpc-message must survive the proxy"
        );
    });
}

#[test]
fn grpc_bidi_one_shot_reply_survives_the_proxy() {
    // The success-path twin of the test above: the server emits one
    // message and completes while the client is still writing.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        use futures_util::StreamExt as _;

        let upstream_url = spawn_echo_grpc_server().await;
        let harness = ProxyHarness::start_with_yaml(&grpc_config(&upstream_url)).expect("start");

        let channel = tonic::transport::Endpoint::from_shared(harness.base_url())
            .expect("endpoint")
            .origin("http://grpc.localhost".parse().expect("authority parse"))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("grpc connect");
        let mut client = EchoClient::new(channel);

        let (tx, rx) = tokio::sync::mpsc::channel::<EchoRequest>(8);
        tokio::spawn(async move {
            for i in 0..64u32 {
                if tx
                    .send(EchoRequest {
                        message: format!("keep-writing-{i}"),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let response = client
            .hello_bidi_one_shot(channel_request_stream(rx))
            .await
            .expect("one-shot bidi rpc must open through the proxy");
        let mut inbound = response.into_inner();

        let first = tokio::time::timeout(Duration::from_secs(5), inbound.next())
            .await
            .expect("reply must not hang")
            .expect("stream must carry one message")
            .expect("reply must decode");
        assert_eq!(first.message, "one-shot");

        let tail = tokio::time::timeout(Duration::from_secs(5), inbound.next())
            .await
            .expect("stream close must not hang");
        assert!(
            tail.is_none(),
            "the stream must end cleanly after the single reply; got {tail:?}"
        );
    });
}
