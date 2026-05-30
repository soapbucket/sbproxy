//! WOR-819 follow-ups: gRPC-Web server-streaming + trailer-status remap.
//!
//! Drives the server-streaming `HelloStream` and the partial-data-
//! then-error `HelloStreamError` RPCs through the gRPC-Web bridge.
//! Asserts:
//!
//! * Server-streaming bridges every message frame through the proxy
//!   (binary and base64-text variants), terminated by a gRPC-Web
//!   trailer frame carrying `grpc-status: 0`.
//! * A streaming RPC that errors after a partial body (real HTTP/2
//!   trailer status) reaches the gRPC-Web client as a trailer frame
//!   whose `grpc-status` and `grpc-message` carry the upstream's
//!   values, not the proxy's defaults.
//!
//! The trailers-only-in-headers error case (tonic's typical immediate-
//! error shape: HEADERS with END_STREAM + grpc-status) is a known
//! limitation: Pingora skips both `response_body_filter` and
//! `response_trailer_filter` for that response shape, so the proxy
//! has no hook to inject the trailer frame into the body. The
//! upstream's `grpc-status` and `grpc-message` headers still reach
//! the client untouched.

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use prost::Message as _;
use sbproxy_e2e::ProxyHarness;

pub mod echo_pb {
    tonic::include_proto!("sbproxy_e2e.echo");
}

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
        Ok(tonic::Response::new(EchoResponse {
            message: request.into_inner().message,
        }))
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
        let items: Vec<Result<EchoResponse, tonic::Status>> = vec![
            Ok(EchoResponse {
                message: "first".into(),
            }),
            Err(tonic::Status::failed_precondition(msg)),
        ];
        let stream = futures_util::stream::iter(items);
        Ok(tonic::Response::new(Box::pin(stream)))
    }
}

fn spawn_echo_grpc_server() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("grpc bind");
    let addr = listener.local_addr().expect("grpc addr");
    drop(listener);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("grpc rt");
        rt.block_on(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(EchoServer::new(EchoSvc))
                .serve(addr)
                .await;
        });
    });
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    format!("grpc://{}", addr)
}

fn config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "grpcweb.localhost":
    action:
      type: grpc
      url: "{upstream_url}"
      grpc_web: true
"#
    )
}

/// Wrap protobuf bytes in a native gRPC length-prefixed frame.
fn grpc_frame(proto: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8];
    f.extend_from_slice(&(proto.len() as u32).to_be_bytes());
    f.extend_from_slice(proto);
    f
}

/// Parse a gRPC-Web body into (message_payloads, trailer_text). The
/// final frame must be a trailer frame (high-bit set); preceding
/// frames are message payloads.
fn split_frames(body: &[u8]) -> (Vec<Vec<u8>>, String) {
    let mut messages = Vec::new();
    let mut trailer = String::new();
    let mut i = 0usize;
    while i + 5 <= body.len() {
        let flag = body[i];
        let len = u32::from_be_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]]) as usize;
        let payload = &body[i + 5..i + 5 + len];
        if flag & 0x80 != 0 {
            trailer = String::from_utf8_lossy(payload).to_string();
        } else {
            messages.push(payload.to_vec());
        }
        i += 5 + len;
    }
    (messages, trailer)
}

#[test]
fn grpc_web_binary_server_streaming_bridges_every_frame() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream)).expect("start");

    // "alpha beta gamma" → 3 streamed echo responses, each a separate
    // message frame, terminated by a gRPC-Web trailer frame.
    let req = EchoRequest {
        message: "alpha beta gamma".into(),
    };
    let frame = grpc_frame(&req.encode_to_vec());

    let resp = harness
        .post_bytes(
            "/sbproxy_e2e.echo.Echo/HelloStream",
            "grpcweb.localhost",
            "application/grpc-web+proto",
            frame,
            &[],
        )
        .expect("post");

    assert_eq!(resp.status, 200);
    let (messages, trailer) = split_frames(&resp.body);
    assert_eq!(
        messages.len(),
        3,
        "expected 3 streamed frames; got {messages:?}"
    );
    let decoded: Vec<String> = messages
        .iter()
        .map(|m| EchoResponse::decode(m.as_slice()).expect("decode").message)
        .collect();
    assert_eq!(decoded, vec!["alpha", "beta", "gamma"]);
    assert!(
        trailer.contains("grpc-status: 0"),
        "trailer carries success status; got: {trailer}"
    );
}

#[test]
fn grpc_web_text_server_streaming_bridges_every_frame() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream)).expect("start");

    let req = EchoRequest {
        message: "one two three four".into(),
    };
    let body = BASE64.encode(grpc_frame(&req.encode_to_vec())).into_bytes();

    let resp = harness
        .post_bytes(
            "/sbproxy_e2e.echo.Echo/HelloStream",
            "grpcweb.localhost",
            "application/grpc-web-text",
            body,
            &[],
        )
        .expect("post");

    assert_eq!(resp.status, 200);
    // -text variant: the full body is one base64 string.
    let decoded = BASE64
        .decode(resp.body)
        .expect("response body is base64 for the -text variant");
    let (messages, trailer) = split_frames(&decoded);
    assert_eq!(messages.len(), 4, "expected 4 streamed frames");
    let names: Vec<String> = messages
        .iter()
        .map(|m| EchoResponse::decode(m.as_slice()).expect("decode").message)
        .collect();
    assert_eq!(names, vec!["one", "two", "three", "four"]);
    assert!(trailer.contains("grpc-status: 0"), "trailer: {trailer}");
}

#[test]
fn grpc_web_streaming_error_after_partial_data_remaps_trailer() {
    // HelloStreamError yields one EchoResponse then closes the
    // stream with FAILED_PRECONDITION. The error rides on real
    // HTTP/2 trailers AFTER the body, which is exactly what the new
    // `response_trailer_filter` is wired to remap: it captures the
    // upstream trailer status and emits a gRPC-Web trailer frame
    // carrying the upstream's grpc-status + grpc-message.
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream)).expect("start");

    let req = EchoRequest {
        message: "boom-detail".into(),
    };
    let frame = grpc_frame(&req.encode_to_vec());

    let resp = harness
        .post_bytes(
            "/sbproxy_e2e.echo.Echo/HelloStreamError",
            "grpcweb.localhost",
            "application/grpc-web+proto",
            frame,
            &[],
        )
        .expect("post");

    // gRPC-Web carries the error in the trailer frame, not the HTTP
    // status line: HTTP 200 is correct.
    assert_eq!(resp.status, 200);
    let (messages, trailer) = split_frames(&resp.body);
    assert_eq!(
        messages.len(),
        1,
        "the one streamed message before the error should make it through; got {messages:?}"
    );
    let echoed = EchoResponse::decode(messages[0].as_slice()).expect("decode");
    assert_eq!(echoed.message, "first");
    // FAILED_PRECONDITION = 9 in the gRPC status enum.
    assert!(
        trailer.contains("grpc-status: 9"),
        "trailer status should be the upstream's FAILED_PRECONDITION (9); got: {trailer}"
    );
    assert!(
        trailer.contains("grpc-message: boom-detail"),
        "trailer message should propagate; got: {trailer}"
    );
}
