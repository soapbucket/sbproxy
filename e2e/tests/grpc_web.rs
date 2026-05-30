//! End-to-end coverage for the gRPC-Web bridge (WOR-819).
//!
//! Stands up the same tonic Echo service used by `action_grpc.rs` and
//! drives a browser-style gRPC-Web request (HTTP/1.1, length-prefixed
//! frame, `application/grpc-web+proto` or the base64 `-text` variant)
//! through the proxy with `grpc_web: true`. Asserts the response is a
//! gRPC-Web body: the message frame followed by a trailer frame carrying
//! `grpc-status: 0`.

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

/// Wrap protobuf bytes in a native gRPC length-prefixed frame
/// (1 compression byte + 4-byte big-endian length + message).
fn grpc_frame(proto: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8];
    f.extend_from_slice(&(proto.len() as u32).to_be_bytes());
    f.extend_from_slice(proto);
    f
}

/// Split a gRPC-Web response body into its first message frame payload
/// and the trailer-frame text. Panics if the framing is malformed.
fn split_message_and_trailer(body: &[u8]) -> (Vec<u8>, String) {
    assert!(body.len() >= 5, "body too short for a frame: {body:?}");
    let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    let msg = body[5..5 + msg_len].to_vec();
    let trailer_start = 5 + msg_len;
    assert_eq!(
        body[trailer_start], 0x80,
        "second frame must be the gRPC-Web trailer frame (flag 0x80)"
    );
    let trailer_payload = &body[trailer_start + 5..];
    (msg, String::from_utf8_lossy(trailer_payload).to_string())
}

#[test]
fn grpc_web_binary_unary_bridges_to_grpc() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream)).expect("start");

    let req = EchoRequest {
        message: "hi-grpcweb".into(),
    };
    let frame = grpc_frame(&req.encode_to_vec());

    let resp = harness
        .post_bytes(
            "/sbproxy_e2e.echo.Echo/Hello",
            "grpcweb.localhost",
            "application/grpc-web+proto",
            frame,
            &[],
        )
        .expect("post");

    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(ct.contains("grpc-web"), "response is gRPC-Web, got {ct}");

    let (msg_proto, trailer) = split_message_and_trailer(&resp.body);
    let echoed = EchoResponse::decode(msg_proto.as_slice()).expect("decode EchoResponse");
    assert_eq!(echoed.message, "hi-grpcweb");
    assert!(
        trailer.contains("grpc-status: 0"),
        "trailer frame carries grpc-status 0, got: {trailer}"
    );
}

#[test]
fn grpc_web_text_unary_bridges_to_grpc() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream)).expect("start");

    let req = EchoRequest {
        message: "hi-text".into(),
    };
    // The `-text` variant base64-encodes the whole framed body.
    let body = BASE64.encode(grpc_frame(&req.encode_to_vec())).into_bytes();

    let resp = harness
        .post_bytes(
            "/sbproxy_e2e.echo.Echo/Hello",
            "grpcweb.localhost",
            "application/grpc-web-text",
            body,
            &[],
        )
        .expect("post");

    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(
        ct.contains("grpc-web-text"),
        "text request gets a text response, got {ct}"
    );

    // The response body is base64; decode then parse the frames.
    let decoded = BASE64
        .decode(resp.body)
        .expect("response body is base64 for the -text variant");
    let (msg_proto, trailer) = split_message_and_trailer(&decoded);
    let echoed = EchoResponse::decode(msg_proto.as_slice()).expect("decode EchoResponse");
    assert_eq!(echoed.message, "hi-text");
    assert!(trailer.contains("grpc-status: 0"), "trailer: {trailer}");
}
