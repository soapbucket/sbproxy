//! Multi-chunk request bodies through the gRPC transcode and gRPC-Web
//! buffers (WOR-2163).
//!
//! Both branches of `request_body_filter` hold the inbound body back
//! and re-emit a rewritten one at end-of-stream: the transcode branch
//! turns JSON into a length-prefixed gRPC frame, the gRPC-Web branch
//! de-frames the browser wire format into native gRPC. Pingora reads a
//! `None` body slot as end-of-body, so a chunk consumed mid-stream has
//! to leave an empty chunk behind. Both branches left `None`, which
//! closed the upstream request body on the first chunk: the gRPC
//! upstream then saw a request with no message frame at all, and the
//! rewritten body the proxy produced at end-of-stream was written after
//! the stream had already been ended.
//!
//! The payloads below are ~768 KiB, well past the 64 KiB the HTTP/1.1
//! reader hands out per call and past the h2 frame size, so every test
//! here drives the multi-chunk path. The filler is position dependent,
//! so a dropped, duplicated, or reordered range changes the bytes and
//! the echo comparison fails.

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use prost::Message as _;
use sbproxy_e2e::ProxyHarness;
use serde_json::json;

pub mod echo_pb {
    // The generated `Echo` service returns `Result<_, tonic::Status>`,
    // and `tonic::Status` is 176 bytes, over the lint's threshold.
    // `tonic-build` re-emits this file on every build, so the signature
    // is not ours to reshape. Same call as `judge_rpc.rs`.
    #![allow(clippy::result_large_err)]
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

    // WOR-2524 added three bidi RPCs to the shared proto so
    // `action_grpc.rs` could drive a real bidirectional stream through
    // the proxy. Every `Echo` impl in the suite has to satisfy the
    // trait; this file does not exercise them, so they answer
    // UNIMPLEMENTED rather than pretending to work.
    type HelloBidiStream = EchoStream;

    async fn hello_bidi(
        &self,
        _request: tonic::Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<tonic::Response<Self::HelloBidiStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("not exercised by this test"))
    }

    type HelloBidiServerFirstStream = EchoStream;

    async fn hello_bidi_server_first(
        &self,
        _request: tonic::Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<tonic::Response<Self::HelloBidiServerFirstStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("not exercised by this test"))
    }

    type HelloBidiOneShotStream = EchoStream;

    async fn hello_bidi_one_shot(
        &self,
        _request: tonic::Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<tonic::Response<Self::HelloBidiOneShotStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("not exercised by this test"))
    }
}

/// Spawn the Echo gRPC server on its own runtime in a background
/// thread and return the `grpc://` URL. The dedicated thread keeps the
/// test bodies synchronous so they can use the harness's blocking
/// helpers without starving the gRPC runtime.
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

/// Bytes the proxy must carry through the hold-and-re-emit buffer
/// without losing a range. Sized past the HTTP/1.1 reader's 64 KiB
/// buffer so the body arrives at `request_body_filter` in a dozen or
/// more chunks; the counter in the filler makes the content position
/// dependent, so a truncation or a reorder changes the compared bytes.
fn multi_chunk_message() -> String {
    const TARGET: usize = 768 * 1024;
    let mut filler = String::with_capacity(TARGET);
    let mut i: u64 = 0;
    while filler.len() < TARGET {
        filler.push_str(&format!("chunk-{i:08x}-"));
        i += 1;
    }
    filler
}

fn transcode_config(upstream_url: &str) -> String {
    let descriptor_set = env!("ECHO_DESCRIPTOR_SET");
    format!(
        r#"
proxy:
  http_bind_port: 0
  http2_cleartext: true
origins:
  "transcode.localhost":
    action:
      type: grpc
      url: "{upstream_url}"
      transcode:
        descriptor_set: "{descriptor_set}"
        routes:
          - method: POST
            path: /echo
            grpc_method: sbproxy_e2e.echo.Echo.Hello
            body: "*"
"#
    )
}

fn grpc_web_config(upstream_url: &str) -> String {
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

/// Payload of the first (message) frame of a gRPC-Web response body.
fn message_frame_payload(body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() >= 5,
        "response body is too short to be a gRPC-Web frame: {} bytes",
        body.len()
    );
    assert_eq!(body[0], 0, "the first frame must be a message frame");
    let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert!(
        body.len() >= 5 + msg_len,
        "message frame declares {msg_len} bytes but the body holds {}",
        body.len()
    );
    body[5..5 + msg_len].to_vec()
}

/// An h2c prior-knowledge client whose `resolve` override routes the
/// origin hostname at the proxy, so the `:authority` pseudo-header
/// carries the hostname the config matches on.
fn h2c_client(host: &str, port: u16) -> reqwest::blocking::Client {
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("proxy addr parses");
    reqwest::blocking::Client::builder()
        .http2_prior_knowledge()
        .resolve(host, proxy_addr)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("h2c client builds")
}

#[test]
fn transcode_multi_chunk_json_reaches_grpc_upstream_over_http1() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&transcode_config(&upstream)).expect("start");

    let message = multi_chunk_message();
    let resp = harness
        .post_json(
            "/echo",
            "transcode.localhost",
            &json!({ "message": message }),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 200,
        "a multi-chunk transcoded POST must succeed"
    );
    let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_else(|e| {
        panic!(
            "response is JSON: {e}; got {} bytes of body",
            resp.body.len()
        )
    });
    assert!(
        v["message"].as_str() == Some(message.as_str()),
        "the gRPC upstream must receive the whole transcoded body: sent {} bytes, echoed {:?}",
        message.len(),
        v["message"].as_str().map(str::len)
    );
}

#[test]
fn transcode_multi_chunk_json_reaches_grpc_upstream_over_http2() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&transcode_config(&upstream)).expect("start");

    let client = h2c_client("transcode.localhost", harness.port());
    let message = multi_chunk_message();
    let body = serde_json::to_vec(&json!({ "message": message })).expect("body serialises");

    let resp = client
        .post(format!(
            "http://transcode.localhost:{}/echo",
            harness.port()
        ))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .expect("send");

    let status = resp.status();
    let bytes = resp.bytes().expect("read response body");
    assert!(
        status.is_success(),
        "a multi-chunk transcoded h2c POST must succeed, got {status}: {}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(512)])
    );
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("response is JSON: {e}; got {} bytes of body", bytes.len()));
    assert!(
        v["message"].as_str() == Some(message.as_str()),
        "the gRPC upstream must receive the whole transcoded body: sent {} bytes, echoed {:?}",
        message.len(),
        v["message"].as_str().map(str::len)
    );
}

#[test]
fn grpc_web_multi_chunk_frame_reaches_grpc_upstream() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&grpc_web_config(&upstream)).expect("start");

    let message = multi_chunk_message();
    let req = EchoRequest {
        message: message.clone(),
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

    assert_eq!(
        resp.status, 200,
        "a multi-chunk gRPC-Web frame must bridge successfully"
    );
    let payload = message_frame_payload(&resp.body);
    let echoed = EchoResponse::decode(payload.as_slice()).expect("decode EchoResponse");
    assert!(
        echoed.message == message,
        "the gRPC upstream must receive the whole de-framed message: sent {} bytes, echoed {}",
        message.len(),
        echoed.message.len()
    );
}

#[test]
fn grpc_web_text_multi_chunk_frame_reaches_grpc_upstream() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&grpc_web_config(&upstream)).expect("start");

    let message = multi_chunk_message();
    let req = EchoRequest {
        message: message.clone(),
    };
    // The `-text` variant base64-encodes the whole framed body, so the
    // accumulated buffer has to be complete before it decodes at all.
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

    assert_eq!(
        resp.status, 200,
        "a multi-chunk gRPC-Web-text frame must bridge successfully"
    );
    let decoded = BASE64
        .decode(resp.body)
        .expect("response body is base64 for the -text variant");
    let payload = message_frame_payload(&decoded);
    let echoed = EchoResponse::decode(payload.as_slice()).expect("decode EchoResponse");
    assert!(
        echoed.message == message,
        "the gRPC upstream must receive the whole de-framed message: sent {} bytes, echoed {}",
        message.len(),
        echoed.message.len()
    );
}
