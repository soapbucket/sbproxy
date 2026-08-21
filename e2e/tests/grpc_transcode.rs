//! End-to-end coverage for REST <-> gRPC transcoding (WOR-819).
//!
//! Stands up the same tiny `tonic` Echo service used by
//! `action_grpc.rs`, but instead of driving a native gRPC client
//! through the proxy, it configures the `grpc` action with a
//! `transcode` block and sends a plain HTTP/JSON `POST`. The proxy
//! decodes the JSON into the `Hello` request message, calls the gRPC
//! upstream, and translates the gRPC response back to JSON.
//!
//! The protobuf `FileDescriptorSet` the transcoder needs is emitted by
//! `e2e/build.rs` (`file_descriptor_set_path`) and its path is handed
//! to the test through the `ECHO_DESCRIPTOR_SET` env var.

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;
use serde_json::json;

// Pull in the generated proto types. `tonic_build` writes
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

use echo_pb::echo_server::{Echo, EchoServer};
use echo_pb::{EchoRequest, EchoResponse};

/// Request message that makes the stub Echo upstream report the
/// `grpc-accept-encoding` it was called with rather than echo.
const ACCEPT_ENCODING_PROBE: &str = "__report_grpc_accept_encoding";

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
        // A caller asking for this exact message gets the request's
        // `grpc-accept-encoding` back instead of an echo. It is the only
        // way a test on the REST side of the transcoder can see a header
        // the proxy adds on the gRPC side, and that header is what stops
        // the upstream from compressing a frame the transcoder cannot
        // read. Any other message echoes as usual.
        let accept_encoding = request
            .metadata()
            .get("grpc-accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<absent>")
            .to_string();
        let msg = request.into_inner().message;
        if msg == ACCEPT_ENCODING_PROBE {
            return Ok(tonic::Response::new(EchoResponse {
                message: accept_encoding,
            }));
        }
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
/// thread and return the `grpc://` URL. Running the server on a
/// dedicated thread keeps the test body synchronous so it can use the
/// harness's blocking `post_json` helper without starving the gRPC
/// runtime.
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

    // Wait for the listener to bind before the proxy first dials it.
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    format!("grpc://{}", addr)
}

fn transcode_config(upstream_url: &str) -> String {
    let descriptor_set = env!("ECHO_DESCRIPTOR_SET");
    format!(
        r#"
proxy:
  http_bind_port: 0
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
          - method: POST
            path: /echo-error
            grpc_method: sbproxy_e2e.echo.Echo.HelloError
            body: "*"
"#
    )
}

#[test]
fn rest_json_transcodes_to_grpc_and_back() {
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&transcode_config(&upstream)).expect("start");

    let resp = harness
        .post_json(
            "/echo",
            "transcode.localhost",
            &json!({ "message": "hi-transcode" }),
            &[],
        )
        .expect("post");

    assert_eq!(resp.status, 200, "transcoded REST call returns 200");
    let v: serde_json::Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("response is JSON: {e}; body={:?}", resp.body));
    assert_eq!(
        v["message"], "hi-transcode",
        "the gRPC reply is translated back to JSON unchanged"
    );
}

#[test]
fn unmapped_path_is_not_transcoded() {
    // A path with no matching transcode route must not be silently
    // routed to the Echo method. The proxy should reject it rather than
    // fabricate a gRPC call, so the caller gets a non-2xx.
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&transcode_config(&upstream)).expect("start");

    let resp = harness
        .post_json(
            "/not-a-route",
            "transcode.localhost",
            &json!({ "message": "nope" }),
            &[],
        )
        .expect("post");

    assert!(
        resp.status >= 400,
        "an unmapped path must not transcode; got {}",
        resp.status
    );
}

#[test]
fn the_transcoded_request_advertises_identity_message_encoding() {
    // The proxy decodes the response frame itself to build JSON, and it
    // can decode exactly one message encoding. A gRPC server compresses
    // only what its caller says it can read, so the caller has to say so;
    // sending nothing leaves a server free to gzip a frame the transcoder
    // then refuses. This asserts the header on the wire the upstream
    // actually received, not the intent at the call site.
    //
    // The REST client deliberately sends its own `grpc-accept-encoding:
    // gzip`. Overriding it is half the claim: on this hop the proxy is
    // the gRPC client, not a forwarder, so what the caller can read says
    // nothing about what the transcoder can read. A probe that sent no
    // header would pass against an implementation that merely defaulted
    // the value when absent and forwarded a client's `gzip` untouched,
    // which is the bug wearing the fix's clothes.
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&transcode_config(&upstream)).expect("start");

    let resp = harness
        .post_json(
            "/echo",
            "transcode.localhost",
            &json!({ "message": ACCEPT_ENCODING_PROBE }),
            &[("grpc-accept-encoding", "gzip")],
        )
        .expect("post");

    assert_eq!(resp.status, 200, "the probe call itself must succeed");
    let v: serde_json::Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("response is JSON: {e}; body={:?}", resp.body));
    assert_eq!(
        v["message"], "identity",
        "the synthesized gRPC request must advertise identity message encoding; \
         upstream saw {}",
        v["message"]
    );
}

#[test]
fn a_grpc_error_becomes_the_mapped_http_status() {
    // A gRPC upstream answers a failed call with HTTP 200 and puts the
    // outcome in `grpc-status`: the status line describes the transport,
    // not the call. A REST client on the near side of the transcoder
    // reads the status line, so forwarding the 200 tells it the call
    // succeeded. `HelloError` always fails with FAILED_PRECONDITION,
    // which google.rpc.Code maps to HTTP 400.
    //
    // This is the trailers-only shape: tonic answers a unary `Err` with
    // a single HEADERS frame carrying `grpc-status`, and pingora skips
    // the body and trailer filters for a HEADERS frame with END_STREAM.
    // So the header filter is the only place the mapping can happen and
    // the status line is the only thing this test can assert on. The
    // headers-then-trailers shape (`HelloStreamError`) is committed
    // downstream before the trailers arrive and keeps its 200; see
    // docs/routing.md.
    let upstream = spawn_echo_grpc_server();
    let harness = ProxyHarness::start_with_yaml(&transcode_config(&upstream)).expect("start");

    let resp = harness
        .post_json(
            "/echo-error",
            "transcode.localhost",
            &json!({ "message": "precondition" }),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 400,
        "FAILED_PRECONDITION must reach the REST client as 400, not as a 200 \
         whose failure is discoverable only by parsing the body"
    );
}
