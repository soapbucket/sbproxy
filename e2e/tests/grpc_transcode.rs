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
    tonic::include_proto!("sbproxy_e2e.echo");
}

use echo_pb::echo_server::{Echo, EchoServer};
use echo_pb::{EchoRequest, EchoResponse};

#[derive(Default)]
struct EchoSvc;

#[tonic::async_trait]
impl Echo for EchoSvc {
    async fn hello(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        let msg = request.into_inner().message;
        Ok(tonic::Response::new(EchoResponse { message: msg }))
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
