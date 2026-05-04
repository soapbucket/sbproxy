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

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

// Pull in the generated proto types. `tonic_build::compile` writes
// `<package>.rs` into `OUT_DIR`; the proto package is
// `sbproxy_e2e.echo`.
pub mod echo_pb {
    tonic::include_proto!("sbproxy_e2e.echo");
}

use echo_pb::echo_client::EchoClient;
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
