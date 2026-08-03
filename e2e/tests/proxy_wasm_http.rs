//! Real-process coverage for Proxy-Wasm HTTP filter attachment.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};

const FILTER_WASM: &[u8] =
    include_bytes!("../../crates/sbproxy-extension/src/bundle/testdata/proxy_wasm/http.wasm");

const MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: http-filter
version: 1.0.0
runtime: proxy_wasm
abi: 0.2.1
entry: filter.wasm
hooks:
  - kind: proxy_wasm
    type: fixture_http_filter
    execution:
      body_mode: streamed
"#;

struct GatedChunkedUpstream {
    port: u16,
    release: Sender<()>,
    join: Option<JoinHandle<std::io::Result<()>>>,
}

impl GatedChunkedUpstream {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (release, released) = mpsc::channel();
        let join = thread::spawn(move || serve_gated_response(listener, released));
        Ok(Self {
            port,
            release,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn release_second_chunk(&self) {
        let _ = self.release.send(());
    }
}

impl Drop for GatedChunkedUpstream {
    fn drop(&mut self) {
        self.release_second_chunk();
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve_gated_response(listener: TcpListener, released: Receiver<()>) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..read]);
    }

    stream.write_all(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/plain\r\n\
          Transfer-Encoding: chunked\r\n\
          Connection: close\r\n\r\n",
    )?;
    stream.write_all(b"5\r\nfirst\r\n")?;
    stream.flush()?;

    released
        .recv_timeout(Duration::from_secs(10))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    stream.write_all(b"6\r\nsecond\r\n0\r\n\r\n")?;
    stream.flush()
}

fn config(upstream: &MockUpstream, gated: &GatedChunkedUpstream) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
extensions:
  bundles_dir: bundles
origins:
  filter.localhost:
    action:
      type: proxy
      url: "{}"
    filters:
      - type: fixture_http_filter
        config:
          enabled: true
        failure_posture: closed
  stream.localhost:
    action:
      type: proxy
      url: "{}"
    filters:
      - type: fixture_http_filter
        config:
          enabled: true
        failure_posture: closed
"#,
        upstream.base_url(),
        gated.base_url(),
    )
}

#[test]
fn installed_proxy_wasm_filter_participates_in_http_exchange() {
    let upstream = MockUpstream::start(serde_json::json!({"upstream": true}))
        .expect("start ordinary upstream");
    let gated = GatedChunkedUpstream::start().expect("start gated upstream");
    let files = [
        ("bundles/http-filter/bundle.yaml", MANIFEST.as_bytes()),
        ("bundles/http-filter/filter.wasm", FILTER_WASM),
    ];
    let proxy = ProxyHarness::start_with_workspace_bytes(&config(&upstream, &gated), &files)
        .expect("start proxy with Proxy-Wasm filter");

    let normal = proxy
        .get_with_headers(
            "/normal",
            "filter.localhost",
            &[("x-input", "request-value")],
        )
        .expect("filter ordinary request");
    assert_eq!(
        normal.headers.get("x-response").map(String::as_str),
        Some("filtered")
    );
    assert_eq!(
        upstream.captured()[0]
            .headers
            .get("x-seen")
            .map(String::as_str),
        Some("request-value")
    );

    let before_block = upstream.captured().len();
    let blocked = proxy
        .get_with_headers("/blocked", "filter.localhost", &[("x-block", "1")])
        .expect("receive local response");
    assert_eq!(blocked.status, 403);
    assert_eq!(blocked.body, b"blocked");
    assert_eq!(upstream.captured().len(), before_block);

    let pause = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build bounded Pause client")
        .get(format!("{}/paused", proxy.base_url()))
        .header("host", "filter.localhost")
        .header("x-pause", "1")
        .send()
        .expect("unresolved Pause should return instead of hanging");
    assert!(
        pause.status().is_server_error(),
        "status was {}",
        pause.status()
    );

    let stream_url = format!("{}/stream", proxy.base_url());
    let (first_bytes, received_first_bytes) = mpsc::sync_channel(1);
    let client = thread::spawn(move || -> anyhow::Result<Vec<u8>> {
        let mut response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?
            .get(stream_url)
            .header("host", "stream.localhost")
            .send()?;
        anyhow::ensure!(
            response.status().is_success(),
            "status was {}",
            response.status()
        );
        let mut first = [0_u8; 8];
        response.read_exact(&mut first)?;
        first_bytes
            .send(first)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut body = first.to_vec();
        response.read_to_end(&mut body)?;
        Ok(body)
    });

    let first = match received_first_bytes.recv_timeout(Duration::from_secs(2)) {
        Ok(first) => first,
        Err(error) => {
            gated.release_second_chunk();
            let _ = client.join();
            panic!("first transformed chunk was buffered: {error}");
        }
    };
    assert_eq!(&first, b"filtered");
    gated.release_second_chunk();

    let complete = client
        .join()
        .expect("stream client thread should not panic")
        .expect("read complete transformed stream");
    assert!(complete.starts_with(b"filtered"));
}
