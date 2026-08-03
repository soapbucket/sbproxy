//! Real-process coverage for Proxy-Wasm HTTP filter attachment.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};

const FILTER_WASM: &[u8] =
    include_bytes!("../../crates/sbproxy-extension/src/bundle/testdata/proxy_wasm/http.wasm");
const HEADER_RESPONSE_WASM: &[u8] = include_bytes!(
    "../../crates/sbproxy-extension/src/bundle/testdata/proxy_wasm/header-response.wasm"
);

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

const HEADER_RESPONSE_MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: header-response-filter
version: 1.0.0
runtime: proxy_wasm
abi: 0.2.1
entry: filter.wasm
hooks:
  - kind: proxy_wasm
    type: header_response_filter
    execution:
      body_mode: none
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

struct HeaderResponseUpstream {
    port: u16,
    release: Sender<()>,
    join: Option<JoinHandle<std::io::Result<()>>>,
}

impl HeaderResponseUpstream {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (release, released) = mpsc::channel();
        let join = thread::spawn(move || serve_header_responses(listener, released));
        Ok(Self {
            port,
            release,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn release_stalled_body(&self) {
        let _ = self.release.send(());
    }
}

impl Drop for HeaderResponseUpstream {
    fn drop(&mut self) {
        self.release_stalled_body();
        for _ in 0..5 {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", self.port)) {
                let _ = stream
                    .write_all(b"GET /shutdown HTTP/1.1\r\nHost: local-response.localhost\r\n\r\n");
            }
        }
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

fn serve_header_responses(listener: TcpListener, released: Receiver<()>) -> std::io::Result<()> {
    for _ in 0..5 {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let request_line = request
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .unwrap_or_default();

        let response = if request_line.contains(" /no-content ") {
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".as_slice()
        } else if request_line.contains(" /not-modified ") {
            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".as_slice()
        } else if request_line.contains(" /zero ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n".as_slice()
        };
        stream.write_all(response)?;
        stream.flush()?;

        if request_line.contains(" /stalled ") {
            released
                .recv_timeout(Duration::from_secs(10))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let _ = stream.write_all(b"origin");
            let _ = stream.flush();
        }
    }
    Ok(())
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

fn header_response_config(upstream: &HeaderResponseUpstream) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
extensions:
  bundles_dir: bundles
origins:
  local-response.localhost:
    action:
      type: proxy
      url: "{}"
    filters:
      - type: header_response_filter
        config:
          enabled: true
        failure_posture: closed
"#,
        upstream.base_url(),
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

#[test]
fn response_header_local_response_does_not_wait_for_an_origin_body() {
    let upstream = HeaderResponseUpstream::start().expect("start header-response upstream");
    let files = [
        (
            "bundles/header-response-filter/bundle.yaml",
            HEADER_RESPONSE_MANIFEST.as_bytes(),
        ),
        (
            "bundles/header-response-filter/filter.wasm",
            HEADER_RESPONSE_WASM,
        ),
    ];
    let proxy =
        ProxyHarness::start_with_workspace_bytes(&header_response_config(&upstream), &files)
            .expect("start proxy with response-header filter");

    for path in ["/no-content", "/not-modified", "/zero"] {
        let response = proxy
            .get(path, "local-response.localhost")
            .unwrap_or_else(|error| panic!("receive local response for {path}: {error:#}"));
        assert_eq!(response.status, 403, "path {path}");
        assert_eq!(response.body, b"local", "path {path}");
        assert_eq!(
            response.headers.get("connection").map(String::as_str),
            Some("close"),
            "path {path}"
        );
    }

    let head = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build bounded HEAD client")
        .head(format!("{}/head", proxy.base_url()))
        .header("host", "local-response.localhost")
        .send()
        .expect("receive immediate local response for HEAD");
    assert_eq!(head.status(), 403);
    assert!(head.bytes().expect("read HEAD response").is_empty());

    let stalled = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build bounded stalled-body client")
        .get(format!("{}/stalled", proxy.base_url()))
        .header("host", "local-response.localhost")
        .send()
        .and_then(|response| {
            let status = response.status();
            response.bytes().map(|body| (status, body))
        });
    upstream.release_stalled_body();
    let (status, body) = stalled.expect("local response must not wait for the stalled origin body");
    assert_eq!(status, 403);
    assert_eq!(body.as_ref(), b"local");
}
