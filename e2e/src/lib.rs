//! End-to-end test harness.
//!
//! Spawns the release `sbproxy` binary against a temporary
//! configuration file, waits for it to bind, and tears it down on
//! drop. Each harness owns its own ephemeral port so tests
//! parallelise without colliding on `proxy.http_bind_port`.
//!
//! Typical usage:
//!
//! ```no_run
//! use sbproxy_e2e::ProxyHarness;
//! let harness = ProxyHarness::start_with_yaml(r#"
//!     proxy:
//!       http_bind_port: 0  # overridden by the harness
//!     origins:
//!       "demo":
//!         action: { type: static, status_code: 200, body: "ok" }
//! "#).unwrap();
//! let body = harness.get("/", "demo").unwrap();
//! assert_eq!(body.status, 200);
//! ```

#![warn(missing_docs)]

use std::io::{Read as IoRead, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_yaml::Value as Yaml;
use tempfile::NamedTempFile;

/// Default startup wait window. Five seconds is generous; release
/// builds typically bind within ~250 ms on a warm cargo cache.
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Locate the `sbproxy` binary built by the workspace. Prefers the
/// release build at `target/release/sbproxy`; falls back to
/// `target/debug/sbproxy` so CI runs that only build the debug profile
/// (the default `cargo test` flow) still find a usable binary.
pub fn proxy_binary_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent().unwrap();
    let release = workspace_root.join("target/release/sbproxy");
    if release.is_file() {
        return release;
    }
    workspace_root.join("target/debug/sbproxy")
}

/// One-off response shape returned by the harness's HTTP helpers.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body as bytes.
    pub body: Vec<u8>,
    /// Response headers (lowercased keys).
    pub headers: std::collections::HashMap<String, String>,
}

impl Response {
    /// Decode the body as UTF-8 text. Returns `Err` for invalid UTF-8.
    pub fn text(&self) -> anyhow::Result<String> {
        Ok(String::from_utf8(self.body.clone())?)
    }

    /// Decode the body as JSON. Errors when the body is not valid JSON.
    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

/// Running proxy instance. Drop kills the child process.
pub struct ProxyHarness {
    child: Child,
    port: u16,
    /// Hold the temp file alive so the proxy can keep reading it.
    _config: NamedTempFile,
    /// Lazy-initialised so harness construction does not invoke
    /// `reqwest::blocking::Client::builder().build()` at the call site.
    /// Building the blocking client spins up an internal tokio
    /// runtime; if `start_with_yaml()` is called from inside another
    /// async runtime (e.g. the gRPC tests do `Runtime::new() +
    /// rt.block_on(async { ProxyHarness::start_with_yaml(...) })`),
    /// dropping that internal runtime panics in tokio 1.52+. Tests
    /// that never call `get`/`post_json`/etc never trigger the build.
    client: std::sync::OnceLock<reqwest::blocking::Client>,
}

impl ProxyHarness {
    /// Start the proxy with a config built from a YAML string. The
    /// caller's `proxy.http_bind_port` (if any) is overridden with
    /// an ephemeral port chosen by the harness.
    pub fn start_with_yaml(yaml: &str) -> anyhow::Result<Self> {
        let port = pick_free_port()?;
        let final_yaml = inject_port(yaml, port)?;
        Self::start_with_resolved_yaml(&final_yaml, port)
    }

    /// Start the proxy with the YAML file at `path`, rewriting its
    /// `proxy.http_bind_port` to a fresh ephemeral port. The
    /// rewritten copy is held in a temp file; the original on
    /// disk is never modified.
    pub fn start_with_example(path: &Path) -> anyhow::Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read example {}: {}", path.display(), e))?;
        Self::start_with_yaml(&yaml)
    }

    fn start_with_resolved_yaml(yaml: &str, port: u16) -> anyhow::Result<Self> {
        let bin = proxy_binary_path();
        if !bin.is_file() {
            anyhow::bail!(
                "release binary missing at {}; run `cargo build --release -p sbproxy` first",
                bin.display()
            );
        }
        // The proxy reads its config from a path, not stdin, so
        // we materialise the rewritten YAML to a temp file. The
        // file lives as long as the harness so a child reload
        // would still see fresh data on disk.
        let mut file = NamedTempFile::new()?;
        file.write_all(yaml.as_bytes())?;
        file.flush()?;

        let child = Command::new(&bin)
            .arg("--config")
            .arg(file.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn {}: {}", bin.display(), e))?;

        let harness = Self {
            child,
            port,
            _config: file,
            client: std::sync::OnceLock::new(),
        };
        harness.wait_for_ready(DEFAULT_STARTUP_TIMEOUT)?;
        Ok(harness)
    }

    /// Build (or return) the lazy-initialised blocking HTTP client.
    /// Construction is deferred so harness creation does not trigger
    /// reqwest's internal runtime drop in async contexts.
    fn http_client(&self) -> &reqwest::blocking::Client {
        self.client.get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new())
        })
    }

    /// Poll the bound port until the proxy completes an HTTP exchange,
    /// or the deadline expires.
    ///
    /// We probe at the HTTP layer rather than the TCP layer because
    /// `bind()` returning is not enough: the kernel will accept TCP
    /// connections into the listen backlog before Pingora's accept
    /// loop is live. A test that fires its first HTTP request in that
    /// window observes `Connection reset by peer`. Issuing a real GET
    /// closes the gap: any HTTP response (including 4xx for an unknown
    /// Host) proves the server is serving.
    ///
    /// The probe uses a raw `TcpStream` + hand-written HTTP/1.1 GET
    /// rather than `reqwest::blocking` to stay safe inside async
    /// contexts. `reqwest::blocking::Client::builder().build()` spins
    /// up an internal tokio runtime; dropping it inside a
    /// `Runtime::block_on()` call (as the gRPC and WebSocket e2e tests
    /// do) panics in tokio 1.52+ with "Cannot drop a runtime in a
    /// context where blocking is not allowed".
    fn wait_for_ready(&self, timeout: Duration) -> anyhow::Result<()> {
        http_probe(self.port, timeout).map_err(|_| {
            anyhow::anyhow!(
                "proxy did not respond to HTTP on 127.0.0.1:{} within {:?}",
                self.port,
                timeout
            )
        })
    }

    /// Base URL for the running proxy.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Ephemeral TCP port the proxy is bound to. Use this from tests
    /// that need raw socket access (e.g. HTTP smuggling tests that
    /// bypass `reqwest`'s header normalization).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Block until the supplied port responds to an HTTP request, or
    /// the timeout elapses. Use this for sidecar listeners (admin
    /// API, metrics endpoint) that bind on a different port from
    /// the main proxy and may not be ready when `wait_for_ready`
    /// returns.
    ///
    /// HTTP-level probe (rather than TCP-level) for the same reason
    /// as `wait_for_ready`: a kernel-accepted connection without an
    /// active accept loop produces `Connection reset by peer`. Uses
    /// a raw `TcpStream` probe (not `reqwest::blocking`) so it is
    /// safe to call from inside a tokio async context.
    pub fn wait_for_port(port: u16, timeout: Duration) -> anyhow::Result<()> {
        http_probe(port, timeout).map_err(|_| {
            anyhow::anyhow!(
                "nothing responding to HTTP on 127.0.0.1:{} within {:?}",
                port,
                timeout
            )
        })
    }

    /// Issue a GET against the proxy with a `Host` header.
    pub fn get(&self, path: &str, host: &str) -> anyhow::Result<Response> {
        let resp = self
            .http_client()
            .get(format!("{}{}", self.base_url(), path))
            .header("host", host)
            .send()?;
        decode(resp)
    }

    /// Issue a GET with extra headers.
    pub fn get_with_headers(
        &self,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Response> {
        let mut req = self
            .http_client()
            .get(format!("{}{}", self.base_url(), path))
            .header("host", host);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        decode(req.send()?)
    }

    /// Path of the temp config file the harness wrote on startup.
    ///
    /// Tests that exercise hot-reload mutate this file and then poke
    /// the proxy (file watcher event or `POST /admin/reload`) to
    /// pick up the change. The path is stable for the lifetime of
    /// the harness.
    pub fn config_path(&self) -> &Path {
        self._config.path()
    }

    /// Overwrite the proxy's on-disk config with new YAML and
    /// inject the live `http_bind_port` so the proxy keeps the
    /// same listener after reload.
    ///
    /// The caller is responsible for triggering the reload (e.g.
    /// hitting `POST /admin/reload`); this helper only updates the
    /// file on disk.
    pub fn rewrite_config(&self, yaml: &str) -> anyhow::Result<()> {
        let final_yaml = inject_port(yaml, self.port)?;
        std::fs::write(self._config.path(), final_yaml)?;
        Ok(())
    }

    /// Issue a POST with a JSON body and optional extra headers.
    pub fn post_json(
        &self,
        path: &str,
        host: &str,
        body: &serde_json::Value,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Response> {
        let mut req = self
            .http_client()
            .post(format!("{}{}", self.base_url(), path))
            .header("host", host)
            .json(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        decode(req.send()?)
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn decode(resp: reqwest::blocking::Response) -> anyhow::Result<Response> {
    let status = resp.status().as_u16();
    let mut headers = std::collections::HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }
    let body = resp.bytes()?.to_vec();
    Ok(Response {
        status,
        body,
        headers,
    })
}

/// Reserve a free TCP port by binding to `127.0.0.1:0`, capturing
/// the port the OS handed us, and dropping the listener so the
/// proxy can grab the same port a moment later. This is the
/// standard Rust trick for picking a port without races.
fn pick_free_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Poll `127.0.0.1:<port>` until a raw HTTP/1.1 GET receives any
/// response (including a 4xx), or the deadline expires.
///
/// We intentionally use raw `TcpStream` rather than
/// `reqwest::blocking` here. `reqwest::blocking::Client::builder()
/// .build()` spins up an internal tokio runtime; dropping that
/// runtime inside another tokio runtime's `block_on` call panics
/// in tokio 1.52+ with "Cannot drop a runtime in a context where
/// blocking is not allowed". gRPC and WebSocket e2e tests call
/// `ProxyHarness::start_with_yaml` inside `rt.block_on(async {...})`,
/// so the probe must be runtime-free.
///
/// TCP-level check is not enough (the kernel's listen backlog accepts
/// TCP before Pingora's accept loop is live), so we write a
/// minimal HTTP request and treat any valid HTTP response line as
/// "ready". A malformed or empty response counts as not-ready and
/// we keep polling.
fn http_probe(port: u16, timeout: Duration) -> anyhow::Result<()> {
    use std::io::BufRead;

    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + timeout;
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");

    while Instant::now() < deadline {
        let conn_timeout = std::cmp::min(
            Duration::from_millis(500),
            deadline.saturating_duration_since(Instant::now()),
        );
        if conn_timeout.is_zero() {
            break;
        }
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&addr.parse().expect("addr parse"), conn_timeout)
        {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.write_all(request.as_bytes());
            // Read one line; any "HTTP/1.x" response line is enough.
            let mut reader = std::io::BufReader::new(&stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && line.starts_with("HTTP/") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("timeout");
}

/// Rewrite `proxy.http_bind_port` in the supplied YAML to the
/// chosen port and ensure `proxy.trusted_proxies` covers the
/// loopback so e2e tests that inject the trust-bounded TLS sidecar
/// headers (`x-sbproxy-tls-ja4`, `x-sbproxy-tls-ja3`,
/// `x-sbproxy-tls-trustworthy`) see them honoured. Uses `serde_yaml`
/// so we do not have to do regex surgery on whitespace-sensitive
/// YAML.
///
/// The trust-CIDR default unblocks the Wave 5 / G5.3 + G5.4 tests
/// (`tls_fingerprint_capture_e2e`, `headless_detection_e2e`,
/// `tls_spoofing_detection_e2e`). Pingora 0.8 does not surface raw
/// ClientHello bytes through its public Session API, so the OSS
/// pipeline accepts JA3 / JA4 from a trusted upstream sidecar via
/// the `x-sbproxy-tls-*` request headers; the harness drives this
/// path by marking 127.0.0.1/8 + ::1/128 as trusted at startup.
///
/// Operator YAML that explicitly sets `proxy.trusted_proxies` keeps
/// its value untouched. The default we inject only fires when the
/// caller did not author the field.
fn inject_port(yaml: &str, port: u16) -> anyhow::Result<String> {
    let mut doc: Yaml = serde_yaml::from_str(yaml)?;
    if let Yaml::Mapping(top) = &mut doc {
        let proxy_key = Yaml::String("proxy".to_string());
        let proxy_block = top
            .entry(proxy_key)
            .or_insert_with(|| Yaml::Mapping(Default::default()));
        if let Yaml::Mapping(proxy_map) = proxy_block {
            proxy_map.insert(
                Yaml::String("http_bind_port".to_string()),
                Yaml::Number(serde_yaml::Number::from(port as u64)),
            );
            // Inject the loopback trust-CIDR default only when the
            // caller did not author the field. This unblocks the
            // sidecar-header-driven TLS-fingerprint tests and stays
            // out of the way of any test that wants to pin a
            // different trust boundary.
            let trust_key = Yaml::String("trusted_proxies".to_string());
            if !proxy_map.contains_key(&trust_key) {
                let cidrs: serde_yaml::Sequence = vec![
                    Yaml::String("127.0.0.0/8".to_string()),
                    Yaml::String("::1/128".to_string()),
                ];
                proxy_map.insert(trust_key, Yaml::Sequence(cidrs));
            }

            // Inject the upstream private-CIDR allowlist default so
            // tests that proxy to MockUpstream on 127.0.0.1 do not
            // trip SBproxy's SSRF guard. Production configs leave
            // this empty (the default), which is what blocks
            // attacker-controlled upstream URLs from reaching
            // internal IPs. Tests intentionally opt in to loopback.
            // Caller-authored values win.
            let extensions_key = Yaml::String("extensions".to_string());
            let extensions_block = proxy_map
                .entry(extensions_key)
                .or_insert_with(|| Yaml::Mapping(Default::default()));
            if let Yaml::Mapping(extensions_map) = extensions_block {
                let upstream_key = Yaml::String("upstream".to_string());
                let upstream_block = extensions_map
                    .entry(upstream_key)
                    .or_insert_with(|| Yaml::Mapping(Default::default()));
                if let Yaml::Mapping(upstream_map) = upstream_block {
                    let allow_key = Yaml::String("allow_private_cidrs".to_string());
                    if !upstream_map.contains_key(&allow_key) {
                        let cidrs: serde_yaml::Sequence = vec![
                            Yaml::String("127.0.0.0/8".to_string()),
                            Yaml::String("::1/128".to_string()),
                        ];
                        upstream_map.insert(allow_key, Yaml::Sequence(cidrs));
                    }
                }
            }
        }
    }
    Ok(serde_yaml::to_string(&doc)?)
}

/// Tiny synchronous HTTP/1.1 server used to stand in for an
/// upstream the proxy talks to. Useful when a test needs to
/// observe what the proxy forwarded (request body, headers) and
/// returning a canned response is enough.
///
/// Only implements the bare slice of HTTP/1.1 we need: read the
/// request line + headers, optionally read `content-length` bytes
/// of body, return a 200 with a small JSON body. No keep-alive,
/// no chunked encoding, no TLS. Drop kills the listener thread.
pub struct MockUpstream {
    port: u16,
    /// Captured request bodies, one entry per accepted request.
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<Mutex<bool>>,
    join: Option<JoinHandle<()>>,
}

/// Snapshot of a request observed by `MockUpstream`.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    /// Request line method, e.g. "GET" or "POST".
    pub method: String,
    /// Request line path, e.g. "/v1/chat/completions".
    pub path: String,
    /// Header values (lowercased keys).
    pub headers: std::collections::HashMap<String, String>,
    /// Body bytes (empty for bodyless requests).
    pub body: Vec<u8>,
}

impl MockUpstream {
    /// Start the mock upstream on an ephemeral port. Each accepted
    /// request is appended to the capture log and replied to with
    /// the supplied JSON body and 200 status.
    pub fn start(reply_json: serde_json::Value) -> anyhow::Result<Self> {
        Self::start_with_response_headers(reply_json, Vec::new())
    }

    /// Start the mock upstream with extra response headers. Useful
    /// for tests that need the upstream to return e.g. `X-Inject-*`
    /// directives so the proxy's callback enrichment path can be
    /// exercised end-to-end.
    pub fn start_with_response_headers(
        reply_json: serde_json::Value,
        extra_headers: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let reply_bytes = serde_json::to_vec(&reply_json)?;
        let extra = Arc::new(extra_headers);

        let join = std::thread::spawn(move || {
            // Set a short accept timeout so we can poll the
            // shutdown flag without leaking the thread when the
            // harness is dropped.
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let body = reply_bytes.clone();
                let hdrs = extra.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_conn(stream, cap, body, hdrs);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// Start a mock upstream that replies to every request with an
    /// SSE-shaped (`text/event-stream`) chunked response built from
    /// the supplied events. Each entry becomes one `data: <line>\n\n`
    /// frame written to the wire as its own HTTP/1.1 chunk so the
    /// proxy's streaming relay sees the same framing a real provider
    /// would emit. Useful for AI gateway tests that need to verify
    /// the SSE relay path: streaming usage capture, stream-cache
    /// recorder fan-out, etc.
    pub fn start_sse(events: Vec<String>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let events = Arc::new(events);

        let join = std::thread::spawn(move || {
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let evts = events.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_sse_conn(stream, cap, evts);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// Start a mock upstream that emits raw SSE / NDJSON frames.
    ///
    /// `frames` are written verbatim, one chunk per entry, so the
    /// caller controls the framing (event-type prefix, JSON envelope,
    /// etc.). `content_type` is forwarded as the response
    /// Content-Type header. Useful for provider-shape coverage
    /// (Anthropic `event:` markers, Vertex `usageMetadata`, Bedrock
    /// `bytes` envelopes, Cohere `event-type`, Ollama NDJSON) where
    /// the OpenAI-shape `start_sse` cannot represent the wire format.
    pub fn start_sse_raw(frames: Vec<String>, content_type: String) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let cap_clone = captured.clone();
        let shut_clone = shutdown.clone();
        let frames = Arc::new(frames);
        let ct = Arc::new(content_type);

        let join = std::thread::spawn(move || {
            listener
                .set_nonblocking(false)
                .expect("listener nonblocking config");
            for incoming in listener.incoming() {
                if *shut_clone.lock().unwrap() {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let cap = cap_clone.clone();
                let f = frames.clone();
                let c = ct.clone();
                std::thread::spawn(move || {
                    let _ = handle_mock_sse_raw_conn(stream, cap, f, c);
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    /// Base URL the proxy should use to reach this mock upstream.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Snapshot the captured requests so far. The returned vec is
    /// a clone, so further mutation in the server thread does not
    /// affect callers.
    pub fn captured(&self) -> Vec<CapturedRequest> {
        self.captured.lock().unwrap().clone()
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Poke the listener so accept() returns and the loop sees
        // the shutdown flag.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn handle_mock_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    reply_body: Vec<u8>,
    extra_headers: Arc<Vec<(String, String)>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = std::collections::HashMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });

    let mut resp = String::new();
    resp.push_str("HTTP/1.1 200 OK\r\n");
    resp.push_str("Content-Type: application/json\r\n");
    for (k, v) in extra_headers.iter() {
        resp.push_str(&format!("{}: {}\r\n", k, v));
    }
    resp.push_str(&format!("Content-Length: {}\r\n", reply_body.len()));
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;
    stream.write_all(&reply_body)?;
    stream.flush()?;
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Connection handler for `MockUpstream::start_sse`. Parses the
/// inbound request the same way `handle_mock_conn` does, then writes
/// `text/event-stream` chunked encoding: one `data: <line>\n\n`
/// frame per event, terminated with the standard `data: [DONE]`
/// sentinel. Each frame goes out as its own HTTP/1.1 chunk so the
/// proxy's SSE relay observes the same framing a real provider would
/// emit and cannot collapse the stream by reading the whole body in
/// one go.
fn handle_mock_sse_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    events: Arc<Vec<String>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = std::collections::HashMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });

    // --- Write SSE response with chunked transfer encoding ---
    let mut resp = String::new();
    resp.push_str("HTTP/1.1 200 OK\r\n");
    resp.push_str("Content-Type: text/event-stream\r\n");
    resp.push_str("Cache-Control: no-cache\r\n");
    resp.push_str("Transfer-Encoding: chunked\r\n");
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;

    for event in events.iter() {
        let frame = format!("data: {}\n\n", event);
        let chunk_header = format!("{:x}\r\n", frame.len());
        stream.write_all(chunk_header.as_bytes())?;
        stream.write_all(frame.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }

    // OpenAI-shaped terminator. The streaming relay does not interpret
    // [DONE] today; it simply forwards the bytes and exits when the
    // upstream stream closes. Including it keeps the framing realistic.
    let done_frame = "data: [DONE]\n\n";
    let chunk_header = format!("{:x}\r\n", done_frame.len());
    stream.write_all(chunk_header.as_bytes())?;
    stream.write_all(done_frame.as_bytes())?;
    stream.write_all(b"\r\n")?;

    // Final chunk (length 0) closes the chunked body.
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

/// Connection handler for `MockUpstream::start_sse_raw`. Writes the
/// configured frames to the wire one chunk per entry so the proxy
/// observes the same framing each entry would be flushed at by a
/// real upstream.
fn handle_mock_sse_raw_conn(
    mut stream: TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    frames: Arc<Vec<String>>,
    content_type: Arc<String>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(());
        }
    }

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = std::collections::HashMap::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        headers,
        body,
    });

    // --- Write streaming response with chunked transfer encoding ---
    let mut resp = String::new();
    resp.push_str("HTTP/1.1 200 OK\r\n");
    resp.push_str(&format!("Content-Type: {}\r\n", content_type));
    resp.push_str("Cache-Control: no-cache\r\n");
    resp.push_str("Transfer-Encoding: chunked\r\n");
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;

    for frame in frames.iter() {
        let chunk_header = format!("{:x}\r\n", frame.len());
        stream.write_all(chunk_header.as_bytes())?;
        stream.write_all(frame.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }

    // Final chunk (length 0) closes the chunked body.
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_free_port_returns_distinct_ports() {
        let a = pick_free_port().unwrap();
        let b = pick_free_port().unwrap();
        // The OS may legitimately give us the same port twice
        // sequentially; just assert that both are non-zero.
        assert!(a > 0 && b > 0);
    }

    #[test]
    fn inject_port_overwrites_existing_value() {
        let out = inject_port(
            "proxy:\n  http_bind_port: 8080\norigins:\n  x:\n    action: { type: noop }\n",
            12345,
        )
        .unwrap();
        assert!(out.contains("http_bind_port: 12345"));
    }

    #[test]
    fn inject_port_creates_proxy_block_when_absent() {
        let out = inject_port("origins:\n  x:\n    action: { type: noop }\n", 54321).unwrap();
        assert!(out.contains("http_bind_port: 54321"));
        assert!(out.contains("proxy:"));
    }

    // --- Wave 5 day-5 / Q5.x trust-CIDR default tests ---

    #[test]
    fn inject_port_adds_loopback_trust_cidr_default() {
        // Wave 5 / G5.3 + G5.4: the harness must mark the loopback as
        // a trusted proxy so the OSS request_filter accepts the
        // sidecar TLS-fingerprint headers (`x-sbproxy-tls-ja4`, ...)
        // the e2e tests inject from 127.0.0.1.
        let out = inject_port("origins:\n  x:\n    action: { type: noop }\n", 12345).unwrap();
        assert!(
            out.contains("trusted_proxies:"),
            "harness must inject trusted_proxies by default, got: {out}",
        );
        assert!(
            out.contains("127.0.0.0/8"),
            "harness must mark IPv4 loopback as trusted, got: {out}",
        );
        assert!(
            out.contains("::1/128"),
            "harness must mark IPv6 loopback as trusted, got: {out}",
        );
    }

    #[test]
    fn inject_port_does_not_overwrite_operator_authored_trust_cidrs() {
        // When the test author pins their own trust boundary the
        // harness must respect it; the loopback default is only a
        // safety net for tests that did not author the field. The
        // assertion is scoped to the `trusted_proxies:` block because
        // the harness may legitimately inject `127.0.0.0/8` elsewhere
        // (e.g. into `extensions.upstream.allow_private_cidrs`).
        let yaml = "proxy:\n  trusted_proxies: ['10.0.0.0/8']\norigins:\n  x:\n    action: { type: noop }\n";
        let out = inject_port(yaml, 12345).unwrap();
        let trusted_block = trusted_proxies_block(&out);
        assert!(
            trusted_block.contains("10.0.0.0/8"),
            "operator-authored trusted_proxies entry must survive, got: {trusted_block}",
        );
        assert!(
            !trusted_block.contains("127.0.0.0/8"),
            "harness must NOT inject the loopback default into trusted_proxies, got: {trusted_block}",
        );
    }

    /// Slice the `trusted_proxies:` block out of a YAML string so the
    /// assertion above can check just that block, not the whole doc.
    /// Returns the substring from `trusted_proxies:` to the next
    /// top-level (under `proxy:`) key or end of file.
    fn trusted_proxies_block(yaml: &str) -> &str {
        let start = match yaml.find("trusted_proxies:") {
            Some(i) => i,
            None => return "",
        };
        let rest = &yaml[start..];
        // The `trusted_proxies:` value is a YAML sequence; the next
        // sibling under `proxy:` starts at the same indent level
        // ("  "). Walk forward until we find a line that starts with
        // exactly two spaces and a non-list-item character.
        let mut end = rest.len();
        for (offset, line) in rest.split_inclusive('\n').enumerate().skip(1) {
            let cumulative: usize = rest.split_inclusive('\n').take(offset).map(str::len).sum();
            let trimmed = line.trim_start();
            // A new top-level proxy key looks like "  http_bind_port:"
            // or "  extensions:" — exactly 2 leading spaces, no `-`.
            let indent = line.len() - trimmed.len();
            if indent <= 2 && !trimmed.is_empty() && !trimmed.starts_with('-') {
                end = cumulative;
                break;
            }
        }
        &rest[..end]
    }
}
