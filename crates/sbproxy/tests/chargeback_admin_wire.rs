// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Real wire compatibility for the authenticated AI chargeback export.
//!
//! The test drives a configured chargeback sink through the shipped child,
//! three OpenAI-shaped requests, and the separately bound admin listener. An
//! in-process handler test cannot prove that query negotiation, auth, the live
//! pipeline, and serialization are connected at the process boundary.

use std::io::{self, Read, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROMPT_MARKER: &str = "group-f-wire-private-prompt";
const ADMIN_AUTH: &str = "Basic YWRtaW46c2VjcmV0";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const FIXTURE_IO_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_FIXTURE_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_CAPTURED_CHILD_OUTPUT_BYTES: usize = 32 * 1024;
const CHILD_OUTPUT_READ_BYTES: usize = 4096;
const PORT_ATTEMPTS: usize = 8;
const PRIVATE_MARKERS: &[&str] = &[
    PROMPT_MARKER,
    ADMIN_AUTH,
    "secret",
    "fixture-provider-key",
    "wire-key-a",
    "wire-key-missing",
    "wire-key-b",
];
const ADDRESS_IN_USE_MARKERS: &[&[u8]] = &[b"address already in use", b"address in use"];

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sbproxy-chargeback-admin-wire-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Default)]
struct UpstreamObservation {
    prompt_requests: AtomicUsize,
}

struct OpenAiFixture {
    address: SocketAddr,
    observation: Arc<UpstreamObservation>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl OpenAiFixture {
    fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let observation = Arc::new(UpstreamObservation::default());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_observation = Arc::clone(&observation);
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(FIXTURE_IO_TIMEOUT));
                        let request = read_bounded_http_request(&mut stream).unwrap_or_default();
                        if contains_bytes(&request, PROMPT_MARKER.as_bytes()) {
                            thread_observation
                                .prompt_requests
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        let _ = write_openai_response(&mut stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            observation,
            stop,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://{}/v1", self.address)
    }

    fn prompt_requests(&self) -> usize {
        self.observation.prompt_requests.load(Ordering::Acquire)
    }
}

impl Drop for OpenAiFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_bounded_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    while request.len() < MAX_FIXTURE_REQUEST_BYTES {
        let remaining = MAX_FIXTURE_REQUEST_BYTES - request.len();
        let read_limit = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_limit]) {
            Ok(0) => break,
            Ok(read) => {
                request.extend_from_slice(&chunk[..read]);
                if http_request_is_complete(&request) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(request)
}

fn http_request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = find_bytes(request, b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    content_length.is_some_and(|length| {
        header_end
            .checked_add(4)
            .and_then(|body_start| body_start.checked_add(length))
            .is_some_and(|expected| request.len() >= expected)
    })
}

fn write_openai_response(stream: &mut TcpStream) -> io::Result<()> {
    const BODY: &str = r#"{"id":"chatcmpl-f-wire","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )?;
    stream.flush()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

#[derive(Clone)]
struct ChargebackFixtureConfig {
    max_entries: usize,
    max_workspaces: usize,
    max_teams: usize,
    workspace_id: String,
    provider_name: String,
    model_name: String,
    team_a: String,
    team_b: String,
}

impl Default for ChargebackFixtureConfig {
    fn default() -> Self {
        Self {
            max_entries: 8,
            max_workspaces: 1,
            max_teams: 3,
            workspace_id: "wire-workspace".to_string(),
            provider_name: "local-openai".to_string(),
            model_name: "gpt-4o".to_string(),
            team_a: "wire-team-a".to_string(),
            team_b: "wire-team-b".to_string(),
        }
    }
}

fn proxy_yaml(
    proxy_port: u16,
    admin_port: u16,
    upstream: &OpenAiFixture,
    config: &ChargebackFixtureConfig,
) -> String {
    format!(
        r#"proxy:
  http_bind_port: {proxy_port}
  bind_address: 127.0.0.1
  tenants:
    - id: {workspace_id}
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: admin
    password: secret
    rate_limit_per_minute: 100000
origins:
  "ready.localhost":
    action:
      type: echo
  "wire.ai.localhost":
    tenant_id: {workspace_id}
    action:
      type: ai_proxy
      require_governed_key: true
      usage_sinks:
        - type: chargeback
          max_entries: {max_entries}
          max_workspaces: {max_workspaces}
          max_teams: {max_teams}
      providers:
        - name: {provider_name}
          provider_type: openai
          api_key: fixture-provider-key
          base_url: {upstream_url}
          allow_private_base_url: true
          default_model: {model_name}
          models: [{model_name}]
    credentials:
      - name: wire-a
        type: ai_provider
        provider: {provider_name}
        key: wire-key-a
        attrs:
          team: {team_a}
      - name: wire-missing
        type: ai_provider
        provider: {provider_name}
        key: wire-key-missing
      - name: wire-b
        type: ai_provider
        provider: {provider_name}
        key: wire-key-b
        attrs:
          team: {team_b}
"#,
        upstream_url = upstream.base_url(),
        workspace_id = config.workspace_id,
        max_entries = config.max_entries,
        max_workspaces = config.max_workspaces,
        max_teams = config.max_teams,
        provider_name = config.provider_name,
        model_name = config.model_name,
        team_a = config.team_a,
        team_b = config.team_b,
    )
}

struct HttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn local_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|error| format!("build bounded loopback client: {error}"))
}

fn bounded_response(mut response: reqwest::blocking::Response) -> Result<HttpResponse, String> {
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let mut body = Vec::new();
    response
        .by_ref()
        .take((MAX_HTTP_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|error| format!("read bounded loopback response: {error}"))?;
    if body.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err("loopback response exceeded the test's fixed byte ceiling".to_string());
    }
    assert_private_markers_absent(&body, "HTTP response")?;
    Ok(HttpResponse {
        status,
        content_type,
        body,
    })
}

fn assert_private_markers_absent(bytes: &[u8], surface: &str) -> Result<(), String> {
    for marker in PRIVATE_MARKERS {
        if contains_bytes(bytes, marker.as_bytes()) {
            return Err(format!("{surface} contained a private test marker"));
        }
    }
    Ok(())
}

#[derive(Default)]
struct BoundedOutputState {
    retained: Vec<u8>,
    total_bytes: u64,
    overflowed: bool,
    private_marker_detected: bool,
    address_in_use: bool,
}

#[derive(Debug)]
struct BoundedOutputSummary {
    retained_bytes: usize,
    total_bytes: u64,
    overflowed: bool,
    private_marker_detected: bool,
    address_in_use: bool,
    drain_failed: bool,
}

impl BoundedOutputSummary {
    fn validate_complete_private_scan(&self) -> Result<(), String> {
        if self.drain_failed {
            return Err("child output could not be scanned to EOF".to_string());
        }
        if self.private_marker_detected {
            return Err("child output contained a private test marker".to_string());
        }
        if self.retained_bytes > MAX_CAPTURED_CHILD_OUTPUT_BYTES {
            return Err("child output exceeded the in-memory diagnostic ceiling".to_string());
        }
        let ceiling = u64::try_from(MAX_CAPTURED_CHILD_OUTPUT_BYTES)
            .expect("the fixed diagnostic ceiling fits in u64");
        if self.overflowed != (self.total_bytes > ceiling)
            || u64::try_from(self.retained_bytes).unwrap_or(u64::MAX)
                != self.total_bytes.min(ceiling)
        {
            return Err("child output accounting was internally inconsistent".to_string());
        }
        Ok(())
    }
}

struct BoundedChildOutput {
    state: Arc<Mutex<BoundedOutputState>>,
    drains: Vec<JoinHandle<io::Result<()>>>,
}

impl BoundedChildOutput {
    fn from_child(child: &mut Child) -> Result<Self, String> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "shipped child stdout pipe was not available".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "shipped child stderr pipe was not available".to_string())?;
        Ok(Self::from_readers(stdout, stderr))
    }

    fn from_readers<Stdout, Stderr>(stdout: Stdout, stderr: Stderr) -> Self
    where
        Stdout: Read + Send + 'static,
        Stderr: Read + Send + 'static,
    {
        let state = Arc::new(Mutex::new(BoundedOutputState::default()));
        let stdout_state = Arc::clone(&state);
        let stderr_state = Arc::clone(&state);
        let drains = vec![
            std::thread::spawn(move || drain_child_output(stdout, stdout_state)),
            std::thread::spawn(move || drain_child_output(stderr, stderr_state)),
        ];
        Self { state, drains }
    }

    fn finish(self) -> BoundedOutputSummary {
        let Self { state, drains } = self;
        let mut drain_failed = false;
        for drain in drains {
            match drain.join() {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => drain_failed = true,
            }
        }
        drain_failed |= state.is_poisoned();
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        BoundedOutputSummary {
            retained_bytes: state.retained.len(),
            total_bytes: state.total_bytes,
            overflowed: state.overflowed,
            private_marker_detected: state.private_marker_detected,
            address_in_use: state.address_in_use,
            drain_failed,
        }
    }
}

fn drain_child_output<Reader>(
    mut reader: Reader,
    state: Arc<Mutex<BoundedOutputState>>,
) -> io::Result<()>
where
    Reader: Read,
{
    let mut scanner_tail = Vec::with_capacity(max_scanner_marker_bytes().saturating_sub(1));
    let mut chunk = [0_u8; CHILD_OUTPUT_READ_BYTES];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => scan_child_output_chunk(&state, &mut scanner_tail, &chunk[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn scan_child_output_chunk(
    state: &Arc<Mutex<BoundedOutputState>>,
    scanner_tail: &mut Vec<u8>,
    chunk: &[u8],
) {
    let mut searchable = Vec::with_capacity(scanner_tail.len() + chunk.len());
    searchable.extend_from_slice(scanner_tail);
    searchable.extend_from_slice(chunk);

    let private_marker_detected = PRIVATE_MARKERS
        .iter()
        .any(|marker| contains_bytes(&searchable, marker.as_bytes()));
    let address_in_use = ADDRESS_IN_USE_MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(&searchable, marker));

    let overlap = max_scanner_marker_bytes().saturating_sub(1);
    let tail_start = searchable.len().saturating_sub(overlap);
    scanner_tail.clear();
    scanner_tail.extend_from_slice(&searchable[tail_start..]);

    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.total_bytes = state
        .total_bytes
        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    let remaining = MAX_CAPTURED_CHILD_OUTPUT_BYTES.saturating_sub(state.retained.len());
    let retained_from_chunk = remaining.min(chunk.len());
    state
        .retained
        .extend_from_slice(&chunk[..retained_from_chunk]);
    state.overflowed |= retained_from_chunk < chunk.len();
    state.private_marker_detected |= private_marker_detected;
    state.address_in_use |= address_in_use;
}

fn max_scanner_marker_bytes() -> usize {
    PRIVATE_MARKERS
        .iter()
        .map(|marker| marker.len())
        .chain(ADDRESS_IN_USE_MARKERS.iter().map(|marker| marker.len()))
        .max()
        .unwrap_or(1)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle.iter())
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        })
}

struct FragmentedReader {
    chunks: std::collections::VecDeque<Vec<u8>>,
    offset: usize,
}

impl FragmentedReader {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into(),
            offset: 0,
        }
    }
}

impl Read for FragmentedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(chunk) = self.chunks.front() else {
                return Ok(0);
            };
            if self.offset == chunk.len() {
                self.chunks.pop_front();
                self.offset = 0;
                continue;
            }
            let read = buffer.len().min(chunk.len() - self.offset);
            buffer[..read].copy_from_slice(&chunk[self.offset..self.offset + read]);
            self.offset += read;
            return Ok(read);
        }
    }
}

struct ProxyChild {
    child: Child,
    proxy_port: u16,
    admin_port: u16,
    model_name: String,
    output: Option<BoundedChildOutput>,
}

impl ProxyChild {
    fn start(root: &TestRoot, upstream: &OpenAiFixture) -> Result<Self, String> {
        Self::start_with_config(root, upstream, &ChargebackFixtureConfig::default())
    }

    fn start_with_config(
        root: &TestRoot,
        upstream: &OpenAiFixture,
        config: &ChargebackFixtureConfig,
    ) -> Result<Self, String> {
        let token = harness_token();
        for attempt in 0..PORT_ATTEMPTS {
            let proxy_reservation = TcpListener::bind("127.0.0.1:0")
                .map_err(|error| format!("reserve proxy port: {error}"))?;
            let admin_reservation = TcpListener::bind("127.0.0.1:0")
                .map_err(|error| format!("reserve admin port: {error}"))?;
            let proxy_port = proxy_reservation
                .local_addr()
                .map_err(|error| format!("read proxy port: {error}"))?
                .port();
            let admin_port = admin_reservation
                .local_addr()
                .map_err(|error| format!("read admin port: {error}"))?
                .port();
            let config_path = root.path().join(format!("sb-{attempt}.yml"));
            std::fs::write(
                &config_path,
                proxy_yaml(proxy_port, admin_port, upstream, config),
            )
            .map_err(|error| format!("write isolated proxy config: {error}"))?;
            let mut command = Command::new(binary());
            command
                .arg("serve")
                .arg(&config_path)
                .arg("--shutdown-grace-ms")
                .arg("0")
                .arg("--log-level")
                .arg("error")
                .env_remove("SB_CONFIG_FILE")
                .env("SBPROXY_E2E_HARNESS_TOKEN", &token)
                .env(
                    "SBPROXY_ENGINE_OWNERSHIP_DIR",
                    root.path().join(format!("ownership-{attempt}")),
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            drop(proxy_reservation);
            drop(admin_reservation);
            let mut child = command
                .spawn()
                .map_err(|error| format!("spawn shipped sbproxy child: {error}"))?;
            let output = match BoundedChildOutput::from_child(&mut child) {
                Ok(output) => output,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            match wait_for_ready(&mut child, proxy_port, admin_port, &token, STARTUP_TIMEOUT) {
                Ok(()) => {
                    return Ok(Self {
                        child,
                        proxy_port,
                        admin_port,
                        model_name: config.model_name.clone(),
                        output: Some(output),
                    });
                }
                Err(StartFailure::EarlyExit(status)) => {
                    let _ = child.wait();
                    let summary = output.finish();
                    summary.validate_complete_private_scan()?;
                    if summary.address_in_use {
                        continue;
                    }
                    return Err(format!(
                        "sbproxy exited before readiness with {status}; retained_output_bytes={}; total_output_bytes={}; output_truncated={}",
                        summary.retained_bytes, summary.total_bytes, summary.overflowed
                    ));
                }
                Err(StartFailure::Timeout) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let summary = output.finish();
                    summary.validate_complete_private_scan()?;
                    if summary.address_in_use {
                        continue;
                    }
                    return Err(format!(
                        "sbproxy missed the bounded readiness deadline; retained_output_bytes={}; total_output_bytes={}; output_truncated={}",
                        summary.retained_bytes, summary.total_bytes, summary.overflowed
                    ));
                }
            }
        }
        Err("could not hand both loopback ports to sbproxy after bounded retries".to_string())
    }

    fn post_ai(&self, key: &str) -> Result<HttpResponse, String> {
        let response = local_client()?
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                self.proxy_port
            ))
            .header("host", "wire.ai.localhost")
            .bearer_auth(key)
            .json(&serde_json::json!({
                "model": self.model_name,
                "messages": [{"role": "user", "content": PROMPT_MARKER}]
            }))
            .send()
            .map_err(|error| format!("send real AI request through child: {error}"))?;
        bounded_response(response)
    }

    fn admin_get(&self, path: &str, authenticated: bool) -> Result<HttpResponse, String> {
        let mut request =
            local_client()?.get(format!("http://127.0.0.1:{}{path}", self.admin_port));
        if authenticated {
            request = request.basic_auth("admin", Some("secret"));
        }
        bounded_response(
            request
                .send()
                .map_err(|error| format!("send bounded admin request: {error}"))?,
        )
    }

    fn shutdown(mut self) -> Result<BoundedOutputSummary, String> {
        let stop_result = self.stop_child();
        let Some(output) = self.output.take() else {
            return Err("child output scanner was already finished".to_string());
        };
        let summary = output.finish();
        let scan_result = summary.validate_complete_private_scan();
        stop_result?;
        scan_result?;
        Ok(summary)
    }

    fn stop_child(&mut self) -> Result<(), String> {
        let mut first_error = None;
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.child.kill() {
                    first_error = Some(format!("stop shipped child: {error}"));
                }
            }
            Err(error) => {
                first_error = Some(format!("inspect shipped child status: {error}"));
                let _ = self.child.kill();
            }
        }
        if let Err(error) = self.child.wait() {
            if first_error.is_none() {
                first_error = Some(format!("reap shipped child: {error}"));
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for ProxyChild {
    fn drop(&mut self) {
        let _ = self.stop_child();
        if let Some(output) = self.output.take() {
            let _ = output.finish();
        }
    }
}

enum StartFailure {
    EarlyExit(std::process::ExitStatus),
    Timeout,
}

fn wait_for_ready(
    child: &mut Child,
    proxy_port: u16,
    admin_port: u16,
    token: &str,
    timeout: Duration,
) -> Result<(), StartFailure> {
    let deadline = Instant::now() + timeout;
    loop {
        if proxy_readiness_probe(proxy_port, token) && admin_readiness_probe(admin_port) {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(StartFailure::EarlyExit(status));
        }
        if Instant::now() >= deadline {
            return Err(StartFailure::Timeout);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn proxy_readiness_probe(port: u16, token: &str) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(250)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(FIXTURE_IO_TIMEOUT));
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: ready.localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    if stream.take(16 * 1024).read_to_end(&mut response).is_err() {
        return false;
    }
    if !response.starts_with(b"HTTP/1.1 200") {
        return false;
    }
    String::from_utf8_lossy(&response).lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim()
                .eq_ignore_ascii_case("x-sbproxy-e2e-harness-token")
                && value.trim() == token
        })
    })
}

fn admin_readiness_probe(port: u16) -> bool {
    let Ok(client) = local_client() else {
        return false;
    };
    client
        .get(format!("http://127.0.0.1:{port}/admin/ai-chargeback"))
        .basic_auth("admin", Some("secret"))
        .send()
        .is_ok_and(|response| response.status().as_u16() == 200)
}

fn harness_token() -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("f-wire-{}-{nonce}", std::process::id())
}

fn parse_json(response: &HttpResponse) -> Result<serde_json::Value, String> {
    if !response.content_type.starts_with("application/json") {
        return Err("admin response did not declare application/json".to_string());
    }
    serde_json::from_slice(&response.body)
        .map_err(|error| format!("parse bounded admin JSON: {error}"))
}

fn wait_for_record_count(proxy: &ProxyChild, expected: u64) -> Result<serde_json::Value, String> {
    wait_for_record_count_at_path(proxy, "/admin/ai-chargeback", expected)
}

fn wait_for_record_count_at_path(
    proxy: &ProxyChild,
    path: &str,
    expected: u64,
) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = proxy.admin_get(path, true)?;
        if response.status == 200 {
            let document = parse_json(&response)?;
            if document["origins"]["wire.ai.localhost"][0]["recorded_entries"]
                == serde_json::json!(expected)
            {
                return Ok(document);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "live chargeback sink did not publish record count {expected} in time"
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn normalized_v1_fixture(document: &serde_json::Value) -> serde_json::Value {
    let tracker = &document["origins"]["wire.ai.localhost"][0];
    let entries = tracker["entries"].as_array().expect("v1 entries array");
    assert_eq!(entries.len(), 3);
    let entry_costs = entries
        .iter()
        .map(|entry| {
            let timestamp = entry["timestamp"].as_str().expect("bounded v1 timestamp");
            assert!(timestamp.len() <= 64 && timestamp.contains('T'));
            let cost = entry["cost"].as_f64().expect("finite v1 entry cost");
            assert!(cost.is_finite() && cost >= 0.0);
            cost
        })
        .collect::<Vec<_>>();
    let workspace_cost = tracker["workspace_totals"]["__other__"]["cost_usd"]
        .as_f64()
        .expect("workspace cost");
    let entry_cost_total = entry_costs.iter().sum::<f64>();
    assert!((workspace_cost - entry_cost_total).abs() < 1e-12);
    for (team, index) in [
        ("wire-team-a", 0_usize),
        ("unattributed", 1_usize),
        ("__other__", 2_usize),
    ] {
        let team_cost = tracker["team_totals"][team]["cost_usd"]
            .as_f64()
            .expect("team cost");
        assert!((team_cost - entry_costs[index]).abs() < 1e-12);
    }

    let mut normalized = document.clone();
    for entry in normalized["origins"]["wire.ai.localhost"][0]["entries"]
        .as_array_mut()
        .expect("mutable v1 entries")
    {
        entry["timestamp"] = serde_json::json!("<timestamp>");
        entry["cost"] = serde_json::json!("<derived-cost>");
    }
    normalized["origins"]["wire.ai.localhost"][0]["workspace_totals"]["__other__"]["cost_usd"] =
        serde_json::json!("<derived-total-cost>");
    for team in ["wire-team-a", "unattributed", "__other__"] {
        normalized["origins"]["wire.ai.localhost"][0]["team_totals"][team]["cost_usd"] =
            serde_json::json!("<derived-cost>");
    }
    normalized
}

fn expected_v1_fixture() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "origins": {
            "wire.ai.localhost": [{
                "max_entries": 8,
                "max_workspaces": 1,
                "max_teams": 3,
                "entries": [
                    {
                        "team": "wire-team-a",
                        "project": "",
                        "provider": "local-openai",
                        "model": "gpt-4o",
                        "tokens": 2,
                        "cost": "<derived-cost>",
                        "timestamp": "<timestamp>"
                    },
                    {
                        "team": "unattributed",
                        "project": "",
                        "provider": "local-openai",
                        "model": "gpt-4o",
                        "tokens": 2,
                        "cost": "<derived-cost>",
                        "timestamp": "<timestamp>"
                    },
                    {
                        "team": "wire-team-b",
                        "project": "",
                        "provider": "local-openai",
                        "model": "gpt-4o",
                        "tokens": 2,
                        "cost": "<derived-cost>",
                        "timestamp": "<timestamp>"
                    }
                ],
                "workspace_totals": {
                    "__other__": {
                        "tokens": 6,
                        "cost_usd": "<derived-total-cost>",
                        "request_count": 3
                    }
                },
                "team_totals": {
                    "__other__": {
                        "tokens": 2,
                        "cost_usd": "<derived-cost>",
                        "request_count": 1
                    },
                    "unattributed": {
                        "tokens": 2,
                        "cost_usd": "<derived-cost>",
                        "request_count": 1
                    },
                    "wire-team-a": {
                        "tokens": 2,
                        "cost_usd": "<derived-cost>",
                        "request_count": 1
                    }
                },
                "recorded_entries": 3,
                "evicted_entries": 0,
                "collapsed_workspace_events": 3,
                "collapsed_team_events": 1
            }]
        }
    })
}

fn assert_v2_fixture(document: &serde_json::Value) {
    assert_eq!(document["schema_version"], serde_json::json!(2));
    let expected_outer_fields = std::collections::BTreeSet::from(["origins", "schema_version"]);
    assert_eq!(
        document
            .as_object()
            .expect("v2 envelope object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_outer_fields
    );
    let tracker = &document["origins"]["wire.ai.localhost"][0];
    assert_eq!(
        document["origins"]
            .as_object()
            .expect("v2 origins object")
            .len(),
        1
    );
    assert_eq!(
        document["origins"]["wire.ai.localhost"]
            .as_array()
            .expect("one v2 tracker array")
            .len(),
        1
    );
    assert_eq!(tracker["schema_version"], serde_json::json!(2));
    assert!(tracker.get("workspace_totals").is_none());
    assert!(tracker.get("team_totals").is_none());
    assert!(tracker["entries"].is_array());
    assert!(tracker["workspace_rollups"].is_array());
    assert!(tracker["team_rollups"].is_array());
    assert_eq!(tracker["recorded_entries"], serde_json::json!(3));
    assert_eq!(tracker["refused_entries"], serde_json::json!(0));
    assert_eq!(tracker["complete"], serde_json::json!(true));

    let entries = tracker["entries"].as_array().expect("typed v2 entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries[0]["workspace"],
        serde_json::json!({"kind": "value", "value": "wire-workspace"})
    );
    assert_eq!(
        entries[0]["team"],
        serde_json::json!({"kind": "value", "value": "wire-team-a"})
    );
    assert_eq!(
        entries[1]["workspace"],
        serde_json::json!({"kind": "value", "value": "wire-workspace"})
    );
    assert_eq!(entries[1]["team"], serde_json::json!({"kind": "missing"}));
    assert_eq!(
        entries[2]["team"],
        serde_json::json!({"kind": "value", "value": "wire-team-b"})
    );
    assert_eq!(
        entries[2]["workspace"],
        serde_json::json!({"kind": "value", "value": "wire-workspace"})
    );
    let entry_costs = entries
        .iter()
        .map(|entry| {
            assert_eq!(entry["provider"], serde_json::json!("local-openai"));
            assert_eq!(entry["model"], serde_json::json!("gpt-4o"));
            assert_eq!(entry["tokens"], serde_json::json!(2));
            let cost = entry["cost"].as_f64().expect("finite v2 entry cost");
            assert!(cost.is_finite() && cost >= 0.0);
            cost
        })
        .collect::<Vec<_>>();

    let workspace_rollups = tracker["workspace_rollups"]
        .as_array()
        .expect("typed workspace rollups");
    assert_eq!(workspace_rollups.len(), 1);
    assert_eq!(
        workspace_rollups[0]["dimension"],
        serde_json::json!({"kind": "overflow"})
    );
    assert_eq!(
        workspace_rollups[0]["totals"]["request_count"],
        serde_json::json!(3)
    );
    assert_eq!(
        workspace_rollups[0]["totals"]["tokens"],
        serde_json::json!(6)
    );
    let workspace_cost = workspace_rollups[0]["totals"]["cost_usd"]
        .as_f64()
        .expect("finite v2 workspace cost");
    assert!((workspace_cost - entry_costs.iter().sum::<f64>()).abs() < 1e-12);

    let team_rollups = tracker["team_rollups"]
        .as_array()
        .expect("typed team rollups");
    for (expected, entry_index) in [
        (
            serde_json::json!({"kind": "value", "value": "wire-team-a"}),
            0_usize,
        ),
        (serde_json::json!({"kind": "missing"}), 1_usize),
        (serde_json::json!({"kind": "overflow"}), 2_usize),
    ] {
        let rollup = team_rollups
            .iter()
            .find(|rollup| rollup["dimension"] == expected)
            .expect("each real team identity has one typed rollup");
        assert_eq!(rollup["totals"]["request_count"], serde_json::json!(1));
        assert_eq!(rollup["totals"]["tokens"], serde_json::json!(2));
        let cost = rollup["totals"]["cost_usd"]
            .as_f64()
            .expect("finite v2 team cost");
        assert!((cost - entry_costs[entry_index]).abs() < 1e-12);
    }
}

#[test]
fn group_f_bounded_child_output_scans_beyond_retention_and_across_chunks() {
    let stdout = FragmentedReader::new(vec![
        vec![b'x'; MAX_CAPTURED_CHILD_OUTPUT_BYTES],
        b"sec".to_vec(),
        b"ret".to_vec(),
    ]);
    let stderr = FragmentedReader::new(vec![b"ADDRESS ".to_vec(), b"IN USE".to_vec()]);

    let summary = BoundedChildOutput::from_readers(stdout, stderr).finish();

    assert_eq!(
        summary.retained_bytes, MAX_CAPTURED_CHILD_OUTPUT_BYTES,
        "retained diagnostics must stop at the fixed in-memory ceiling"
    );
    assert_eq!(
        summary.total_bytes,
        u64::try_from(MAX_CAPTURED_CHILD_OUTPUT_BYTES + 20).expect("small literal byte total"),
        "the scanner must account for the complete stdout and stderr streams"
    );
    assert!(summary.overflowed);
    assert!(
        summary.private_marker_detected,
        "a secret after 32 KiB and split across reads must still be detected"
    );
    assert!(
        summary.address_in_use,
        "sanitized retry classification must also survive a chunk boundary"
    );
    assert!(!summary.drain_failed);
    let failure = summary
        .validate_complete_private_scan()
        .expect_err("the full-stream private marker must reject captured output");
    assert_private_markers_absent(failure.as_bytes(), "bounded scanner failure")
        .expect("scanner failures must remain sanitized");
}

#[test]
fn group_f_admin_chargeback_wire_preserves_v1_and_negotiates_typed_v2() {
    let root = TestRoot::new().expect("create isolated chargeback wire root");
    let upstream = OpenAiFixture::start().expect("start bounded OpenAI fixture");
    let proxy = ProxyChild::start(&root, &upstream)
        .expect("start shipped child with live chargeback and admin listeners");

    let unauthorized = proxy
        .admin_get("/admin/ai-chargeback", false)
        .expect("read unauthenticated admin response");
    assert_eq!(unauthorized.status, 401);

    for (index, key) in ["wire-key-a", "wire-key-missing", "wire-key-b"]
        .into_iter()
        .enumerate()
    {
        let response = proxy
            .post_ai(key)
            .expect("drive one real AI completion through the configured sink");
        assert_eq!(response.status, 200);
        let _ = wait_for_record_count(&proxy, (index + 1) as u64)
            .expect("observe the sequential live sink commit");
    }
    assert_eq!(
        upstream.prompt_requests(),
        3,
        "all three real requests must reach the local provider fixture"
    );

    let default_v1 =
        wait_for_record_count(&proxy, 3).expect("observe the complete live v1 fixture");
    let normalized_v1 = normalized_v1_fixture(&default_v1);
    assert_eq!(normalized_v1, expected_v1_fixture());

    let explicit_v2 = proxy
        .admin_get("/admin/ai-chargeback?schema_version=2", true)
        .expect("read explicit typed v2 response");
    assert_eq!(explicit_v2.status, 200);
    assert_v2_fixture(&parse_json(&explicit_v2).expect("parse typed v2 response"));

    let default_after_v2 = proxy
        .admin_get("/admin/ai-chargeback", true)
        .expect("read default schema again after v2 negotiation");
    assert_eq!(default_after_v2.status, 200);
    assert_eq!(
        normalized_v1_fixture(&parse_json(&default_after_v2).expect("parse repeated v1")),
        normalized_v1,
        "v2 negotiation must not mutate or silently upgrade the default legacy contract"
    );

    let ignored_query_value = "bounded-noise-must-not-be-echoed";
    for (path, requested) in [
        (
            format!("/admin/ai-chargeback?schema_version=3&ignored={ignored_query_value}"),
            serde_json::json!(3),
        ),
        (
            "/admin/ai-chargeback?schema_version=future".to_string(),
            serde_json::json!("future"),
        ),
    ] {
        let unsupported = proxy
            .admin_get(&path, true)
            .expect("read typed unsupported-version response");
        assert_eq!(unsupported.status, 400);
        assert!(!contains_bytes(
            &unsupported.body,
            ignored_query_value.as_bytes()
        ));
        assert_eq!(
            parse_json(&unsupported).expect("parse typed 400 response"),
            serde_json::json!({
                "code": "unsupported_schema_version",
                "requested_schema_version": requested,
                "supported_schema_versions": [1, 2]
            })
        );
    }

    let output = proxy
        .shutdown()
        .expect("drain and scan the complete bounded child output");
    assert!(output.retained_bytes <= MAX_CAPTURED_CHILD_OUTPUT_BYTES);
    assert_eq!(
        output.overflowed,
        output.total_bytes > MAX_CAPTURED_CHILD_OUTPUT_BYTES as u64,
        "the retained-output overflow bit must describe the complete stream"
    );
}

#[test]
fn group_f_admin_chargeback_wire_paginates_and_refuses_oversized_pages() {
    let root = TestRoot::new().expect("create isolated chargeback F3 wire root");
    let upstream = OpenAiFixture::start().expect("start bounded OpenAI fixture");
    let oversized = ChargebackFixtureConfig {
        max_entries: 900,
        max_workspaces: 1,
        max_teams: 1,
        workspace_id: format!("wire-workspace-{}", "w".repeat(192)),
        provider_name: format!("provider-{}", "p".repeat(192)),
        model_name: format!("model-{}", "m".repeat(192)),
        team_a: format!("wire-team-a-{}", "t".repeat(192)),
        team_b: "wire-team-unused".to_string(),
    };
    let proxy = ProxyChild::start_with_config(&root, &upstream, &oversized)
        .expect("start shipped child with oversized live chargeback fixture");

    for _ in 0..3 {
        let response = proxy
            .post_ai("wire-key-a")
            .expect("drive paged AI completion through the configured sink");
        assert_eq!(response.status, 200);
    }
    let first_page = proxy
        .admin_get("/admin/ai-chargeback?schema_version=2&limit=2", true)
        .expect("read first typed paged chargeback response");
    assert_eq!(first_page.status, 200);
    let first_page = parse_json(&first_page).expect("parse first typed paged response");
    assert_eq!(first_page["schema_version"], serde_json::json!(2));
    assert_eq!(first_page["limit"], serde_json::json!(2));
    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("plus-one live page returns a continuation")
        .to_string();
    assert_eq!(
        first_page["origins"]["wire.ai.localhost"][0]["entries"]
            .as_array()
            .expect("live paged entries")
            .len(),
        2
    );
    assert_eq!(
        first_page["origins"]["wire.ai.localhost"][0]["recorded_entries"],
        serde_json::json!(3)
    );
    let second_page = proxy
        .admin_get(
            &format!("/admin/ai-chargeback?schema_version=2&limit=2&cursor={cursor}"),
            true,
        )
        .expect("read second typed paged chargeback response");
    assert_eq!(second_page.status, 200);
    let second_page = parse_json(&second_page).expect("parse second typed paged response");
    assert_eq!(second_page["next_cursor"], serde_json::Value::Null);
    assert_eq!(
        second_page["origins"]["wire.ai.localhost"][0]["entries"]
            .as_array()
            .expect("tail live paged entries")
            .len(),
        1
    );
    assert_eq!(
        second_page["origins"]["wire.ai.localhost"][0]["workspace_rollups"]
            .as_array()
            .expect("live workspace rollups remain whole")
            .len(),
        1
    );

    const OVERSIZED_RECORD_COUNT: u64 = 800;
    for _ in 3..OVERSIZED_RECORD_COUNT {
        let response = proxy
            .post_ai("wire-key-a")
            .expect("drive oversized AI completion through the configured sink");
        assert_eq!(response.status, 200);
    }
    let ready_path = "/admin/ai-chargeback?schema_version=2&limit=1";
    let ready = wait_for_record_count_at_path(&proxy, ready_path, OVERSIZED_RECORD_COUNT)
        .expect("observe the complete oversized live sink commit through a bounded page");
    assert_eq!(ready["schema_version"], serde_json::json!(2));
    assert_eq!(ready["limit"], serde_json::json!(1));
    assert!(
        ready["next_cursor"].is_string(),
        "bounded live pages must return a continuation before the oversize refusal"
    );

    let refused = proxy
        .admin_get(
            &format!(
                "/admin/ai-chargeback?schema_version=2&limit={}",
                oversized.max_entries
            ),
            true,
        )
        .expect("read oversized live chargeback refusal");
    assert_eq!(refused.status, 413);
    assert_eq!(
        parse_json(&refused).expect("parse typed 413 response"),
        serde_json::json!({
            "code": "chargeback_response_too_large",
            "max_response_bytes": 524288,
            "hint": "retry with ?limit=<1..=1000> and the returned next_cursor"
        })
    );

    let output = proxy
        .shutdown()
        .expect("drain and scan the complete bounded child output");
    assert!(output.retained_bytes <= MAX_CAPTURED_CHILD_OUTPUT_BYTES);
}
