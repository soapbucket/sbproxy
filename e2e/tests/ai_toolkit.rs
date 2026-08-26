//! Live acceptance proof for the bounded AI toolkit.
//!
//! This deliberately uses the shipped `sbproxy` process twice: once through
//! [`ProxyHarness`] for the server and again for every documented CLI command.
//! No runtime API is called in-process, and every outbound peer is a bounded
//! loopback HTTP server owned by this test. Redis is not involved.

use std::collections::{BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use base64::Engine as _;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sbproxy_e2e::{proxy_binary_path, ProxyHarness};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const ADMIN_USER: &str = "admin";
const ADMIN_SECRET: &str = "e2e-admin-secret-never-emit";
const TENANT_ADMIN_USER: &str = "tenant-b-admin";
const TENANT_ADMIN_SECRET: &str = "e2e-tenant-admin-secret-never-emit";
const AGENT_SECRET: &str = "e2e-agent-secret-never-emit";
const PROVIDER_KEY: &str = "e2e-provider-key-never-emit";
const WORKFLOW_INPUT: &str = "e2e-workflow-input-never-retain";
const DENIED_WORKFLOW_INPUT: &str = "e2e-denied-workflow-input-never-retain";
const SLOW_WORKFLOW_INPUT: &str = "e2e-slow-workflow-input-never-retain";
const AGENT_OUTPUT: &str = "e2e-agent-output-never-retain";
const DATASET_INPUT: &str = "e2e-dataset-input-never-retain";
const EVALUATION_RESPONSE: &str = "e2e-evaluation-response-never-retain";
const PROMPT_CONTENT: &str = "e2e-rollout-prompt-content-never-emit";
const RAW_COHORT: &str = "e2e-raw-cohort-never-emit";
const ORIGIN_HOST: &str = "ai.localhost";
const ORIGIN_ID: &str = ORIGIN_HOST;
const ORIGIN_TENANT: &str = "tenant-a";
const OTHER_TENANT: &str = "tenant-b";
const WORKFLOW: &str = "summarize-flow";
const DENIED_WORKFLOW: &str = "denied-flow";
const SLOW_WORKFLOW: &str = "slow-flow";
const DATASET: &str = "quality-set";
const PROMPT: &str = "support-system";

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const ADMIN_TIMEOUT: Duration = Duration::from_secs(5);
const CLI_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_CLEANUP_RESERVE: Duration = Duration::from_secs(2);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const MOCK_SERVER_LIFETIME: Duration = Duration::from_secs(120);
const MOCK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_MOCK_CONNECTIONS: usize = 8;
const MAX_MOCK_REQUESTS: usize = 8;
const MAX_MOCK_HEADERS: usize = 64;
const MAX_MOCK_ERRORS: usize = 8;
const MAX_MOCK_ERROR_BYTES: usize = 4 * 1024;
const MAX_MOCK_ERROR_ENTRY_BYTES: usize = 512;
const MAX_MOCK_REQUEST_BYTES: usize = 256 * 1024;
const MAX_MOCK_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_EVENT_FILE_BYTES: usize = 256 * 1024;
const MAX_EVENT_RECORDS: usize = 64;
const MAX_CLI_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_CLI_STDERR_BYTES: usize = 64 * 1024;
const CLI_PIPE_READ_BYTES: usize = 8 * 1024;
const MAX_ADMIN_TOOLKIT_BODY_BYTES: usize = 256 * 1024;
const DEFAULT_ADMIN_OPERATOR_PEPPER: &[u8] = b"sbproxy-admin-operator-default-pepper-v1";

#[derive(Clone, Debug)]
struct CapturedRequest {
    request_line: String,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Clone, Debug, Default)]
struct MockErrorLog {
    entries: Vec<String>,
    retained_bytes: usize,
    truncated_entries: usize,
    dropped_entries: usize,
}

impl MockErrorLog {
    fn record(&mut self, error: impl std::fmt::Display) {
        if self.entries.len() >= MAX_MOCK_ERRORS || self.retained_bytes >= MAX_MOCK_ERROR_BYTES {
            self.dropped_entries = self.dropped_entries.saturating_add(1);
            return;
        }

        let rendered = error.to_string();
        let available = MAX_MOCK_ERROR_BYTES.saturating_sub(self.retained_bytes);
        let mut retained = rendered
            .len()
            .min(MAX_MOCK_ERROR_ENTRY_BYTES)
            .min(available);
        while retained > 0 && !rendered.is_char_boundary(retained) {
            retained -= 1;
        }
        if retained == 0 && !rendered.is_empty() {
            self.dropped_entries = self.dropped_entries.saturating_add(1);
            return;
        }
        if retained < rendered.len() {
            self.truncated_entries = self.truncated_entries.saturating_add(1);
        }
        self.entries.push(rendered[..retained].to_owned());
        self.retained_bytes = self.retained_bytes.saturating_add(retained);
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.truncated_entries == 0 && self.dropped_entries == 0
    }
}

fn record_mock_error(errors: &Arc<Mutex<MockErrorLog>>, error: impl std::fmt::Display) {
    errors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .record(error);
}

fn reserve_bounded_slot(counter: &AtomicUsize, limit: usize) -> bool {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < limit).then_some(current + 1)
        })
        .is_ok()
}

fn store_mock_request(
    requests: &Arc<Mutex<Vec<CapturedRequest>>>,
    request: CapturedRequest,
) -> io::Result<()> {
    let mut requests = requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if requests.len() >= MAX_MOCK_REQUESTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mock request exceeded request-count cap",
        ));
    }
    requests.push(request);
    Ok(())
}

/// A dependency-free HTTP/1.1 peer with bounded request reads and a bounded
/// shutdown. The proxy closes each connection because every response says so.
struct LoopbackJsonServer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    errors: Arc<Mutex<MockErrorLog>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    worker_done: mpsc::Receiver<()>,
}

impl LoopbackJsonServer {
    fn start(response_body: &str) -> Self {
        Self::start_delayed(response_body, Duration::ZERO)
    }

    fn start_delayed(response_body: &str, response_delay: Duration) -> Self {
        assert!(
            response_body.len() <= MAX_MOCK_RESPONSE_BYTES,
            "loopback mock response exceeds {MAX_MOCK_RESPONSE_BYTES}-byte cap"
        );
        assert!(
            response_delay <= IO_TIMEOUT,
            "loopback mock response delay exceeds its I/O deadline"
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock");
        listener
            .set_nonblocking(true)
            .expect("make loopback mock nonblocking");
        let port = listener.local_addr().expect("loopback address").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(MockErrorLog::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_done_tx, worker_done) = mpsc::sync_channel(1);
        let worker_requests = Arc::clone(&requests);
        let worker_accepted = Arc::clone(&accepted);
        let worker_errors = Arc::clone(&errors);
        let worker_stop = Arc::clone(&stop);
        let response_body = response_body.to_owned();
        let worker = std::thread::spawn(move || {
            let lifetime_deadline = Instant::now() + MOCK_SERVER_LIFETIME;
            while !worker_stop.load(Ordering::Acquire) {
                if Instant::now() >= lifetime_deadline {
                    record_mock_error(
                        &worker_errors,
                        format_args!("loopback mock exceeded {MOCK_SERVER_LIFETIME:?}"),
                    );
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if !reserve_bounded_slot(&worker_accepted, MAX_MOCK_CONNECTIONS) {
                            record_mock_error(
                                &worker_errors,
                                format_args!(
                                    "loopback mock exceeded {MAX_MOCK_CONNECTIONS} connections"
                                ),
                            );
                            break;
                        }
                        if let Err(error) = serve_json(
                            &mut stream,
                            &response_body,
                            response_delay,
                            Arc::clone(&worker_requests),
                        ) {
                            record_mock_error(&worker_errors, error);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        record_mock_error(&worker_errors, error);
                        break;
                    }
                }
            }
            let _ = worker_done_tx.send(());
        });
        Self {
            port,
            accepted,
            requests,
            errors,
            stop,
            worker: Some(worker),
            worker_done,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn wait_for_requests(&self, count: usize) -> Vec<CapturedRequest> {
        assert!(
            count <= MAX_MOCK_REQUESTS,
            "cannot wait for more than {MAX_MOCK_REQUESTS} bounded mock requests"
        );
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let requests = self.requests.lock().expect("mock request lock").clone();
            if requests.len() >= count {
                let errors = self.errors.lock().expect("mock error lock");
                assert!(errors.is_empty(), "loopback mock errors: {errors:?}");
                return requests;
            }
            assert!(
                Instant::now() < deadline,
                "loopback mock received {} of {count} requests; errors: {:?}",
                requests.len(),
                self.errors.lock().expect("mock error lock")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_no_connections_for(&self, observation: Duration) {
        let deadline = Instant::now() + observation;
        loop {
            assert_eq!(
                self.accepted.load(Ordering::Acquire),
                0,
                "governed refusal reached its denied socket"
            );
            if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for LoopbackJsonServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
        let _ = TcpStream::connect_timeout(&address, Duration::from_millis(100));
        match self.worker_done.recv_timeout(MOCK_SHUTDOWN_TIMEOUT) {
            Ok(()) => {
                // The completion signal is the bounded join: after it, the
                // worker has left its accept/serve loop. Dropping the handle
                // avoids adding an unbounded OS-thread join to test cleanup.
                let _ = self.worker.take();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = self.worker.take();
                panic!("loopback mock exited without a completion signal");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = self.worker.take();
                panic!("loopback mock did not stop within {MOCK_SHUTDOWN_TIMEOUT:?}");
            }
        }
    }
}

fn serve_json(
    stream: &mut TcpStream,
    response_body: &str,
    response_delay: Duration,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        if let Some(header_end) = find_headers_end(&bytes) {
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = parse_content_length(&headers)?;
            let request_end = header_end
                .checked_add(4)
                .and_then(|body_start| body_start.checked_add(content_length))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "mock request length overflow",
                    )
                })?;
            if request_end > MAX_MOCK_REQUEST_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mock request exceeded byte cap",
                ));
            }
            if bytes.len() >= request_end {
                break;
            }
        }
        if bytes.len() >= MAX_MOCK_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mock request exceeded byte cap",
            ));
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "mock request deadline elapsed",
            ));
        }
        let available = MAX_MOCK_REQUEST_BYTES.saturating_sub(bytes.len());
        let read_len = available.min(chunk.len());
        let read = stream.read(&mut chunk[..read_len])?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }

    let header_end = find_headers_end(&bytes).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP header end")
    })?;
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = HashMap::new();
    for (header_index, line) in lines.enumerate() {
        if header_index >= MAX_MOCK_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mock request exceeded header-count cap",
            ));
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = parse_content_length(&header_text)?;
    let body_start = header_end + 4;
    let body_end = body_start.checked_add(content_length).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "mock body length overflow")
    })?;
    if body_end > bytes.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "mock request body ended early",
        ));
    }
    let body = String::from_utf8_lossy(&bytes[body_start..body_end]).into_owned();
    store_mock_request(
        &requests,
        CapturedRequest {
            request_line,
            headers,
            body,
        },
    )?;

    if !response_delay.is_zero() {
        std::thread::sleep(response_delay);
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn find_headers_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> std::io::Result<usize> {
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse::<usize>().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Content-Length")
                });
            }
        }
    }
    Ok(0)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral address")
        .port()
}

fn config(
    admin_port: u16,
    agent_port: u16,
    denied_agent_port: u16,
    slow_agent_port: u16,
    provider_url: &str,
    events_path: &std::path::Path,
    tenant_admin_password_hash: &str,
) -> String {
    let events_path = serde_json::to_string(&events_path.display().to_string())
        .expect("serialize events path as a YAML string");
    format!(
        r#"
proxy:
  http_bind_port: 0
  tenants:
    - id: {ORIGIN_TENANT}
    - id: {OTHER_TENANT}
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: ${{AI_TOOLKIT_ADMIN_PASSWORD}}
    operators:
      - username: {TENANT_ADMIN_USER}
        password_hash: {tenant_admin_password_hash}
        role: admin
        tenant: {OTHER_TENANT}
  ai_toolkit:
    limits:
      max_agents: 4
      max_workflows: 4
      max_datasets: 4
      max_dataset_versions: 4
      max_dataset_entries: 8
      max_rollouts: 4
      max_rollout_versions: 4
      max_retained_operations: 32
      max_request_bytes: 65536
      max_response_bytes: 65536
      agent_concurrency: 2
      evaluation_concurrency: 2
      default_workflow_timeout_ms: 3000
      max_workflow_timeout_ms: 3000
    agents:
      - origin: {ORIGIN_HOST}
        id: loopback-agent
        endpoint: http://127.0.0.1:{agent_port}/invoke
        auth:
          shared_secret: env:AI_TOOLKIT_AGENT_SECRET
        capabilities:
          - name: summarize
            description: Return one bounded summary
            input_schema:
              type: object
              required:
                - question
              properties:
                question:
                  type: string
              additionalProperties: false
            output_schema:
              type: object
              required:
                - summary
              properties:
                summary:
                  type: string
              additionalProperties: false
      - origin: {ORIGIN_HOST}
        id: denied-agent
        endpoint: http://127.0.0.1:{denied_agent_port}/invoke
        auth:
          shared_secret: env:AI_TOOLKIT_AGENT_SECRET
        capabilities:
          - name: denied
            description: Exercise a governed refusal
            input_schema:
              type: object
              required:
                - question
              properties:
                question:
                  type: string
              additionalProperties: false
            output_schema:
              type: object
              required:
                - summary
              properties:
                summary:
                  type: string
              additionalProperties: false
      - origin: {ORIGIN_HOST}
        id: slow-agent
        endpoint: http://127.0.0.1:{slow_agent_port}/invoke
        auth:
          shared_secret: env:AI_TOOLKIT_AGENT_SECRET
        capabilities:
          - name: slow
            description: Exercise the whole-workflow deadline
            input_schema:
              type: object
              required:
                - question
              properties:
                question:
                  type: string
              additionalProperties: false
            output_schema:
              type: object
              required:
                - summary
              properties:
                summary:
                  type: string
              additionalProperties: false
    workflows:
      - origin: {ORIGIN_HOST}
        name: {WORKFLOW}
        initial_state: summarize
        max_steps: 2
        timeout_ms: 3000
        states:
          - name: summarize
            action: summarize
            transitions: {{}}
      - origin: {ORIGIN_HOST}
        name: {DENIED_WORKFLOW}
        initial_state: denied
        max_steps: 2
        timeout_ms: 3000
        states:
          - name: denied
            action: denied
            transitions: {{}}
      - origin: {ORIGIN_HOST}
        name: {SLOW_WORKFLOW}
        initial_state: slow
        max_steps: 2
        timeout_ms: 50
        states:
          - name: slow
            action: slow
            transitions: {{}}
    datasets: []
    prompt_rollouts:
      - origin: {ORIGIN_HOST}
        name: {PROMPT}
        salt: e2e-stable-salt-never-emit
        versions:
          - version: 7
            content: {PROMPT_CONTENT}
            weight: 1.0

egress:
  agent_orchestration:
    mode: deny_by_default
    hosts:
      - 127.0.0.1
    ports:
      - {agent_port}
      - {slow_agent_port}
    allow_private: true

events:
  sink: file
  path: {events_path}
  types:
    - ai_workflow_operation
    - ai_evaluation_operation
    - ai_prompt_rollout_selected
  queue_capacity: 32

observability:
  metrics:
    enabled: true

origins:
  "{ORIGIN_HOST}":
    tenant_id: {ORIGIN_TENANT}
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: ${{AI_TOOLKIT_PROVIDER_KEY}}
          base_url: "{provider_url}"
          allow_private_base_url: true
          models:
            - gpt-4o
      routing:
        strategy: round_robin
"#
    )
}

#[derive(Debug)]
struct BoundedCliCapture {
    retained: Vec<u8>,
    total_bytes: u64,
    overflowed: bool,
}

impl BoundedCliCapture {
    fn validate(&self, limit: usize, label: &str) -> Result<(), String> {
        let limit = u64::try_from(limit).unwrap_or(u64::MAX);
        let retained = u64::try_from(self.retained.len()).unwrap_or(u64::MAX);
        if retained != self.total_bytes.min(limit) || self.overflowed != (self.total_bytes > limit)
        {
            return Err(format!(
                "{label} capture accounting is inconsistent: retained={retained}, total={}, \
                 limit={limit}, overflowed={}",
                self.total_bytes, self.overflowed
            ));
        }
        Ok(())
    }
}

fn read_bounded_cli_stream<Reader>(
    mut reader: Reader,
    limit: usize,
) -> io::Result<BoundedCliCapture>
where
    Reader: Read,
{
    let mut capture = BoundedCliCapture {
        retained: Vec::with_capacity(limit.min(CLI_PIPE_READ_BYTES)),
        total_bytes: 0,
        overflowed: false,
    };
    let mut chunk = [0_u8; CLI_PIPE_READ_BYTES];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(capture),
            Ok(read) => {
                capture.total_bytes = capture
                    .total_bytes
                    .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                let available = limit.saturating_sub(capture.retained.len());
                let retain = available.min(read);
                capture.retained.extend_from_slice(&chunk[..retain]);
                capture.overflowed |= retain < read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

struct CliPipeDrain {
    receiver: mpsc::Receiver<io::Result<BoundedCliCapture>>,
    worker: JoinHandle<()>,
}

impl CliPipeDrain {
    fn start<Reader>(reader: Reader, limit: usize) -> Self
    where
        Reader: Read + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _ = sender.send(read_bounded_cli_stream(reader, limit));
        });
        Self { receiver, worker }
    }

    fn finish_before(self, deadline: Instant, label: &str) -> Result<BoundedCliCapture, String> {
        let Self { receiver, worker } = self;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let received = receiver.recv_timeout(remaining);
        // Never turn a bounded diagnostic read into an unbounded thread join.
        // Receiving a value proves the reader completed; disconnection proves it
        // exited or panicked. A timed-out reader remains memory-capped and its
        // JoinHandle is detached when dropped.
        drop(worker);
        match received {
            Ok(result) => result.map_err(|error| format!("drain {label}: {error}")),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(format!("{label} pipe drain exited without a result"))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "{label} pipe did not reach EOF before the CLI deadline"
            )),
        }
    }
}

struct BoundedCliOutput {
    stdout: CliPipeDrain,
    stderr: CliPipeDrain,
}

impl BoundedCliOutput {
    fn from_child(child: &mut Child) -> Result<Self, String> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "sbproxy CLI stdout pipe was unavailable".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "sbproxy CLI stderr pipe was unavailable".to_owned())?;
        Ok(Self {
            stdout: CliPipeDrain::start(stdout, MAX_CLI_STDOUT_BYTES),
            stderr: CliPipeDrain::start(stderr, MAX_CLI_STDERR_BYTES),
        })
    }

    fn finish_before(
        self,
        deadline: Instant,
    ) -> Result<(BoundedCliCapture, BoundedCliCapture), String> {
        let stdout = self.stdout.finish_before(deadline, "stdout");
        let stderr = self.stderr.finish_before(deadline, "stderr");
        match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => Ok((stdout, stderr)),
            (Err(stdout), Err(stderr)) => Err(format!(
                "stdout drain failed: {stdout}; stderr drain failed: {stderr}"
            )),
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        }
    }
}

fn run_cli(admin_port: u16, args: &[String]) -> Value {
    let deadline = Instant::now() + CLI_TIMEOUT;
    let mut child = Command::new(proxy_binary_path())
        .args(args)
        .env_remove("SB_ADMIN_URL")
        .env_remove("SB_ADMIN_USERNAME")
        .env_remove("SB_ADMIN_PASSWORD")
        .env("SB_ADMIN_URL", format!("http://127.0.0.1:{admin_port}"))
        .env("SB_ADMIN_USERNAME", ADMIN_USER)
        .env("SB_ADMIN_PASSWORD", ADMIN_SECRET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn sbproxy {args:?}: {error}"));
    let operation_deadline = deadline
        .checked_sub(CLI_CLEANUP_RESERVE)
        .unwrap_or(deadline);
    let drains = BoundedCliOutput::from_child(&mut child)
        .unwrap_or_else(|error| panic!("capture sbproxy {args:?}: {error}"));
    let mut timed_out = false;
    let mut poll_failure = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if !timed_out && Instant::now() >= operation_deadline => {
                timed_out = true;
                if let Err(error) = child.kill() {
                    poll_failure = Some(format!("kill timed-out sbproxy CLI: {error}"));
                }
            }
            Ok(None) if Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(remaining.min(Duration::from_millis(25)));
            }
            Ok(None) => {
                let _ = child.kill();
                poll_failure = Some(format!(
                    "sbproxy CLI did not exit before its enclosing {CLI_TIMEOUT:?} deadline"
                ));
                break None;
            }
            Err(error) => {
                let _ = child.kill();
                poll_failure = Some(format!("poll sbproxy CLI: {error}"));
                break None;
            }
        }
    };

    let (stdout, stderr) = drains.finish_before(deadline).unwrap_or_else(|error| {
        panic!("collect bounded sbproxy {args:?} output: {error}; poll_failure={poll_failure:?}")
    });
    stdout
        .validate(MAX_CLI_STDOUT_BYTES, "stdout")
        .unwrap_or_else(|error| panic!("sbproxy {args:?}: {error}"));
    stderr
        .validate(MAX_CLI_STDERR_BYTES, "stderr")
        .unwrap_or_else(|error| panic!("sbproxy {args:?}: {error}"));
    assert!(
        !stdout.overflowed && !stderr.overflowed,
        "sbproxy {args:?} output exceeded its capture cap: stdout_total={}, \
         stdout_cap={MAX_CLI_STDOUT_BYTES}, stderr_total={}, \
         stderr_cap={MAX_CLI_STDERR_BYTES}\nstdout prefix:\n{}\nstderr prefix:\n{}",
        stdout.total_bytes,
        stderr.total_bytes,
        String::from_utf8_lossy(&stdout.retained),
        String::from_utf8_lossy(&stderr.retained)
    );
    if timed_out || poll_failure.is_some() {
        panic!(
            "sbproxy {args:?} exceeded its operation deadline or could not be reaped: {}\n\
             stdout:\n{}\nstderr:\n{}",
            poll_failure
                .as_deref()
                .unwrap_or("operation deadline elapsed"),
            String::from_utf8_lossy(&stdout.retained),
            String::from_utf8_lossy(&stderr.retained)
        );
    }
    let status = status.unwrap_or_else(|| {
        panic!("sbproxy {args:?} ended without an exit status: {poll_failure:?}")
    });
    assert!(
        status.success(),
        "sbproxy {args:?} failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        status.code(),
        String::from_utf8_lossy(&stdout.retained),
        String::from_utf8_lossy(&stderr.retained)
    );
    serde_json::from_slice(&stdout.retained).unwrap_or_else(|error| {
        panic!(
            "sbproxy {args:?} returned non-JSON stdout: {error}\n{}",
            String::from_utf8_lossy(&stdout.retained)
        )
    })
}

fn cli_args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn admin_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(ADMIN_TIMEOUT)
        .build()
        .expect("build bounded admin client")
}

fn tenant_admin_password_hash() -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(DEFAULT_ADMIN_OPERATOR_PEPPER)
        .expect("HMAC-SHA256 accepts the fixed operator pepper");
    mac.update(TENANT_ADMIN_SECRET.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn authenticated_admin_post(
    client: &reqwest::blocking::Client,
    port: u16,
    path: &str,
    body: Value,
) -> (u16, String) {
    let response = client
        .post(format!("http://127.0.0.1:{port}{path}"))
        .basic_auth(ADMIN_USER, Some(ADMIN_SECRET))
        .json(&body)
        .send()
        .unwrap_or_else(|error| panic!("POST {path}: {error}"));
    let status = response.status().as_u16();
    let body = response
        .text()
        .unwrap_or_else(|error| panic!("read POST {path}: {error}"));
    (status, body)
}

fn declared_oversized_admin_request(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect admin body boundary");
    stream
        .set_read_timeout(Some(ADMIN_TIMEOUT))
        .expect("bound oversized admin response read");
    stream
        .set_write_timeout(Some(ADMIN_TIMEOUT))
        .expect("bound oversized admin request write");
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{ADMIN_USER}:{ADMIN_SECRET}"));
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Basic {credentials}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_ADMIN_TOOLKIT_BODY_BYTES + 1
    );
    stream
        .write_all(request.as_bytes())
        .expect("write declared cap-plus-one admin request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read declared cap-plus-one admin response");
    response
}

fn authenticated_admin_get(client: &reqwest::blocking::Client, port: u16, path: &str) -> Value {
    let response = client
        .get(format!("http://127.0.0.1:{port}{path}"))
        .basic_auth(ADMIN_USER, Some(ADMIN_SECRET))
        .send()
        .unwrap_or_else(|error| panic!("GET {path}: {error}"));
    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|error| panic!("read GET {path}: {error}"));
    assert!(status.is_success(), "GET {path} returned {status}: {body}");
    serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("GET {path} returned non-JSON: {error}: {body}"))
}

fn read_bounded_event_file(path: &std::path::Path) -> Result<String, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(format!("open {}: {error}", path.display())),
    };
    let read_limit = u64::try_from(MAX_EVENT_FILE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(MAX_EVENT_FILE_BYTES.min(8 * 1024));
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > MAX_EVENT_FILE_BYTES {
        return Err(format!(
            "{} exceeded the {MAX_EVENT_FILE_BYTES}-byte event-file cap",
            path.display()
        ));
    }
    String::from_utf8(bytes).map_err(|error| format!("{} was not UTF-8: {error}", path.display()))
}

fn validate_event_record_count(body: &str) -> Result<(), String> {
    let record_count = body.lines().count();
    if record_count > MAX_EVENT_RECORDS {
        return Err(format!(
            "typed event feed contained {record_count} records; cap is {MAX_EVENT_RECORDS}"
        ));
    }
    Ok(())
}

fn wait_for_typed_events(path: &std::path::Path) -> Vec<Value> {
    let expected = [
        "ai_workflow_operation",
        "ai_evaluation_operation",
        "ai_prompt_rollout_selected",
    ];
    let deadline = Instant::now() + EVENT_TIMEOUT;
    loop {
        let last = read_bounded_event_file(path)
            .unwrap_or_else(|error| panic!("bounded typed event read failed: {error}"));
        validate_event_record_count(&last)
            .unwrap_or_else(|error| panic!("bounded typed event read failed: {error}"));
        let events: Vec<Value> = last
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let has_all_types = expected.iter().all(|expected_type| {
            events
                .iter()
                .any(|event| event["event_type"] == *expected_type)
        });
        let has_negative_workflow_terminals = [
            (DENIED_WORKFLOW, "egress_refused"),
            (SLOW_WORKFLOW, "timeout"),
        ]
        .iter()
        .all(|(workflow, outcome)| {
            events.iter().any(|event| {
                event["event_type"] == "ai_workflow_operation"
                    && event["data"]["workflow_id"] == *workflow
                    && event["data"]["outcome"] == *outcome
            })
        });
        if has_all_types && has_negative_workflow_terminals {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "typed event feed did not converge within {EVENT_TIMEOUT:?}: {last}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn assert_no_sensitive_material(surface: &str, body: &str) {
    for sensitive in [
        ADMIN_SECRET,
        TENANT_ADMIN_SECRET,
        AGENT_SECRET,
        PROVIDER_KEY,
        WORKFLOW_INPUT,
        DENIED_WORKFLOW_INPUT,
        SLOW_WORKFLOW_INPUT,
        AGENT_OUTPUT,
        DATASET_INPUT,
        EVALUATION_RESPONSE,
        PROMPT_CONTENT,
        RAW_COHORT,
        "e2e-stable-salt-never-emit",
    ] {
        assert!(
            !body.contains(sensitive),
            "{surface} leaked sensitive/raw value {sensitive:?}: {body}"
        );
    }
}

fn assert_typed_event_contract(events: &[Value]) {
    let contracts: [(&str, &[&str]); 3] = [
        (
            "ai_workflow_operation",
            &[
                "duration_ms",
                "origin_id",
                "outcome",
                "steps",
                "workflow_id",
            ],
        ),
        (
            "ai_evaluation_operation",
            &[
                "cases",
                "dataset",
                "dataset_version",
                "duration_ms",
                "experiment_id",
                "origin_id",
                "outcome",
            ],
        ),
        (
            "ai_prompt_rollout_selected",
            &["cohort_digest", "origin_id", "outcome", "prompt", "version"],
        ),
    ];
    for (event_type, expected_fields) in contracts {
        let matching: Vec<_> = events
            .iter()
            .filter(|event| event["event_type"] == event_type)
            .collect();
        assert!(!matching.is_empty(), "missing {event_type}: {events:?}");
        assert!(
            matching
                .iter()
                .any(|event| event["data"]["outcome"] == "success"),
            "missing successful {event_type}: {events:?}"
        );
        let expected: BTreeSet<_> = expected_fields.iter().copied().collect();
        for event in matching {
            let actual: BTreeSet<_> = event["data"]
                .as_object()
                .unwrap_or_else(|| panic!("{event_type} data is not an object: {event}"))
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(actual, expected, "{event_type} field allowlist drifted");
            assert_eq!(event["data"]["origin_id"], ORIGIN_ID, "{event}");
            assert!(
                [
                    "success",
                    "invalid",
                    "unauthorized",
                    "not_found",
                    "egress_refused",
                    "timeout",
                    "body_too_large",
                    "response_too_large",
                    "internal",
                ]
                .contains(&event["data"]["outcome"].as_str().unwrap_or_default()),
                "{event_type} emitted an open outcome: {event}"
            );
            if event_type == "ai_prompt_rollout_selected" {
                let digest = event["data"]["cohort_digest"]
                    .as_str()
                    .expect("prompt event digest");
                assert_eq!(digest.len(), 64, "{event}");
                assert!(
                    digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                    "prompt event digest is not lowercase SHA-256 hex: {event}"
                );
            }
        }
    }
    for (workflow, outcome) in [
        (DENIED_WORKFLOW, "egress_refused"),
        (SLOW_WORKFLOW, "timeout"),
    ] {
        assert!(
            events.iter().any(|event| {
                event["event_type"] == "ai_workflow_operation"
                    && event["data"]["workflow_id"] == workflow
                    && event["data"]["outcome"] == outcome
            }),
            "missing terminal {outcome} event for {workflow}: {events:?}"
        );
    }
}

fn assert_exact_toolkit_metric(metrics: &str) {
    const FAMILY: &str = "sbproxy_ai_toolkit_operations_total";
    const CAPABILITIES: [&str; 3] = ["workflow", "evaluation", "prompt_rollout"];
    const OUTCOMES: [&str; 9] = [
        "success",
        "invalid",
        "unauthorized",
        "not_found",
        "egress_refused",
        "timeout",
        "body_too_large",
        "response_too_large",
        "internal",
    ];

    assert_eq!(
        metrics
            .lines()
            .filter(|line| line.starts_with(&format!("# HELP {FAMILY} ")))
            .count(),
        1,
        "metric HELP family missing or duplicated"
    );
    let type_line = format!("# TYPE {FAMILY} counter");
    assert_eq!(
        metrics
            .lines()
            .filter(|line| *line == type_line.as_str())
            .count(),
        1,
        "metric TYPE family missing or duplicated"
    );
    for line in metrics
        .lines()
        .filter(|line| line.contains("sbproxy_ai_toolkit_"))
    {
        assert!(
            line.starts_with(&format!("# HELP {FAMILY} "))
                || line == type_line.as_str()
                || line.starts_with(&format!("{FAMILY}{{")),
            "unexpected AI toolkit metric family: {line}"
        );
    }

    let mut observed = BTreeSet::new();
    for line in metrics
        .lines()
        .filter(|line| line.starts_with(&format!("{FAMILY}{{")))
    {
        let labels = line
            .split_once('{')
            .and_then(|(_, rest)| rest.split_once('}').map(|(labels, _)| labels))
            .unwrap_or_else(|| panic!("malformed toolkit metric sample: {line}"));
        let parsed: HashMap<_, _> = labels
            .split(',')
            .map(|label| {
                let (name, value) = label
                    .split_once('=')
                    .unwrap_or_else(|| panic!("malformed metric label: {line}"));
                (name, value.trim_matches('"'))
            })
            .collect();
        assert_eq!(
            parsed.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from(["capability", "outcome"]),
            "toolkit metric gained an unbounded label: {line}"
        );
        let capability = parsed["capability"];
        let outcome = parsed["outcome"];
        assert!(CAPABILITIES.contains(&capability), "{line}");
        assert!(OUTCOMES.contains(&outcome), "{line}");
        observed.insert((capability, outcome));
    }
    for expected in [
        ("workflow", "success"),
        ("workflow", "unauthorized"),
        ("workflow", "body_too_large"),
        ("workflow", "egress_refused"),
        ("workflow", "timeout"),
        ("evaluation", "success"),
        ("prompt_rollout", "success"),
    ] {
        assert!(
            observed.contains(&expected),
            "missing toolkit metric sample {expected:?}: {metrics}"
        );
    }
}

#[test]
fn live_ai_toolkit_contract_is_bounded_scoped_redacted_and_observable() {
    let agent_response = format!(r#"{{"outcome":"done","output":{{"summary":"{AGENT_OUTPUT}"}}}}"#);
    let provider_response = r#"{"id":"chatcmpl-e2e","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"provider-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let agent = LoopbackJsonServer::start(&agent_response);
    let denied_agent = LoopbackJsonServer::start(&agent_response);
    let slow_agent = LoopbackJsonServer::start_delayed(&agent_response, Duration::from_millis(250));
    let provider = LoopbackJsonServer::start(provider_response);
    let admin_port = free_port();
    let artifacts = tempfile::tempdir().expect("AI toolkit e2e artifacts");
    let events_path = artifacts.path().join("ai-toolkit.ndjson");
    let workflow_path = artifacts.path().join("workflow.yml");
    let input_path = artifacts.path().join("input.json");
    let dataset_path = artifacts.path().join("dataset.json");
    let responses_path = artifacts.path().join("responses.json");

    std::fs::write(
        &workflow_path,
        format!(
            r#"name: {WORKFLOW}
initial_state: summarize
states:
  - name: summarize
    action: summarize
    transitions: {{}}
max_steps: 2
timeout_ms: 3000
"#
        ),
    )
    .expect("write workflow fixture");
    std::fs::write(
        &input_path,
        serde_json::json!({"question": WORKFLOW_INPUT}).to_string(),
    )
    .expect("write workflow input");
    std::fs::write(
        &dataset_path,
        serde_json::json!({
            "name": DATASET,
            "version": 1,
            "entries": [{
                "input": DATASET_INPUT,
                "expected_output": EVALUATION_RESPONSE,
                "metadata": {"source": "e2e"}
            }]
        })
        .to_string(),
    )
    .expect("write dataset fixture");
    std::fs::write(
        &responses_path,
        serde_json::json!([EVALUATION_RESPONSE]).to_string(),
    )
    .expect("write evaluation responses");

    let yaml = config(
        admin_port,
        agent.port,
        denied_agent.port,
        slow_agent.port,
        &provider.base_url(),
        &events_path,
        &tenant_admin_password_hash(),
    );
    let proxy = ProxyHarness::start_with_workspace_shutdown_grace_and_env(
        &yaml,
        &[],
        3_000,
        &[
            ("AI_TOOLKIT_ADMIN_PASSWORD", ADMIN_SECRET),
            ("AI_TOOLKIT_AGENT_SECRET", AGENT_SECRET),
            ("AI_TOOLKIT_PROVIDER_KEY", PROVIDER_KEY),
        ],
    )
    .unwrap_or_else(|error| panic!("start live AI toolkit proxy: {error:#}"));
    proxy
        .wait_for_secondary_port(admin_port, Duration::from_secs(10))
        .unwrap_or_else(|error| panic!("AI toolkit admin listener: {error:#}"));

    let discovered = run_cli(
        admin_port,
        &cli_args(&[
            "ai",
            "workflow",
            "discover",
            "--origin",
            ORIGIN_ID,
            "--capability",
            "summarize",
        ]),
    );
    assert_eq!(discovered["agents"][0]["id"], "loopback-agent");
    assert_eq!(discovered["agents"][0]["capabilities"][0], "summarize");

    let validated = run_cli(
        admin_port,
        &[
            "ai".into(),
            "workflow".into(),
            "validate".into(),
            workflow_path.display().to_string(),
            "--origin".into(),
            ORIGIN_ID.into(),
        ],
    );
    assert_eq!(validated["valid"], true, "{validated}");

    let workflow = run_cli(
        admin_port,
        &[
            "ai".into(),
            "workflow".into(),
            "run".into(),
            "--origin".into(),
            ORIGIN_ID.into(),
            "--workflow".into(),
            WORKFLOW.into(),
            "--input".into(),
            input_path.display().to_string(),
        ],
    );
    assert_eq!(workflow["workflow"], WORKFLOW, "{workflow}");
    assert_eq!(workflow["completed"], true, "{workflow}");
    assert_eq!(workflow["final_state"], "summarize", "{workflow}");
    assert_eq!(workflow["output"]["summary"], AGENT_OUTPUT, "{workflow}");
    assert_eq!(workflow["steps"][0]["agent_id"], "loopback-agent");

    let agent_requests = agent.wait_for_requests(1);
    let agent_request = &agent_requests[0];
    assert!(agent_request.request_line.starts_with("POST /invoke "));
    assert!(agent_request.body.contains(WORKFLOW_INPUT));
    assert_eq!(
        agent_request
            .headers
            .get("x-sbproxy-agent-id")
            .map(String::as_str),
        Some("loopback-agent")
    );
    let mut token_digest = Sha256::new();
    token_digest.update(b"loopback-agent:");
    token_digest.update(AGENT_SECRET.as_bytes());
    let expected_token = hex::encode(token_digest.finalize());
    let expected_authorization = format!("Bearer {expected_token}");
    assert_eq!(
        agent_request
            .headers
            .get("authorization")
            .map(String::as_str),
        Some(expected_authorization.as_str())
    );
    assert!(
        !agent_request.body.contains(AGENT_SECRET),
        "raw agent secret reached request body"
    );

    let registered = run_cli(
        admin_port,
        &[
            "ai".into(),
            "dataset".into(),
            "register".into(),
            "--origin".into(),
            ORIGIN_ID.into(),
            "--dataset".into(),
            dataset_path.display().to_string(),
        ],
    );
    assert_eq!(registered["name"], DATASET, "{registered}");
    assert_eq!(registered["version"], 1, "{registered}");
    assert_eq!(registered["entries"], 1, "{registered}");

    let evaluation = run_cli(
        admin_port,
        &[
            "ai".into(),
            "evaluate".into(),
            "--origin".into(),
            ORIGIN_ID.into(),
            "--dataset".into(),
            DATASET.into(),
            "--version".into(),
            "1".into(),
            "--responses".into(),
            responses_path.display().to_string(),
            "--experiment-id".into(),
            "e2e-experiment".into(),
            "--experiment-name".into(),
            "AI toolkit e2e".into(),
            "--model".into(),
            "recorded-model".into(),
            "--min-bytes".into(),
            "1".into(),
            "--max-bytes".into(),
            "256".into(),
        ],
    );
    assert_eq!(evaluation["experiment_id"], "e2e-experiment");
    assert_eq!(evaluation["dataset"]["name"], DATASET);
    assert_eq!(evaluation["dataset"]["version"], 1);
    assert_eq!(evaluation["cases"], 1);
    assert_eq!(evaluation["expected_match_rate"], 1.0);
    assert_eq!(evaluation["metric_pass_rate"], 1.0);
    assert_no_sensitive_material(
        "evaluation result",
        &serde_json::to_string(&evaluation).expect("serialize evaluation result"),
    );

    let selection = run_cli(
        admin_port,
        &cli_args(&[
            "ai", "prompt", "select", "--origin", ORIGIN_ID, "--name", PROMPT, "--cohort",
            RAW_COHORT,
        ]),
    );
    assert_eq!(selection["name"], PROMPT, "{selection}");
    assert_eq!(selection["version"], 7, "{selection}");
    assert_eq!(selection["weight"], 1.0, "{selection}");
    let cohort_digest = selection["cohort_digest"]
        .as_str()
        .expect("prompt selection digest");
    assert_eq!(cohort_digest.len(), 64, "{selection}");
    let selection_wire = serde_json::to_string(&selection).expect("serialize prompt selection");
    assert!(selection.get("content").is_none(), "{selection}");
    assert_no_sensitive_material("prompt selection", &selection_wire);

    let live = proxy
        .post_json(
            "/v1/chat/completions",
            ORIGIN_HOST,
            &serde_json::json!({
                "model": "gpt-4o",
                "prompt": PROMPT,
                "messages": [{"role": "user", "content": "hello"}]
            }),
            &[],
        )
        .expect("live bare prompt rollout request");
    assert_eq!(live.status, 200, "{}", live.text().unwrap_or_default());
    let provider_requests = provider.wait_for_requests(1);
    let provider_request = &provider_requests[0];
    assert!(
        provider_request.request_line.contains("chat/completions"),
        "{}",
        provider_request.request_line
    );
    let forwarded: Value =
        serde_json::from_str(&provider_request.body).expect("provider request JSON");
    let provider_authorization = format!("Bearer {PROVIDER_KEY}");
    assert_eq!(
        provider_request
            .headers
            .get("authorization")
            .map(String::as_str),
        Some(provider_authorization.as_str())
    );
    assert!(!provider_request.body.contains(PROVIDER_KEY));
    assert_eq!(forwarded["messages"][0]["role"], "system", "{forwarded}");
    assert_eq!(
        forwarded["messages"][0]["content"], PROMPT_CONTENT,
        "{forwarded}"
    );
    assert_eq!(forwarded["messages"][1]["role"], "user", "{forwarded}");
    assert!(
        forwarded.get("prompt").is_none(),
        "gateway-only prompt selector reached provider: {forwarded}"
    );

    let client = admin_client();
    let unauthenticated = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/admin/ai-toolkit/agents?origin={ORIGIN_ID}"
        ))
        .send()
        .expect("unauthenticated toolkit request");
    assert_eq!(unauthenticated.status().as_u16(), 401);

    let tenant_login = client
        .post(format!("http://127.0.0.1:{admin_port}/admin/login"))
        .json(&serde_json::json!({
            "username": TENANT_ADMIN_USER,
            "password": TENANT_ADMIN_SECRET
        }))
        .send()
        .expect("tenant-scoped admin login");
    assert_eq!(tenant_login.status().as_u16(), 200);
    let tenant_cookie = tenant_login
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .expect("tenant-scoped admin session cookie");
    let tenant_session_token = tenant_cookie
        .split_once('=')
        .map(|(_, token)| token.to_owned())
        .expect("tenant-scoped admin session token");
    let tenant_login_body = tenant_login.text().expect("tenant login response body");
    assert_no_sensitive_material("tenant login response", &tenant_login_body);

    let cross_scope = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/admin/ai-toolkit/agents?origin={ORIGIN_ID}"
        ))
        .header(reqwest::header::COOKIE, tenant_cookie.as_str())
        .send()
        .expect("cross-scope toolkit request");
    assert_eq!(cross_scope.status().as_u16(), 403);
    let cross_scope_body = cross_scope.text().expect("cross-scope response body");
    assert!(
        cross_scope_body.contains("origin_outside_tenant_scope"),
        "{cross_scope_body}"
    );
    assert!(!cross_scope_body.contains(ORIGIN_TENANT));
    assert!(!cross_scope_body.contains(OTHER_TENANT));

    let oversized = declared_oversized_admin_request(admin_port, "/admin/ai-toolkit/workflows/run");
    assert!(oversized.starts_with("HTTP/1.1 413"), "{oversized}");
    assert!(oversized.contains("request_body_too_large"), "{oversized}");

    let (denied_status, denied_body) = authenticated_admin_post(
        &client,
        admin_port,
        "/admin/ai-toolkit/workflows/run",
        serde_json::json!({
            "origin": ORIGIN_ID,
            "workflow": DENIED_WORKFLOW,
            "input": {"question": DENIED_WORKFLOW_INPUT}
        }),
    );
    assert_eq!(denied_status, 502, "{denied_body}");
    assert!(
        denied_body.contains("agent_operation_failed"),
        "{denied_body}"
    );
    denied_agent.assert_no_connections_for(Duration::from_millis(200));

    let slow_started = Instant::now();
    let (slow_status, slow_body) = authenticated_admin_post(
        &client,
        admin_port,
        "/admin/ai-toolkit/workflows/run",
        serde_json::json!({
            "origin": ORIGIN_ID,
            "workflow": SLOW_WORKFLOW,
            "input": {"question": SLOW_WORKFLOW_INPUT}
        }),
    );
    assert_eq!(slow_status, 504, "{slow_body}");
    assert!(slow_body.contains("deadline_exceeded"), "{slow_body}");
    assert!(
        slow_started.elapsed() < Duration::from_secs(2),
        "50ms workflow deadline was not the outer bound"
    );
    assert_eq!(slow_agent.wait_for_requests(1).len(), 1);

    let snapshot = authenticated_admin_get(
        &client,
        admin_port,
        &format!("/admin/ai-toolkit/snapshot?origin={ORIGIN_ID}&limit=32"),
    );
    assert_eq!(snapshot["scope"]["origin_id"], ORIGIN_ID, "{snapshot}");
    assert_eq!(snapshot["scope"]["tenant_id"], ORIGIN_TENANT, "{snapshot}");
    assert!(
        snapshot["agents"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["id"] == "loopback-agent")),
        "{snapshot}"
    );
    assert!(
        snapshot["workflows"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["name"] == WORKFLOW)),
        "{snapshot}"
    );
    assert!(
        snapshot["datasets"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["name"] == DATASET && row["version"] == 1)),
        "{snapshot}"
    );
    assert!(
        snapshot["rollouts"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["name"] == PROMPT)),
        "{snapshot}"
    );
    assert!(
        snapshot["experiments"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["experiment_id"] == "e2e-experiment")),
        "{snapshot}"
    );
    let snapshot_wire = serde_json::to_string(&snapshot).expect("serialize snapshot");
    assert_no_sensitive_material("toolkit snapshot", &snapshot_wire);
    for endpoint in [
        agent.base_url(),
        denied_agent.base_url(),
        slow_agent.base_url(),
        provider.base_url(),
    ] {
        assert!(
            !snapshot_wire.contains(&endpoint),
            "toolkit snapshot leaked endpoint {endpoint}: {snapshot_wire}"
        );
    }

    let events = wait_for_typed_events(&events_path);
    assert_typed_event_contract(&events);
    let event_wire = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert_no_sensitive_material("typed event feed", &event_wire);

    let process_logs = format!("{}\n{}", proxy.stdout_contents(), proxy.stderr_contents());
    assert_no_sensitive_material("proxy process logs", &process_logs);
    for (surface, body) in [
        ("toolkit snapshot", snapshot_wire.as_str()),
        ("typed event feed", event_wire.as_str()),
        ("proxy process logs", process_logs.as_str()),
    ] {
        for token in [expected_token.as_str(), tenant_session_token.as_str()] {
            assert!(
                !body.contains(token),
                "{surface} leaked a derived bearer/session token"
            );
        }
    }

    let metrics = proxy
        .get("/metrics", ORIGIN_HOST)
        .expect("scrape live toolkit metrics");
    assert_eq!(metrics.status, 200);
    assert_exact_toolkit_metric(&metrics.text().expect("metrics UTF-8"));
}

#[test]
fn cli_pipe_capture_is_bounded_at_exact_and_cap_plus_one() {
    const CAP: usize = 32;
    let exact = CliPipeDrain::start(std::io::Cursor::new(vec![b'a'; CAP]), CAP)
        .finish_before(Instant::now() + Duration::from_secs(1), "exact fixture")
        .unwrap_or_else(|error| panic!("drain exact fixture: {error}"));
    exact
        .validate(CAP, "exact fixture")
        .unwrap_or_else(|error| panic!("validate exact fixture: {error}"));
    assert_eq!(exact.retained.len(), CAP);
    assert_eq!(exact.total_bytes, CAP as u64);
    assert!(!exact.overflowed);

    let over = CliPipeDrain::start(std::io::Cursor::new(vec![b'b'; CAP + 1]), CAP)
        .finish_before(
            Instant::now() + Duration::from_secs(1),
            "cap-plus-one fixture",
        )
        .unwrap_or_else(|error| panic!("drain cap-plus-one fixture: {error}"));
    over.validate(CAP, "cap-plus-one fixture")
        .unwrap_or_else(|error| panic!("validate cap-plus-one fixture: {error}"));
    assert_eq!(over.retained.len(), CAP);
    assert_eq!(over.total_bytes, (CAP + 1) as u64);
    assert!(over.overflowed);
}

#[test]
fn mock_connection_request_and_error_ledgers_are_bounded() {
    let connections = AtomicUsize::new(0);
    for _ in 0..MAX_MOCK_CONNECTIONS {
        assert!(reserve_bounded_slot(&connections, MAX_MOCK_CONNECTIONS));
    }
    assert!(!reserve_bounded_slot(&connections, MAX_MOCK_CONNECTIONS));
    assert_eq!(connections.load(Ordering::Acquire), MAX_MOCK_CONNECTIONS);

    let requests = Arc::new(Mutex::new(Vec::new()));
    let request = CapturedRequest {
        request_line: "POST / HTTP/1.1".to_owned(),
        headers: HashMap::new(),
        body: String::new(),
    };
    for _ in 0..MAX_MOCK_REQUESTS {
        store_mock_request(&requests, request.clone())
            .unwrap_or_else(|error| panic!("store in-cap mock request: {error}"));
    }
    let overflow = match store_mock_request(&requests, request) {
        Err(error) => error,
        Ok(()) => panic!("cap-plus-one mock request was stored"),
    };
    assert_eq!(overflow.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        MAX_MOCK_REQUESTS
    );

    let mut errors = MockErrorLog::default();
    let long_error = "x".repeat(MAX_MOCK_ERROR_ENTRY_BYTES + 1);
    for _ in 0..=MAX_MOCK_ERRORS {
        errors.record(&long_error);
    }
    assert_eq!(errors.entries.len(), MAX_MOCK_ERRORS);
    assert_eq!(errors.retained_bytes, MAX_MOCK_ERROR_BYTES);
    assert_eq!(errors.truncated_entries, MAX_MOCK_ERRORS);
    assert_eq!(errors.dropped_entries, 1);
}

#[test]
fn event_file_and_record_caps_reject_cap_plus_one() {
    let artifacts = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("create bounded event fixture directory: {error}"));
    let path = artifacts.path().join("events.ndjson");
    std::fs::write(&path, vec![b'x'; MAX_EVENT_FILE_BYTES])
        .unwrap_or_else(|error| panic!("write exact-cap event fixture: {error}"));
    let exact = read_bounded_event_file(&path)
        .unwrap_or_else(|error| panic!("read exact-cap event fixture: {error}"));
    assert_eq!(exact.len(), MAX_EVENT_FILE_BYTES);

    std::fs::write(&path, vec![b'x'; MAX_EVENT_FILE_BYTES + 1])
        .unwrap_or_else(|error| panic!("write cap-plus-one event fixture: {error}"));
    assert!(read_bounded_event_file(&path).is_err());

    let exact_records = "{}\n".repeat(MAX_EVENT_RECORDS);
    validate_event_record_count(&exact_records)
        .unwrap_or_else(|error| panic!("validate exact record count: {error}"));
    let too_many_records = "{}\n".repeat(MAX_EVENT_RECORDS + 1);
    assert!(validate_event_record_count(&too_many_records).is_err());
}
