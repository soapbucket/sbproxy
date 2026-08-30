#![cfg(unix)]

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const PIPE_CAPTURE_BYTES: usize = 16 * 1024;
const HTTP_CAPTURE_BYTES: usize = 1024 * 1024;
const EXTERNAL_WAIT: Duration = Duration::from_secs(5);

/// How long the very first exec of the shipped binary may take.
///
/// Two orders of magnitude above `EXTERNAL_WAIT` on purpose: this bounds an
/// operating-system assessment, not anything this workspace computes.
const FIRST_EXEC_WAIT: Duration = Duration::from_secs(120);

/// Pay the shipped binary's first-exec cost once, on its own thread, with a
/// deadline.
///
/// On macOS the FIRST exec of a freshly linked Mach-O blocks inside
/// `posix_spawn` while `syspolicyd` assesses the binary's provenance and
/// caches the verdict by cdhash. The block is in the PARENT and it happens
/// before any of the child's own code runs, so it is invisible to every
/// deadline in this file: they all start counting after `spawn` returns.
/// That is why the two listener tests below stalled for more than thirty
/// minutes on a cold binary on one machine and then passed in 0.3 seconds on
/// the retry that found the verdict cached. Nothing in the test was slow;
/// the test never started.
///
/// So the wait is moved here, where it can be bounded and named. `--help` is
/// what gets executed: clap answers it and exits, so if the deadline is
/// exceeded and this process leaves the exec behind, what it leaves behind
/// terminates on its own and holds no listener.
///
/// This never skips anything. On timeout it fails, loudly, with the
/// diagnosis, and the run that follows it finds a warm cache.
fn warm_shipped_binary() {
    static WARM: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARM.get_or_init(|| {
        let started = Instant::now();
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let status = Command::new(env!("CARGO_BIN_EXE_sbproxy-classifier"))
                .arg("--help")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = sender.send(status);
        });
        match receiver.recv_timeout(FIRST_EXEC_WAIT) {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                panic!("the shipped classifier binary could not be executed at all: {error}")
            }
            Err(_) => panic!(
                "the shipped classifier binary did not answer `--help` within {}s \
                 (waited {}s).\n\
                 \n\
                 This is almost certainly not a bug in this test. On macOS the first \
                 exec of a freshly linked binary blocks in posix_spawn while \
                 syspolicyd assesses its provenance, and a wedged daemon turns that \
                 into tens of minutes. Confirm it with `ps aux | grep -iE \
                 'syspolicyd|XprotectService'` (sustained CPU) and `sample <pid>` on \
                 a stuck child (parked at _dyld_start +0).\n\
                 \n\
                 Clear it with `sudo spctl --global-disable` (no reboot; re-enable \
                 with --global-enable) or by rebooting, then run this test again. \
                 The verdict is cached by cdhash, so the second exec is instant.",
                FIRST_EXEC_WAIT.as_secs(),
                started.elapsed().as_secs()
            ),
        }
    });
}

#[derive(Debug)]
struct Capture {
    retained: Vec<u8>,
    total: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStage {
    ChildWait,
    ChildKill,
    StdoutDrain,
    StderrDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupFailureKind {
    DeadlineExceeded,
    Io,
    ThreadPanicked,
    MissingOwnedHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DropFailureObservation {
    stage: CleanupStage,
    kind: CleanupFailureKind,
    during_unwind: bool,
}

#[derive(Default)]
struct ChildDropObservation {
    failures: Mutex<Vec<DropFailureObservation>>,
}

impl ChildDropObservation {
    fn record(&self, stage: CleanupStage, kind: CleanupFailureKind) {
        self.failures
            .lock()
            .expect("drop observation mutex remains owned")
            .push(DropFailureObservation {
                stage,
                kind,
                during_unwind: std::thread::panicking(),
            });
    }

    fn snapshot(&self) -> Vec<DropFailureObservation> {
        self.failures
            .lock()
            .expect("drop observation mutex remains owned")
            .clone()
    }
}

struct PipeDrainFailure {
    stage: CleanupStage,
    kind: CleanupFailureKind,
    source: Option<std::io::Error>,
    drain: Option<PipeDrain>,
}

struct PipeDrain {
    result: mpsc::Receiver<std::io::Result<Capture>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PipeDrain {
    fn spawn(mut pipe: impl Read + Send + 'static) -> Self {
        let (sender, result) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let mut retained = Vec::with_capacity(PIPE_CAPTURE_BYTES);
            let mut total = 0usize;
            let mut chunk = [0u8; 4096];
            let result = loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break Ok(Capture { retained, total }),
                    Ok(read) => {
                        total = match total.checked_add(read) {
                            Some(total) => total,
                            None => {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "child output byte count overflowed",
                                ));
                            }
                        };
                        let keep = PIPE_CAPTURE_BYTES.saturating_sub(retained.len()).min(read);
                        retained.extend_from_slice(&chunk[..keep]);
                    }
                    Err(error) => break Err(error),
                }
            };
            let _ = sender.send(result);
        });
        Self {
            result,
            thread: Some(thread),
        }
    }

    fn finish_before(
        mut self,
        deadline: Instant,
        stage: CleanupStage,
    ) -> Result<Capture, PipeDrainFailure> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.result.recv_timeout(remaining) {
            Ok(Ok(capture)) => match self.thread.take() {
                Some(thread) => match thread.join() {
                    Ok(()) => Ok(capture),
                    Err(_) => Err(PipeDrainFailure {
                        stage,
                        kind: CleanupFailureKind::ThreadPanicked,
                        source: None,
                        drain: None,
                    }),
                },
                None => Err(PipeDrainFailure {
                    stage,
                    kind: CleanupFailureKind::MissingOwnedHandle,
                    source: None,
                    drain: None,
                }),
            },
            Ok(Err(error)) => {
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
                Err(PipeDrainFailure {
                    stage,
                    kind: CleanupFailureKind::Io,
                    source: Some(error),
                    drain: None,
                })
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(PipeDrainFailure {
                stage,
                kind: CleanupFailureKind::DeadlineExceeded,
                source: Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("{stage:?} missed the cleanup deadline"),
                )),
                drain: Some(self),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let kind = match self.thread.take() {
                    Some(thread) => match thread.join() {
                        Ok(()) => CleanupFailureKind::Io,
                        Err(_) => CleanupFailureKind::ThreadPanicked,
                    },
                    None => CleanupFailureKind::MissingOwnedHandle,
                };
                Err(PipeDrainFailure {
                    stage,
                    kind,
                    source: Some(std::io::Error::other(
                        "pipe drain disconnected before producing a capture",
                    )),
                    drain: None,
                })
            }
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
    exited: Option<ExitedChild>,
    stdout: Option<PipeDrain>,
    stderr: Option<PipeDrain>,
    stdout_capture: Option<Capture>,
    stderr_capture: Option<Capture>,
    drop_observation: Arc<ChildDropObservation>,
    drop_cleanup_enabled: bool,
}

#[derive(Debug)]
struct CleanupReport {
    status: ExitStatus,
    killed: bool,
    stdout: Capture,
    stderr: Capture,
}

#[derive(Debug)]
struct ExitedChild {
    status: ExitStatus,
    killed: bool,
}

struct ChildCleanupError {
    stage: CleanupStage,
    kind: CleanupFailureKind,
    source: Option<std::io::Error>,
    guard: ChildGuard,
}

impl std::fmt::Debug for ChildCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildCleanupError")
            .field("stage", &self.stage)
            .field("kind", &self.kind)
            .field(
                "source",
                &self.source.as_ref().map(std::io::Error::to_string),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ChildCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => write!(
                formatter,
                "child cleanup failed at {:?} with {:?}: {source}",
                self.stage, self.kind
            ),
            None => write!(
                formatter,
                "child cleanup failed at {:?} with {:?}",
                self.stage, self.kind
            ),
        }
    }
}

impl std::error::Error for ChildCleanupError {}

impl ChildCleanupError {
    fn stage(&self) -> CleanupStage {
        self.stage
    }

    fn kind(&self) -> CleanupFailureKind {
        self.kind
    }

    fn into_guard(self) -> ChildGuard {
        self.guard
    }
}

impl ChildGuard {
    fn spawn(mut command: Command) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("shipped classifier binary starts");
        let stdout = PipeDrain::spawn(child.stdout.take().expect("child stdout is piped"));
        let stderr = PipeDrain::spawn(child.stderr.take().expect("child stderr is piped"));
        Self {
            child: Some(child),
            exited: None,
            stdout: Some(stdout),
            stderr: Some(stderr),
            stdout_capture: None,
            stderr_capture: None,
            drop_observation: Arc::new(ChildDropObservation::default()),
            drop_cleanup_enabled: true,
        }
    }

    fn drop_observation(&self) -> Arc<ChildDropObservation> {
        Arc::clone(&self.drop_observation)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self.child.as_mut() {
            Some(child) => child.try_wait(),
            None => Ok(self.exited.as_ref().map(|child| child.status)),
        }
    }

    // The error hands the child guard back to the caller so a failed cleanup
    // can still be retried or dropped deliberately, which makes it far larger
    // than the success value. Boxing keeps the common `Ok` path cheap.
    fn cleanup_before(
        mut self,
        deadline: Instant,
    ) -> Result<CleanupReport, Box<ChildCleanupError>> {
        if self.exited.is_none() {
            let Some(mut child) = self.child.take() else {
                return Err(self.cleanup_error(
                    CleanupStage::ChildWait,
                    CleanupFailureKind::MissingOwnedHandle,
                    None,
                ));
            };
            let killed = match child.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => match child.kill() {
                    Ok(()) => true,
                    Err(error) => {
                        self.child = Some(child);
                        return Err(self.cleanup_error(
                            CleanupStage::ChildKill,
                            CleanupFailureKind::Io,
                            Some(error),
                        ));
                    }
                },
                Err(error) => {
                    self.child = Some(child);
                    return Err(self.cleanup_error(
                        CleanupStage::ChildWait,
                        CleanupFailureKind::Io,
                        Some(error),
                    ));
                }
            };
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => {}
                    Err(error) => {
                        self.child = Some(child);
                        return Err(self.cleanup_error(
                            CleanupStage::ChildWait,
                            CleanupFailureKind::Io,
                            Some(error),
                        ));
                    }
                }
                if Instant::now() >= deadline {
                    self.child = Some(child);
                    return Err(self.cleanup_error(
                        CleanupStage::ChildWait,
                        CleanupFailureKind::DeadlineExceeded,
                        Some(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "shipped child missed its cleanup deadline",
                        )),
                    ));
                }
                std::thread::yield_now();
            };
            self.exited = Some(ExitedChild { status, killed });
        }

        if self.stdout_capture.is_none() {
            let Some(stdout) = self.stdout.take() else {
                return Err(self.cleanup_error(
                    CleanupStage::StdoutDrain,
                    CleanupFailureKind::MissingOwnedHandle,
                    None,
                ));
            };
            match stdout.finish_before(deadline, CleanupStage::StdoutDrain) {
                Ok(capture) => self.stdout_capture = Some(capture),
                Err(error) => {
                    self.stdout = error.drain;
                    return Err(self.cleanup_error(error.stage, error.kind, error.source));
                }
            }
        }

        if self.stderr_capture.is_none() {
            let Some(stderr) = self.stderr.take() else {
                return Err(self.cleanup_error(
                    CleanupStage::StderrDrain,
                    CleanupFailureKind::MissingOwnedHandle,
                    None,
                ));
            };
            match stderr.finish_before(deadline, CleanupStage::StderrDrain) {
                Ok(capture) => self.stderr_capture = Some(capture),
                Err(error) => {
                    self.stderr = error.drain;
                    return Err(self.cleanup_error(error.stage, error.kind, error.source));
                }
            }
        }

        let Some(exited) = self.exited.take() else {
            return Err(self.cleanup_error(
                CleanupStage::ChildWait,
                CleanupFailureKind::MissingOwnedHandle,
                None,
            ));
        };
        let Some(stdout) = self.stdout_capture.take() else {
            return Err(self.cleanup_error(
                CleanupStage::StdoutDrain,
                CleanupFailureKind::MissingOwnedHandle,
                None,
            ));
        };
        let Some(stderr) = self.stderr_capture.take() else {
            return Err(self.cleanup_error(
                CleanupStage::StderrDrain,
                CleanupFailureKind::MissingOwnedHandle,
                None,
            ));
        };
        Ok(CleanupReport {
            status: exited.status,
            killed: exited.killed,
            stdout,
            stderr,
        })
    }

    fn cleanup_error(
        self,
        stage: CleanupStage,
        kind: CleanupFailureKind,
        source: Option<std::io::Error>,
    ) -> Box<ChildCleanupError> {
        Box::new(ChildCleanupError {
            stage,
            kind,
            source,
            guard: self,
        })
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.drop_cleanup_enabled {
            return;
        }
        if self.child.is_none()
            && self.exited.is_none()
            && self.stdout.is_none()
            && self.stderr.is_none()
        {
            return;
        }
        let owned = Self {
            child: self.child.take(),
            exited: self.exited.take(),
            stdout: self.stdout.take(),
            stderr: self.stderr.take(),
            stdout_capture: self.stdout_capture.take(),
            stderr_capture: self.stderr_capture.take(),
            drop_observation: Arc::clone(&self.drop_observation),
            drop_cleanup_enabled: false,
        };
        if let Err(error) = owned.cleanup_before(Instant::now() + Duration::from_millis(250)) {
            self.drop_observation.record(error.stage(), error.kind());
            drop(error.into_guard());
        }
    }
}

fn startup_owner_metric_samples(metrics: &[u8]) -> usize {
    let metrics = std::str::from_utf8(metrics).expect("metrics response is utf-8");
    metrics
        .lines()
        .filter(|line| {
            line.starts_with("sbproxy_classifier_startup_owner_info{")
                && line.contains("entrypoint=\"release_main\"")
                && line.contains("owner=\"prepared_capability\"")
                && line.ends_with(" 1")
        })
        .count()
}

fn reserve_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners = (0..count)
        .map(|_| std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect()
}

async fn http_get(address: SocketAddr, path: &str) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream
        .take(HTTP_CAPTURE_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .await?;
    if response.len() > HTTP_CAPTURE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP response exceeded its test capture ceiling",
        ));
    }
    Ok(response)
}

async fn wait_for_http_ready(child: &mut ChildGuard, address: SocketAddr) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + EXTERNAL_WAIT;
    loop {
        if let Some(status) = child.try_wait().expect("child status remains observable") {
            panic!("shipped classifier exited before readiness: {status}");
        }
        if let Ok(response) = http_get(address, "/readyz").await {
            if response.starts_with(b"HTTP/1.1 200 ") {
                return response;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "shipped classifier did not publish readiness before its deadline"
        );
        tokio::task::yield_now().await;
    }
}

#[derive(Serialize)]
struct WireRequest<'a> {
    cmd: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    admin_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<TenantConfig<'a>>,
}

impl<'a> WireRequest<'a> {
    fn new(cmd: &'a str) -> Self {
        Self {
            cmd,
            admin_token: None,
            tenant: None,
            text: None,
            config: None,
        }
    }

    fn authorized_by(mut self, token: &'a str) -> Self {
        self.admin_token = Some(token);
        self
    }

    fn for_tenant(mut self, tenant: &'a str) -> Self {
        self.tenant = Some(tenant);
        self
    }

    fn carrying_text(mut self, text: &'a str) -> Self {
        self.text = Some(text);
        self
    }

    fn carrying_config(mut self, config: TenantConfig<'a>) -> Self {
        self.config = Some(config);
        self
    }
}

#[derive(Serialize)]
struct TenantConfig<'a> {
    labels: Vec<TenantLabel<'a>>,
}

#[derive(Serialize)]
struct TenantLabel<'a> {
    name: &'a str,
    patterns: Vec<String>,
    weight: f64,
}

#[derive(Deserialize)]
struct AdminResponse {
    ok: bool,
}

#[derive(Deserialize)]
struct VersionResponse {
    name: String,
    version: String,
}

async fn wire_exchange<T: for<'de> Deserialize<'de>>(
    address: SocketAddr,
    request: &WireRequest<'_>,
) -> T {
    let payload = rmp_serde::to_vec_named(request).unwrap();
    let mut stream = tokio::time::timeout(EXTERNAL_WAIT, TcpStream::connect(address))
        .await
        .expect("wire connect is bounded")
        .unwrap();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&payload).await.unwrap();
    let length = stream.read_u32().await.unwrap() as usize;
    assert!(length <= 4 * 1024 * 1024);
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).await.unwrap();
    rmp_serde::from_slice(&response).unwrap()
}

struct CleanupDeadlineRelease {
    release: Option<UnixStream>,
    _socket_dir: tempfile::TempDir,
}

impl CleanupDeadlineRelease {
    fn release(mut self) {
        if let Some(mut release) = self.release.take() {
            release
                .write_all(&[1])
                .expect("fixture release byte reaches descendant");
        }
    }
}

impl Drop for CleanupDeadlineRelease {
    fn drop(&mut self) {
        if let Some(mut release) = self.release.take() {
            let _ = release.write_all(&[1]);
        }
    }
}

fn spawn_cleanup_deadline_fixture() -> (ChildGuard, CleanupDeadlineRelease) {
    let socket_dir = tempfile::tempdir().expect("cleanup fixture tempdir creates");
    let socket_path = socket_dir.path().join("cleanup-hold.sock");
    let listener =
        UnixListener::bind(&socket_path).expect("cleanup fixture binds readiness socket");
    listener
        .set_nonblocking(true)
        .expect("cleanup fixture socket stays configurable");

    let mut command = Command::new("python3");
    command.arg("-c").arg(
        r#"import os, signal, socket, sys
path = sys.argv[1]
pid = os.fork()
if pid == 0:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    sock.sendall(b"R")
    sock.recv(1)
    sock.close()
    os._exit(0)
signal.pause()
"#,
    );
    command.arg(socket_path.as_os_str());
    let child = ChildGuard::spawn(command);

    let deadline = Instant::now() + Duration::from_secs(2);
    let release = loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("cleanup fixture readiness stream stays readable");
                let mut ready = [0u8; 1];
                stream
                    .read_exact(&mut ready)
                    .expect("descendant readiness byte arrives");
                assert_eq!(
                    ready,
                    [b'R'],
                    "descendant must confirm it is holding inherited pipe ownership"
                );
                break stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "cleanup fixture descendant never proved inherited pipe ownership"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("cleanup fixture readiness socket failed: {error}"),
        }
    };
    release
        .set_nonblocking(false)
        .expect("cleanup fixture release stream stays writable");
    (
        child,
        CleanupDeadlineRelease {
            release: Some(release),
            _socket_dir: socket_dir,
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shipped_binary_uses_production_http_tcp_and_grpc_startup_owners() {
    warm_shipped_binary();
    let addresses = reserve_addresses(4);
    let (grpc, public, admin, http) = (addresses[0], addresses[1], addresses[2], addresses[3]);
    let token_dir = tempfile::tempdir().expect("admin token tempdir creates");
    let token_path = token_dir.path().join("admin-tokens.json");
    std::fs::write(
        &token_path,
        br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#,
    )
    .unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_sbproxy-classifier"));
    let args = [
        "--listen".to_string(),
        grpc.to_string(),
        "--listen-tcp".to_string(),
        public.to_string(),
        "--listen-admin".to_string(),
        admin.to_string(),
        "--admin-token-file".to_string(),
        token_path.to_string_lossy().into_owned(),
        "--metrics-addr".to_string(),
        http.to_string(),
    ];
    command.args(args);
    let mut child = ChildGuard::spawn(command);

    let ready = wait_for_http_ready(&mut child, http).await;
    assert!(ready.starts_with(b"HTTP/1.1 200 "));
    assert!(http_get(http, "/healthz")
        .await
        .unwrap()
        .starts_with(b"HTTP/1.1 200 "));
    let metrics = http_get(http, "/metrics").await.unwrap();
    assert_eq!(
        startup_owner_metric_samples(&metrics),
        1,
        "the shipped child must expose exactly one release startup-owner sample"
    );

    let public_version: VersionResponse = wire_exchange(public, &WireRequest::new("version")).await;
    assert_eq!(public_version.name, "sbproxy-classifier");
    assert!(!public_version.version.is_empty());

    let admin_list: AdminResponse =
        wire_exchange(admin, &WireRequest::new("list").authorized_by("secret")).await;
    assert!(admin_list.ok);

    let mut grpc_client = tokio::time::timeout(
        EXTERNAL_WAIT,
        sbproxy_classifier_proto::InferenceServiceClient::connect(format!("http://{grpc}")),
    )
    .await
    .expect("generated gRPC connect is bounded")
    .unwrap();
    let version = tokio::time::timeout(
        EXTERNAL_WAIT,
        grpc_client.version(sbproxy_classifier_proto::VersionRequest {}),
    )
    .await
    .expect("generated Version is bounded")
    .unwrap()
    .into_inner();
    assert!(version.version.contains("sbproxy-classifier"));

    let cleanup = child
        .cleanup_before(Instant::now() + Duration::from_secs(3))
        .expect("shipped child cleanup remains bounded and fully owned");
    assert!(
        cleanup.killed,
        "listener child must still be live before cleanup"
    );
    assert!(!cleanup.status.success());
    assert_eq!(cleanup.stdout.retained.len(), cleanup.stdout.total);
    assert_eq!(cleanup.stderr.retained.len(), cleanup.stderr.total);
    assert!(cleanup.stdout.total <= PIPE_CAPTURE_BYTES);
    assert!(cleanup.stderr.total <= PIPE_CAPTURE_BYTES);
}

/// The shipped binary's public classify path runs on the bounded executor
/// its `--inference-*` flags configure.
///
/// This is the one lane a `#[cfg(test)]`-only wiring cannot pass. The
/// in-crate regressions drive the same listener pair but compile with
/// `cfg(test)` set, so they went green against a release build that threw
/// the executor away and ran `handle_classify` inline on a tokio worker with
/// no cap, no queue, and no deadline. Here the child is the real release
/// entrypoint: the only way its answer can carry the deadline refusal, and
/// the only way `sbproxy_classifier_terminal_outcomes_total` can carry
/// `stage="worker",reason="deadline"` for `transport="tcp"`, is if the
/// shipped code path is the executor's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shipped_binary_bounds_public_classify_with_its_configured_inference_deadline() {
    warm_shipped_binary();
    let addresses = reserve_addresses(4);
    let (grpc, public, admin, http) = (addresses[0], addresses[1], addresses[2], addresses[3]);
    let token_dir = tempfile::tempdir().expect("admin token tempdir creates");
    let token_path = token_dir.path().join("admin-tokens.json");
    std::fs::write(
        &token_path,
        br#"{"tokens":[{"token":"secret","tenants":["*"]}]}"#,
    )
    .unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_sbproxy-classifier"));
    command.args([
        "--listen".to_string(),
        grpc.to_string(),
        "--listen-tcp".to_string(),
        public.to_string(),
        "--listen-admin".to_string(),
        admin.to_string(),
        "--admin-token-file".to_string(),
        token_path.to_string_lossy().into_owned(),
        "--metrics-addr".to_string(),
        http.to_string(),
        // One millisecond is the smallest deadline `Admission::new` accepts.
        // The classify below is 64 patterns over 256 KiB of text, which is
        // orders of magnitude more work than that, so the refusal is the
        // deadline rather than a race with it.
        "--inference-deadline-ms".to_string(),
        "1".to_string(),
    ]);
    let mut child = ChildGuard::spawn(command);
    wait_for_http_ready(&mut child, http).await;

    let register: AdminResponse = wire_exchange(
        admin,
        &WireRequest::new("register")
            .authorized_by("secret")
            .for_tenant("tenant.example")
            .carrying_config(TenantConfig {
                labels: (0..64)
                    .map(|index| TenantLabel {
                        name: "greeting",
                        patterns: vec![format!("(?i)needle-{index}-[a-z0-9]+")],
                        weight: 1.0,
                    })
                    .collect(),
            }),
    )
    .await;
    assert!(register.ok, "the shipped child must accept the tenant");

    let text = "lorem ipsum dolor sit amet ".repeat(10_000);
    let refusal: AdminResponse = wire_exchange(
        public,
        &WireRequest::new("classify")
            .for_tenant("tenant.example")
            .carrying_text(&text),
    )
    .await;
    assert!(
        !refusal.ok,
        "the shipped release build must refuse a classify past --inference-deadline-ms rather than running it inline to completion"
    );

    let metrics = http_get(http, "/metrics").await.unwrap();
    assert_eq!(
        public_classify_worker_deadline_samples(&metrics),
        1,
        "the shipped child must record the bounded executor's deadline outcome for the public TCP transport"
    );

    child
        .cleanup_before(Instant::now() + Duration::from_secs(3))
        .expect("shipped child cleanup remains bounded and fully owned");
}

fn public_classify_worker_deadline_samples(metrics: &[u8]) -> usize {
    let metrics = std::str::from_utf8(metrics).expect("metrics response is utf-8");
    metrics
        .lines()
        .filter(|line| {
            line.starts_with("sbproxy_classifier_terminal_outcomes_total{")
                && line.contains("cmd=\"classify\"")
                && line.contains("reason=\"deadline\"")
                && line.contains("stage=\"worker\"")
                && line.contains("transport=\"tcp\"")
                && line.ends_with(" 1")
        })
        .count()
}

#[test]
fn shipped_child_cleanup_surfaces_failures_and_never_detaches_owned_handles() {
    let (child, release) = spawn_cleanup_deadline_fixture();
    let observation = child.drop_observation();
    let error = match child.cleanup_before(Instant::now() + Duration::from_millis(25)) {
        Ok(report) => panic!(
            "expected cleanup deadline failure, got status={:?} killed={}",
            report.status, report.killed
        ),
        Err(error) => error,
    };
    assert_eq!(error.kind(), CleanupFailureKind::DeadlineExceeded);
    assert_eq!(error.stage(), CleanupStage::StdoutDrain);

    release.release();
    let cleanup = error
        .into_guard()
        .cleanup_before(Instant::now() + Duration::from_secs(2))
        .expect("retry retains all owned handles until drain completion");
    assert_eq!(cleanup.stdout.retained.len(), cleanup.stdout.total);
    assert_eq!(cleanup.stderr.retained.len(), cleanup.stderr.total);
    assert!(observation.snapshot().is_empty());

    let (child, release) = spawn_cleanup_deadline_fixture();
    let drop_observation = child.drop_observation();
    let error = child
        .cleanup_before(Instant::now() + Duration::from_millis(25))
        .expect_err("short deadline must surface a typed cleanup failure");
    drop(error.into_guard());
    let failures = drop_observation.snapshot();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].stage, CleanupStage::StdoutDrain);
    assert_eq!(failures[0].kind, CleanupFailureKind::DeadlineExceeded);
    assert!(
        !failures[0].during_unwind,
        "drop observation in the regression test runs outside unwind"
    );
    release.release();
}
