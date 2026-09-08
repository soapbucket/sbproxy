// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{
    EngineAvailability, EngineCapabilities, EngineDetection, EngineDriverError,
    EngineExecutionIdentity, EngineHealth, EngineKind,
};
use sb_runtime_host::{
    BackoffPolicy, EngineCommand, EngineDriver, EngineProcess, EngineProcessRunner,
    EngineSupervisor, LaunchRequest, LoopbackReadinessProbe, ProvisionRequest, ProvisionedEngine,
    RunningEngine, TokioCommandExecutor,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const CHILD_PORT: &str = "NEUTRAL_RUNTIME_CONSUMER_PORT";
const CHILD_STOP_MARKER: &str = "NEUTRAL_RUNTIME_CONSUMER_STOP_MARKER";
const CHILD_TEST: &str = "external_consumer_runs_real_child_through_neutral_lifecycle";

struct ConsumerDriver {
    runner: EngineProcessRunner,
    provisions: AtomicU32,
    stop_marker: PathBuf,
}

#[async_trait]
impl EngineDriver for ConsumerDriver {
    type ArtifactFormat = &'static str;
    type Accelerator = &'static str;
    type Worker = ();
    type Provisioning = ();
    type ProvisionRequest = ProvisionRequest<&'static str, (), ()>;
    type ProvisionedEngine = ProvisionedEngine<()>;
    type LaunchRequest = LaunchRequest<&'static str, u64, &'static str, ()>;
    type RunningEngine = RunningEngine<&'static str, u64, dyn EngineProcess>;

    fn kind(&self) -> EngineKind {
        EngineKind::LlamaCpp
    }

    fn capabilities(&self) -> EngineCapabilities<Self::ArtifactFormat, Self::Accelerator> {
        EngineCapabilities {
            artifact_formats: vec!["consumer-fixture"],
            accelerators: vec!["cpu"],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(&self, _worker: &(), _provisioning: &()) -> EngineDetection {
        EngineDetection {
            kind: self.kind(),
            availability: EngineAvailability::Available,
            version: None,
            reason: "consumer test executable is installed".into(),
            remediation: None,
        }
    }

    fn launch_identity(&self, request: &Self::LaunchRequest) -> EngineExecutionIdentity {
        request.identity.clone()
    }

    fn running_identity(&self, running: &Self::RunningEngine) -> EngineExecutionIdentity {
        running.identity.clone()
    }

    async fn provision(
        &self,
        request: &Self::ProvisionRequest,
    ) -> Result<Self::ProvisionedEngine, EngineDriverError> {
        self.provisions.fetch_add(1, Ordering::SeqCst);
        Ok(ProvisionedEngine {
            kind: self.kind(),
            executable: std::env::current_exe().expect("resolve consumer executable"),
            version: Some("consumer-v1".into()),
            fingerprint: request.artifact.into(),
            state: (),
        })
    }

    async fn launch(
        &self,
        provisioned: &Self::ProvisionedEngine,
        request: &Self::LaunchRequest,
    ) -> Result<Self::RunningEngine, EngineDriverError> {
        request.validate()?;
        let command = EngineCommand {
            executable: provisioned.executable.clone(),
            arguments: vec!["--exact".into(), CHILD_TEST.into(), "--nocapture".into()],
            environment: BTreeMap::from([
                (CHILD_PORT.into(), request.identity.port.to_string()),
                (
                    CHILD_STOP_MARKER.into(),
                    self.stop_marker
                        .to_str()
                        .expect("UTF-8 temporary path")
                        .into(),
                ),
            ]),
            port: request.identity.port,
            health_path: "/health".into(),
            ready_timeout: request.ready_timeout,
            stderr_tail_lines: 10,
        };
        let process = self.runner.launch(&command).await?;
        Ok(RunningEngine {
            identity: request.identity.clone(),
            selected_devices: request.selected_devices.clone(),
            accelerator: request.accelerator,
            started_at_ms: 1,
            artifact_digest: request.artifact.into(),
            engine_version: provisioned.version.clone(),
            memory: request.fit,
            process,
        })
    }

    async fn health(
        &self,
        running: &Self::RunningEngine,
    ) -> Result<EngineHealth, EngineDriverError> {
        if running.process.has_exited().await? {
            return Ok(EngineHealth::Stopped);
        }
        Ok(
            if self.runner.ready(running.identity.port, "/health").await? {
                EngineHealth::Ready
            } else {
                EngineHealth::Unhealthy
            },
        )
    }

    async fn shutdown(
        &self,
        running: Self::RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError> {
        running.process.shutdown(grace).await
    }
}

async fn serve_child(port: u16) {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("register graceful termination before readiness");
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind child readiness endpoint");
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = terminate.recv() => {
                let path = std::env::var_os(CHILD_STOP_MARKER).expect("owned stop marker path");
                std::fs::write(path, b"graceful-stop").expect("record graceful termination");
                return;
            }
            _ = &mut deadline => panic!("child exceeded its independent lifetime bound"),
            connection = listener.accept() => {
                let (mut stream, _) = connection.expect("accept readiness connection");
                tokio::time::timeout(Duration::from_secs(1), async {
                    let mut request = [0_u8; 1024];
                    let mut count = 0;
                    while !request[..count].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        assert!(count < request.len(), "health request exceeded its bound");
                        let received = stream.read(&mut request[count..]).await.expect("read bounded health request");
                        assert_ne!(received, 0, "health request ended before its headers");
                        count += received;
                    }
                    let response: &[u8] = if request[..count].starts_with(b"GET /health HTTP/1.") {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    } else {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    stream.write_all(response).await.expect("write bounded health response");
                    stream.shutdown().await.expect("finish response");
                }).await.expect("bounded health exchange");
            }
        }
    }
}

#[tokio::test]
async fn external_consumer_runs_real_child_through_neutral_lifecycle() {
    if let Ok(port) = std::env::var(CHILD_PORT) {
        serve_child(port.parse().expect("valid child port")).await;
        return;
    }
    let directory = tempfile::tempdir().expect("owned consumer directory");
    let stop_marker = directory.path().join("graceful-stop");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("allocate loopback port");
    let port = listener.local_addr().expect("allocated port").port();
    let runner = EngineProcessRunner::new(
        Arc::new(TokioCommandExecutor::at(directory.path().join("ownership"))),
        Arc::new(LoopbackReadinessProbe),
    )
    .with_poll_interval(Duration::from_millis(10));
    let driver = Arc::new(ConsumerDriver {
        runner,
        provisions: AtomicU32::new(0),
        stop_marker: stop_marker.clone(),
    });
    let mut supervisor = EngineSupervisor::new(
        "consumer-runtime",
        Arc::clone(&driver),
        BackoffPolicy {
            max_attempts: Some(1),
            ..BackoffPolicy::default()
        },
    );
    let provisioned = supervisor
        .provision(&ProvisionRequest {
            artifact: "fixture-artifact",
            worker: (),
            provisioning: (),
            engine_cache_dir: directory.path().to_path_buf(),
        })
        .await
        .expect("provision through neutral supervisor");
    assert_eq!(driver.provisions.load(Ordering::SeqCst), 1);
    let identity = EngineExecutionIdentity {
        deployment: "consumer-runtime".into(),
        generation: 1,
        kind: EngineKind::LlamaCpp,
        port,
    };
    drop(listener);
    let running = supervisor
        .ensure_ready(
            &provisioned,
            &LaunchRequest {
                identity: identity.clone(),
                artifact: "fixture-artifact",
                fit: 0,
                accelerator: "cpu",
                selected_devices: vec![],
                tuning: (),
                max_concurrency: 1,
                ready_timeout: Duration::from_secs(5),
            },
        )
        .await
        .expect("spawn and probe real child");
    let pid = running.process.id().expect("real child PID");
    assert_ne!(pid, std::process::id());
    assert_eq!(running.identity, identity);
    assert!(!running.process.has_exited().await.expect("live child"));
    assert_eq!(
        supervisor.health(&running).await.expect("real HTTP health"),
        EngineHealth::Ready
    );
    assert!(!driver
        .runner
        .ready(port, "/not-health")
        .await
        .expect("negative HTTP probe"));
    supervisor
        .shutdown(Duration::from_secs(2))
        .await
        .expect("graceful neutral shutdown");
    assert!(supervisor.running().is_none());
    assert!(running
        .process
        .has_exited()
        .await
        .expect("child was reaped"));
    assert_eq!(
        supervisor.health(&running).await.expect("stopped health"),
        EngineHealth::Stopped
    );
    assert_eq!(
        std::fs::read(stop_marker).expect("child handled termination"),
        b"graceful-stop"
    );
    assert_eq!(
        std::fs::read_dir(directory.path().join("ownership"))
            .expect("ownership directory")
            .count(),
        0
    );
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn external_consumer_uses_public_retry_and_process_fakes() {
    use sb_runtime_core::EngineFailureReason;
    use sb_runtime_host::{
        FakeProcess, ManualClock, ScriptedDriver, ScriptedLaunchRequest, ScriptedProvisionedEngine,
        ScriptedRunningEngine,
    };

    const CANARY: &str = "CONSUMER_DEBUG_CANARY";
    let process = Arc::new(FakeProcess::new(Some(41)));
    process.set_stderr_tail(format!("Bearer {CANARY}"));
    let driver = Arc::new(ScriptedDriver::new(EngineKind::LlamaCpp, process.clone()));
    driver.push_launch_error(EngineDriverError::new(
        EngineFailureReason::EngineEarlyExit,
        format!("fixture startup refused with Bearer {CANARY}"),
        "retry fixture",
        true,
    ));
    assert!(!format!("{process:?}").contains(CANARY));
    assert!(!format!("{driver:?}").contains(CANARY));
    let clock = Arc::new(ManualClock::at(500));
    let mut supervisor = EngineSupervisor::new(
        "fixture-runtime",
        Arc::clone(&driver),
        BackoffPolicy {
            base: Duration::from_millis(7),
            max: Duration::from_millis(20),
            max_attempts: Some(2),
        },
    )
    .with_clock(clock.clone());
    let provisioned: ScriptedProvisionedEngine = supervisor
        .provision(&ProvisionRequest {
            artifact: "fixture-artifact".into(),
            worker: "cpu".into(),
            provisioning: "fixture".into(),
            engine_cache_dir: PathBuf::from("consumer-cache"),
        })
        .await
        .expect("fake provisioning");
    let launch: ScriptedLaunchRequest = LaunchRequest {
        identity: EngineExecutionIdentity {
            deployment: "fixture-runtime".into(),
            generation: 1,
            kind: EngineKind::LlamaCpp,
            port: 8000,
        },
        artifact: "fixture-artifact".into(),
        fit: 0,
        accelerator: "cpu".into(),
        selected_devices: vec![],
        tuning: (),
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    let running: ScriptedRunningEngine = supervisor
        .ensure_ready(&provisioned, &launch)
        .await
        .expect("one scripted retry then ready");
    assert_eq!(driver.launch_count(), 2);
    assert_eq!(clock.sleeps(), vec![Duration::from_millis(7)]);
    driver.set_health(EngineHealth::Unhealthy);
    assert_eq!(
        supervisor.health(&running).await.expect("fake unhealthy"),
        EngineHealth::Unhealthy
    );
    driver.set_health(EngineHealth::Ready);
    assert_eq!(
        supervisor.health(&running).await.expect("fake health"),
        EngineHealth::Ready
    );
    supervisor
        .shutdown(Duration::from_millis(1))
        .await
        .expect("fake shutdown");
    assert_eq!(process.shutdown_count(), 1);
    assert!(process.has_exited().await.expect("fake exited"));
    assert!(supervisor.running().is_none());
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn external_consumer_controls_public_executor_probe_and_process_fakes() {
    use std::path::Path;

    use sb_runtime_core::EngineFailureReason;
    use sb_runtime_host::{
        CommandExecutor, CommandOutput, EngineReadinessProbe, FakeCommandExecutor, FakeProcess,
        FakeReadinessProbe, ScriptedProvisionRequest, TokioSupervisorClock,
    };

    let _: TokioSupervisorClock = Default::default();
    let _: ScriptedProvisionRequest = ProvisionRequest {
        artifact: "fixture-artifact".into(),
        worker: "cpu".into(),
        provisioning: "fixture".into(),
        engine_cache_dir: PathBuf::from("consumer-cache"),
    };

    let process = Arc::new(FakeProcess::new(Some(42)));
    process.set_exited(true);
    assert!(process.has_exited().await.expect("scripted exit"));
    process.set_exited(false);
    process.set_shutdown_failure(true);
    let failure = process
        .shutdown(Duration::from_millis(1))
        .await
        .expect_err("scripted shutdown failure");
    assert_eq!(failure.reason(), EngineFailureReason::EngineShutdownFailed);
    process.set_shutdown_failure(false);

    let process_handle: Arc<dyn EngineProcess> = process.clone();
    let executor = FakeCommandExecutor::new(process_handle);
    executor.push_output(Ok(CommandOutput {
        success: true,
        stdout: "fixture-output".into(),
        stderr: String::new(),
    }));
    let output = executor
        .output(
            Path::new("/fixture/executable"),
            &[],
            &BTreeMap::new(),
            Duration::from_secs(1),
            1024,
        )
        .await
        .expect("queued command output");
    assert_eq!(output.stdout, "fixture-output");
    let spawned = executor
        .spawn(Path::new("/fixture/executable"), &[], &BTreeMap::new(), 8)
        .await
        .expect("fake spawn");
    assert_eq!(spawned.id(), Some(42));
    assert_eq!(executor.spawn_count(), 1);

    let probe = FakeReadinessProbe::new(false);
    probe.push(Ok(true));
    assert!(probe
        .ready(8000, "/health")
        .await
        .expect("queued readiness"));
    assert!(!probe
        .ready(8000, "/health")
        .await
        .expect("fallback readiness"));
    probe.set_fallback(true);
    assert!(probe
        .ready(8000, "/health")
        .await
        .expect("updated fallback readiness"));
    assert_eq!(probe.probe_count(), 3);
}
