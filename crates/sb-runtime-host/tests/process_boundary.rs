// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{EngineDriverError, EngineFailureReason};
use sb_runtime_host::{
    CommandExecutor, CommandOutput, EngineCommand, EngineProcess, EngineProcessRunner,
    EngineReadinessProbe,
};

#[derive(Debug)]
struct FixtureProcess {
    exited: AtomicBool,
    shutdowns: AtomicUsize,
    tail: String,
}

#[async_trait]
impl EngineProcess for FixtureProcess {
    fn id(&self) -> Option<u32> {
        Some(42)
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        Ok(self.exited.load(Ordering::SeqCst))
    }

    async fn shutdown(&self, _grace: Duration) -> Result<(), EngineDriverError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.exited.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stderr_tail(&self) -> String {
        self.tail.clone()
    }
}

#[derive(Debug)]
struct FixtureExecutor {
    process: Arc<FixtureProcess>,
}

#[async_trait]
impl CommandExecutor for FixtureExecutor {
    async fn spawn(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        Ok(self.process.clone())
    }
}

#[derive(Debug)]
struct FixtureProbe(bool);

#[async_trait]
impl EngineReadinessProbe for FixtureProbe {
    async fn ready(&self, _port: u16, _path: &str) -> Result<bool, EngineDriverError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct PendingProbe;

#[async_trait]
impl EngineReadinessProbe for PendingProbe {
    async fn ready(&self, _port: u16, _path: &str) -> Result<bool, EngineDriverError> {
        std::future::pending().await
    }
}

#[derive(Debug)]
struct CanaryOutputExecutor;

#[async_trait]
impl CommandExecutor for CanaryOutputExecutor {
    async fn spawn(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        Err(EngineDriverError::blocked("unused", "unused"))
    }

    async fn output(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        Ok(CommandOutput {
            success: true,
            stdout: "{\"authorization\":\"Bearer SYNTHETIC_JSON_CANARY\"}".to_string(),
            stderr: "--api-key=SYNTHETIC_ATTACHED_CANARY".to_string(),
        })
    }
}

fn command() -> EngineCommand {
    EngineCommand {
        executable: "/fixture/engine".into(),
        arguments: vec!["serve".to_string()],
        environment: BTreeMap::new(),
        port: 18_080,
        health_path: "/health".to_string(),
        ready_timeout: Duration::from_millis(5),
        stderr_tail_lines: 20,
    }
}

#[tokio::test]
async fn tokenized_runner_returns_only_after_the_typed_probe_is_ready() {
    let process = Arc::new(FixtureProcess {
        exited: AtomicBool::new(false),
        shutdowns: AtomicUsize::new(0),
        tail: String::new(),
    });
    let runner = EngineProcessRunner::new(
        Arc::new(FixtureExecutor {
            process: process.clone(),
        }),
        Arc::new(FixtureProbe(true)),
    );

    let running = runner.launch(&command()).await.expect("ready process");
    assert_eq!(running.id(), Some(42));
    assert_eq!(process.shutdowns.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn readiness_timeout_cleans_up_the_spawned_process() {
    let process = Arc::new(FixtureProcess {
        exited: AtomicBool::new(false),
        shutdowns: AtomicUsize::new(0),
        tail: String::new(),
    });
    let runner = EngineProcessRunner::new(
        Arc::new(FixtureExecutor {
            process: process.clone(),
        }),
        Arc::new(FixtureProbe(false)),
    )
    .with_poll_interval(Duration::from_millis(1));

    let error = runner
        .launch(&command())
        .await
        .expect_err("unready process must time out");
    assert_eq!(error.reason(), EngineFailureReason::EngineReadinessTimeout);
    assert_eq!(process.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn early_exit_retains_only_redacted_bounded_diagnostics() {
    let process = Arc::new(FixtureProcess {
        exited: AtomicBool::new(true),
        shutdowns: AtomicUsize::new(0),
        tail: "failure --api-key=SYNTHETIC_CANARY".to_string(),
    });
    let runner = EngineProcessRunner::new(
        Arc::new(FixtureExecutor { process }),
        Arc::new(FixtureProbe(false)),
    );

    let error = runner
        .launch(&command())
        .await
        .expect_err("exited process must fail launch");
    assert_eq!(error.reason(), EngineFailureReason::EngineEarlyExit);
    assert_eq!(
        error.diagnostic_tail(),
        Some("failure --api-key=[REDACTED]")
    );
}

#[tokio::test]
async fn dropped_launch_future_still_cleans_up_the_spawned_process() {
    let process = Arc::new(FixtureProcess {
        exited: AtomicBool::new(false),
        shutdowns: AtomicUsize::new(0),
        tail: String::new(),
    });
    let runner = EngineProcessRunner::new(
        Arc::new(FixtureExecutor {
            process: process.clone(),
        }),
        Arc::new(PendingProbe),
    );

    let launch = tokio::spawn(async move { runner.launch(&command()).await });
    tokio::task::yield_now().await;
    launch.abort();
    let _ = launch.await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while process.shutdowns.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancellation cleanup");
    assert_eq!(process.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn public_command_output_is_bounded_and_redacted_again_at_the_runner_boundary() {
    let raw = CommandOutput {
        success: true,
        stdout: r#"{"authorization":"Bearer SYNTHETIC_DIRECT_CANARY"}"#.to_string(),
        stderr: "--hf-token=SYNTHETIC_DIRECT_ATTACHED".to_string(),
    };
    let raw_debug = format!("{raw:?}");
    assert!(!raw_debug.contains("SYNTHETIC_DIRECT_CANARY"));
    assert!(!raw_debug.contains("SYNTHETIC_DIRECT_ATTACHED"));

    let runner =
        EngineProcessRunner::new(Arc::new(CanaryOutputExecutor), Arc::new(FixtureProbe(true)));
    let output = runner
        .output(
            Path::new("/fixture/probe"),
            &[],
            &BTreeMap::new(),
            Duration::from_secs(1),
            4_096,
        )
        .await
        .expect("bounded output");
    let diagnostic = format!("{output:?}");
    assert!(!diagnostic.contains("SYNTHETIC_JSON_CANARY"));
    assert!(!diagnostic.contains("SYNTHETIC_ATTACHED_CANARY"));
    assert!(output.stdout.contains("[REDACTED]"));
    assert!(output.stderr.contains("[REDACTED]"));
}

#[test]
fn typed_command_rejects_runtime_boundary_overrides_and_invalid_bounds() {
    let mut invalid = command();
    invalid.executable = Path::new("").into();
    assert_eq!(
        invalid.validate().expect_err("empty executable").reason(),
        EngineFailureReason::EngineSpawnFailed
    );

    invalid = command();
    invalid.arguments.push("bad\0argument".to_string());
    assert_eq!(
        invalid.validate().expect_err("NUL argument").reason(),
        EngineFailureReason::UnsafeArgument
    );

    invalid = command();
    invalid
        .environment
        .insert("INVALID=KEY".to_string(), "value".to_string());
    assert_eq!(
        invalid
            .validate()
            .expect_err("invalid environment key")
            .reason(),
        EngineFailureReason::UnsafeArgument
    );

    invalid = command();
    invalid.port = 0;
    assert_eq!(
        invalid.validate().expect_err("zero port").reason(),
        EngineFailureReason::EngineInternal
    );

    invalid = command();
    invalid.stderr_tail_lines = 101;
    assert_eq!(
        invalid.validate().expect_err("unbounded tail").reason(),
        EngineFailureReason::EngineInternal
    );
}

#[test]
fn typed_command_debug_omits_argument_environment_and_probe_path_values() {
    let mut command = command();
    command
        .arguments
        .push("--token=SYNTHETIC_CANARY".to_string());
    command
        .environment
        .insert("SECRET".to_string(), "SYNTHETIC_CANARY".to_string());
    command.health_path = "/SYNTHETIC_CANARY".to_string();

    let diagnostic = format!("{command:?}");
    assert!(!diagnostic.contains("SYNTHETIC_CANARY"));
    assert!(diagnostic.contains("argument_count"));
    assert!(diagnostic.contains("environment_count"));
}
