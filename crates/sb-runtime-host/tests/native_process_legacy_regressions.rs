// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sb_runtime_core::EngineFailureReason;
use sb_runtime_host::{
    capture_managed_engine_owner, CommandExecutor, EngineProcess, EngineProcessRunner,
    EngineReadinessProbe, TokioCommandExecutor,
};

const ENVIRONMENT_CHILD: &str = "NEUTRAL_RUNTIME_ENVIRONMENT_CHILD";
const SECRET_SENTINEL: &str = "NEUTRAL_HOST_SECRET_SENTINEL";

#[derive(Debug)]
struct NeverReady;

#[async_trait::async_trait]
impl EngineReadinessProbe for NeverReady {
    async fn ready(
        &self,
        _port: u16,
        _path: &str,
    ) -> Result<bool, sb_runtime_core::EngineDriverError> {
        Ok(false)
    }
}

fn enter_environment_subprocess(test_name: &str) -> bool {
    if std::env::var_os(ENVIRONMENT_CHILD).is_some() {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env(ENVIRONMENT_CHILD, "1")
        .env(SECRET_SENTINEL, "must-not-leak")
        .status()
        .expect("run isolated environment fixture");
    assert!(status.success(), "isolated environment fixture failed");
    true
}

async fn wait_for_exit(process: &Arc<dyn EngineProcess>) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !process.has_exited().await.expect("inspect process") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("process exits promptly");
}

async fn wait_for_generation_to_exit(owner: &sb_runtime_host::ManagedEngineOwner, pid: u32) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while capture_managed_engine_owner(pid)
            .as_ref()
            .is_some_and(|actual| owner.same_process_generation(actual))
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("captured process generation exits");
}

fn record_count(directory: &Path) -> usize {
    std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|value| value == "json")
                })
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn missing_executable_reports_a_typed_early_exit_and_clears_ownership() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    let process = TokioCommandExecutor::at(&directory)
        .spawn(
            Path::new("/definitely/missing/neutral-engine"),
            &[],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("durable gate starts before attempting exec");

    wait_for_exit(&process).await;

    assert!(process.stderr_tail().contains("neutral-engine"));
    assert_eq!(record_count(&directory), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn path_resolution_and_typed_environment_do_not_inherit_unlisted_values() {
    if enter_environment_subprocess(
        "path_resolution_and_typed_environment_do_not_inherit_unlisted_values",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    let process = TokioCommandExecutor::at(&directory)
        .spawn(
            Path::new("sh"),
            &[
                "-c".to_string(),
                "printf '%s|%s\\n' \"$NEUTRAL_HOST_TYPED_VISIBLE\" \"${NEUTRAL_HOST_SECRET_SENTINEL:-}\" >&2"
                    .to_string(),
            ],
            &BTreeMap::from([
                ("PATH".to_string(), "/bin:/usr/bin".to_string()),
                ("NEUTRAL_HOST_TYPED_VISIBLE".to_string(), "yes".to_string()),
            ]),
            20,
        )
        .await
        .expect("spawn through typed PATH");

    wait_for_exit(&process).await;

    assert_eq!(process.stderr_tail(), "yes|");
    assert_eq!(record_count(&directory), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn compatibility_output_receives_only_baseline_and_typed_environment() {
    if enter_environment_subprocess(
        "compatibility_output_receives_only_baseline_and_typed_environment",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary directory");
    let output = TokioCommandExecutor::at(root.path().join("owners"))
        .output(
            Path::new("/usr/bin/env"),
            &[],
            &BTreeMap::from([("NEUTRAL_HOST_TYPED_VISIBLE".to_string(), "yes".to_string())]),
            Duration::from_secs(2),
            64 * 1024,
        )
        .await
        .expect("run bounded environment probe");

    assert!(output.stdout.contains("NEUTRAL_HOST_TYPED_VISIBLE=yes"));
    assert!(!output.stdout.contains("NEUTRAL_HOST_SECRET_SENTINEL"));
    assert!(!output.stdout.contains("must-not-leak"));
}

#[tokio::test]
async fn stderr_is_retained_only_in_a_bounded_memory_tail() {
    let root = tempfile::tempdir().expect("temporary directory");
    let process = TokioCommandExecutor::at(root.path().join("owners"))
        .spawn(
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "i=0; while [ $i -lt 12000 ]; do echo noise-$i >&2; i=$((i+1)); done; echo FINAL-MARKER >&2"
                    .to_string(),
            ],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("spawn noisy process");

    wait_for_exit(&process).await;
    let tail = process.stderr_tail();
    assert!(tail.contains("FINAL-MARKER"));
    assert!(tail.len() <= 8_192);
    assert!(tail.lines().count() <= 20);
}

#[test]
fn stderr_capture_survives_the_launch_runtime() {
    let root = tempfile::tempdir().expect("temporary directory");
    let release = root.path().join("release");
    let ownership = root.path().join("owners");
    let release_argument = release.display().to_string();
    let process = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build launch runtime")
            .block_on(TokioCommandExecutor::at(ownership).spawn(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "echo BEFORE-RUNTIME-DROP >&2; while [ ! -f \"$1\" ]; do sleep 0.01; done; echo AFTER-RUNTIME-DROP >&2; exec sleep 5"
                        .to_string(),
                    "neutral-stderr-fixture".to_string(),
                    release_argument,
                ],
                &BTreeMap::new(),
                20,
            ))
    })
    .join()
    .expect("launch thread")
    .expect("spawn engine");

    std::fs::write(&release, b"release").expect("release fixture");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build observation runtime");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !process.stderr_tail().contains("AFTER-RUNTIME-DROP") {
                assert!(!process.has_exited().await.expect("inspect process"));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stderr remains readable after launch runtime drops");
        process
            .shutdown(Duration::from_millis(100))
            .await
            .expect("shutdown fixture");
    });
}

#[tokio::test]
async fn native_fast_exit_preserves_the_typed_reason_and_stderr() {
    let root = tempfile::tempdir().expect("temporary directory");
    let runner = EngineProcessRunner::new(
        Arc::new(TokioCommandExecutor::at(root.path().join("owners"))),
        Arc::new(NeverReady),
    )
    .with_poll_interval(Duration::from_millis(1));
    let command = sb_runtime_host::EngineCommand {
        executable: PathBuf::from("/bin/sh"),
        arguments: vec![
            "-c".to_string(),
            "echo FAST-EXIT-DIAGNOSTIC >&2; exit 42".to_string(),
        ],
        environment: BTreeMap::new(),
        port: 9,
        health_path: "/health".to_string(),
        ready_timeout: Duration::from_secs(2),
        stderr_tail_lines: 20,
    };

    let error = runner
        .launch(&command)
        .await
        .expect_err("fast exit fails before readiness");

    assert_eq!(error.reason(), EngineFailureReason::EngineEarlyExit);
    assert_eq!(error.diagnostic_tail(), Some("FAST-EXIT-DIAGNOSTIC"));
}

#[tokio::test]
async fn shutdown_refuses_to_signal_after_the_exact_group_leader_exits() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    let descendant_path = root.path().join("descendant.pid");
    let process = TokioCommandExecutor::at(&directory)
        .spawn(
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "/bin/sleep 30 & echo \"$!\" > \"$1\"".to_string(),
                "neutral-leaderless-group-fixture".to_string(),
                descendant_path.display().to_string(),
            ],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("spawn managed group fixture");
    let leader_pid = process.id().expect("leader PID");
    let leader = capture_managed_engine_owner(leader_pid).expect("leader generation");
    let descendant_pid = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(&descendant_path) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    break pid;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fixture publishes descendant PID");
    let descendant = capture_managed_engine_owner(descendant_pid).expect("descendant generation");
    wait_for_generation_to_exit(&leader, leader_pid).await;

    let error = process
        .shutdown(Duration::from_millis(20))
        .await
        .expect_err("shutdown fails closed without its exact group leader");

    assert!(
        error.to_string().contains("exact engine generation"),
        "{error}"
    );
    assert!(capture_managed_engine_owner(descendant_pid)
        .as_ref()
        .is_some_and(|actual| descendant.same_process_generation(actual)));
    assert_eq!(record_count(&directory), 1);

    unsafe {
        libc::kill(descendant_pid as i32, libc::SIGKILL);
    }
    wait_for_generation_to_exit(&descendant, descendant_pid).await;
    process
        .shutdown(Duration::from_millis(20))
        .await
        .expect("clear retained ownership after exact group exit");
    assert_eq!(record_count(&directory), 0);
}

#[test]
fn spawned_child_resets_an_inherited_blocked_signal_mask() {
    let root = tempfile::tempdir().expect("temporary directory");
    let ownership = root.path().join("owners");
    let marker = root.path().join("survived-sigterm");
    let marker_for_child = marker.display().to_string();
    let status = std::thread::spawn(move || {
        let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
        assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGTERM) }, 0);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()) },
            0
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let exited = runtime.block_on(async {
            let process = TokioCommandExecutor::at(ownership)
                .spawn(
                    Path::new("/bin/sh"),
                    &[
                        "-c".to_string(),
                        "kill -TERM $$; printf survived > \"$1\"".to_string(),
                        "neutral-signal-reset-fixture".to_string(),
                        marker_for_child,
                    ],
                    &BTreeMap::new(),
                    20,
                )
                .await
                .expect("spawn with blocked caller signal");
            wait_for_exit(&process).await;
            process.has_exited().await.expect("inspect process")
        });
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, std::ptr::null_mut()) },
            0
        );
        exited
    })
    .join()
    .expect("signal fixture thread");

    assert!(status);
    assert!(!marker.exists(), "child inherited a blocked SIGTERM mask");
}
