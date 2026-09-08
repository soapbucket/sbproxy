// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use sb_runtime_host::{
    capture_managed_engine_owner, reap_managed_engines_owned_by_identity_at,
    reap_stale_managed_engines_at, CommandExecutor, ProcessOwnershipStore, TokioCommandExecutor,
};

fn record_path(directory: &Path) -> std::path::PathBuf {
    std::fs::read_dir(directory)
        .expect("read ownership directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("one ownership record")
}

async fn spawn_sleeping_group(
    directory: &Path,
) -> std::sync::Arc<dyn sb_runtime_host::EngineProcess> {
    spawn_group(directory, "trap 'exit 0' TERM; sleep 30 & wait").await
}

async fn spawn_group(
    directory: &Path,
    script: &str,
) -> std::sync::Arc<dyn sb_runtime_host::EngineProcess> {
    TokioCommandExecutor::at(directory)
        .spawn(
            Path::new("/bin/sh"),
            &["-c".to_string(), script.to_string()],
            &BTreeMap::new(),
            8,
        )
        .await
        .expect("spawn isolated child group")
}

#[test]
fn store_refuses_unsafe_ancestor_record_symlink_and_oversized_record() {
    let root = tempfile::tempdir().expect("temporary directory");
    let unsafe_parent = root.path().join("unsafe");
    std::fs::create_dir(&unsafe_parent).expect("create unsafe ancestor");
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777))
        .expect("make ancestor unsafe");
    assert!(ProcessOwnershipStore::at(unsafe_parent.join("owners"))
        .ensure_private_directory()
        .is_err());

    let directory = root.path().join("owners");
    ProcessOwnershipStore::at(&directory)
        .ensure_private_directory()
        .expect("create private directory");
    let target = root.path().join("target");
    std::fs::write(&target, b"{}").expect("write target");
    std::os::unix::fs::symlink(&target, directory.join("linked.json"))
        .expect("create record symlink");
    assert!(reap_stale_managed_engines_at(&directory, Duration::ZERO).is_err());
    std::fs::remove_file(directory.join("linked.json")).expect("remove record symlink");

    let oversized = directory.join("oversized.json");
    std::fs::write(&oversized, vec![b'x'; 64 * 1024 + 1]).expect("write oversized record");
    std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600))
        .expect("make record private");
    assert!(reap_stale_managed_engines_at(&directory, Duration::ZERO).is_err());
}

#[tokio::test]
async fn failed_durable_write_never_releases_the_executable_gate() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    ProcessOwnershipStore::at(&directory)
        .ensure_private_directory()
        .expect("create private directory");
    for index in 0..4_096 {
        let path = directory.join(format!("synthetic-{index}.json"));
        std::fs::write(&path, b"{}").expect("write bounded record name");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("make record private");
    }
    let marker = root.path().join("must-not-exist");
    let script = format!("printf ran > '{}'", marker.display());
    let error = TokioCommandExecutor::at(&directory)
        .spawn(
            Path::new("/bin/sh"),
            &["-c".to_string(), script],
            &BTreeMap::new(),
            8,
        )
        .await
        .expect_err("record cap must fail durable persistence");
    assert_eq!(
        error.reason(),
        sb_runtime_core::EngineFailureReason::EngineShutdownFailed
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!marker.exists(), "executable ran before durable ownership");
}

#[test]
fn explicit_store_creates_private_directory_and_refuses_symlink() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    ProcessOwnershipStore::at(&directory)
        .ensure_private_directory()
        .expect("create private directory");
    let mode = std::fs::symlink_metadata(&directory)
        .expect("ownership metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);

    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&directory, &linked).expect("create test symlink");
    let error = ProcessOwnershipStore::at(linked)
        .ensure_private_directory()
        .expect_err("ownership symlink must fail closed");
    assert_eq!(
        error.reason(),
        sb_runtime_core::EngineFailureReason::EngineShutdownFailed
    );
}

#[test]
fn store_tightens_owner_only_legacy_directory_on_create_and_recovery() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    std::fs::create_dir(&directory).expect("create legacy directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
        .expect("set legacy permissions");
    let store = ProcessOwnershipStore::at(&directory);

    store
        .ensure_private_directory()
        .expect("spawn path tightens an owner-only legacy directory");
    assert_eq!(
        std::fs::symlink_metadata(&directory)
            .expect("ownership metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
        .expect("restore legacy permissions");
    assert_eq!(
        reap_stale_managed_engines_at(&directory, Duration::ZERO)
            .expect("recovery path tightens an owner-only legacy directory"),
        0
    );
    assert_eq!(
        std::fs::symlink_metadata(&directory)
            .expect("ownership metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[tokio::test]
async fn exact_owner_refuses_live_owner_and_pid_reuse_token() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    let owner = capture_managed_engine_owner(std::process::id()).expect("owner identity");
    let process = spawn_sleeping_group(&directory).await;
    let record = record_path(&directory);
    let mode = std::fs::symlink_metadata(&record)
        .expect("record metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let error = reap_managed_engines_owned_by_identity_at(
        &directory,
        &owner,
        Duration::ZERO,
        Duration::from_millis(10),
    )
    .expect_err("a live exact owner must not authorize cleanup");
    assert_eq!(
        error.reason(),
        sb_runtime_core::EngineFailureReason::EngineShutdownFailed
    );

    let mut reused_value = serde_json::to_value(&owner).expect("serialize owner");
    let fingerprint = reused_value["start_fingerprint"]
        .as_u64()
        .expect("fingerprint");
    reused_value["start_fingerprint"] = serde_json::json!(fingerprint.wrapping_add(1));
    let reused = serde_json::from_value(reused_value).expect("deserialize reused token");
    assert!(!owner.same_process_generation(&reused));
    assert_eq!(
        reap_managed_engines_owned_by_identity_at(
            &directory,
            &reused,
            Duration::ZERO,
            Duration::from_millis(10),
        )
        .expect("unmatched generation is inert"),
        0
    );
    assert!(!process.has_exited().await.expect("inspect child"));

    process
        .shutdown(Duration::from_secs(1))
        .await
        .expect("shutdown exact group");
    assert!(process.has_exited().await.expect("inspect stopped child"));
    assert!(!record.exists());
}

#[tokio::test]
async fn stale_record_reaps_only_the_exact_engine_generation() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    let process = spawn_sleeping_group(&directory).await;
    let record = record_path(&directory);
    let bytes = std::fs::read(&record).expect("read synthetic record");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse record");
    let fingerprint = value["owner"]["start_fingerprint"]
        .as_u64()
        .expect("owner fingerprint");
    value["owner"]["start_fingerprint"] = serde_json::json!(fingerprint.wrapping_add(1));
    std::fs::write(
        &record,
        serde_json::to_vec(&value).expect("encode synthetic stale record"),
    )
    .expect("replace synthetic record contents");

    assert_eq!(
        reap_stale_managed_engines_at(&directory, Duration::from_secs(1))
            .expect("reap stale exact generation"),
        1
    );
    assert!(process.has_exited().await.expect("inspect reaped child"));
    assert!(!record.exists());
}

#[tokio::test]
async fn shutdown_forces_an_uncooperative_process_group_and_removes_record() {
    let root = tempfile::tempdir().expect("temporary directory");
    let directory = root.path().join("owners");
    let process = spawn_group(
        &directory,
        "trap '' TERM; /bin/sh -c \"trap '' TERM; sleep 30\" & wait",
    )
    .await;
    let record = record_path(&directory);

    process
        .shutdown(Duration::ZERO)
        .await
        .expect("force exact process group shutdown");
    assert!(process.has_exited().await.expect("inspect forced shutdown"));
    assert!(!record.exists());
}
