// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Released ownership regressions exercised through the neutral public boundary.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sb_runtime_host::{
    capture_managed_engine_owner, reap_managed_engines_owned_by_at, reap_stale_managed_engines_at,
    CommandExecutor, ManagedEngineOwner, ProcessOwnershipStore, TokioCommandExecutor,
};
use serde_json::{json, Value};

const GRACE: Duration = Duration::from_millis(100);

fn private_directory(path: &Path) {
    ProcessOwnershipStore::at(path)
        .ensure_private_directory()
        .expect("create private ownership directory");
}

fn missing_owner() -> Value {
    json!({"pid": u32::MAX, "start_fingerprint": u64::MAX, "executable": null})
}

fn identity(pid: u32) -> Value {
    serde_json::to_value(capture_managed_engine_owner(pid).expect("live fixture identity"))
        .expect("serialize fixture identity")
}

fn record(directory: &Path, owner: Value, engine: Value, group: u32) -> PathBuf {
    private_directory(directory);
    let path = directory.join(format!(
        "{}-{}.json",
        engine["pid"].as_u64().expect("PID"),
        engine["start_fingerprint"].as_u64().expect("fingerprint")
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create private ownership fixture");
    serde_json::to_writer(
        &mut file,
        &json!({"schema_version": 1, "owner": owner, "engine": engine, "process_group": group}),
    )
    .expect("write ownership fixture");
    file.sync_all().expect("persist ownership fixture");
    path
}

/// Cleanup is restricted to the exact process generation this fixture spawned.
struct OwnedChild {
    child: Child,
    generation: ManagedEngineOwner,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> Self {
        let child = command
            .process_group(0)
            .spawn()
            .expect("spawn isolated fixture");
        let generation = capture_managed_engine_owner(child.id()).expect("capture spawned fixture");
        Self { child, generation }
    }

    fn sleep() -> Self {
        Self::spawn(Command::new("/bin/sleep").arg("30"))
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn alive(&self) -> bool {
        capture_managed_engine_owner(self.id())
            .is_some_and(|actual| self.generation.same_process_generation(&actual))
    }

    fn stop(&mut self) {
        if self.alive() {
            self.child.kill().expect("kill exact owned fixture");
        }
        let result = self.child.wait();
        assert!(
            result.is_ok() || result.is_err_and(|error| error.raw_os_error() == Some(libc::ECHILD)),
            "fixture must be reaped by its guard or production reaper"
        );
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.alive() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct DescendantGuard {
    pid: u32,
    generation: ManagedEngineOwner,
}

impl DescendantGuard {
    fn alive(&self) -> bool {
        capture_managed_engine_owner(self.pid)
            .is_some_and(|actual| self.generation.same_process_generation(&actual))
    }

    fn terminate(&self) {
        if self.alive() {
            // Signal only this fixture's captured descendant, never an ambiguous group.
            unsafe {
                libc::kill(self.pid as i32, libc::SIGKILL);
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while self.alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for DescendantGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[test]
fn recovery_does_not_create_a_missing_ownership_directory() {
    let root = tempfile::tempdir().expect("fixture root");
    let missing = root.path().join("missing");
    assert_eq!(
        reap_stale_managed_engines_at(&missing, GRACE).expect("empty recovery"),
        0
    );
    assert!(!missing.exists());
}

#[test]
fn ownership_directory_has_private_mode_and_effective_uid() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    private_directory(&directory);
    let metadata = std::fs::symlink_metadata(directory).expect("directory metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
}

#[test]
fn ownership_store_rejects_a_directory_owned_by_another_uid() {
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 {
        // This public-boundary fixture needs an unprivileged process, as the released test did.
        return;
    }
    let before = std::fs::symlink_metadata("/usr").expect("system-owned real directory");
    assert!(before.is_dir() && !before.file_type().is_symlink());
    assert_ne!(before.uid(), effective_uid);
    let error = ProcessOwnershipStore::at("/usr")
        .ensure_private_directory()
        .expect_err("foreign-owned descriptor must fail before chmod or enumeration");
    assert!(
        error.to_string().contains("owned by the effective user"),
        "{error}"
    );
    let after = std::fs::symlink_metadata("/usr").expect("unchanged system metadata");
    assert_eq!(after.uid(), before.uid());
    assert_eq!(after.permissions().mode(), before.permissions().mode());
}

#[test]
fn ownership_store_rejects_symlinked_parent_and_ancestor() {
    let root = tempfile::tempdir().expect("fixture root");
    let real = root.path().join("real");
    std::fs::create_dir_all(real.join("nested")).expect("real ancestor");
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked).expect("ancestor symlink");
    for selected in [linked.join("owners"), linked.join("nested/owners")] {
        let error = ProcessOwnershipStore::at(selected)
            .ensure_private_directory()
            .expect_err("symlink ancestor must fail closed");
        assert_eq!(
            error.reason(),
            sb_runtime_core::EngineFailureReason::EngineShutdownFailed
        );
    }
    assert!(!real.join("owners").exists());
    assert!(!real.join("nested/owners").exists());
}

#[test]
fn ownership_store_rejects_writable_non_sticky_parent_and_ancestor() {
    let root = tempfile::tempdir().expect("fixture root");
    let unsafe_parent = root.path().join("unsafe");
    std::fs::create_dir_all(unsafe_parent.join("nested")).expect("ancestor");
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777))
        .expect("unsafe mode");
    for selected in [
        unsafe_parent.join("owners"),
        unsafe_parent.join("nested/owners"),
    ] {
        let error = ProcessOwnershipStore::at(selected)
            .ensure_private_directory()
            .expect_err("writable ancestor must fail closed");
        assert_eq!(
            error.reason(),
            sb_runtime_core::EngineFailureReason::EngineShutdownFailed
        );
        assert!(error.to_string().contains("sticky"), "{error}");
    }
    assert!(!unsafe_parent.join("owners").exists());
    assert!(!unsafe_parent.join("nested/owners").exists());
}

#[test]
fn ownership_store_rejects_permissive_precreated_directory() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    std::fs::create_dir(&directory).expect("precreated directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
        .expect("unsafe mode");
    assert!(ProcessOwnershipStore::at(&directory)
        .ensure_private_directory()
        .is_err());
    assert!(reap_stale_managed_engines_at(&directory, GRACE).is_err());
    assert_eq!(
        std::fs::metadata(directory)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o777
    );
}

#[test]
fn ownership_store_bounds_record_enumeration_before_decoding() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    private_directory(&directory);
    for index in 0..4_097 {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(directory.join(format!("{index}.json")))
            .expect("empty fixture record");
    }
    let error = reap_stale_managed_engines_at(&directory, GRACE)
        .expect_err("enumeration must refuse before malformed record decoding");
    assert!(error.to_string().contains("record limit"), "{error}");
}

#[tokio::test]
async fn stored_ownership_remains_pinned_when_selected_path_is_replaced() {
    let root = tempfile::tempdir().expect("fixture root");
    let selected = root.path().join("owners");
    let moved = root.path().join("original");
    let process = TokioCommandExecutor::at(&selected)
        .spawn(
            Path::new("/bin/sleep"),
            &["30".to_owned()],
            &BTreeMap::new(),
            8,
        )
        .await
        .expect("spawn durably owned child");
    let name = std::fs::read_dir(&selected)
        .expect("records")
        .map(|entry| entry.expect("record entry").file_name())
        .find(|name| {
            Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("persisted record name");
    std::fs::rename(&selected, &moved).expect("move original pinned directory");
    private_directory(&selected);
    let replacement = selected.join(&name);
    std::fs::write(&replacement, b"replacement must remain").expect("replacement sentinel");
    process
        .shutdown(GRACE)
        .await
        .expect("shutdown through pinned ownership");
    assert!(!moved.join(name).exists());
    assert_eq!(
        std::fs::read(replacement).expect("replacement untouched"),
        b"replacement must remain"
    );
}

#[test]
fn reused_engine_pid_with_wrong_start_fingerprint_is_never_signalled() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    let engine = OwnedChild::sleep();
    let mut wrong = identity(engine.id());
    wrong["start_fingerprint"] = json!(wrong["start_fingerprint"]
        .as_u64()
        .expect("fingerprint")
        .wrapping_add(1));
    let path = record(&directory, missing_owner(), wrong, engine.id());
    let error =
        reap_stale_managed_engines_at(&directory, GRACE).expect_err("ambiguous group refusal");
    assert!(engine.alive());
    assert!(path.exists());
    assert!(
        error.to_string().contains("exact engine generation"),
        "{error}"
    );
}

#[test]
fn matching_pid_and_start_is_reaped_when_executable_audit_path_changed() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    let engine = OwnedChild::sleep();
    let mut audit_changed = identity(engine.id());
    audit_changed["executable"] = json!("/previous/path/to/the-same-executable");
    let path = record(&directory, missing_owner(), audit_changed, engine.id());
    assert_eq!(
        reap_stale_managed_engines_at(&directory, GRACE).expect("exact generation recovery"),
        1
    );
    assert!(!engine.alive());
    assert!(!path.exists());
}

#[test]
fn live_owner_is_preserved_with_original_or_changed_executable_audit_path() {
    let root = tempfile::tempdir().expect("fixture root");
    for changed in [false, true] {
        let directory = root.path().join(format!("owners-{changed}"));
        let engine = OwnedChild::sleep();
        let mut owner = identity(std::process::id());
        if changed {
            owner["executable"] = json!("/previous/path/to/the-same-owner");
        }
        let path = record(&directory, owner, identity(engine.id()), engine.id());
        assert_eq!(
            reap_stale_managed_engines_at(&directory, GRACE).expect("live owner inspection"),
            0
        );
        assert!(engine.alive());
        assert!(path.exists());
    }
}

#[test]
fn killed_owner_recovery_is_scoped_and_preserves_unrelated_stale_engine() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    let mut owner = OwnedChild::sleep();
    let engine = OwnedChild::sleep();
    let unrelated = OwnedChild::sleep();
    let owned_path = record(
        &directory,
        identity(owner.id()),
        identity(engine.id()),
        engine.id(),
    );
    let unrelated_path = record(
        &directory,
        missing_owner(),
        identity(unrelated.id()),
        unrelated.id(),
    );
    owner.stop();
    assert_eq!(
        reap_managed_engines_owned_by_at(&directory, owner.id(), GRACE, GRACE)
            .expect("recover only killed owner's engine"),
        1
    );
    assert!(!engine.alive());
    assert!(!owned_path.exists());
    assert!(unrelated.alive());
    assert!(unrelated_path.exists());
}

#[test]
fn exited_leader_with_live_descendant_is_not_signalled_or_forgotten() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    let pid_file = root.path().join("descendant.pid");
    let mut leader = OwnedChild::spawn(
        Command::new("/bin/sh")
            .args([
                "-c",
                "IFS= read -r release; /bin/sleep 30 & echo \"$!\" > \"$1\"",
                "neutral-descendant-fixture",
            ])
            .arg(&pid_file)
            .stdin(Stdio::piped()),
    );
    let path = record(
        &directory,
        missing_owner(),
        identity(leader.id()),
        leader.id(),
    );
    leader
        .child
        .stdin
        .take()
        .expect("release pipe")
        .write_all(b"release\n")
        .expect("release child");
    leader
        .child
        .wait()
        .expect("leader exits after starting descendant");
    let pid: u32 = std::fs::read_to_string(pid_file)
        .expect("published descendant PID")
        .trim()
        .parse()
        .expect("PID");
    let generation = capture_managed_engine_owner(pid).expect("live descendant generation");
    let descendant = DescendantGuard { pid, generation };
    let error =
        reap_stale_managed_engines_at(&directory, GRACE).expect_err("leaderless group refusal");
    assert!(capture_managed_engine_owner(pid)
        .is_some_and(|actual| descendant.generation.same_process_generation(&actual)));
    assert!(path.exists());
    assert!(
        error.to_string().contains("exact engine generation"),
        "{error}"
    );
    descendant.terminate();
    assert!(
        !descendant.alive(),
        "owned descendant cleanup must complete"
    );
}

#[test]
fn stale_reap_waits_for_the_entire_managed_process_group() {
    let root = tempfile::tempdir().expect("fixture root");
    let directory = root.path().join("owners");
    let pid_file = root.path().join("descendant.pid");
    let leader = OwnedChild::spawn(
        Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' TERM; /bin/sleep 30 & child=$!; echo \"$child\" > \"$1\"; wait \"$child\"",
                "neutral-stale-group-fixture",
            ])
            .arg(&pid_file),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let pid = loop {
        if let Ok(contents) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                break pid;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fixture must publish descendant PID"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let descendant = DescendantGuard {
        pid,
        generation: capture_managed_engine_owner(pid).expect("live descendant"),
    };
    let path = record(
        &directory,
        missing_owner(),
        identity(leader.id()),
        leader.id(),
    );
    assert_eq!(
        reap_stale_managed_engines_at(&directory, GRACE)
            .expect("recover the entire exact stale group"),
        1
    );
    assert!(!leader.alive());
    assert!(
        !descendant.alive(),
        "stale recovery must await every group member"
    );
    assert!(!path.exists(), "record clears only after group exit");
}
