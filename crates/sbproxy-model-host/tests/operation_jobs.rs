// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::fs;
use std::thread;
use std::time::Duration;

use sbproxy_model_host::{
    FileJobStore, JobError, OperationKind, OperationProgress, OperationState,
};
use tempfile::tempdir;

fn progress(completed_bytes: u64, total_bytes: u64, current_file: &str) -> OperationProgress {
    OperationProgress {
        completed_bytes,
        total_bytes,
        current_file: Some(current_file.to_string()),
    }
}

#[test]
fn create_assigns_a_stable_ulid_and_persists_queued_state() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 20).expect("open job store");

    let job = store
        .create(OperationKind::Pull, "artifact:sha256:abc".to_string())
        .expect("create pull job");

    job.id.parse::<ulid::Ulid>().expect("job ID is a ULID");
    assert_eq!(job.kind, OperationKind::Pull);
    assert_eq!(job.state, OperationState::Queued);
    assert_eq!(job.progress, OperationProgress::default());
    assert!(job.terminal_at_ms.is_none());
    assert!(job.error.is_none());
    assert_eq!(store.get(&job.id).unwrap(), Some(job.clone()));
    assert_eq!(store.list().unwrap(), vec![job]);
}

#[test]
fn pull_progress_and_terminal_state_survive_restart() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 20).expect("open job store");
    let queued = store
        .create(OperationKind::Pull, "artifact:one".to_string())
        .expect("create job");

    let downloading = store
        .transition(
            &queued.id,
            OperationState::Downloading,
            progress(10, 100, "model.safetensors"),
            None,
        )
        .expect("start download");
    assert_eq!(downloading.progress.completed_bytes, 10);
    let downloading = store
        .transition(
            &queued.id,
            OperationState::Downloading,
            progress(80, 100, "model.safetensors"),
            None,
        )
        .expect("persist download progress");
    assert_eq!(downloading.progress.completed_bytes, 80);
    let verifying = store
        .transition(
            &queued.id,
            OperationState::Verifying,
            progress(100, 100, "model.safetensors"),
            None,
        )
        .expect("verify download");
    assert!(verifying.terminal_at_ms.is_none());
    let ready = store
        .transition(
            &queued.id,
            OperationState::Ready,
            progress(100, 100, "model.safetensors"),
            None,
        )
        .expect("finish download");
    assert!(ready.terminal_at_ms.is_some());
    assert!(ready.updated_at_ms >= ready.created_at_ms);

    let reopened = FileJobStore::open(directory.path(), 20).expect("reopen job store");
    assert_eq!(reopened.get(&queued.id).unwrap(), Some(ready.clone()));
    assert_eq!(reopened.list().unwrap(), vec![ready]);
}

#[test]
fn backward_and_post_terminal_transitions_are_rejected_without_mutation() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 20).expect("open job store");
    let job = store
        .create(OperationKind::Pull, "artifact:two".to_string())
        .expect("create job");
    store
        .transition(
            &job.id,
            OperationState::Downloading,
            progress(50, 100, "weights.gguf"),
            None,
        )
        .unwrap();
    let verifying = store
        .transition(
            &job.id,
            OperationState::Verifying,
            progress(100, 100, "weights.gguf"),
            None,
        )
        .unwrap();

    let error = store
        .transition(
            &job.id,
            OperationState::Downloading,
            progress(100, 100, "weights.gguf"),
            None,
        )
        .expect_err("verification cannot move backward to downloading");
    assert!(matches!(error, JobError::InvalidTransition { .. }));
    assert_eq!(store.get(&job.id).unwrap(), Some(verifying));

    let failed = store
        .transition(
            &job.id,
            OperationState::Failed,
            progress(100, 100, "weights.gguf"),
            Some("digest mismatch"),
        )
        .unwrap();
    assert!(failed.terminal_at_ms.is_some());
    store
        .transition(
            &job.id,
            OperationState::Ready,
            progress(100, 100, "weights.gguf"),
            None,
        )
        .expect_err("terminal jobs are immutable");
    assert_eq!(store.get(&job.id).unwrap(), Some(failed));
}

#[test]
fn failed_jobs_redact_bearer_credentials_before_return_and_persistence() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 20).expect("open job store");
    let job = store
        .create(OperationKind::Pull, "artifact:secret-test".to_string())
        .expect("create job");
    let failed = store
        .transition(
            &job.id,
            OperationState::Failed,
            OperationProgress::default(),
            Some("request failed: Authorization: Bearer hf_super_secret_token at upstream"),
        )
        .expect("record redacted failure");

    let message = failed.error.as_deref().expect("failure message");
    assert!(message.contains("Bearer [REDACTED]"));
    assert!(!message.contains("hf_super_secret_token"));
    let bytes = fs::read(
        directory
            .path()
            .join("jobs")
            .join(format!("{}.json", job.id)),
    )
    .expect("job file");
    let stored = String::from_utf8(bytes).expect("job JSON is UTF-8");
    assert!(!stored.contains("hf_super_secret_token"));
    assert!(stored.contains("[REDACTED]"));
    assert_eq!(store.get(&job.id).unwrap(), Some(failed));
}

#[test]
fn deletion_uses_its_own_forward_only_state_path() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 20).expect("open job store");
    let job = store
        .create(OperationKind::Delete, "artifact:old".to_string())
        .expect("create deletion");
    store
        .transition(
            &job.id,
            OperationState::Downloading,
            OperationProgress::default(),
            None,
        )
        .expect_err("delete jobs cannot download");
    let deleting = store
        .transition(
            &job.id,
            OperationState::Deleting,
            OperationProgress::default(),
            None,
        )
        .expect("begin deletion");
    assert_eq!(deleting.state, OperationState::Deleting);
    let deleted = store
        .transition(
            &job.id,
            OperationState::Deleted,
            OperationProgress::default(),
            None,
        )
        .expect("finish deletion");
    assert!(deleted.terminal_at_ms.is_some());
}

#[test]
fn pruning_removes_oldest_terminal_jobs_but_never_active_jobs() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 2).expect("open job store");
    let active = store
        .create(OperationKind::Pull, "artifact:active".to_string())
        .expect("create active job");

    let mut terminal_ids = Vec::new();
    for index in 0..3 {
        let job = store
            .create(OperationKind::Pull, format!("artifact:terminal-{index}"))
            .expect("create terminal job");
        store
            .transition(
                &job.id,
                OperationState::Failed,
                OperationProgress::default(),
                Some("fixture failure"),
            )
            .expect("finish terminal job");
        terminal_ids.push(job.id);
        thread::sleep(Duration::from_millis(2));
    }

    let jobs = store.list().expect("list pruned jobs");
    assert_eq!(jobs.len(), 3, "one active plus two terminal jobs remain");
    assert!(jobs.iter().any(|job| job.id == active.id));
    assert!(!jobs.iter().any(|job| job.id == terminal_ids[0]));
    assert!(jobs.iter().any(|job| job.id == terminal_ids[1]));
    assert!(jobs.iter().any(|job| job.id == terminal_ids[2]));
}

#[test]
fn invalid_progress_is_rejected_and_unknown_jobs_are_not_created() {
    let directory = tempdir().expect("temp dir");
    let store = FileJobStore::open(directory.path(), 20).expect("open job store");
    let job = store
        .create(OperationKind::Pull, "artifact:progress".to_string())
        .expect("create job");

    store
        .transition(
            &job.id,
            OperationState::Downloading,
            progress(101, 100, "weights.gguf"),
            None,
        )
        .expect_err("completed bytes cannot exceed total bytes");
    assert_eq!(store.get(&job.id).unwrap(), Some(job));
    let unknown = ulid::Ulid::new().to_string();
    assert!(matches!(
        store.transition(
            &unknown,
            OperationState::Failed,
            OperationProgress::default(),
            Some("not found")
        ),
        Err(JobError::NotFound(_))
    ));
    assert!(store.get("../../sb.yml").is_err());
}
