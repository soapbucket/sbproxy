// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Durable operation jobs shared by CLI, runtime, and future admin APIs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Operation performed for a model deployment or artifact.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Acquire and verify an artifact.
    Pull,
    /// Reverify an existing artifact.
    Verify,
    /// Provision a managed engine.
    Provision,
    /// Launch an engine process.
    Launch,
    /// Load a model replica.
    Load,
    /// Drain a model replica.
    Drain,
    /// Stop a model replica.
    Stop,
    /// Replace a deployment generation.
    Rollout,
    /// Delete an artifact or deployment resource.
    Delete,
    /// Explicitly clear a retained deployment crash loop.
    Reset,
}

/// Durable lifecycle state of an operation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Accepted but not yet started.
    Queued,
    /// Artifact bytes are being acquired.
    Downloading,
    /// Artifact bytes are being verified.
    Verifying,
    /// Operation completed successfully.
    Ready,
    /// Operation failed and carries a redacted error.
    Failed,
    /// Resource deletion is in progress.
    Deleting,
    /// Resource deletion completed.
    Deleted,
}

impl OperationState {
    /// Whether this state cannot transition further.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ready | Self::Failed | Self::Deleted)
    }
}

/// Persisted byte progress for an operation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct OperationProgress {
    /// Bytes completed across the operation.
    pub completed_bytes: u64,
    /// Known total bytes, or zero before the total is known.
    pub total_bytes: u64,
    /// Current repository-relative file, when applicable.
    pub current_file: Option<String>,
}

impl OperationProgress {
    fn validate(&self) -> Result<(), JobError> {
        if self.completed_bytes > self.total_bytes {
            return Err(JobError::Invalid(
                "operation completed_bytes exceeds total_bytes".to_string(),
            ));
        }
        if self
            .current_file
            .as_deref()
            .is_some_and(|file| file.trim().is_empty())
        {
            return Err(JobError::Invalid(
                "operation current_file must not be blank".to_string(),
            ));
        }
        Ok(())
    }
}

/// One durable operation visible to CLI and admin consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationJob {
    /// Stable ULID job identity.
    pub id: String,
    /// Operation category.
    pub kind: OperationKind,
    /// Canonical artifact or deployment subject.
    pub subject: String,
    /// Current durable state.
    pub state: OperationState,
    /// Current byte progress.
    pub progress: OperationProgress,
    /// Creation timestamp as Unix milliseconds.
    pub created_at_ms: u64,
    /// Last transition timestamp as Unix milliseconds.
    pub updated_at_ms: u64,
    /// Terminal timestamp as Unix milliseconds.
    pub terminal_at_ms: Option<u64>,
    /// Redacted failure message, present only in `failed` state.
    pub error: Option<String>,
}

impl OperationJob {
    fn validate(&self) -> Result<(), JobError> {
        validate_id(&self.id)?;
        validate_subject(&self.subject)?;
        self.progress.validate()?;
        if self.updated_at_ms < self.created_at_ms {
            return Err(JobError::Invalid(
                "operation updated_at_ms precedes created_at_ms".to_string(),
            ));
        }
        match (self.state.is_terminal(), self.terminal_at_ms) {
            (true, Some(terminal)) if terminal >= self.updated_at_ms => {}
            (true, _) => {
                return Err(JobError::Invalid(
                    "terminal operation requires a valid terminal_at_ms".to_string(),
                ))
            }
            (false, None) => {}
            (false, Some(_)) => {
                return Err(JobError::Invalid(
                    "active operation cannot have terminal_at_ms".to_string(),
                ))
            }
        }
        match (self.state, self.error.as_deref()) {
            (OperationState::Failed, Some(error)) if !error.trim().is_empty() => {
                if redact_bearer_credentials(error) != error {
                    return Err(JobError::Invalid(
                        "stored operation error contains an unredacted bearer credential"
                            .to_string(),
                    ));
                }
            }
            (OperationState::Failed, _) => {
                return Err(JobError::Invalid(
                    "failed operation requires a redacted error".to_string(),
                ))
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(JobError::Invalid(
                    "only failed operations may store an error".to_string(),
                ))
            }
        }
        Ok(())
    }
}

/// Durable job-store or state-machine failure.
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    /// File operation failed.
    #[error("{operation} '{}': {source}", path.display())]
    Io {
        /// Concise operation name.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Job JSON could not be encoded or decoded.
    #[error("{operation} job JSON '{}': {source}", path.display())]
    Json {
        /// Encode or decode operation.
        operation: &'static str,
        /// Job path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// Stored or requested job data is invalid.
    #[error("invalid operation job: {0}")]
    Invalid(String),
    /// Job ID was well formed but absent.
    #[error("operation job '{0}' was not found")]
    NotFound(String),
    /// Requested state transition is not legal for this operation.
    #[error("operation job '{id}' cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Job ID.
        id: String,
        /// Durable current state.
        from: OperationState,
        /// Requested next state.
        to: OperationState,
    },
    /// Wall-clock time was unavailable.
    #[error("read operation clock: {0}")]
    Clock(String),
}

/// File-backed operation jobs with atomic replacement and bounded history.
#[derive(Debug, Clone)]
pub struct FileJobStore {
    jobs_dir: PathBuf,
    lock_path: PathBuf,
    terminal_history_limit: usize,
}

impl FileJobStore {
    /// Open `<root>/jobs`, creating it when absent.
    pub fn open(root: impl Into<PathBuf>, terminal_history_limit: usize) -> Result<Self, JobError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(JobError::Invalid(
                "operation job root must not be empty".to_string(),
            ));
        }
        let jobs_dir = root.join("jobs");
        fs::create_dir_all(&jobs_dir)
            .map_err(|source| io_error("create operation jobs directory", &jobs_dir, source))?;
        let lock_path = jobs_dir.join(".lock");
        Ok(Self {
            jobs_dir,
            lock_path,
            terminal_history_limit,
        })
    }

    /// Create and persist a queued operation with a new ULID.
    pub fn create(&self, kind: OperationKind, subject: String) -> Result<OperationJob, JobError> {
        validate_subject(&subject)?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)
            .map_err(|source| io_error("lock operation jobs", &self.lock_path, source))?;

        let created_at_ms = now_ms()?;
        let id = loop {
            let candidate = Ulid::new().to_string();
            if !self.job_path(&candidate).exists() {
                break candidate;
            }
        };
        let job = OperationJob {
            id,
            kind,
            subject,
            state: OperationState::Queued,
            progress: OperationProgress::default(),
            created_at_ms,
            updated_at_ms: created_at_ms,
            terminal_at_ms: None,
            error: None,
        };
        job.validate()?;
        self.write_atomic(&job)?;
        Ok(job)
    }

    /// Apply one legal durable transition and persist its progress.
    pub fn transition(
        &self,
        id: &str,
        next: OperationState,
        progress: OperationProgress,
        error: Option<&str>,
    ) -> Result<OperationJob, JobError> {
        validate_id(id)?;
        progress.validate()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)
            .map_err(|source| io_error("lock operation jobs", &self.lock_path, source))?;
        let mut job = self
            .load_job_unlocked(id)?
            .ok_or_else(|| JobError::NotFound(id.to_string()))?;
        if !transition_allowed(job.kind, job.state, next) {
            return Err(JobError::InvalidTransition {
                id: id.to_string(),
                from: job.state,
                to: next,
            });
        }
        if progress.completed_bytes < job.progress.completed_bytes {
            return Err(JobError::Invalid(
                "operation progress cannot move backward".to_string(),
            ));
        }
        if job.progress.total_bytes != 0 && progress.total_bytes != job.progress.total_bytes {
            return Err(JobError::Invalid(
                "operation total_bytes cannot change after it is known".to_string(),
            ));
        }
        let stored_error = match (next, error) {
            (OperationState::Failed, Some(message)) if !message.trim().is_empty() => {
                Some(redact_bearer_credentials(message))
            }
            (OperationState::Failed, _) => {
                return Err(JobError::Invalid(
                    "failed operation requires an error".to_string(),
                ))
            }
            (_, None) => None,
            (_, Some(_)) => {
                return Err(JobError::Invalid(
                    "only failed operations may accept an error".to_string(),
                ))
            }
        };

        let updated_at_ms = now_ms()?.max(job.updated_at_ms);
        job.state = next;
        job.progress = progress;
        job.updated_at_ms = updated_at_ms;
        job.terminal_at_ms = next.is_terminal().then_some(updated_at_ms);
        job.error = stored_error;
        job.validate()?;
        self.write_atomic(&job)?;
        if next.is_terminal() {
            self.prune_terminal_unlocked()?;
        }
        Ok(job)
    }

    /// Read one validated job by ULID.
    pub fn get(&self, id: &str) -> Result<Option<OperationJob>, JobError> {
        validate_id(id)?;
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)
            .map_err(|source| io_error("lock operation jobs", &self.lock_path, source))?;
        self.load_job_unlocked(id)
    }

    /// List every active job plus retained terminal history.
    pub fn list(&self) -> Result<Vec<OperationJob>, JobError> {
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)
            .map_err(|source| io_error("lock operation jobs", &self.lock_path, source))?;
        self.list_unlocked()
    }

    fn open_lock(&self) -> Result<File, JobError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(|source| io_error("open operation jobs lock", &self.lock_path, source))
    }

    fn job_path(&self, id: &str) -> PathBuf {
        self.jobs_dir.join(format!("{id}.json"))
    }

    fn load_job_unlocked(&self, id: &str) -> Result<Option<OperationJob>, JobError> {
        let path = self.job_path(id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(io_error("read operation job", &path, source)),
        };
        let job: OperationJob =
            serde_json::from_slice(&bytes).map_err(|source| JobError::Json {
                operation: "parse",
                path: path.clone(),
                source,
            })?;
        job.validate()?;
        if job.id != id {
            return Err(JobError::Invalid(format!(
                "operation job filename ID '{id}' differs from stored ID"
            )));
        }
        Ok(Some(job))
    }

    fn list_unlocked(&self) -> Result<Vec<OperationJob>, JobError> {
        let entries = fs::read_dir(&self.jobs_dir)
            .map_err(|source| io_error("list operation jobs directory", &self.jobs_dir, source))?;
        let mut jobs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| {
                io_error("read operation jobs directory", &self.jobs_dir, source)
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    JobError::Invalid("operation job filename is not UTF-8".to_string())
                })?;
            validate_id(id)?;
            let job = self.load_job_unlocked(id)?.ok_or_else(|| {
                JobError::Invalid(format!("operation job '{id}' disappeared during listing"))
            })?;
            jobs.push(job);
        }
        jobs.sort_by(|left, right| {
            (left.created_at_ms, left.id.as_str()).cmp(&(right.created_at_ms, right.id.as_str()))
        });
        Ok(jobs)
    }

    fn write_atomic(&self, job: &OperationJob) -> Result<(), JobError> {
        let destination = self.job_path(&job.id);
        let mut bytes = serde_json::to_vec_pretty(job).map_err(|source| JobError::Json {
            operation: "serialize",
            path: destination.clone(),
            source,
        })?;
        bytes.push(b'\n');
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self.jobs_dir.join(format!(
            ".{}.json.tmp.{}.{}",
            job.id,
            std::process::id(),
            sequence
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|source| {
                    io_error("create operation job temporary file", &temporary, source)
                })?;
            file.write_all(&bytes).map_err(|source| {
                io_error("write operation job temporary file", &temporary, source)
            })?;
            file.sync_all().map_err(|source| {
                io_error("sync operation job temporary file", &temporary, source)
            })?;
            fs::rename(&temporary, &destination)
                .map_err(|source| io_error("replace operation job", &destination, source))?;
            sync_directory(&self.jobs_dir)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn prune_terminal_unlocked(&self) -> Result<(), JobError> {
        let mut terminal: Vec<_> = self
            .list_unlocked()?
            .into_iter()
            .filter(|job| job.state.is_terminal())
            .collect();
        if terminal.len() <= self.terminal_history_limit {
            return Ok(());
        }
        terminal.sort_by(|left, right| {
            (
                left.terminal_at_ms.unwrap_or(u64::MAX),
                left.created_at_ms,
                left.id.as_str(),
            )
                .cmp(&(
                    right.terminal_at_ms.unwrap_or(u64::MAX),
                    right.created_at_ms,
                    right.id.as_str(),
                ))
        });
        let remove_count = terminal.len() - self.terminal_history_limit;
        for job in terminal.into_iter().take(remove_count) {
            let path = self.job_path(&job.id);
            fs::remove_file(&path)
                .map_err(|source| io_error("prune terminal operation job", &path, source))?;
        }
        sync_directory(&self.jobs_dir)
    }
}

fn transition_allowed(kind: OperationKind, current: OperationState, next: OperationState) -> bool {
    use OperationKind::{Delete, Pull, Verify};
    use OperationState::{Deleted, Deleting, Downloading, Failed, Queued, Ready, Verifying};

    match kind {
        Pull => matches!(
            (current, next),
            (Queued, Downloading | Verifying | Ready | Failed)
                | (Downloading, Downloading | Verifying | Failed)
                | (Verifying, Verifying | Ready | Failed)
        ),
        Verify => matches!(
            (current, next),
            (Queued, Verifying | Ready | Failed) | (Verifying, Verifying | Ready | Failed)
        ),
        Delete => matches!(
            (current, next),
            (Queued, Deleting | Failed) | (Deleting, Deleting | Deleted | Failed)
        ),
        _ => matches!((current, next), (Queued, Ready | Failed)),
    }
}

fn validate_id(id: &str) -> Result<(), JobError> {
    id.parse::<Ulid>()
        .map(|_| ())
        .map_err(|_| JobError::Invalid("operation job ID must be a ULID".to_string()))
}

fn validate_subject(subject: &str) -> Result<(), JobError> {
    if subject.trim().is_empty() || subject.len() > 512 || subject.chars().any(char::is_control) {
        return Err(JobError::Invalid(
            "operation subject must be 1 to 512 printable characters".to_string(),
        ));
    }
    Ok(())
}

fn now_ms() -> Result<u64, JobError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| JobError::Clock(error.to_string()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| JobError::Clock("Unix millisecond timestamp overflow".to_string()))
}

fn redact_bearer_credentials(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut result = String::with_capacity(message.len());
    let mut cursor = 0;
    let mut scan = 0;
    while scan + 6 <= bytes.len() {
        if bytes[scan..scan + 6].eq_ignore_ascii_case(b"bearer")
            && (scan == 0 || !bytes[scan - 1].is_ascii_alphanumeric())
            && bytes.get(scan + 6).is_some_and(u8::is_ascii_whitespace)
        {
            let mut token_start = scan + 6;
            while bytes.get(token_start).is_some_and(u8::is_ascii_whitespace) {
                token_start += 1;
            }
            if token_start == bytes.len() {
                break;
            }
            let mut token_end = token_start;
            while bytes
                .get(token_end)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                token_end += 1;
            }
            result.push_str(&message[cursor..scan]);
            result.push_str("Bearer [REDACTED]");
            cursor = token_end;
            scan = token_end;
            continue;
        }
        scan += 1;
    }
    result.push_str(&message[cursor..]);
    result
}

fn sync_directory(path: &Path) -> Result<(), JobError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync operation jobs directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> JobError {
    JobError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
