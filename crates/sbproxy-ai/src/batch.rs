//! Batch API types and in-memory store for batch processing jobs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Batch job status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// Job is queued and has not started processing yet.
    Pending,
    /// Job is actively processing requests.
    InProgress,
    /// Job has finished processing all requests successfully.
    Completed,
    /// Job terminated with a fatal error before completing.
    Failed,
    /// Job was cancelled by user or system before completion.
    Cancelled,
}

/// A single batch job tracking multiple AI requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchJob {
    /// Unique identifier for the batch job.
    pub id: String,
    /// Current lifecycle status of the job.
    pub status: BatchStatus,
    /// Unix timestamp (seconds) when the job was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the job finished, if applicable.
    pub completed_at: Option<u64>,
    /// Total number of requests included in the batch.
    pub total_requests: usize,
    /// Number of requests that finished successfully so far.
    pub completed_requests: usize,
    /// Number of requests that failed so far.
    pub failed_requests: usize,
    /// User-supplied tags and metadata associated with the job.
    pub metadata: HashMap<String, String>,
}

/// Batch storage trait for persisting batch jobs.
pub trait BatchStore: Send + Sync + 'static {
    /// Persist a newly created batch job.
    fn create(&self, job: BatchJob) -> anyhow::Result<()>;
    /// Fetch a batch job by its identifier.
    fn get(&self, id: &str) -> anyhow::Result<Option<BatchJob>>;
    /// Update an existing batch job in place.
    fn update(&self, job: &BatchJob) -> anyhow::Result<()>;
    /// List batch jobs, optionally filtered by status.
    fn list(&self, status: Option<BatchStatus>) -> anyhow::Result<Vec<BatchJob>>;
    /// Delete a batch job by identifier.
    fn delete(&self, id: &str) -> anyhow::Result<()>;
}

/// In-memory batch store backed by a mutex-protected HashMap.
pub struct MemoryBatchStore {
    jobs: Mutex<HashMap<String, BatchJob>>,
}

impl MemoryBatchStore {
    /// Create an empty in-memory batch store.
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryBatchStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchStore for MemoryBatchStore {
    fn create(&self, job: BatchJob) -> anyhow::Result<()> {
        self.jobs.lock().unwrap().insert(job.id.clone(), job);
        Ok(())
    }

    fn get(&self, id: &str) -> anyhow::Result<Option<BatchJob>> {
        Ok(self.jobs.lock().unwrap().get(id).cloned())
    }

    fn update(&self, job: &BatchJob) -> anyhow::Result<()> {
        self.jobs
            .lock()
            .unwrap()
            .insert(job.id.clone(), job.clone());
        Ok(())
    }

    fn list(&self, status: Option<BatchStatus>) -> anyhow::Result<Vec<BatchJob>> {
        let jobs = self.jobs.lock().unwrap();
        Ok(match status {
            Some(s) => jobs.values().filter(|j| j.status == s).cloned().collect(),
            None => jobs.values().cloned().collect(),
        })
    }

    fn delete(&self, id: &str) -> anyhow::Result<()> {
        self.jobs.lock().unwrap().remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_job(id: &str, status: BatchStatus) -> BatchJob {
        BatchJob {
            id: id.to_string(),
            status,
            created_at: 1000,
            completed_at: None,
            total_requests: 10,
            completed_requests: 0,
            failed_requests: 0,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn create_and_get() {
        let store = MemoryBatchStore::new();
        let job = make_job("batch-1", BatchStatus::Pending);
        store.create(job).unwrap();

        let retrieved = store.get("batch-1").unwrap().unwrap();
        assert_eq!(retrieved.id, "batch-1");
        assert_eq!(retrieved.status, BatchStatus::Pending);
        assert_eq!(retrieved.total_requests, 10);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = MemoryBatchStore::new();
        assert!(store.get("no-such-id").unwrap().is_none());
    }

    #[test]
    fn update_job() {
        let store = MemoryBatchStore::new();
        let job = make_job("batch-2", BatchStatus::Pending);
        store.create(job).unwrap();

        let mut updated = store.get("batch-2").unwrap().unwrap();
        updated.status = BatchStatus::InProgress;
        updated.completed_requests = 3;
        store.update(&updated).unwrap();

        let retrieved = store.get("batch-2").unwrap().unwrap();
        assert_eq!(retrieved.status, BatchStatus::InProgress);
        assert_eq!(retrieved.completed_requests, 3);
    }

    #[test]
    fn list_all() {
        let store = MemoryBatchStore::new();
        store.create(make_job("a", BatchStatus::Pending)).unwrap();
        store.create(make_job("b", BatchStatus::Completed)).unwrap();
        store.create(make_job("c", BatchStatus::Failed)).unwrap();

        let all = store.list(None).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_with_status_filter() {
        let store = MemoryBatchStore::new();
        store.create(make_job("a", BatchStatus::Pending)).unwrap();
        store.create(make_job("b", BatchStatus::Completed)).unwrap();
        store.create(make_job("c", BatchStatus::Pending)).unwrap();

        let pending = store.list(Some(BatchStatus::Pending)).unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().all(|j| j.status == BatchStatus::Pending));

        let completed = store.list(Some(BatchStatus::Completed)).unwrap();
        assert_eq!(completed.len(), 1);
    }

    #[test]
    fn delete_job() {
        let store = MemoryBatchStore::new();
        store
            .create(make_job("del-1", BatchStatus::Pending))
            .unwrap();
        assert!(store.get("del-1").unwrap().is_some());

        store.delete("del-1").unwrap();
        assert!(store.get("del-1").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_is_ok() {
        let store = MemoryBatchStore::new();
        // Should not error
        store.delete("no-such-id").unwrap();
    }
}
