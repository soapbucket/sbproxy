//! Shared bounded admission for CPU-bound rich-sidecar RPC work.

use anyhow::bail;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tonic::Status;

#[derive(Clone, Debug)]
pub struct Admission {
    running: Arc<Semaphore>,
    queued: Arc<Semaphore>,
    deadline: Duration,
}

pub struct Lease {
    _running: OwnedSemaphorePermit,
    expires: Instant,
}

impl Lease {
    pub fn expires(&self) -> Instant {
        self.expires
    }
}

impl Admission {
    pub fn new(max_running: usize, max_queued: usize, deadline: Duration) -> anyhow::Result<Self> {
        if max_running == 0 {
            bail!("inference max running must be greater than zero");
        }
        if deadline.is_zero() {
            bail!("inference deadline must be greater than zero");
        }
        Ok(Self {
            running: Arc::new(Semaphore::new(max_running)),
            queued: Arc::new(Semaphore::new(max_queued)),
            deadline,
        })
    }

    pub async fn acquire(&self, command: &'static str) -> Result<Lease, Status> {
        let expires = Instant::now() + self.deadline;
        let running = match Arc::clone(&self.running).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let queued = Arc::clone(&self.queued).try_acquire_owned().map_err(|_| {
                    crate::metrics::record_admission_refusal(command, "queue_full");
                    Status::resource_exhausted("classifier inference queue is full")
                })?;
                crate::metrics::adjust_admission_queue(command, 1);
                let acquired =
                    tokio::time::timeout_at(expires, Arc::clone(&self.running).acquire_owned())
                        .await;
                crate::metrics::adjust_admission_queue(command, -1);
                drop(queued);
                match acquired {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => {
                        crate::metrics::record_admission_refusal(command, "resource_limit");
                        return Err(Status::unavailable("classifier admission is closed"));
                    }
                    Err(_) => {
                        crate::metrics::record_admission_refusal(command, "deadline");
                        return Err(Status::deadline_exceeded(
                            "classifier inference deadline exceeded while queued",
                        ));
                    }
                }
            }
        };
        Ok(Lease {
            _running: running,
            expires,
        })
    }

    pub async fn run_blocking<F, T>(&self, command: &'static str, work: F) -> Result<T, Status>
    where
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let lease = self.acquire(command).await?;
        let expires = lease.expires();
        let worker = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            work()
        });
        match tokio::time::timeout_at(expires, worker).await {
            Ok(Ok(result)) => result
                .map_err(|error| Status::internal(format!("classifier inference failed: {error}"))),
            Ok(Err(error)) => Err(Status::internal(format!(
                "classifier worker failed: {error}"
            ))),
            Err(_) => {
                crate::metrics::record_admission_refusal(command, "deadline");
                Err(Status::deadline_exceeded(
                    "classifier inference deadline exceeded",
                ))
            }
        }
    }

    pub async fn run_with_lease<F, T>(
        &self,
        command: &'static str,
        lease: Lease,
        work: F,
    ) -> Result<T, Status>
    where
        F: Future<Output = Result<T, Status>>,
    {
        let expires = lease.expires();
        let result = tokio::time::timeout_at(expires, work).await;
        drop(lease);
        match result {
            Ok(result) => result,
            Err(_) => {
                crate::metrics::record_admission_refusal(command, "deadline");
                Err(Status::deadline_exceeded(
                    "classifier inference deadline exceeded",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_work_beyond_running_and_queue_budget() {
        let admission = Admission::new(1, 0, std::time::Duration::from_secs(1)).unwrap();
        let first = {
            let admission = admission.clone();
            tokio::spawn(async move {
                admission
                    .run_blocking("quality", || {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        Ok::<_, anyhow::Error>(())
                    })
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let error = admission
            .run_blocking("quality", || Ok::<_, anyhow::Error>(()))
            .await
            .expect_err("queue budget must refuse excess work");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        first.await.unwrap().unwrap();
    }
}
