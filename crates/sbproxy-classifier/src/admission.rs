//! Shared bounded admission for CPU-bound rich-sidecar RPC work.

use anyhow::{anyhow, bail};
#[cfg(test)]
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::panic::AssertUnwindSafe;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{Condvar, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tonic::Status;

#[derive(Clone, Debug)]
pub struct Admission {
    running: Arc<Semaphore>,
    queued: Arc<Semaphore>,
    deadline: Duration,
    #[cfg(test)]
    test_probe: Option<Arc<AdmissionProbe>>,
}

pub struct Lease {
    running: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    running_semaphore: Arc<Semaphore>,
    #[cfg(test)]
    probe: Option<Arc<AdmissionProbe>>,
    expires: Instant,
}

impl Lease {
    pub fn expires(&self) -> Instant {
        self.expires
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        drop(self.running.take());
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            probe.set_available_running_permits(self.running_semaphore.available_permits());
        }
    }
}

struct QueueWaitGuard {
    command: &'static str,
    permit: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    queued_semaphore: Arc<Semaphore>,
    #[cfg(test)]
    probe: Option<Arc<AdmissionProbe>>,
}

impl QueueWaitGuard {
    fn new(
        command: &'static str,
        permit: OwnedSemaphorePermit,
        _queued_semaphore: Arc<Semaphore>,
    ) -> Self {
        crate::metrics::adjust_admission_queue(command, 1);
        Self {
            command,
            permit: Some(permit),
            #[cfg(test)]
            queued_semaphore: _queued_semaphore,
            #[cfg(test)]
            probe: None,
        }
    }

    #[cfg(test)]
    fn with_probe(mut self, probe: Option<Arc<AdmissionProbe>>) -> Self {
        if let Some(probe) = &probe {
            probe.set_available_queue_permits(self.queued_semaphore.available_permits());
        }
        self.probe = probe;
        self
    }
}

impl Drop for QueueWaitGuard {
    fn drop(&mut self) {
        crate::metrics::adjust_admission_queue(self.command, -1);
        drop(self.permit.take());
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            probe.set_available_queue_permits(self.queued_semaphore.available_permits());
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockingWorkLimits {
    pub max_running: usize,
    pub max_queued: usize,
    pub deadline: Duration,
}

impl BlockingWorkLimits {
    pub fn admission(&self) -> anyhow::Result<Admission> {
        Admission::new(self.max_running, self.max_queued, self.deadline)
    }
}

#[derive(Debug, Default)]
#[cfg(test)]
pub(crate) struct AdmissionProbe {
    available_running_permits: AtomicUsize,
    available_queue_permits: AtomicUsize,
}

#[cfg(test)]
impl AdmissionProbe {
    fn set_available_running_permits(&self, value: usize) {
        self.available_running_permits
            .store(value, Ordering::SeqCst);
    }

    fn set_available_queue_permits(&self, value: usize) {
        self.available_queue_permits.store(value, Ordering::SeqCst);
    }

    pub(crate) async fn wait_for_available_queue_permits(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.available_queue_permits.load(Ordering::SeqCst) == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "available queue permits did not reach {expected}; current value is {}",
                    self.available_queue_permits.load(Ordering::SeqCst)
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[derive(Debug, Default)]
#[cfg(test)]
pub(crate) struct WorkerBarrier {
    state: Mutex<WorkerBarrierState>,
    wake: Condvar,
}

#[derive(Debug, Default)]
#[cfg(test)]
struct WorkerBarrierState {
    entered: usize,
    released: usize,
    release_all: bool,
}

#[cfg(test)]
impl WorkerBarrier {
    fn enter_and_wait(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.entered = state.entered.saturating_add(1);
        let ticket = state.entered;
        self.wake.notify_all();
        while !state.release_all && state.released < ticket {
            state = self
                .wake
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    pub(crate) fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.released = state.released.saturating_add(1);
        self.wake.notify_all();
    }

    pub(crate) async fn wait_until_entered(&self, within: Duration) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .entered
                > 0
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("worker barrier was not entered before its deadline");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[derive(Clone, Debug)]
#[cfg(test)]
pub(crate) enum BlockingExecutorFault {
    Error(String),
    Panic(String),
    Hold(Arc<WorkerBarrier>),
}

#[derive(Debug)]
#[cfg(test)]
pub(crate) struct ArmedBlockingExecutorFault {
    consumed: AtomicUsize,
}

#[cfg(test)]
impl ArmedBlockingExecutorFault {
    fn mark_consumed(&self) {
        self.consumed.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn assert_consumed_exactly_once(&self) {
        assert_eq!(
            self.consumed.load(Ordering::SeqCst),
            1,
            "blocking executor fault must be consumed exactly once"
        );
    }
}

#[derive(Debug, Default)]
#[cfg(test)]
pub(crate) struct BlockingExecutorFaultControl {
    faults: Mutex<HashMap<String, VecDeque<PendingBlockingExecutorFault>>>,
    active_workers: Mutex<HashMap<String, usize>>,
}

#[derive(Debug)]
#[cfg(test)]
struct PendingBlockingExecutorFault {
    fault: BlockingExecutorFault,
    armed: Arc<ArmedBlockingExecutorFault>,
}

#[cfg(test)]
impl BlockingExecutorFaultControl {
    pub(crate) fn arm_next(
        &self,
        command: &str,
        fault: BlockingExecutorFault,
    ) -> Arc<ArmedBlockingExecutorFault> {
        let armed = Arc::new(ArmedBlockingExecutorFault {
            consumed: AtomicUsize::new(0),
        });
        self.faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(command.to_string())
            .or_default()
            .push_back(PendingBlockingExecutorFault {
                fault,
                armed: Arc::clone(&armed),
            });
        armed
    }

    fn take_fault(&self, command: &str) -> Option<BlockingExecutorFault> {
        let pending = self
            .faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(command)
            .and_then(VecDeque::pop_front);
        pending.map(|pending| {
            pending.armed.mark_consumed();
            pending.fault
        })
    }

    fn worker_started(&self, command: &str) {
        let mut counts = self
            .active_workers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *counts.entry(command.to_string()).or_default() += 1;
    }

    fn worker_finished(&self, command: &str) {
        let mut counts = self
            .active_workers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(count) = counts.get_mut(command) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(command);
            }
        }
    }

    pub(crate) async fn wait_for_active_workers(
        &self,
        command: &str,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let current = self
                .active_workers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(command)
                .copied()
                .unwrap_or(0);
            if current == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("active workers for {command:?} did not reach {expected}; current value is {current}");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockingWorkExecutor {
    admission: Admission,
    #[cfg(test)]
    test_fault_control: Option<Arc<BlockingExecutorFaultControl>>,
}

impl BlockingWorkExecutor {
    pub fn new(admission: Admission) -> Self {
        Self {
            admission,
            #[cfg(test)]
            test_fault_control: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_fault_control(
        mut self,
        control: Arc<BlockingExecutorFaultControl>,
    ) -> Self {
        self.test_fault_control = Some(control);
        self
    }

    pub fn admission(&self) -> &Admission {
        &self.admission
    }

    // `tonic::Status` is 176 bytes, over `result_large_err`'s threshold; see the
    // note on `check_text_bytes` for why this takes the allow, not the reshape.
    #[allow(clippy::result_large_err)]
    pub async fn run_blocking<F, T>(&self, command: &'static str, work: F) -> Result<T, Status>
    where
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let lease = self.admission.acquire(command).await?;
        let expires = lease.expires();
        #[cfg(test)]
        let faults = self.test_fault_control.clone();
        let worker = tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                let _lease = lease;
                #[cfg(test)]
                let _worker_guard = faults
                    .as_ref()
                    .map(|faults| ActiveWorkerGuard::new(Arc::clone(faults), command));
                #[cfg(test)]
                if let Some(faults) = &faults {
                    match faults.take_fault(command) {
                        Some(BlockingExecutorFault::Error(message)) => {
                            return Err(anyhow!(message))
                        }
                        Some(BlockingExecutorFault::Panic(_message)) => panic!(),
                        Some(BlockingExecutorFault::Hold(barrier)) => barrier.enter_and_wait(),
                        None => {}
                    }
                }
                work()
            }))
            .unwrap_or_else(|_| Err(anyhow!("classifier inference failed")))
        });
        sanitize_blocking_result(command, expires, worker).await
    }
}

#[cfg(test)]
struct ActiveWorkerGuard {
    faults: Arc<BlockingExecutorFaultControl>,
    command: &'static str,
}

#[cfg(test)]
impl ActiveWorkerGuard {
    fn new(faults: Arc<BlockingExecutorFaultControl>, command: &'static str) -> Self {
        faults.worker_started(command);
        Self { faults, command }
    }
}

#[cfg(test)]
impl Drop for ActiveWorkerGuard {
    fn drop(&mut self) {
        self.faults.worker_finished(self.command);
    }
}

// `tonic::Status` is 176 bytes, over `result_large_err`'s threshold; see the
// note on `check_text_bytes` for why this takes the allow, not the reshape.
#[allow(clippy::result_large_err)]
async fn sanitize_blocking_result<T>(
    command: &'static str,
    expires: Instant,
    worker: tokio::task::JoinHandle<anyhow::Result<T>>,
) -> Result<T, Status>
where
    T: Send + 'static,
{
    match tokio::time::timeout_at(expires, worker).await {
        Ok(Ok(result)) => result.map_err(|_error| Status::internal("classifier inference failed")),
        Ok(Err(_join_error)) => Err(Status::internal("classifier inference failed")),
        Err(_) => {
            crate::metrics::record_admission_refusal(command, "deadline");
            Err(Status::deadline_exceeded(
                "classifier inference deadline exceeded",
            ))
        }
    }
}

impl Admission {
    pub fn new(max_running: usize, max_queued: usize, deadline: Duration) -> anyhow::Result<Self> {
        if !(1..=64).contains(&max_running) {
            bail!("inference max running must be in 1..=64");
        }
        if max_queued > 1024 {
            bail!("inference max queued must be in 0..=1024");
        }
        if deadline.is_zero() || deadline > Duration::from_secs(30) {
            bail!("inference deadline must be in 1..=30000ms");
        }
        Ok(Self {
            running: Arc::new(Semaphore::new(max_running)),
            queued: Arc::new(Semaphore::new(max_queued)),
            deadline,
            #[cfg(test)]
            test_probe: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_probe(mut self, probe: Arc<AdmissionProbe>) -> Self {
        probe.set_available_running_permits(self.running.available_permits());
        probe.set_available_queue_permits(self.queued.available_permits());
        self.test_probe = Some(probe);
        self
    }

    // `tonic::Status` is 176 bytes, over `result_large_err`'s threshold; see the
    // note on `check_text_bytes` for why this takes the allow, not the reshape.
    #[allow(clippy::result_large_err)]
    pub async fn acquire(&self, command: &'static str) -> Result<Lease, Status> {
        let expires = Instant::now()
            .checked_add(self.deadline)
            .ok_or_else(|| Status::deadline_exceeded("unrepresentable deadline"))?;
        let running = match Arc::clone(&self.running).try_acquire_owned() {
            Ok(permit) => {
                #[cfg(test)]
                if let Some(probe) = &self.test_probe {
                    probe.set_available_running_permits(self.running.available_permits());
                }
                permit
            }
            Err(_) => {
                let queued = Arc::clone(&self.queued).try_acquire_owned().map_err(|_| {
                    crate::metrics::record_admission_refusal(command, "queue_full");
                    Status::resource_exhausted("classifier inference queue is full")
                })?;
                let queued = QueueWaitGuard::new(command, queued, Arc::clone(&self.queued));
                #[cfg(test)]
                let queued = queued.with_probe(self.test_probe.clone());
                let acquired =
                    tokio::time::timeout_at(expires, Arc::clone(&self.running).acquire_owned())
                        .await;
                match acquired {
                    Ok(Ok(permit)) => {
                        drop(queued);
                        #[cfg(test)]
                        if let Some(probe) = &self.test_probe {
                            probe.set_available_running_permits(self.running.available_permits());
                        }
                        permit
                    }
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
            running: Some(running),
            #[cfg(test)]
            running_semaphore: Arc::clone(&self.running),
            #[cfg(test)]
            probe: self.test_probe.clone(),
            expires,
        })
    }

    // `tonic::Status` is 176 bytes, over `result_large_err`'s threshold; see the
    // note on `check_text_bytes` for why this takes the allow, not the reshape.
    #[allow(clippy::result_large_err)]
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
        sanitize_blocking_result(command, expires, worker).await
    }

    // `tonic::Status` is 176 bytes, over `result_large_err`'s threshold; see the
    // note on `check_text_bytes` for why this takes the allow, not the reshape.
    #[allow(clippy::result_large_err)]
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

    #[test]
    fn config_rejects_out_of_bounds_limits() {
        for (running, queued, deadline) in [
            (0, 0, Duration::from_millis(100)),
            (65, 0, Duration::from_millis(100)),
            (usize::MAX, 0, Duration::from_millis(100)),
            (1, 1025, Duration::from_millis(100)),
            (1, usize::MAX, Duration::from_millis(100)),
            (1, 0, Duration::from_millis(0)),
            (1, 0, Duration::from_secs(31)),
            (1, 0, Duration::MAX),
        ] {
            assert!(Admission::new(running, queued, deadline).is_err());
        }
    }

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_blocking_worker_retains_running_lease_until_worker_exit() {
        struct ReleaseWorkerOnDrop(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

        impl Drop for ReleaseWorkerOnDrop {
            fn drop(&mut self) {
                let (lock, wake) = &*self.0;
                *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
                wake.notify_all();
            }
        }

        let admission = Admission::new(1, 0, Duration::from_millis(40)).unwrap();
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let _release_worker_on_drop = ReleaseWorkerOnDrop(Arc::clone(&gate));
        let replacement_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let timed_out = {
            let admission = admission.clone();
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                admission
                    .run_blocking("model_info", move || {
                        let _ = started_tx.send(());
                        let (lock, wake) = &*gate;
                        let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
                        while !*released {
                            released = wake
                                .wait(released)
                                .unwrap_or_else(|error| error.into_inner());
                        }
                        Ok::<_, anyhow::Error>(())
                    })
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(3), started_rx)
            .await
            .expect("blocking worker startup signal has a deadline")
            .expect("blocking worker reached its real work body");
        let timeout = timed_out
            .await
            .expect("caller task joins")
            .expect_err("the caller deadline must expire while work remains live");
        assert_eq!(timeout.code(), tonic::Code::DeadlineExceeded);

        let replacement = {
            let replacement_started = Arc::clone(&replacement_started);
            admission
                .run_blocking("model_info", move || {
                    replacement_started.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, anyhow::Error>(())
                })
                .await
        };
        let replacement_started_before_release =
            replacement_started.load(std::sync::atomic::Ordering::SeqCst);

        {
            let (lock, wake) = &*gate;
            *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
            wake.notify_all();
        }
        let refused = replacement.expect_err("capacity must remain owned by the timed-out worker");
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
        assert!(
            !replacement_started_before_release,
            "replacement work started while the timed-out worker was still running"
        );
        let recovery_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match admission
                .run_blocking("model_info", || Ok::<_, anyhow::Error>(()))
                .await
            {
                Ok(()) => break,
                Err(status)
                    if status.code() == tonic::Code::ResourceExhausted
                        && tokio::time::Instant::now() < recovery_deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(status) => panic!("worker capacity did not recover after exit: {status}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_error_and_panic_child() {
        let Some(marker) = std::env::var_os("SBPROXY_CLASSIFIER_WORKER_PRIVACY_MARKER") else {
            return;
        };
        const ERROR_SENTINEL: &str = "synthetic-error-sentinel-9b184c";
        const PANIC_SENTINEL: &str = "synthetic-panic-sentinel-4ac738";

        // This is deliberately a production-assembly compile-RED.  The same
        // installer and executor/runtime constructors must be called by
        // `main`; a direct `Admission` fixture cannot prove the release panic
        // path or the handler-to-worker wiring.
        crate::startup::install_classifier_panic_policy();
        let faults = Arc::new(BlockingExecutorFaultControl::default());
        let startup_control = crate::startup::RuntimeTestControl::default()
            .with_blocking_executor_faults(Arc::clone(&faults));
        let manifest = crate::grpc::ModelManifest {
            models: Vec::new(),
            default_classifier: None,
            default_embedder: None,
        };
        let runtime = tokio::time::timeout(
            Duration::from_secs(3),
            startup_control.observe_current_task(crate::startup::ClassifierRuntime::prepare(
                manifest,
                crate::startup::RuntimeLimits::test_defaults().with_blocking_work_limits(
                    BlockingWorkLimits {
                        max_running: 1,
                        max_queued: 0,
                        deadline: Duration::from_secs(1),
                    },
                ),
            )),
        )
        .await
        .expect("privacy runtime startup assembly is bounded")
        .expect("empty-catalog privacy runtime is valid");
        startup_control.assert_blocking_executor_wired_exactly_once();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cleanup = Arc::new(crate::grpc::GrpcListenerCleanupProbe::default());
        let server = tokio::spawn(crate::grpc::serve_on(
            listener,
            runtime.grpc_state(),
            crate::grpc::GrpcServerLimits::test_defaults().with_cleanup_probe(Arc::clone(&cleanup)),
        ));
        let mut client = tokio::time::timeout(
            Duration::from_secs(3),
            sbproxy_classifier_proto::ClassifierServiceClient::connect(format!("http://{address}")),
        )
        .await
        .expect("privacy child connects to the production gRPC assembly")
        .unwrap();

        let error_fault = faults.arm_next(
            "quality",
            BlockingExecutorFault::Error(ERROR_SENTINEL.to_string()),
        );
        let error = tokio::time::timeout(
            Duration::from_secs(3),
            client.quality(sbproxy_classifier_proto::QualityRequest {
                tenant: String::new(),
                text: "error request".to_string(),
            }),
        )
        .await
        .expect("worker-error RPC reaches a bounded terminal status")
        .expect_err("synthetic production worker error must fail");
        error_fault.assert_consumed_exactly_once();

        let panic_fault = faults.arm_next(
            "quality",
            BlockingExecutorFault::Panic(PANIC_SENTINEL.to_string()),
        );
        let panic = tokio::time::timeout(
            Duration::from_secs(3),
            client.quality(sbproxy_classifier_proto::QualityRequest {
                tenant: String::new(),
                text: "panic request".to_string(),
            }),
        )
        .await
        .expect("worker-panic RPC reaches a bounded terminal status")
        .expect_err("synthetic production worker panic must fail");
        panic_fault.assert_consumed_exactly_once();

        let recovered = tokio::time::timeout(
            Duration::from_secs(3),
            client.quality(sbproxy_classifier_proto::QualityRequest {
                tenant: String::new(),
                text: "recovery request".to_string(),
            }),
        )
        .await
        .expect("worker lease recovery is bounded")
        .is_ok();
        drop(client);
        assert!(
            !server.is_finished(),
            "privacy gRPC listener exited before explicit cleanup"
        );
        let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        cleanup.request_graceful_shutdown_before(shutdown_deadline);
        let server_join = tokio::time::timeout_at(shutdown_deadline, server)
            .await
            .expect("privacy gRPC listener joins before cleanup deadline")
            .expect("privacy gRPC listener task must not panic");
        let exit = server_join.expect("privacy gRPC listener reports clean graceful shutdown");
        exit.assert_quiescent_at_return()
            .expect("privacy gRPC owner returns with no detached child or reaper");
        assert_eq!(exit.active_connection_children(), 0);
        assert_eq!(
            exit.connection_children_spawned(),
            exit.connection_children_finished()
        );
        assert_eq!(
            exit.connection_child_results_collected(),
            exit.connection_children_spawned(),
            "privacy startup owner joins every connection child"
        );
        assert_eq!(exit.connection_child_panics(), 0);
        assert_eq!(exit.connection_child_events_after_owner_return(), 0);
        assert_eq!(
            exit.collection_deadline_id(),
            cleanup.shutdown_deadline_id()
        );
        std::fs::write(
            marker,
            format!(
                "error={}\npanic={}\nrecovered={recovered}\n",
                error.message(),
                panic.message()
            ),
        )
        .unwrap();
    }

    #[test]
    fn worker_failures_use_fixed_wire_status_and_never_log_panic_payloads() {
        use std::io::Read as _;

        const MAX_CAPTURE_BYTES: usize = 16 * 1024;

        fn read_bounded(path: &std::path::Path) -> String {
            let mut bytes = Vec::new();
            let file = std::fs::File::open(path).unwrap();
            assert!(
                file.metadata().unwrap().len() <= MAX_CAPTURE_BYTES as u64,
                "privacy marker exceeded its {MAX_CAPTURE_BYTES}-byte capture contract"
            );
            file.take(MAX_CAPTURE_BYTES as u64)
                .read_to_end(&mut bytes)
                .unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        }

        /// A bounded pipe drain: the receiver of one capture attempt, and the
        /// thread doing the reading.
        type BoundedDrain = (
            std::sync::mpsc::Receiver<std::io::Result<(Vec<u8>, usize)>>,
            std::thread::JoinHandle<()>,
        );

        fn drain_pipe_bounded<R>(mut pipe: R) -> BoundedDrain
        where
            R: std::io::Read + Send + 'static,
        {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || {
                let result = (|| {
                    let mut captured = Vec::with_capacity(MAX_CAPTURE_BYTES);
                    let mut total = 0usize;
                    let mut chunk = [0u8; 4096];
                    loop {
                        let read = pipe.read(&mut chunk)?;
                        if read == 0 {
                            break;
                        }
                        total = total.saturating_add(read);
                        let remaining = MAX_CAPTURE_BYTES.saturating_sub(captured.len());
                        captured.extend_from_slice(&chunk[..read.min(remaining)]);
                        // Continue draining after the capture ceiling so the
                        // child can never block on a full stdout/stderr pipe.
                    }
                    Ok((captured, total))
                })();
                let _ = send.send(result);
            });
            (receive, thread)
        }

        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("worker-privacy.txt");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("admission::tests::worker_error_and_panic_child")
            .arg("--nocapture")
            .env("SBPROXY_CLASSIFIER_WORKER_PRIVACY_MARKER", &marker)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let (stdout, stdout_thread) =
            drain_pipe_bounded(child.stdout.take().expect("child stdout is piped"));
        let (stderr, stderr_thread) =
            drain_pipe_bounded(child.stderr.take().expect("child stderr is piped"));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let (status, exceeded_deadline) = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break (status, false);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let reap_deadline = std::time::Instant::now() + Duration::from_secs(3);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    assert!(
                        std::time::Instant::now() < reap_deadline,
                        "isolated worker privacy child could not be reaped after kill"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                };
                break (status, true);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_total) = stdout
            .recv_timeout(Duration::from_secs(3))
            .expect("stdout drain reaches EOF after child exit")
            .expect("stdout drain succeeds");
        let (stderr, stderr_total) = stderr
            .recv_timeout(Duration::from_secs(3))
            .expect("stderr drain reaches EOF after child exit")
            .expect("stderr drain succeeds");
        stdout_thread
            .join()
            .expect("stdout drain thread joins after its bounded EOF signal");
        stderr_thread
            .join()
            .expect("stderr drain thread joins after its bounded EOF signal");
        assert!(
            !exceeded_deadline,
            "isolated worker privacy child exceeded its 10-second deadline"
        );
        assert!(
            stdout_total <= MAX_CAPTURE_BYTES,
            "privacy child stdout exceeded its {MAX_CAPTURE_BYTES}-byte capture contract"
        );
        assert!(
            stderr_total <= MAX_CAPTURE_BYTES,
            "privacy child stderr exceeded its {MAX_CAPTURE_BYTES}-byte capture contract"
        );
        let stdout = String::from_utf8_lossy(&stdout).into_owned();
        let stderr = String::from_utf8_lossy(&stderr).into_owned();
        assert!(
            status.success(),
            "isolated worker privacy child failed: {}",
            stderr
        );

        let marker_text = read_bounded(&marker);
        let captured = format!("{marker_text}\n{stdout}\n{stderr}");
        assert_eq!(
            marker_text,
            "error=classifier inference failed\npanic=classifier inference failed\nrecovered=true\n",
            "both internal worker failures need one fixed public contract"
        );
        assert!(!captured.contains("synthetic-error-sentinel-9b184c"));
        assert!(!captured.contains("synthetic-panic-sentinel-4ac738"));
    }
}
