// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-deployment bounded priority admission and drain lifecycle.

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Notify};

use crate::PriorityClass;

/// Stable local admission rejection taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionReason {
    /// Selected device cannot hold the requested generation.
    InsufficientCapacity,
    /// Per-deployment queue reached its configured bound.
    QueueFull,
    /// Request did not reach active capacity before its deadline.
    QueueTimeout,
    /// Engine health prevents safe admission.
    EngineUnhealthy,
    /// Engine launch budget is exhausted until explicit reset.
    CrashLoop,
    /// Deployment is draining and rejects new work.
    Draining,
}

impl AdmissionReason {
    /// Stable snake-case reason code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientCapacity => "insufficient_capacity",
            Self::QueueFull => "queue_full",
            Self::QueueTimeout => "queue_timeout",
            Self::EngineUnhealthy => "engine_unhealthy",
            Self::CrashLoop => "crash_loop",
            Self::Draining => "draining",
        }
    }
}

impl std::fmt::Display for AdmissionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded operator-safe admission rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{reason}: {detail}")]
pub struct AdmissionRejection {
    /// Stable reason code.
    pub reason: AdmissionReason,
    /// Concise bounded explanation.
    pub detail: String,
    /// Whether a later attempt may succeed without config changes.
    pub retryable: bool,
    /// Suggested delay before retry, when meaningful.
    pub retry_after_ms: Option<u64>,
}

impl AdmissionRejection {
    /// Construct a bounded rejection.
    pub fn new(
        reason: AdmissionReason,
        detail: impl AsRef<str>,
        retryable: bool,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            reason,
            detail: bounded_detail(detail.as_ref()),
            retryable,
            retry_after_ms,
        }
    }
}

/// Current active and queued request counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionCounts {
    /// Requests holding an active permit.
    pub active: usize,
    /// Live waiters in the priority queue.
    pub queued: usize,
    /// Whether new work is rejected for drain.
    pub draining: bool,
}

/// Result of one bounded drain wait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DrainReport {
    /// Active requests when drain began.
    pub active_at_start: usize,
    /// Queued requests rejected when drain began.
    pub cancelled_queued: usize,
    /// Active requests still present when the wait returned.
    pub remaining_active: usize,
    /// Whether the deadline elapsed before every active permit left.
    pub timed_out: bool,
}

struct Waiter {
    id: u64,
    priority: PriorityClass,
    arrival: u64,
    sender: oneshot::Sender<Result<AdmissionPermit, AdmissionRejection>>,
}

struct GateState {
    active: usize,
    draining: bool,
    next_waiter_id: u64,
    queue: Vec<Waiter>,
    last_completed: Option<tokio::time::Instant>,
}

struct GateCore {
    max_active: usize,
    max_queue: usize,
    queue_timeout: Duration,
    telemetry: Mutex<AdmissionTelemetry>,
    state: Mutex<GateState>,
    idle_notify: Notify,
}

struct AdmissionTelemetry {
    deployment: Option<String>,
    observer: Arc<dyn crate::ModelHostObserver>,
}

impl GateCore {
    fn publish_counts(&self) {
        let (deployment, observer) = {
            let telemetry = self.telemetry.lock().expect("admission telemetry poisoned");
            (telemetry.deployment.clone(), telemetry.observer.clone())
        };
        let Some(deployment) = deployment else {
            return;
        };
        let counts = {
            let state = self.state.lock().expect("admission mutex poisoned");
            (state.active, state.queue.len())
        };
        observer.set_deployment_requests(&deployment, counts.0, counts.1);
    }

    fn publish_rejection(&self, priority: PriorityClass, rejection: &AdmissionRejection) {
        let (deployment, observer) = {
            let telemetry = self.telemetry.lock().expect("admission telemetry poisoned");
            (telemetry.deployment.clone(), telemetry.observer.clone())
        };
        let Some(deployment) = deployment else {
            return;
        };
        observer.on_admission_rejected(&deployment, priority, rejection.reason);
    }
}

/// Cloneable per-deployment admission gate.
#[derive(Clone)]
pub struct AdmissionGate {
    core: Arc<GateCore>,
}

impl std::fmt::Debug for AdmissionGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionGate")
            .field("max_active", &self.core.max_active)
            .field("max_queue", &self.core.max_queue)
            .field("queue_timeout", &self.core.queue_timeout)
            .field("counts", &self.counts())
            .finish()
    }
}

impl AdmissionGate {
    /// Create one gate with a positive active cap and timeout.
    pub fn new(
        max_active: usize,
        max_queue: usize,
        queue_timeout: Duration,
    ) -> Result<Self, String> {
        if max_active == 0 || queue_timeout.is_zero() {
            return Err("admission max_active and queue_timeout must be positive".to_string());
        }
        Ok(Self {
            core: Arc::new(GateCore {
                max_active,
                max_queue,
                queue_timeout,
                telemetry: Mutex::new(AdmissionTelemetry {
                    deployment: None,
                    observer: Arc::new(crate::NoopObserver),
                }),
                state: Mutex::new(GateState {
                    active: 0,
                    draining: false,
                    next_waiter_id: 1,
                    queue: Vec::new(),
                    last_completed: None,
                }),
                idle_notify: Notify::new(),
            }),
        })
    }

    /// Attach bounded deployment telemetry before the gate receives traffic.
    pub fn with_observer(
        self,
        deployment: impl Into<String>,
        observer: Arc<dyn crate::ModelHostObserver>,
    ) -> Self {
        self.set_observer(deployment, observer);
        self
    }

    pub(crate) fn set_observer(
        &self,
        deployment: impl Into<String>,
        observer: Arc<dyn crate::ModelHostObserver>,
    ) {
        let mut telemetry = self
            .core
            .telemetry
            .lock()
            .expect("admission telemetry poisoned");
        telemetry.deployment = Some(deployment.into());
        telemetry.observer = observer;
        drop(telemetry);
        self.core.publish_counts();
    }

    /// Admit immediately or wait in priority/FIFO order until the queue deadline.
    pub async fn admit(
        &self,
        priority: PriorityClass,
    ) -> Result<AdmissionPermit, AdmissionRejection> {
        let receiver = {
            let mut state = self.core.state.lock().expect("admission mutex poisoned");
            if state.draining {
                let rejection = draining_rejection();
                drop(state);
                self.core.publish_rejection(priority, &rejection);
                return Err(rejection);
            }
            if state.active < self.core.max_active && state.queue.is_empty() {
                state.active += 1;
                drop(state);
                self.core.publish_counts();
                return Ok(AdmissionPermit::new(self.core.clone()));
            }
            if state.queue.len() >= self.core.max_queue {
                let rejection = AdmissionRejection::new(
                    AdmissionReason::QueueFull,
                    "deployment admission queue is full",
                    true,
                    Some(duration_ms(self.core.queue_timeout)),
                );
                drop(state);
                self.core.publish_rejection(priority, &rejection);
                return Err(rejection);
            }
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.saturating_add(1);
            let (sender, receiver) = oneshot::channel();
            state.queue.push(Waiter {
                id,
                priority,
                arrival: id,
                sender,
            });
            (id, receiver)
        };
        let (id, receiver) = receiver;
        self.core.publish_counts();
        let mut cancellation = QueueCancellation {
            core: Arc::downgrade(&self.core),
            id,
            armed: true,
        };
        let result = tokio::select! {
            biased;
            result = receiver => match result {
                Ok(result) => result,
                Err(_) => Err(AdmissionRejection::new(
                    AdmissionReason::EngineUnhealthy,
                    "deployment admission queue closed unexpectedly",
                    true,
                    None,
                )),
            },
            () = tokio::time::sleep(self.core.queue_timeout) => Err(AdmissionRejection::new(
                AdmissionReason::QueueTimeout,
                "deployment admission queue deadline elapsed",
                true,
                Some(duration_ms(self.core.queue_timeout)),
            )),
        };
        cancellation.cancel();
        if let Err(rejection) = &result {
            self.core.publish_rejection(priority, rejection);
        }
        result
    }

    /// Enter draining, reject queued work, and wait boundedly for active permits.
    pub async fn drain(&self, deadline: Duration) -> DrainReport {
        let (active_at_start, cancelled_queued, waiters) = {
            let mut state = self.core.state.lock().expect("admission mutex poisoned");
            state.draining = true;
            let active = state.active;
            let waiters = std::mem::take(&mut state.queue);
            (active, waiters.len(), waiters)
        };
        for waiter in waiters {
            let _ = waiter.sender.send(Err(draining_rejection()));
        }
        self.core.publish_counts();
        let wait = async {
            loop {
                let notified = self.core.idle_notify.notified();
                if self.counts().active == 0 {
                    break;
                }
                notified.await;
            }
        };
        let timed_out = tokio::time::timeout(deadline, wait).await.is_err();
        DrainReport {
            active_at_start,
            cancelled_queued,
            remaining_active: self.counts().active,
            timed_out,
        }
    }

    /// Leave drain state after an explicit reset or restart.
    pub fn resume(&self) {
        self.core
            .state
            .lock()
            .expect("admission mutex poisoned")
            .draining = false;
        self.core.publish_counts();
    }

    /// Mark a ready deployment with no requests as newly idle.
    pub fn mark_ready_idle(&self) {
        let mut state = self.core.state.lock().expect("admission mutex poisoned");
        if state.active == 0 && state.queue.is_empty() && !state.draining {
            state.last_completed = Some(tokio::time::Instant::now());
        }
    }

    /// Whether an otherwise eligible deployment exceeded keep-alive.
    pub fn is_idle_expired(&self, keep_alive: Duration) -> bool {
        self.is_idle_expired_at(tokio::time::Instant::now(), keep_alive)
    }

    /// Deterministic keep-alive check at an explicit monotonic instant.
    pub fn is_idle_expired_at(&self, now: tokio::time::Instant, keep_alive: Duration) -> bool {
        let state = self.core.state.lock().expect("admission mutex poisoned");
        idle_expired(&state, now, keep_alive)
    }

    /// Atomically enter drain only when the gate is idle and keep-alive has elapsed.
    pub fn begin_idle_drain_if_expired_at(
        &self,
        now: tokio::time::Instant,
        keep_alive: Duration,
    ) -> bool {
        let mut state = self.core.state.lock().expect("admission mutex poisoned");
        if !idle_expired(&state, now, keep_alive) {
            return false;
        }
        state.draining = true;
        drop(state);
        self.core.publish_counts();
        true
    }

    /// Atomically enter drain only when no active or queued request exists.
    pub(crate) fn begin_idle_drain(&self) -> bool {
        let mut state = self.core.state.lock().expect("admission mutex poisoned");
        if state.draining || state.active != 0 || !state.queue.is_empty() {
            return false;
        }
        state.draining = true;
        drop(state);
        self.core.publish_counts();
        true
    }

    /// Current exact active, queued, and draining counts.
    pub fn counts(&self) -> AdmissionCounts {
        let state = self.core.state.lock().expect("admission mutex poisoned");
        AdmissionCounts {
            active: state.active,
            queued: state.queue.len(),
            draining: state.draining,
        }
    }
}

/// Active request ownership. Dropping it completes the request and wakes one waiter.
pub struct AdmissionPermit {
    core: Arc<GateCore>,
    released: bool,
}

impl std::fmt::Debug for AdmissionPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionPermit")
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl AdmissionPermit {
    fn new(core: Arc<GateCore>) -> Self {
        Self {
            core,
            released: false,
        }
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut state = self.core.state.lock().expect("admission mutex poisoned");
        state.active = state.active.saturating_sub(1);
        if state.active == 0 {
            state.last_completed = Some(tokio::time::Instant::now());
            self.core.idle_notify.notify_waiters();
        }
        while !state.draining && state.active < self.core.max_active && !state.queue.is_empty() {
            let index = state
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(_, waiter)| (waiter.priority.rank(), waiter.arrival))
                .map(|(index, _)| index)
                .expect("nonempty admission queue");
            let waiter = state.queue.remove(index);
            state.active += 1;
            let permit = AdmissionPermit::new(self.core.clone());
            if let Err(Ok(mut permit)) = waiter.sender.send(Ok(permit)) {
                permit.released = true;
                state.active = state.active.saturating_sub(1);
            }
        }
        drop(state);
        self.core.publish_counts();
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.release();
    }
}

struct QueueCancellation {
    core: Weak<GateCore>,
    id: u64,
    armed: bool,
}

impl QueueCancellation {
    fn cancel(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if let Some(core) = self.core.upgrade() {
            let mut state = core.state.lock().expect("admission mutex poisoned");
            state.queue.retain(|waiter| waiter.id != self.id);
            drop(state);
            core.publish_counts();
        }
    }
}

impl Drop for QueueCancellation {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn draining_rejection() -> AdmissionRejection {
    AdmissionRejection::new(
        AdmissionReason::Draining,
        "deployment is draining",
        true,
        None,
    )
}

fn idle_expired(state: &GateState, now: tokio::time::Instant, keep_alive: Duration) -> bool {
    !state.draining
        && state.active == 0
        && state.queue.is_empty()
        && state
            .last_completed
            .is_some_and(|completed| now.saturating_duration_since(completed) >= keep_alive)
}

fn bounded_detail(detail: &str) -> String {
    detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect()
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropped_handoff_receiver_rolls_back_active_capacity() {
        let gate = AdmissionGate::new(1, 1, Duration::from_secs(1)).unwrap();
        let active = gate.admit(PriorityClass::Standard).await.unwrap();
        let (sender, receiver) = oneshot::channel();
        drop(receiver);
        gate.core.state.lock().unwrap().queue.push(Waiter {
            id: 1,
            priority: PriorityClass::Standard,
            arrival: 1,
            sender,
        });

        drop(active);

        assert_eq!(gate.counts().active, 0);
        assert_eq!(gate.counts().queued, 0);
    }
}
