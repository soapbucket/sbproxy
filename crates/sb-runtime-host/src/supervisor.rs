// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Retry and crash-loop lifecycle for typed managed-engine drivers.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::EngineDriver;
use sb_runtime_core::{
    EngineDriverError, EngineExecutionIdentity, EngineFailureReason, EngineHealth,
};

/// Bounded exponential-backoff policy for launch retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// Delay before the first retry.
    pub base: Duration,
    /// Maximum retry delay.
    pub max: Duration,
    /// Maximum consecutive launch attempts, or no limit.
    pub max_attempts: Option<u32>,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            max_attempts: Some(5),
        }
    }
}

impl BackoffPolicy {
    /// Delay before the next attempt after `attempt` failures.
    #[must_use]
    pub fn delay_for(self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(20);
        self.base.saturating_mul(1_u32 << shift).min(self.max)
    }

    /// Whether another attempt is allowed after `attempts` failures.
    #[must_use]
    pub fn should_retry(self, attempts: u32) -> bool {
        self.max_attempts.is_none_or(|maximum| attempts < maximum)
    }
}

/// Time boundary used by managed-engine retry supervision.
#[async_trait]
pub trait SupervisorClock: Send + Sync {
    /// Wait for one retry delay.
    async fn sleep(&self, duration: Duration);

    /// Current Unix timestamp in milliseconds.
    fn now_ms(&self) -> u64;
}

/// Production retry clock backed by Tokio and the system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSupervisorClock;

#[async_trait]
impl SupervisorClock for TokioSupervisorClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0)
    }
}

/// Retained terminal launch failure that requires an explicit reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CrashLoopState {
    /// Consecutive failed launch attempts.
    pub attempts: u32,
    /// Stable reason reported by the last attempt.
    pub reason: EngineFailureReason,
    /// Bounded operator-safe message from the last attempt.
    pub last_error: String,
    /// Bounded, credential-redacted engine diagnostic tail.
    pub stderr_tail: Option<String>,
    /// Timestamp of the first failure in this retry sequence.
    pub first_failure_at_ms: u64,
    /// Timestamp of the terminal failure in this retry sequence.
    pub last_failure_at_ms: u64,
    /// Operator action required before retrying.
    pub next_remediation: String,
}

/// Typed lifecycle supervisor for one canonical managed deployment.
pub struct EngineSupervisor<D>
where
    D: EngineDriver + ?Sized,
{
    deployment: String,
    driver: Arc<D>,
    backoff: BackoffPolicy,
    clock: Arc<dyn SupervisorClock>,
    running: Option<D::RunningEngine>,
    crash_loop: Option<CrashLoopState>,
}

impl<D> std::fmt::Debug for EngineSupervisor<D>
where
    D: EngineDriver + ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineSupervisor")
            .field("deployment", &self.deployment)
            .field("driver_kind", &self.driver.kind())
            .field("backoff", &self.backoff)
            .field("has_running_generation", &self.running.is_some())
            .field("crash_loop", &self.crash_loop)
            .finish_non_exhaustive()
    }
}

impl<D> EngineSupervisor<D>
where
    D: EngineDriver + ?Sized,
{
    /// Construct an idle supervisor for one canonical deployment.
    #[must_use]
    pub fn new(deployment: impl Into<String>, driver: Arc<D>, backoff: BackoffPolicy) -> Self {
        Self {
            deployment: deployment.into(),
            driver,
            backoff,
            clock: Arc::new(TokioSupervisorClock),
            running: None,
            crash_loop: None,
        }
    }

    /// Override the retry clock, primarily for deterministic tests.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn SupervisorClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Currently running engine generation, when ready.
    #[must_use]
    pub fn running(&self) -> Option<&D::RunningEngine> {
        self.running.as_ref()
    }

    /// Retained terminal crash loop, when reset is required.
    #[must_use]
    pub fn crash_loop(&self) -> Option<&CrashLoopState> {
        self.crash_loop.as_ref()
    }

    /// Provision one exact managed-engine installation.
    pub async fn provision(
        &self,
        request: &D::ProvisionRequest,
    ) -> Result<D::ProvisionedEngine, EngineDriverError> {
        self.validate_deployment()?;
        self.driver.provision(request).await
    }

    /// Launch a provisioned engine with bounded delayed retries.
    ///
    /// A terminal failure is retained and later calls fail without invoking
    /// the driver until [`Self::reset`] is called.
    pub async fn ensure_ready(
        &mut self,
        provisioned: &D::ProvisionedEngine,
        request: &D::LaunchRequest,
    ) -> Result<D::RunningEngine, EngineDriverError> {
        self.validate_deployment()?;
        let identity = self.driver.launch_identity(request);
        self.validate_identity(&identity, "launch")?;
        if let Some(running) = self.running.take() {
            if self.driver.running_identity(&running) == identity {
                self.running = Some(running.clone());
                return Ok(running);
            }
            self.shutdown_for_replacement(running).await?;
        }
        if let Some(crash_loop) = &self.crash_loop {
            return Err(self.crash_loop_error(crash_loop));
        }

        let mut attempts = 0_u32;
        let mut retained: Option<CrashLoopState> = None;
        loop {
            match self.driver.launch(provisioned, request).await {
                Ok(running) => {
                    let running_identity = self.driver.running_identity(&running);
                    if running_identity != identity {
                        self.shutdown_for_replacement(running).await?;
                        return Err(EngineDriverError::new(
                            EngineFailureReason::EngineInternal,
                            "driver returned a running identity that differs from the launch request",
                            "repair the typed driver identity mapping before retrying",
                            false,
                        ));
                    }
                    self.crash_loop = None;
                    self.running = Some(running.clone());
                    return Ok(running);
                }
                Err(error) => {
                    attempts = attempts.saturating_add(1);
                    tracing::error!(
                        deployment = %self.deployment,
                        reason = %error.reason(),
                        attempts,
                        retryable = error.retryable(),
                        stderr_tail = error.diagnostic_tail().unwrap_or(""),
                        "managed engine launch attempt failed"
                    );
                    let now_ms = self.clock.now_ms();
                    let first_failure_at_ms = retained
                        .as_ref()
                        .map_or(now_ms, |state| state.first_failure_at_ms);
                    retained = Some(CrashLoopState {
                        attempts,
                        reason: error.reason(),
                        last_error: error.message().to_string(),
                        stderr_tail: error.diagnostic_tail().map(str::to_string),
                        first_failure_at_ms,
                        last_failure_at_ms: now_ms.max(first_failure_at_ms),
                        next_remediation: error.remediation().to_string(),
                    });
                    if error.retryable() && self.backoff.should_retry(attempts) {
                        self.clock.sleep(self.backoff.delay_for(attempts)).await;
                        continue;
                    }
                    self.crash_loop = retained;
                    return Err(error);
                }
            }
        }
    }

    /// Check the retained running generation through its typed driver.
    pub async fn health(
        &self,
        running: &D::RunningEngine,
    ) -> Result<EngineHealth, EngineDriverError> {
        self.validate_deployment()?;
        self.validate_identity(&self.driver.running_identity(running), "health")?;
        self.driver.health(running).await
    }

    /// Clear a retained crash loop and permit a later launch.
    pub fn reset(&mut self) -> bool {
        self.crash_loop.take().is_some()
    }

    /// Stop the running generation, retaining it when shutdown fails.
    pub async fn shutdown(&mut self, grace: Duration) -> Result<(), EngineDriverError> {
        self.validate_deployment()?;
        let Some(running) = self.running.clone() else {
            return Ok(());
        };
        self.driver.shutdown(running, grace).await?;
        self.running = None;
        Ok(())
    }

    async fn shutdown_for_replacement(
        &mut self,
        running: D::RunningEngine,
    ) -> Result<(), EngineDriverError> {
        if let Err(error) = self
            .driver
            .shutdown(running.clone(), Duration::from_secs(1))
            .await
        {
            self.running = Some(running);
            return Err(error);
        }
        Ok(())
    }

    fn validate_deployment(&self) -> Result<(), EngineDriverError> {
        if self.deployment.trim().is_empty()
            || self.deployment.len() > 128
            || self.deployment.chars().any(char::is_control)
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "engine supervisor deployment ID is invalid",
                "reconcile a canonical deployment ID before provisioning",
                false,
            ));
        }
        Ok(())
    }

    fn validate_identity(
        &self,
        identity: &EngineExecutionIdentity,
        operation: &str,
    ) -> Result<(), EngineDriverError> {
        identity.validate()?;
        if identity.deployment != self.deployment {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                format!(
                    "{operation} deployment {:?} does not match supervisor {:?}",
                    identity.deployment, self.deployment
                ),
                "reconcile the lifecycle through the matching deployment supervisor",
                false,
            ));
        }
        if identity.kind != self.driver.kind() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "lifecycle identity kind does not match the typed driver",
                "route the lifecycle request through its matching managed driver",
                false,
            ));
        }
        Ok(())
    }

    fn crash_loop_error(&self, state: &CrashLoopState) -> EngineDriverError {
        let error = EngineDriverError::new(
            EngineFailureReason::CrashLoop,
            format!(
                "deployment {:?} exhausted {} launch attempts",
                self.deployment, state.attempts
            ),
            &state.next_remediation,
            false,
        );
        state
            .stderr_tail
            .as_deref()
            .map_or(error.clone(), |tail| error.with_diagnostic_tail(tail))
    }
}
