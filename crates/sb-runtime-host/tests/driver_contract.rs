// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{
    EngineAvailability, EngineCapabilities, EngineDetection, EngineDriverError,
    EngineExecutionIdentity, EngineHealth, EngineKind,
};
use sb_runtime_host::{
    EngineDriver, LaunchRequest, ProvisionRequest, ProvisionedEngine, RunningEngine,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureProcess;

#[derive(Clone)]
struct CanaryPayload;

impl std::fmt::Debug for CanaryPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SYNTHETIC_CANARY")
    }
}

#[derive(Debug)]
struct FixtureDriver;

#[async_trait]
impl EngineDriver for FixtureDriver {
    type ArtifactFormat = &'static str;
    type Accelerator = &'static str;
    type Worker = &'static str;
    type Provisioning = &'static str;
    type ProvisionRequest = ProvisionRequest<&'static str, &'static str, &'static str>;
    type ProvisionedEngine = ProvisionedEngine<&'static str>;
    type LaunchRequest = LaunchRequest<&'static str, u64, &'static str, ()>;
    type RunningEngine = RunningEngine<&'static str, u64, FixtureProcess>;

    fn kind(&self) -> EngineKind {
        EngineKind::LlamaCpp
    }

    fn capabilities(&self) -> EngineCapabilities<Self::ArtifactFormat, Self::Accelerator> {
        EngineCapabilities {
            artifact_formats: vec!["gguf"],
            accelerators: vec!["cpu"],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(
        &self,
        _worker: &Self::Worker,
        _provisioning: &Self::Provisioning,
    ) -> EngineDetection {
        EngineDetection {
            kind: self.kind(),
            availability: EngineAvailability::Available,
            version: Some("fixture-v1".to_string()),
            reason: "fixture executable is pinned".to_string(),
            remediation: None,
        }
    }

    fn launch_identity(&self, request: &Self::LaunchRequest) -> EngineExecutionIdentity {
        request.identity.clone()
    }

    fn running_identity(&self, running: &Self::RunningEngine) -> EngineExecutionIdentity {
        running.identity.clone()
    }

    async fn provision(
        &self,
        request: &Self::ProvisionRequest,
    ) -> Result<Self::ProvisionedEngine, EngineDriverError> {
        Ok(ProvisionedEngine {
            kind: self.kind(),
            executable: request.engine_cache_dir.join("fixture-engine"),
            version: Some("fixture-v1".to_string()),
            fingerprint: "sha256:fixture".to_string(),
            state: request.provisioning,
        })
    }

    async fn launch(
        &self,
        _provisioned: &Self::ProvisionedEngine,
        request: &Self::LaunchRequest,
    ) -> Result<Self::RunningEngine, EngineDriverError> {
        request.validate()?;
        Ok(RunningEngine {
            identity: request.identity.clone(),
            selected_devices: Vec::new(),
            accelerator: request.accelerator,
            started_at_ms: 1,
            artifact_digest: "sha256:model".to_string(),
            engine_version: Some("fixture-v1".to_string()),
            memory: request.fit,
            process: Arc::new(FixtureProcess),
        })
    }

    async fn health(
        &self,
        running: &Self::RunningEngine,
    ) -> Result<EngineHealth, EngineDriverError> {
        Ok(if running.identity.port == 18_080 {
            EngineHealth::Ready
        } else {
            EngineHealth::Unhealthy
        })
    }

    async fn shutdown(
        &self,
        _running: Self::RunningEngine,
        _grace: Duration,
    ) -> Result<(), EngineDriverError> {
        Ok(())
    }
}

#[tokio::test]
async fn neutral_associated_type_driver_completes_a_typed_lifecycle() {
    let driver = FixtureDriver;
    let provision = ProvisionRequest {
        artifact: "sha256:model",
        worker: "worker-a",
        provisioning: "pinned",
        engine_cache_dir: PathBuf::from("/managed/engines"),
    };
    let provisioned = driver.provision(&provision).await.expect("provision");
    let launch = LaunchRequest {
        identity: EngineExecutionIdentity {
            deployment: "fixture-deployment".to_string(),
            generation: 1,
            kind: EngineKind::LlamaCpp,
            port: 18_080,
        },
        artifact: provision.artifact,
        fit: 1_024,
        accelerator: "cpu",
        selected_devices: Vec::<u32>::new(),
        tuning: (),
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(5),
    };

    let running = driver.launch(&provisioned, &launch).await.expect("launch");
    assert_eq!(driver.health(&running).await, Ok(EngineHealth::Ready));
    assert_eq!(driver.running_identity(&running), launch.identity);
    driver
        .shutdown(running, Duration::from_secs(1))
        .await
        .expect("shutdown");
}

#[test]
fn neutral_launch_envelope_rejects_invalid_runtime_owned_identity() {
    let mut request = LaunchRequest {
        identity: EngineExecutionIdentity {
            deployment: " ".to_string(),
            generation: 0,
            kind: EngineKind::Vllm,
            port: 0,
        },
        artifact: "sha256:model",
        fit: 1_024_u64,
        accelerator: "cpu",
        selected_devices: Vec::<u32>::new(),
        tuning: (),
        max_concurrency: 0,
        ready_timeout: Duration::ZERO,
    };

    let deployment = request.validate().expect_err("deployment must fail first");
    assert_eq!(deployment.message(), "launch deployment must not be empty");
    request.identity.deployment = "fixture".to_string();
    let generation = request.validate().expect_err("generation must fail second");
    assert_eq!(generation.message(), "launch generation must be positive");
    request.identity.generation = 1;
    let port = request.validate().expect_err("port must fail third");
    assert_eq!(port.message(), "launch port must be positive");
    request.identity.port = 18_080;
    let timeout = request.validate().expect_err("timeout must fail fourth");
    assert_eq!(timeout.message(), "readiness timeout must be positive");
    request.ready_timeout = Duration::from_secs(1);
    let concurrency = request
        .validate()
        .expect_err("concurrency must fail after identity and timeout");
    assert_eq!(
        concurrency.message(),
        "launch max_concurrency must be positive"
    );
}

#[test]
fn opaque_consumer_payloads_and_process_debug_never_reach_host_diagnostics() {
    let provision = ProvisionRequest {
        artifact: CanaryPayload,
        worker: CanaryPayload,
        provisioning: CanaryPayload,
        engine_cache_dir: PathBuf::from("/managed/engines"),
    };
    let launch = LaunchRequest {
        identity: EngineExecutionIdentity {
            deployment: "fixture".to_string(),
            generation: 1,
            kind: EngineKind::LlamaCpp,
            port: 18_080,
        },
        artifact: CanaryPayload,
        fit: CanaryPayload,
        accelerator: CanaryPayload,
        selected_devices: Vec::<u32>::new(),
        tuning: CanaryPayload,
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    let running = RunningEngine {
        identity: launch.identity.clone(),
        selected_devices: Vec::<u32>::new(),
        accelerator: CanaryPayload,
        started_at_ms: 1,
        artifact_digest: "sha256:model".to_string(),
        engine_version: None,
        memory: CanaryPayload,
        process: Arc::new(FixtureProcess),
    };

    assert!(!format!("{provision:?}").contains("SYNTHETIC_CANARY"));
    assert!(!format!("{launch:?}").contains("SYNTHETIC_CANARY"));
    assert!(!format!("{running:?}").contains("SYNTHETIC_CANARY"));
}

#[test]
fn running_engine_clone_shares_a_non_clone_process_handle() {
    let running = RunningEngine {
        identity: EngineExecutionIdentity {
            deployment: "fixture".to_string(),
            generation: 1,
            kind: EngineKind::LlamaCpp,
            port: 18_080,
        },
        selected_devices: Vec::<u32>::new(),
        accelerator: "cpu",
        started_at_ms: 1,
        artifact_digest: "sha256:model".to_string(),
        engine_version: None,
        memory: 1_024_u64,
        process: Arc::new(FixtureProcess),
    };

    let clone = running.clone();
    assert!(Arc::ptr_eq(&running.process, &clone.process));
}
