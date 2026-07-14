use std::collections::BTreeMap;
use std::sync::Arc;

use sbproxy_model_host::{ModelRuntimeManager, PriorityClass};

use super::ModelPlaneError;
use crate::server::model_host::{ManagedModelPermit, ProductionModelRuntime};

/// Ready loopback engine target with request-lifetime admission ownership.
pub struct PreparedWorkerExecution {
    /// Root loopback URL of the selected managed engine.
    pub base_url: String,
    /// Exact model identifier accepted by the managed engine.
    pub engine_model: String,
    /// Admission held until the complete response stream is dropped.
    pub permit: ManagedModelPermit,
}

impl std::fmt::Debug for PreparedWorkerExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedWorkerExecution")
            .field("base_url", &self.base_url)
            .field("engine_model", &self.engine_model)
            .field("permit", &self.permit)
            .finish()
    }
}

#[derive(Clone)]
enum WorkerExecutionSource {
    Production {
        runtime: Arc<ProductionModelRuntime>,
        local_node_id: String,
    },
    Fixed {
        manager: Arc<ModelRuntimeManager>,
        assignments: Arc<BTreeMap<String, u64>>,
    },
}

/// Shared generation-fenced admission and readiness service for local and peer calls.
#[derive(Clone)]
pub struct WorkerModelExecution {
    source: WorkerExecutionSource,
}

impl std::fmt::Debug for WorkerModelExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerModelExecution")
            .finish_non_exhaustive()
    }
}

struct ExecutionSnapshot {
    manager: Arc<ModelRuntimeManager>,
    assignment_generation: Option<u64>,
    runtime_epoch: u64,
}

impl WorkerModelExecution {
    /// Bind the service to the permanent process runtime and one installed node ID.
    pub fn production(runtime: Arc<ProductionModelRuntime>, local_node_id: String) -> Self {
        Self {
            source: WorkerExecutionSource::Production {
                runtime,
                local_node_id,
            },
        }
    }

    /// Build a deterministic service around one manager and external generation map.
    #[doc(hidden)]
    pub fn from_manager(
        manager: Arc<ModelRuntimeManager>,
        assignments: BTreeMap<String, u64>,
    ) -> Self {
        Self {
            source: WorkerExecutionSource::Fixed {
                manager,
                assignments: Arc::new(assignments),
            },
        }
    }

    /// Verify assignment, admit, and make one exact deployment generation ready.
    pub async fn prepare(
        &self,
        deployment: &str,
        deployment_generation: u64,
        priority: PriorityClass,
    ) -> Result<PreparedWorkerExecution, ModelPlaneError> {
        let before = self.snapshot(deployment);
        match before.assignment_generation {
            None => return Err(ModelPlaneError::DeploymentNotAssigned),
            Some(generation) if generation != deployment_generation => {
                return Err(ModelPlaneError::StaleDeploymentGeneration);
            }
            Some(_) => {}
        }

        let admission = before.manager.admit(deployment, priority).await?;
        let after = self.snapshot(deployment);
        if after.assignment_generation != Some(deployment_generation)
            || after.runtime_epoch != before.runtime_epoch
            || !Arc::ptr_eq(&after.manager, &before.manager)
        {
            return Err(ModelPlaneError::StaleDeploymentGeneration);
        }
        let permit =
            ManagedModelPermit::from_admission(before.manager, deployment.to_string(), admission);
        let running = permit.ensure_ready(priority).await?;
        Ok(PreparedWorkerExecution {
            base_url: format!("http://127.0.0.1:{}", running.port),
            engine_model: deployment.to_string(),
            permit,
        })
    }

    fn snapshot(&self, deployment: &str) -> ExecutionSnapshot {
        match &self.source {
            WorkerExecutionSource::Production {
                runtime,
                local_node_id,
            } => ExecutionSnapshot {
                manager: runtime.active_manager(),
                assignment_generation: runtime
                    .cluster_assignment_generation(local_node_id, deployment),
                runtime_epoch: runtime.current_revision(),
            },
            WorkerExecutionSource::Fixed {
                manager,
                assignments,
            } => ExecutionSnapshot {
                manager: Arc::clone(manager),
                assignment_generation: assignments.get(deployment).copied(),
                runtime_epoch: manager.current_revision(),
            },
        }
    }
}
