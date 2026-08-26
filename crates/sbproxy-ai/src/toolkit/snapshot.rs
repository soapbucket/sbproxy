use super::runtime::metric_outcome;
use super::validation::{ensure_serialized, validate_scope};
use super::{
    AgentSummary, AiToolkitRuntime, DatasetSummary, ToolkitError, ToolkitSnapshot,
    ToolkitSnapshotRequest,
};

impl AiToolkitRuntime {
    /// Return a bounded, redacted snapshot for exactly one authenticated scope.
    pub fn snapshot(
        &self,
        request: ToolkitSnapshotRequest,
    ) -> Result<ToolkitSnapshot, ToolkitError> {
        let scope = request.scope.clone();
        let result = self.snapshot_inner(request);
        self.record_operation(
            scope,
            "toolkit_snapshot",
            metric_outcome(&result).as_label(),
        );
        result
    }

    fn snapshot_inner(
        &self,
        request: ToolkitSnapshotRequest,
    ) -> Result<ToolkitSnapshot, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        let limit = request
            .limit
            .unwrap_or(self.limits.max_retained_operations)
            .min(self.limits.max_retained_operations);
        let mut truncated = false;

        let mut agents = self
            .agents
            .get(&request.scope)
            .map(|scoped| {
                scoped
                    .registry
                    .list_agents()
                    .into_iter()
                    .map(|id| {
                        let mut capabilities = scoped.registry.discover(&id).unwrap_or_default();
                        capabilities.sort();
                        AgentSummary { id, capabilities }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        truncate_front(&mut agents, limit, &mut truncated);

        let mut workflows = self.workflow_summaries(&request.scope);
        truncate_front(&mut workflows, limit, &mut truncated);

        let mut datasets: Vec<_> = self
            .datasets
            .lock()
            .versions
            .iter()
            .filter(|((scope, _, _), _)| scope == &request.scope)
            .map(|((_, name, version), dataset)| DatasetSummary {
                name: name.clone(),
                version: *version,
                entries: dataset.entries.len(),
            })
            .collect();
        datasets.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.version.cmp(&right.version))
        });
        truncate_front(&mut datasets, limit, &mut truncated);

        let mut rollouts = self.rollout_summaries(&request.scope);
        truncate_front(&mut rollouts, limit, &mut truncated);

        let mut experiments: Vec<_> = self
            .experiments
            .lock()
            .iter()
            .filter(|(scope, _)| scope == &request.scope)
            .map(|(_, row)| row.clone())
            .collect();
        truncate_oldest(&mut experiments, limit, &mut truncated);

        let mut operations: Vec<_> = self
            .operations
            .lock()
            .iter()
            .filter(|(scope, _)| scope == &request.scope)
            .map(|(_, row)| row.clone())
            .collect();
        truncate_oldest(&mut operations, limit, &mut truncated);

        let snapshot = ToolkitSnapshot {
            scope: request.scope,
            agents,
            workflows,
            datasets,
            rollouts,
            experiments,
            operations,
            truncated,
        };
        ensure_serialized(
            &snapshot,
            "toolkit_snapshot_response_bytes",
            self.limits.max_response_bytes,
        )?;
        Ok(snapshot)
    }
}

fn truncate_front<T>(rows: &mut Vec<T>, limit: usize, truncated: &mut bool) {
    if rows.len() > limit {
        rows.truncate(limit);
        *truncated = true;
    }
}

fn truncate_oldest<T>(rows: &mut Vec<T>, limit: usize, truncated: &mut bool) {
    if rows.len() > limit {
        let remove = rows.len() - limit;
        rows.drain(..remove);
        *truncated = true;
    }
}
