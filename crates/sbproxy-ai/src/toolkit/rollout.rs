use crate::ai_metrics::{record_ai_toolkit_operation, AiToolkitCapability};
use crate::prompt_versioning::PromptSelectionError;
use sha2::{Digest as _, Sha256};

use super::runtime::metric_outcome;
use super::validation::{validate_identifier, validate_scope};
use super::{AiToolkitRuntime, PromptSelectionRequest, PromptSelectionResult, ToolkitError};

impl AiToolkitRuntime {
    /// Check an immutable generation for a scoped rollout without recording an operation.
    pub fn has_prompt_rollout(
        &self,
        scope: &super::ToolkitScope,
        name: &str,
    ) -> Result<bool, ToolkitError> {
        validate_scope(scope, &self.limits)?;
        validate_identifier(
            name,
            "prompt_selection.name",
            self.limits.max_identifier_bytes,
        )?;
        Ok(self
            .rollouts
            .get(scope)
            .is_some_and(|scoped| scoped.salts.contains_key(name)))
    }

    /// Select one mature weighted prompt version by stable cohort assignment.
    pub fn select_prompt(
        &self,
        request: PromptSelectionRequest,
    ) -> Result<PromptSelectionResult, ToolkitError> {
        let scope = request.scope.clone();
        let result = self.select_prompt_inner(request);
        let outcome = metric_outcome(&result);
        // Selection runs on the live AI request path, once per request, so a
        // successful row stays out of the bounded operations ring for the
        // same reason a successful snapshot read does (`snapshot.rs`), plus
        // one the read paths do not have: taking the process-wide
        // `operations` mutex per request would serialize the data plane of
        // every origin that owns a rollout behind one lock and a full scan
        // of the ring. The counter below still records every selection, so
        // the rate is not lost; only a refusal is worth a row.
        if result.is_err() {
            self.record_operation(scope, "prompt_selection", outcome.as_label());
        }
        record_ai_toolkit_operation(AiToolkitCapability::PromptRollout, outcome);
        result
    }

    fn select_prompt_inner(
        &self,
        request: PromptSelectionRequest,
    ) -> Result<PromptSelectionResult, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        validate_identifier(
            &request.name,
            "prompt_selection.name",
            self.limits.max_identifier_bytes,
        )?;
        validate_identifier(
            &request.cohort,
            "prompt_selection.cohort",
            self.limits.max_identifier_bytes,
        )?;
        let scoped = self
            .rollouts
            .get(&request.scope)
            .ok_or(ToolkitError::NotFound {
                resource: "prompt_rollout",
            })?;
        let salt = scoped
            .salts
            .get(&request.name)
            .ok_or(ToolkitError::NotFound {
                resource: "prompt_rollout",
            })?;
        let selected = scoped
            .store
            .select_for_cohort_typed(&request.name, &request.cohort, salt)
            .map_err(|error| match error {
                PromptSelectionError::MissingRollout { .. } => ToolkitError::NotFound {
                    resource: "prompt_rollout",
                },
                PromptSelectionError::InvalidTotalWeight { .. } => {
                    ToolkitError::InvalidConfiguration {
                        field: "rollout.versions",
                    }
                }
            })?;
        let cohort_digest = digest_cohort(
            &request.scope.origin_id,
            &request.scope.tenant_id,
            &request.name,
            salt,
            &request.cohort,
        );
        Ok(PromptSelectionResult {
            name: selected.name,
            version: selected.version,
            content: selected.content,
            weight: selected.weight,
            cohort_digest,
        })
    }
}

fn digest_cohort(origin: &str, tenant: &str, name: &str, salt: &str, cohort: &str) -> String {
    let mut digest = Sha256::new();
    for component in [origin, tenant, name, salt, cohort] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component.as_bytes());
    }
    hex::encode(digest.finalize())
}
