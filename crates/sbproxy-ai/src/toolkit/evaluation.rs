use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use crate::ai_metrics::{record_ai_toolkit_operation, AiToolkitCapability, AiToolkitOutcome};
use crate::evaluation::parse_judge_response;

use super::runtime::metric_outcome;
use super::validation::{
    compile_schema, ensure_count, ensure_serialized, validate_identifier, validate_scope,
    validate_text,
};
use super::{
    AiToolkitRuntime, EvaluationRunRequest, EvaluationRunResult, MetricSpec, ToolkitError,
};

const OFFLINE_EVALUATION_DEADLINE: Duration = Duration::from_secs(30);

enum CompiledMetric {
    Regex(regex::Regex),
    JsonSchema(jsonschema::JSONSchema),
    LengthRange { min: usize, max: usize },
    ContainsKeywords(Vec<String>),
}

impl CompiledMetric {
    fn passes(&self, response: &str) -> bool {
        match self {
            Self::Regex(pattern) => pattern.is_match(response),
            Self::JsonSchema(schema) => serde_json::from_str::<serde_json::Value>(response)
                .map(|instance| schema.is_valid(&instance))
                .unwrap_or(false),
            Self::LengthRange { min, max } => response.len() >= *min && response.len() <= *max,
            Self::ContainsKeywords(keywords) => keywords
                .iter()
                .all(|keyword| response.contains(keyword.as_str())),
        }
    }
}

impl AiToolkitRuntime {
    /// Evaluate recorded candidate and judge responses entirely offline.
    pub fn run_evaluation(
        &self,
        request: EvaluationRunRequest,
    ) -> Result<EvaluationRunResult, ToolkitError> {
        let scope = request.scope.clone();
        let permit = match self.evaluation_semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                self.record_operation(
                    scope,
                    "offline_evaluation",
                    AiToolkitOutcome::Busy.as_label(),
                );
                record_ai_toolkit_operation(
                    AiToolkitCapability::Evaluation,
                    AiToolkitOutcome::Busy,
                );
                return Err(ToolkitError::Busy {
                    operation: "offline_evaluation",
                });
            }
        };
        let deadline = Instant::now() + OFFLINE_EVALUATION_DEADLINE;
        let result = self.run_evaluation_inner(request, deadline);
        drop(permit);
        self.record_operation(
            scope,
            "offline_evaluation",
            metric_outcome(&result).as_label(),
        );
        record_ai_toolkit_operation(AiToolkitCapability::Evaluation, metric_outcome(&result));
        result
    }

    fn run_evaluation_inner(
        &self,
        request: EvaluationRunRequest,
        deadline: Instant,
    ) -> Result<EvaluationRunResult, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        for (field, value) in [
            ("evaluation.experiment_id", request.experiment_id.as_str()),
            (
                "evaluation.experiment_name",
                request.experiment_name.as_str(),
            ),
            ("evaluation.dataset.name", request.dataset.name.as_str()),
            ("evaluation.model", request.model.as_str()),
        ] {
            validate_identifier(value, field, self.limits.max_identifier_bytes)?;
        }
        if let Some(prompt_version) = request.prompt_version.as_deref() {
            validate_identifier(
                prompt_version,
                "evaluation.prompt_version",
                self.limits.max_identifier_bytes,
            )?;
        }
        if request.dataset.version == 0 {
            return Err(ToolkitError::InvalidConfiguration {
                field: "evaluation.dataset.version",
            });
        }
        ensure_count(
            "evaluation_cases",
            request.responses.len(),
            self.limits.max_evaluation_cases,
        )?;
        ensure_count(
            "evaluation_metrics",
            request.metrics.len(),
            self.limits.max_metrics,
        )?;
        ensure_serialized(
            &request,
            "evaluation_request_bytes",
            self.limits.max_request_bytes,
        )?;

        let dataset = self
            .datasets
            .lock()
            .versions
            .get(&(
                request.scope.clone(),
                request.dataset.name.clone(),
                request.dataset.version,
            ))
            .cloned()
            .ok_or(ToolkitError::NotFound {
                resource: "dataset",
            })?;
        if dataset.entries.is_empty() || request.responses.len() != dataset.entries.len() {
            return Err(ToolkitError::InvalidConfiguration {
                field: "evaluation.responses",
            });
        }

        let metrics = self.compile_metrics(&request.metrics, deadline)?;
        let judge = if let Some(judge) = request.judge.as_ref() {
            validate_identifier(
                &judge.judge_model,
                "evaluation.judge_model",
                self.limits.max_identifier_bytes,
            )?;
            if judge.criteria.is_empty() {
                return Err(ToolkitError::InvalidConfiguration {
                    field: "evaluation.judge.criteria",
                });
            }
            ensure_count(
                "judge_criteria",
                judge.criteria.len(),
                self.limits.max_judge_criteria,
            )?;
            if judge.responses.len() != dataset.entries.len() {
                return Err(ToolkitError::InvalidConfiguration {
                    field: "evaluation.judge.responses",
                });
            }
            let mut criteria = HashSet::new();
            for criterion in &judge.criteria {
                validate_identifier(
                    criterion,
                    "evaluation.judge.criterion",
                    self.limits.max_identifier_bytes,
                )?;
                if !criteria.insert(criterion.as_str()) {
                    return Err(ToolkitError::InvalidConfiguration {
                        field: "evaluation.judge.criteria",
                    });
                }
            }
            Some(judge)
        } else {
            None
        };

        let mut expected_matches = 0usize;
        let mut expected_cases = 0usize;
        let mut metric_total = 0.0f64;
        let mut judge_total = 0.0f64;
        let mut criteria_totals: BTreeMap<String, f64> = BTreeMap::new();

        for (index, (entry, response)) in dataset
            .entries
            .iter()
            .zip(request.responses.iter())
            .enumerate()
        {
            ensure_before_deadline(deadline)?;
            if response.len() > self.limits.max_response_bytes {
                return Err(ToolkitError::LimitExceeded {
                    resource: "evaluation_response_bytes",
                    limit: self.limits.max_response_bytes,
                    observed: response.len(),
                });
            }
            if let Some(expected) = entry.expected_output.as_deref() {
                expected_cases += 1;
                if response == expected {
                    expected_matches += 1;
                }
            }
            metric_total += evaluate_compiled_metrics(response, &metrics, deadline)?;

            if let Some(judge) = judge {
                let parsed = parse_judge_response(&judge.responses[index], &judge.criteria)
                    .map_err(|_| ToolkitError::InvalidJudgeResponse)?;
                judge_total += parsed.score;
                for (criterion, score) in parsed.criteria_scores {
                    *criteria_totals.entry(criterion).or_default() += score;
                }
                // `parsed.reasoning` is intentionally dropped here. It never enters
                // a registry, result, error, log, metric, event, or snapshot.
            }
        }
        ensure_before_deadline(deadline)?;

        let cases = dataset.entries.len();
        let judge_score = judge.map(|_| judge_total / cases as f64);
        if judge.is_some() {
            for total in criteria_totals.values_mut() {
                *total /= cases as f64;
            }
        }
        let row = EvaluationRunResult {
            experiment_id: request.experiment_id,
            experiment_name: request.experiment_name,
            dataset: request.dataset,
            model: request.model,
            prompt_version: request.prompt_version,
            cases,
            expected_match_rate: (expected_cases > 0)
                .then_some(expected_matches as f64 / expected_cases as f64),
            metric_pass_rate: metric_total / cases as f64,
            judge_score,
            criteria_scores: criteria_totals,
            recorded_at: chrono::Utc::now().to_rfc3339(),
        };
        // Parameters are accepted for experiment compatibility and bounded above,
        // but deliberately disappear at this line instead of being retained.
        drop(request.parameters);
        self.retain_experiment(request.scope, row.clone())?;
        Ok(row)
    }

    fn compile_metrics(
        &self,
        specs: &[MetricSpec],
        deadline: Instant,
    ) -> Result<Vec<CompiledMetric>, ToolkitError> {
        let mut metrics = Vec::with_capacity(specs.len());
        for spec in specs {
            ensure_before_deadline(deadline)?;
            let metric =
                match spec {
                    MetricSpec::Regex { pattern } => {
                        validate_text(
                            pattern,
                            "evaluation.metric.regex",
                            self.limits.max_description_bytes,
                            false,
                        )?;
                        let compiled = regex::Regex::new(pattern).map_err(|_| {
                            ToolkitError::InvalidConfiguration {
                                field: "evaluation.metric.regex",
                            }
                        })?;
                        CompiledMetric::Regex(compiled)
                    }
                    MetricSpec::JsonSchema { schema } => CompiledMetric::JsonSchema(
                        compile_schema(schema, &self.limits, "evaluation_metric")?,
                    ),
                    MetricSpec::LengthRange { min, max } => {
                        if min > max || *max > self.limits.max_response_bytes {
                            return Err(ToolkitError::InvalidConfiguration {
                                field: "evaluation.metric.length_range",
                            });
                        }
                        CompiledMetric::LengthRange {
                            min: *min,
                            max: *max,
                        }
                    }
                    MetricSpec::ContainsKeywords { keywords } => {
                        ensure_count("metric_keywords", keywords.len(), self.limits.max_metrics)?;
                        for keyword in keywords {
                            validate_text(
                                keyword,
                                "evaluation.metric.keyword",
                                self.limits.max_description_bytes,
                                false,
                            )?;
                        }
                        CompiledMetric::ContainsKeywords(keywords.clone())
                    }
                };
            metrics.push(metric);
        }
        ensure_before_deadline(deadline)?;
        Ok(metrics)
    }
}

fn evaluate_compiled_metrics(
    response: &str,
    metrics: &[CompiledMetric],
    deadline: Instant,
) -> Result<f64, ToolkitError> {
    evaluate_compiled_metrics_with(response, metrics, || ensure_before_deadline(deadline))
}

fn evaluate_compiled_metrics_with(
    response: &str,
    metrics: &[CompiledMetric],
    mut check_deadline: impl FnMut() -> Result<(), ToolkitError>,
) -> Result<f64, ToolkitError> {
    if metrics.is_empty() {
        return Ok(1.0);
    }

    let mut passed = 0usize;
    for metric in metrics {
        check_deadline()?;
        if metric.passes(response) {
            passed += 1;
        }
    }
    check_deadline()?;
    Ok(passed as f64 / metrics.len() as f64)
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), ToolkitError> {
    if Instant::now() >= deadline {
        Err(ToolkitError::Deadline {
            operation: "offline_evaluation",
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_metrics_preserve_pass_rate_semantics() {
        let schema = jsonschema::JSONSchema::options()
            .compile(&serde_json::json!({
                "type": "object",
                "required": ["ok"],
                "properties": {"ok": {"type": "boolean"}}
            }))
            .expect("schema compiles");
        let metrics = vec![
            CompiledMetric::Regex(regex::Regex::new(r"^\{").expect("regex compiles")),
            CompiledMetric::JsonSchema(schema),
            CompiledMetric::LengthRange { min: 0, max: 5 },
            CompiledMetric::ContainsKeywords(vec!["true".to_string()]),
        ];

        let rate = evaluate_compiled_metrics(
            "{\"ok\":true}",
            &metrics,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("metrics evaluate");

        assert!((rate - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn deadline_is_checked_before_every_metric() {
        let metrics = vec![
            CompiledMetric::LengthRange { min: 0, max: 10 },
            CompiledMetric::ContainsKeywords(vec!["ok".to_string()]),
        ];
        let mut checks = 0usize;

        let error = evaluate_compiled_metrics_with("ok", &metrics, || {
            checks += 1;
            if checks == 2 {
                Err(ToolkitError::Deadline {
                    operation: "offline_evaluation",
                })
            } else {
                Ok(())
            }
        })
        .expect_err("second metric must observe the expired deadline");

        assert!(matches!(
            error,
            ToolkitError::Deadline {
                operation: "offline_evaluation"
            }
        ));
        assert_eq!(checks, 2);
    }
}
