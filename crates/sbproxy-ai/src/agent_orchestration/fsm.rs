//! Finite-state-machine (FSM) orchestrator for multi-agent workflows.
//!
//! A [`FsmWorkflow`] describes a directed graph of states.  Each state names
//! the agent to invoke (`action`) and maps outcome labels to the next state.
//! [`FsmExecution`] drives an in-progress run, recording history and detecting
//! terminal states.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// A single node in the workflow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsmState {
    /// Unique name of this state.
    pub name: String,
    /// The agent ID (or action label) to invoke when entering this state.
    pub action: String,
    /// Map of outcome labels to the name of the next state.
    /// If the map is empty, or a result has no matching key, the workflow ends.
    pub transitions: HashMap<String, String>,
}

/// A complete workflow graph.
#[derive(Debug, Clone, Serialize)]
pub struct FsmWorkflow {
    name: String,
    states: HashMap<String, FsmState>,
    initial_state: String,
    max_steps: usize,
}

#[derive(Deserialize)]
struct RawWorkflow {
    name: String,
    states: Vec<FsmState>,
    initial_state: String,
    max_steps: usize,
}

impl<'de> Deserialize<'de> for FsmWorkflow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawWorkflow::deserialize(deserializer)?;
        Self::new(raw.name, raw.initial_state, raw.states, raw.max_steps)
            .map_err(serde::de::Error::custom)
    }
}

/// Structural configuration error for an FSM workflow.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FsmValidationError {
    /// The workflow has no usable name.
    #[error("workflow name must not be empty")]
    EmptyName,
    /// The step/history budget is zero.
    #[error("workflow max_steps must be greater than zero")]
    ZeroStepBudget,
    /// A state name occurs more than once.
    #[error("workflow contains duplicate state {state:?}")]
    DuplicateState {
        /// Repeated state name.
        state: String,
    },
    /// A state has no name.
    #[error("workflow contains a state with an empty name")]
    EmptyStateName,
    /// A state has no action to execute.
    #[error("workflow state {state:?} has an empty action")]
    EmptyAction {
        /// State missing its action.
        state: String,
    },
    /// The declared initial state is absent.
    #[error("workflow initial state {state:?} does not exist")]
    MissingInitialState {
        /// Missing initial-state name.
        state: String,
    },
    /// A transition points to an absent state.
    #[error("workflow state {state:?} outcome {outcome:?} targets missing state {target:?}")]
    MissingTransitionTarget {
        /// State containing the bad edge.
        state: String,
        /// Outcome label for the bad edge.
        outcome: String,
        /// Missing target-state name.
        target: String,
    },
}

impl FsmWorkflow {
    /// Validate and construct a bounded workflow graph.
    pub fn new(
        name: impl Into<String>,
        initial_state: impl Into<String>,
        states: Vec<FsmState>,
        max_steps: usize,
    ) -> Result<Self, FsmValidationError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(FsmValidationError::EmptyName);
        }
        if max_steps == 0 {
            return Err(FsmValidationError::ZeroStepBudget);
        }
        let mut indexed = HashMap::with_capacity(states.len());
        for state in states {
            if state.name.trim().is_empty() {
                return Err(FsmValidationError::EmptyStateName);
            }
            if state.action.trim().is_empty() {
                return Err(FsmValidationError::EmptyAction { state: state.name });
            }
            let state_name = state.name.clone();
            if indexed.insert(state_name.clone(), state).is_some() {
                return Err(FsmValidationError::DuplicateState { state: state_name });
            }
        }
        let initial_state = initial_state.into();
        if !indexed.contains_key(&initial_state) {
            return Err(FsmValidationError::MissingInitialState {
                state: initial_state,
            });
        }
        for state in indexed.values() {
            for (outcome, target) in &state.transitions {
                if !indexed.contains_key(target) {
                    return Err(FsmValidationError::MissingTransitionTarget {
                        state: state.name.clone(),
                        outcome: outcome.clone(),
                        target: target.clone(),
                    });
                }
            }
        }
        Ok(Self {
            name,
            states: indexed,
            initial_state,
            max_steps,
        })
    }

    /// Human-readable workflow name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Maximum transitions/history records allowed in one execution.
    pub fn max_steps(&self) -> usize {
        self.max_steps
    }

    /// Return the current state's configured action.
    pub fn action(&self, state: &str) -> Option<&str> {
        self.states.get(state).map(|state| state.action.as_str())
    }
}

/// An in-progress execution of a [`FsmWorkflow`].
pub struct FsmExecution {
    workflow: FsmWorkflow,
    current_state: String,
    /// Ordered record of `(state_name, result_label)` pairs that have been
    /// processed.
    history: Vec<(String, String)>,
    completed: bool,
}

/// Result of one successful FSM transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmTransition {
    /// Execution advanced to the named state.
    Advanced(String),
    /// No transition matched, so execution completed.
    Completed,
}

/// Runtime error from a bounded FSM execution.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FsmExecutionError {
    /// A transition was requested after completion.
    #[error("workflow execution is already completed")]
    AlreadyCompleted,
    /// The configured step/history budget was exhausted.
    #[error("workflow exhausted its {max_steps}-step budget")]
    StepLimit {
        /// Configured maximum transitions/history records.
        max_steps: usize,
    },
}

impl FsmExecution {
    /// Start executing `workflow` from its initial state.
    pub fn new(workflow: FsmWorkflow) -> Self {
        let current_state = workflow.initial_state.clone();
        Self {
            workflow,
            current_state,
            history: Vec::new(),
            completed: false,
        }
    }

    /// Return the name of the state the execution is currently in.
    pub fn current_state(&self) -> &str {
        &self.current_state
    }

    /// Return the configured action for the current state.
    pub fn current_action(&self) -> &str {
        self.workflow
            .action(&self.current_state)
            .unwrap_or_default()
    }

    /// Advance the FSM by applying `result` to the current state's transition
    /// table.
    ///
    /// Records the `(current_state, result)` pair in history, then:
    /// - Returns [`FsmTransition::Advanced`] if a transition exists.
    /// - Sets [`Self::is_completed`] and returns [`FsmTransition::Completed`]
    ///   if there is no matching transition.
    /// - Returns [`FsmExecutionError::StepLimit`] before history can exceed
    ///   the configured budget.
    pub fn transition(&mut self, result: &str) -> Result<FsmTransition, FsmExecutionError> {
        if self.completed {
            return Err(FsmExecutionError::AlreadyCompleted);
        }
        if self.history.len() >= self.workflow.max_steps {
            self.completed = true;
            return Err(FsmExecutionError::StepLimit {
                max_steps: self.workflow.max_steps,
            });
        }

        let next_state = self
            .workflow
            .states
            .get(&self.current_state)
            .and_then(|s| s.transitions.get(result))
            .cloned();

        self.history
            .push((self.current_state.clone(), result.to_string()));

        if let Some(next) = next_state {
            self.current_state = next;
            Ok(FsmTransition::Advanced(self.current_state.clone()))
        } else {
            self.completed = true;
            Ok(FsmTransition::Completed)
        }
    }

    /// Return `true` if the execution has reached a terminal state.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Return the ordered history of `(state_name, result_label)` pairs.
    pub fn history(&self) -> &[(String, String)] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_rejects_duplicate_and_missing_transition_targets() {
        let duplicate = FsmState {
            name: "start".to_string(),
            action: "agent".to_string(),
            transitions: [("again".to_string(), "missing".to_string())].into(),
        };
        let error = FsmWorkflow::new(
            "invalid",
            "start",
            vec![
                duplicate,
                FsmState {
                    name: "start".to_string(),
                    action: "other".to_string(),
                    transitions: HashMap::new(),
                },
            ],
            4,
        )
        .unwrap_err();
        assert!(matches!(error, FsmValidationError::DuplicateState { .. }));

        let error = FsmWorkflow::new(
            "invalid-target",
            "start",
            vec![FsmState {
                name: "start".to_string(),
                action: "agent".to_string(),
                transitions: [("again".to_string(), "missing".to_string())].into(),
            }],
            4,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FsmValidationError::MissingTransitionTarget { .. }
        ));
    }

    #[test]
    fn cyclic_execution_stops_at_the_step_budget_without_growing_history() {
        let workflow = FsmWorkflow::new(
            "cycle",
            "a",
            vec![
                FsmState {
                    name: "a".to_string(),
                    action: "agent-a".to_string(),
                    transitions: [("next".to_string(), "b".to_string())].into(),
                },
                FsmState {
                    name: "b".to_string(),
                    action: "agent-b".to_string(),
                    transitions: [("next".to_string(), "a".to_string())].into(),
                },
            ],
            2,
        )
        .unwrap();
        let mut execution = FsmExecution::new(workflow);
        execution.transition("next").unwrap();
        execution.transition("next").unwrap();
        let error = execution.transition("next").unwrap_err();
        assert!(matches!(
            error,
            FsmExecutionError::StepLimit { max_steps: 2 }
        ));
        assert_eq!(execution.history().len(), 2);
    }

    /// Build a simple linear workflow: start -> middle -> end (terminal).
    fn linear_workflow() -> FsmWorkflow {
        FsmWorkflow::new(
            "linear",
            "start",
            vec![
                FsmState {
                    name: "start".to_string(),
                    action: "agent-a".to_string(),
                    transitions: [("ok".to_string(), "middle".to_string())].into(),
                },
                FsmState {
                    name: "middle".to_string(),
                    action: "agent-b".to_string(),
                    transitions: [("done".to_string(), "end".to_string())].into(),
                },
                FsmState {
                    name: "end".to_string(),
                    action: "agent-c".to_string(),
                    transitions: HashMap::new(), // terminal
                },
            ],
            8,
        )
        .unwrap()
    }

    /// Build a branching workflow: decide -> success OR failure (both terminal).
    fn branching_workflow() -> FsmWorkflow {
        FsmWorkflow::new(
            "branching",
            "decide",
            vec![
                FsmState {
                    name: "decide".to_string(),
                    action: "router".to_string(),
                    transitions: [
                        ("pass".to_string(), "success".to_string()),
                        ("fail".to_string(), "failure".to_string()),
                    ]
                    .into(),
                },
                FsmState {
                    name: "success".to_string(),
                    action: "success-handler".to_string(),
                    transitions: HashMap::new(),
                },
                FsmState {
                    name: "failure".to_string(),
                    action: "failure-handler".to_string(),
                    transitions: HashMap::new(),
                },
            ],
            8,
        )
        .unwrap()
    }

    #[test]
    fn linear_workflow_transitions_correctly() {
        let mut exec = FsmExecution::new(linear_workflow());
        assert_eq!(exec.current_state(), "start");
        assert!(!exec.is_completed());

        let next = exec.transition("ok");
        assert_eq!(next, Ok(FsmTransition::Advanced("middle".to_string())));
        assert_eq!(exec.current_state(), "middle");

        let next = exec.transition("done");
        assert_eq!(next, Ok(FsmTransition::Advanced("end".to_string())));
        assert_eq!(exec.current_state(), "end");

        // Terminal state - no more transitions.
        let next = exec.transition("anything");
        assert_eq!(next, Ok(FsmTransition::Completed));
        assert!(exec.is_completed());
    }

    #[test]
    fn branching_workflow_takes_pass_branch() {
        let mut exec = FsmExecution::new(branching_workflow());
        let next = exec.transition("pass");
        assert_eq!(next, Ok(FsmTransition::Advanced("success".to_string())));
        assert_eq!(exec.current_state(), "success");
    }

    #[test]
    fn branching_workflow_takes_fail_branch() {
        let mut exec = FsmExecution::new(branching_workflow());
        let next = exec.transition("fail");
        assert_eq!(next, Ok(FsmTransition::Advanced("failure".to_string())));
        assert_eq!(exec.current_state(), "failure");
    }

    #[test]
    fn completed_detection_after_terminal() {
        let mut exec = FsmExecution::new(branching_workflow());
        exec.transition("pass").unwrap(); // -> success (terminal)
        assert!(!exec.is_completed()); // success state has no transitions but hasn't been processed yet
        exec.transition("done").unwrap(); // unknown result for success state -> completed
        assert!(exec.is_completed());
    }

    #[test]
    fn unknown_result_marks_completed() {
        let mut exec = FsmExecution::new(linear_workflow());
        let next = exec.transition("unknown_result");
        assert_eq!(next, Ok(FsmTransition::Completed));
        assert!(exec.is_completed());
    }

    #[test]
    fn history_records_all_transitions() {
        let mut exec = FsmExecution::new(linear_workflow());
        exec.transition("ok").unwrap();
        exec.transition("done").unwrap();

        let history = exec.history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], ("start".to_string(), "ok".to_string()));
        assert_eq!(history[1], ("middle".to_string(), "done".to_string()));
    }

    #[test]
    fn transition_after_completed_returns_typed_error() {
        let mut exec = FsmExecution::new(branching_workflow());
        exec.transition("pass").unwrap();
        exec.transition("done").unwrap(); // completes
        let result = exec.transition("more");
        assert_eq!(result, Err(FsmExecutionError::AlreadyCompleted));
        assert!(exec.is_completed());
    }
}
