//! Finite-state-machine (FSM) orchestrator for multi-agent workflows.
//!
//! A [`FsmWorkflow`] describes a directed graph of states.  Each state names
//! the agent to invoke (`action`) and maps outcome labels to the next state.
//! [`FsmExecution`] drives an in-progress run, recording history and detecting
//! terminal states.

use std::collections::HashMap;

/// A single node in the workflow graph.
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
pub struct FsmWorkflow {
    /// Human-readable name.
    pub name: String,
    /// All states keyed by state name.
    pub states: HashMap<String, FsmState>,
    /// The name of the starting state.
    pub initial_state: String,
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

    /// Advance the FSM by applying `result` to the current state's transition
    /// table.
    ///
    /// Records the `(current_state, result)` pair in history, then:
    /// - Returns the name of the next state if a transition exists.
    /// - Sets [`Self::is_completed`] to `true` and returns `None` if there is no
    ///   matching transition (terminal state).
    pub fn transition(&mut self, result: &str) -> Option<&str> {
        if self.completed {
            return None;
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
            Some(&self.current_state)
        } else {
            self.completed = true;
            None
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

    /// Build a simple linear workflow: start -> middle -> end (terminal).
    fn linear_workflow() -> FsmWorkflow {
        let mut states = HashMap::new();
        states.insert(
            "start".to_string(),
            FsmState {
                name: "start".to_string(),
                action: "agent-a".to_string(),
                transitions: [("ok".to_string(), "middle".to_string())].into(),
            },
        );
        states.insert(
            "middle".to_string(),
            FsmState {
                name: "middle".to_string(),
                action: "agent-b".to_string(),
                transitions: [("done".to_string(), "end".to_string())].into(),
            },
        );
        states.insert(
            "end".to_string(),
            FsmState {
                name: "end".to_string(),
                action: "agent-c".to_string(),
                transitions: HashMap::new(), // terminal
            },
        );
        FsmWorkflow {
            name: "linear".to_string(),
            states,
            initial_state: "start".to_string(),
        }
    }

    /// Build a branching workflow: decide -> success OR failure (both terminal).
    fn branching_workflow() -> FsmWorkflow {
        let mut states = HashMap::new();
        states.insert(
            "decide".to_string(),
            FsmState {
                name: "decide".to_string(),
                action: "router".to_string(),
                transitions: [
                    ("pass".to_string(), "success".to_string()),
                    ("fail".to_string(), "failure".to_string()),
                ]
                .into(),
            },
        );
        states.insert(
            "success".to_string(),
            FsmState {
                name: "success".to_string(),
                action: "success-handler".to_string(),
                transitions: HashMap::new(),
            },
        );
        states.insert(
            "failure".to_string(),
            FsmState {
                name: "failure".to_string(),
                action: "failure-handler".to_string(),
                transitions: HashMap::new(),
            },
        );
        FsmWorkflow {
            name: "branching".to_string(),
            states,
            initial_state: "decide".to_string(),
        }
    }

    #[test]
    fn linear_workflow_transitions_correctly() {
        let mut exec = FsmExecution::new(linear_workflow());
        assert_eq!(exec.current_state(), "start");
        assert!(!exec.is_completed());

        let next = exec.transition("ok");
        assert_eq!(next, Some("middle"));
        assert_eq!(exec.current_state(), "middle");

        let next = exec.transition("done");
        assert_eq!(next, Some("end"));
        assert_eq!(exec.current_state(), "end");

        // Terminal state - no more transitions.
        let next = exec.transition("anything");
        assert!(next.is_none());
        assert!(exec.is_completed());
    }

    #[test]
    fn branching_workflow_takes_pass_branch() {
        let mut exec = FsmExecution::new(branching_workflow());
        let next = exec.transition("pass");
        assert_eq!(next, Some("success"));
        assert_eq!(exec.current_state(), "success");
    }

    #[test]
    fn branching_workflow_takes_fail_branch() {
        let mut exec = FsmExecution::new(branching_workflow());
        let next = exec.transition("fail");
        assert_eq!(next, Some("failure"));
        assert_eq!(exec.current_state(), "failure");
    }

    #[test]
    fn completed_detection_after_terminal() {
        let mut exec = FsmExecution::new(branching_workflow());
        exec.transition("pass"); // -> success (terminal)
        assert!(!exec.is_completed()); // success state has no transitions but hasn't been processed yet
        exec.transition("done"); // unknown result for success state -> completed
        assert!(exec.is_completed());
    }

    #[test]
    fn unknown_result_marks_completed() {
        let mut exec = FsmExecution::new(linear_workflow());
        let next = exec.transition("unknown_result");
        assert!(next.is_none());
        assert!(exec.is_completed());
    }

    #[test]
    fn history_records_all_transitions() {
        let mut exec = FsmExecution::new(linear_workflow());
        exec.transition("ok");
        exec.transition("done");

        let history = exec.history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], ("start".to_string(), "ok".to_string()));
        assert_eq!(history[1], ("middle".to_string(), "done".to_string()));
    }

    #[test]
    fn transition_after_completed_returns_none() {
        let mut exec = FsmExecution::new(branching_workflow());
        exec.transition("pass");
        exec.transition("done"); // completes
        let result = exec.transition("more");
        assert!(result.is_none());
        assert!(exec.is_completed());
    }
}
