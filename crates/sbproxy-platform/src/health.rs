//! Health tracking for upstream services.
//!
//! Maintains a thread-safe map of target identifiers to their current health state.

use std::collections::HashMap;
use std::sync::Mutex;

/// Health state of an upstream target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Target is responding normally.
    Healthy,
    /// Target is failing health checks.
    Unhealthy,
    /// No health data available yet.
    Unknown,
}

/// Thread-safe tracker for upstream service health states.
pub struct HealthTracker {
    states: Mutex<HashMap<String, HealthState>>,
}

impl HealthTracker {
    /// Create a new health tracker with no entries.
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Get the health state of a target. Returns `Unknown` if the target has not
    /// been registered.
    pub fn get_state(&self, target: &str) -> HealthState {
        let states = self.states.lock().unwrap();
        states.get(target).copied().unwrap_or(HealthState::Unknown)
    }

    /// Set the health state of a target.
    pub fn set_state(&self, target: &str, state: HealthState) {
        let mut states = self.states.lock().unwrap();
        states.insert(target.to_string(), state);
    }

    /// Remove a target from the tracker.
    pub fn remove(&self, target: &str) {
        let mut states = self.states.lock().unwrap();
        states.remove(target);
    }

    /// List all tracked targets and their states.
    pub fn all_states(&self) -> Vec<(String, HealthState)> {
        let states = self.states.lock().unwrap();
        states.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_unknown() {
        let tracker = HealthTracker::new();
        assert_eq!(tracker.get_state("upstream-1"), HealthState::Unknown);
    }

    #[test]
    fn set_and_get_state() {
        let tracker = HealthTracker::new();
        tracker.set_state("upstream-1", HealthState::Healthy);
        assert_eq!(tracker.get_state("upstream-1"), HealthState::Healthy);

        tracker.set_state("upstream-1", HealthState::Unhealthy);
        assert_eq!(tracker.get_state("upstream-1"), HealthState::Unhealthy);
    }

    #[test]
    fn multiple_targets() {
        let tracker = HealthTracker::new();
        tracker.set_state("a", HealthState::Healthy);
        tracker.set_state("b", HealthState::Unhealthy);
        tracker.set_state("c", HealthState::Unknown);

        assert_eq!(tracker.get_state("a"), HealthState::Healthy);
        assert_eq!(tracker.get_state("b"), HealthState::Unhealthy);
        assert_eq!(tracker.get_state("c"), HealthState::Unknown);
    }

    #[test]
    fn remove_target() {
        let tracker = HealthTracker::new();
        tracker.set_state("upstream-1", HealthState::Healthy);
        tracker.remove("upstream-1");
        assert_eq!(tracker.get_state("upstream-1"), HealthState::Unknown);
    }

    #[test]
    fn all_states_returns_tracked_entries() {
        let tracker = HealthTracker::new();
        tracker.set_state("x", HealthState::Healthy);
        tracker.set_state("y", HealthState::Unhealthy);

        let mut states = tracker.all_states();
        states.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(states.len(), 2);
        assert_eq!(states[0], ("x".to_string(), HealthState::Healthy));
        assert_eq!(states[1], ("y".to_string(), HealthState::Unhealthy));
    }
}
