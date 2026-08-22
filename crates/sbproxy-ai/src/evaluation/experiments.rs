//! Experiment tracking for AI model evaluation.
//!
//! Records experiment runs with their parameters and results so teams can
//! compare model versions, prompt templates, and hyperparameters over time.

use parking_lot::Mutex;

// --- Types ---

/// A single experiment run.
#[derive(Debug, Clone)]
pub struct Experiment {
    /// Unique identifier for this run (e.g. a UUID).
    pub id: String,
    /// Human-readable experiment name (e.g. "gpt4-vs-claude3-summarization").
    pub name: String,
    /// Model used for this experiment.
    pub model: String,
    /// Prompt version identifier (e.g. "summarization-v2").
    pub prompt_version: String,
    /// Free-form experiment parameters (temperature, max_tokens, etc.).
    pub parameters: serde_json::Value,
    /// Optional result payload after evaluation.
    pub result: Option<serde_json::Value>,
    /// ISO-8601 timestamp when the experiment was recorded.
    pub timestamp: String,
}

impl Experiment {
    /// Create a new experiment without a result yet.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        model: impl Into<String>,
        prompt_version: impl Into<String>,
        parameters: serde_json::Value,
        timestamp: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            model: model.into(),
            prompt_version: prompt_version.into(),
            parameters,
            result: None,
            timestamp: timestamp.into(),
        }
    }
}

// --- Store ---

/// Thread-safe, in-memory experiment store.
pub struct ExperimentStore {
    experiments: Mutex<Vec<Experiment>>,
}

impl ExperimentStore {
    /// Create an empty experiment store.
    pub fn new() -> Self {
        Self {
            experiments: Mutex::new(Vec::new()),
        }
    }

    /// Record a new experiment run.
    pub fn record(&self, experiment: Experiment) {
        self.experiments.lock().push(experiment);
    }

    /// Return all experiments with the given name.
    pub fn list_by_name(&self, name: &str) -> Vec<Experiment> {
        self.experiments
            .lock()
            .iter()
            .filter(|e| e.name == name)
            .cloned()
            .collect()
    }

    /// Return the total number of recorded experiments.
    pub fn count(&self) -> usize {
        self.experiments.lock().len()
    }

    /// Return all recorded experiments.
    pub fn list_all(&self) -> Vec<Experiment> {
        self.experiments.lock().clone()
    }

    /// Find an experiment by its ID.
    pub fn get_by_id(&self, id: &str) -> Option<Experiment> {
        self.experiments.lock().iter().find(|e| e.id == id).cloned()
    }
}

impl Default for ExperimentStore {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_experiment(id: &str, name: &str) -> Experiment {
        Experiment::new(
            id,
            name,
            "gpt-4o",
            "prompt-v1",
            json!({"temperature": 0.7}),
            "2026-04-16T00:00:00Z",
        )
    }

    #[test]
    fn record_increases_count() {
        let store = ExperimentStore::new();
        assert_eq!(store.count(), 0);
        store.record(make_experiment("1", "test-a"));
        assert_eq!(store.count(), 1);
        store.record(make_experiment("2", "test-b"));
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn list_by_name_returns_matching_experiments() {
        let store = ExperimentStore::new();
        store.record(make_experiment("1", "exp-alpha"));
        store.record(make_experiment("2", "exp-beta"));
        store.record(make_experiment("3", "exp-alpha"));
        let results = store.list_by_name("exp-alpha");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.name == "exp-alpha"));
    }

    #[test]
    fn list_by_name_returns_empty_when_no_match() {
        let store = ExperimentStore::new();
        store.record(make_experiment("1", "other"));
        assert!(store.list_by_name("nonexistent").is_empty());
    }

    #[test]
    fn get_by_id_finds_experiment() {
        let store = ExperimentStore::new();
        store.record(make_experiment("abc-123", "test"));
        let found = store.get_by_id("abc-123").expect("should find");
        assert_eq!(found.id, "abc-123");
    }

    #[test]
    fn get_by_id_returns_none_for_missing() {
        let store = ExperimentStore::new();
        assert!(store.get_by_id("not-here").is_none());
    }

    #[test]
    fn experiment_stores_parameters_and_model() {
        let store = ExperimentStore::new();
        store.record(make_experiment("x", "check-fields"));
        let all = store.list_all();
        assert_eq!(all[0].model, "gpt-4o");
        assert_eq!(all[0].parameters["temperature"], 0.7);
    }

    #[test]
    fn experiment_result_defaults_to_none() {
        let e = make_experiment("1", "no-result");
        assert!(e.result.is_none());
    }

    #[test]
    fn default_creates_empty_store() {
        let store = ExperimentStore::default();
        assert_eq!(store.count(), 0);
    }
}
