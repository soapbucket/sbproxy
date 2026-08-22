//! Dataset management for AI evaluation pipelines.
//!
//! Provides a versioned, named dataset store backed by an in-memory map.
//! Datasets hold input/expected-output pairs used in offline evaluations.

use parking_lot::Mutex;
use std::collections::HashMap;

// --- Types ---

/// A single entry in an evaluation dataset.
#[derive(Debug, Clone)]
pub struct DatasetEntry {
    /// The input prompt or text.
    pub input: String,
    /// Optional expected output used for correctness evaluation.
    pub expected_output: Option<String>,
    /// Arbitrary metadata (labels, source, difficulty, etc.).
    pub metadata: serde_json::Value,
}

impl DatasetEntry {
    /// Create a basic entry with only an input.
    pub fn new(input: impl Into<String>) -> Self {
        Self {
            input: input.into(),
            expected_output: None,
            metadata: serde_json::Value::Null,
        }
    }

    /// Create an entry with an expected output.
    pub fn with_expected(input: impl Into<String>, expected: impl Into<String>) -> Self {
        Self {
            input: input.into(),
            expected_output: Some(expected.into()),
            metadata: serde_json::Value::Null,
        }
    }
}

/// A versioned collection of evaluation entries.
#[derive(Debug, Clone)]
pub struct Dataset {
    /// Dataset name used as the storage key.
    pub name: String,
    /// Monotonically increasing version number.
    pub version: u32,
    /// The entries in this dataset version.
    pub entries: Vec<DatasetEntry>,
}

impl Dataset {
    /// Create a new dataset at version 1.
    pub fn new(name: impl Into<String>, entries: Vec<DatasetEntry>) -> Self {
        Self {
            name: name.into(),
            version: 1,
            entries,
        }
    }
}

// --- Store ---

/// Thread-safe, in-memory dataset store.
pub struct DatasetStore {
    datasets: Mutex<HashMap<String, Dataset>>,
}

impl DatasetStore {
    /// Create an empty dataset store.
    pub fn new() -> Self {
        Self {
            datasets: Mutex::new(HashMap::new()),
        }
    }

    /// Save or replace a dataset. The name is taken from `dataset.name`.
    pub fn save(&self, dataset: Dataset) {
        self.datasets.lock().insert(dataset.name.clone(), dataset);
    }

    /// Retrieve a dataset by name. Returns `None` if not found.
    pub fn get(&self, name: &str) -> Option<Dataset> {
        self.datasets.lock().get(name).cloned()
    }

    /// List all stored dataset names, sorted alphabetically.
    pub fn list(&self) -> Vec<String> {
        let guard = self.datasets.lock();
        let mut names: Vec<String> = guard.keys().cloned().collect();
        names.sort();
        names
    }

    /// Delete a dataset by name. No-op if the dataset does not exist.
    pub fn delete(&self, name: &str) {
        self.datasets.lock().remove(name);
    }

    /// Return the total number of stored datasets.
    pub fn count(&self) -> usize {
        self.datasets.lock().len()
    }
}

impl Default for DatasetStore {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_dataset(name: &str, n: usize) -> Dataset {
        let entries = (0..n)
            .map(|i| DatasetEntry::with_expected(format!("input-{i}"), format!("output-{i}")))
            .collect();
        Dataset::new(name, entries)
    }

    #[test]
    fn save_and_get_roundtrip() {
        let store = DatasetStore::new();
        store.save(make_dataset("qa-bench", 3));
        let ds = store.get("qa-bench").expect("should exist");
        assert_eq!(ds.name, "qa-bench");
        assert_eq!(ds.entries.len(), 3);
    }

    #[test]
    fn get_returns_none_for_missing_dataset() {
        let store = DatasetStore::new();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn list_returns_sorted_names() {
        let store = DatasetStore::new();
        store.save(make_dataset("z-set", 1));
        store.save(make_dataset("a-set", 1));
        store.save(make_dataset("m-set", 1));
        assert_eq!(store.list(), vec!["a-set", "m-set", "z-set"]);
    }

    #[test]
    fn delete_removes_dataset() {
        let store = DatasetStore::new();
        store.save(make_dataset("to-delete", 2));
        assert_eq!(store.count(), 1);
        store.delete("to-delete");
        assert_eq!(store.count(), 0);
        assert!(store.get("to-delete").is_none());
    }

    #[test]
    fn delete_noop_when_not_found() {
        let store = DatasetStore::new();
        store.delete("ghost"); // should not panic
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn save_replaces_existing_dataset() {
        let store = DatasetStore::new();
        store.save(make_dataset("bench", 2));
        store.save(make_dataset("bench", 5));
        let ds = store.get("bench").unwrap();
        assert_eq!(ds.entries.len(), 5);
    }

    #[test]
    fn dataset_entry_with_metadata() {
        let mut entry = DatasetEntry::new("prompt");
        entry.metadata = json!({"difficulty": "hard"});
        assert_eq!(entry.metadata["difficulty"], "hard");
    }

    #[test]
    fn dataset_entry_expected_output() {
        let entry = DatasetEntry::with_expected("q", "a");
        assert_eq!(entry.expected_output.as_deref(), Some("a"));
    }

    #[test]
    fn dataset_version_defaults_to_one() {
        let ds = make_dataset("v-test", 0);
        assert_eq!(ds.version, 1);
    }
}
