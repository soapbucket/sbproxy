//! Dataset management for AI evaluation pipelines.
//!
//! Provides a versioned, named dataset store backed by an in-memory map.
//! Datasets hold input/expected-output pairs used in offline evaluations.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// --- Types ---

/// A single entry in an evaluation dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Dataset name used as the storage key.
    pub name: String,
    /// Monotonically increasing version number.
    pub version: u32,
    /// The entries in this dataset version.
    pub entries: Vec<DatasetEntry>,
}

impl Dataset {
    /// Create an explicitly versioned dataset.
    pub fn new(
        name: impl Into<String>,
        version: u32,
        entries: Vec<DatasetEntry>,
    ) -> Result<Self, DatasetError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(DatasetError::EmptyName);
        }
        if version == 0 {
            return Err(DatasetError::ZeroVersion);
        }
        Ok(Self {
            name,
            version,
            entries,
        })
    }
}

/// Dataset construction or storage error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DatasetError {
    /// Dataset names must be usable keys.
    #[error("dataset name must not be empty")]
    EmptyName,
    /// Version zero is reserved and invalid.
    #[error("dataset version must be greater than zero")]
    ZeroVersion,
    /// Immutable dataset versions cannot be overwritten.
    #[error("dataset {name:?} version {version} already exists")]
    VersionAlreadyExists {
        /// Dataset name.
        name: String,
        /// Existing version.
        version: u32,
    },
}

// --- Store ---

/// Thread-safe, in-memory dataset store.
///
/// # Unbounded: not for live traffic
///
/// An offline primitive with no cap and no eviction:
/// [`DatasetStore::save`] grows without limit and retains every entry
/// verbatim. The bounded equivalent is
/// [`crate::toolkit::AiToolkitRuntime`], which caps dataset names,
/// versions, entries, and retained bytes per scope and across the
/// process.
pub struct DatasetStore {
    datasets: Mutex<HashMap<(String, u32), Dataset>>,
}

impl DatasetStore {
    /// Create an empty dataset store.
    pub fn new() -> Self {
        Self {
            datasets: Mutex::new(HashMap::new()),
        }
    }

    /// Save one immutable dataset version.
    pub fn save(&self, dataset: Dataset) -> Result<(), DatasetError> {
        if dataset.name.trim().is_empty() {
            return Err(DatasetError::EmptyName);
        }
        if dataset.version == 0 {
            return Err(DatasetError::ZeroVersion);
        }
        let key = (dataset.name.clone(), dataset.version);
        let mut datasets = self.datasets.lock();
        if datasets.contains_key(&key) {
            return Err(DatasetError::VersionAlreadyExists {
                name: key.0,
                version: key.1,
            });
        }
        datasets.insert(key, dataset);
        Ok(())
    }

    /// Retrieve an exact dataset version.
    pub fn get(&self, name: &str, version: u32) -> Option<Dataset> {
        self.datasets
            .lock()
            .get(&(name.to_string(), version))
            .cloned()
    }

    /// Retrieve the highest stored version of a dataset.
    pub fn latest(&self, name: &str) -> Option<Dataset> {
        self.datasets
            .lock()
            .iter()
            .filter(|((candidate, _), _)| candidate == name)
            .max_by_key(|((_, version), _)| *version)
            .map(|(_, dataset)| dataset.clone())
    }

    /// List all stored dataset names, sorted alphabetically.
    pub fn list(&self) -> Vec<String> {
        let guard = self.datasets.lock();
        let mut names: Vec<String> = guard.keys().map(|(name, _)| name.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Delete an exact dataset version.
    pub fn delete(&self, name: &str, version: u32) -> bool {
        self.datasets
            .lock()
            .remove(&(name.to_string(), version))
            .is_some()
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
        Dataset::new(name, 1, entries).unwrap()
    }

    #[test]
    fn save_and_get_roundtrip() {
        let store = DatasetStore::new();
        store.save(make_dataset("qa-bench", 3)).unwrap();
        let ds = store.get("qa-bench", 1).expect("should exist");
        assert_eq!(ds.name, "qa-bench");
        assert_eq!(ds.entries.len(), 3);
    }

    #[test]
    fn get_returns_none_for_missing_dataset() {
        let store = DatasetStore::new();
        assert!(store.get("nope", 1).is_none());
    }

    #[test]
    fn list_returns_sorted_names() {
        let store = DatasetStore::new();
        store.save(make_dataset("z-set", 1)).unwrap();
        store.save(make_dataset("a-set", 1)).unwrap();
        store.save(make_dataset("m-set", 1)).unwrap();
        assert_eq!(store.list(), vec!["a-set", "m-set", "z-set"]);
    }

    #[test]
    fn delete_removes_dataset() {
        let store = DatasetStore::new();
        store.save(make_dataset("to-delete", 2)).unwrap();
        assert_eq!(store.count(), 1);
        assert!(store.delete("to-delete", 1));
        assert_eq!(store.count(), 0);
        assert!(store.get("to-delete", 1).is_none());
    }

    #[test]
    fn delete_noop_when_not_found() {
        let store = DatasetStore::new();
        assert!(!store.delete("ghost", 1));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn save_rejects_existing_dataset_version() {
        let store = DatasetStore::new();
        store.save(make_dataset("bench", 2)).unwrap();
        assert!(matches!(
            store.save(make_dataset("bench", 5)),
            Err(DatasetError::VersionAlreadyExists { .. })
        ));
        let ds = store.get("bench", 1).unwrap();
        assert_eq!(ds.entries.len(), 2);
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
    fn dataset_version_is_explicit() {
        let ds = make_dataset("v-test", 0);
        assert_eq!(ds.version, 1);
    }

    #[test]
    fn versions_are_preserved_and_duplicate_saves_are_rejected() {
        let store = DatasetStore::new();
        let v1 = Dataset::new("bench", 1, vec![DatasetEntry::new("one")]).unwrap();
        let v2 = Dataset::new("bench", 2, vec![DatasetEntry::new("two")]).unwrap();
        store.save(v1.clone()).unwrap();
        store.save(v2.clone()).unwrap();
        assert_eq!(store.get("bench", 1).unwrap().entries[0].input, "one");
        assert_eq!(store.latest("bench").unwrap().version, 2);
        assert!(matches!(
            store.save(v2),
            Err(DatasetError::VersionAlreadyExists { .. })
        ));
    }

    #[test]
    fn save_revalidates_public_dataset_fields() {
        let store = DatasetStore::new();
        assert!(matches!(
            store.save(Dataset {
                name: " ".to_string(),
                version: 1,
                entries: Vec::new(),
            }),
            Err(DatasetError::EmptyName)
        ));
        assert!(matches!(
            store.save(Dataset {
                name: "bench".to_string(),
                version: 0,
                entries: Vec::new(),
            }),
            Err(DatasetError::ZeroVersion)
        ));
    }
}
