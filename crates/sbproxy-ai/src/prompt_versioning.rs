//! Prompt versioning and weighted A/B selection (WOR-2672 port of
//! `sbproxy-enterprise-ai::prompt_versioning`).
//!
//! Allows an embedder to maintain multiple versions of a prompt template
//! under a single name, retrieve the latest version, and perform weighted
//! stable cohort selection for gradual rollouts and A/B experiments. Fully
//! self-contained and in-memory: no config surface, no request-path
//! wiring, no rendering.
//!
//! # Not [`crate::prompts`]
//!
//! `sbproxy_ai::prompts` (WOR-800) is this crate's shipped, config-declared
//! prompt store: `NamedPrompt` / `PromptVersion` / `PromptStore` there are
//! per-origin, minijinja-rendered, resolved by `"name@version"` on the
//! request path, and support a runtime overlay that *pins* one version
//! live. This module's types are named `WeightedPromptVersion` /
//! `WeightedPromptStore` rather than the same `PromptVersion` /
//! `PromptStore` names the enterprise source used, specifically to avoid
//! colliding with those existing, more mature types.
//!
//! The capability gap this module fills that `crate::prompts` does not:
//! `crate::prompts`'s pin is deterministic (one version is live at a
//! time); this module's [`crate::prompt_versioning::WeightedPromptStore::select_for_cohort`] instead
//! answers "which version should THIS caller get" from a weighted random
//! draw, which is what a gradual percentage rollout needs. It is shipped
//! through the supported `sbproxy ai prompt select` command. See
//! `docs/prompt-versioning.md`.

use parking_lot::Mutex;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use thiserror::Error;

// --- Types ---

/// A single versioned prompt template.
#[derive(Debug, Clone)]
pub struct WeightedPromptVersion {
    /// Shared name that groups related versions (e.g. "system-prompt").
    pub name: String,
    /// Monotonically increasing version number. Higher is newer.
    pub version: u32,
    /// The actual prompt content for this version.
    pub content: String,
    /// Relative weight used for A/B traffic splitting. Must be non-negative.
    pub weight: f64,
}

impl WeightedPromptVersion {
    /// Create a new prompt version.
    pub fn new(
        name: impl Into<String>,
        version: u32,
        content: impl Into<String>,
        weight: f64,
    ) -> Result<Self, PromptVersionError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(PromptVersionError::EmptyName);
        }
        if version == 0 {
            return Err(PromptVersionError::ZeroVersion);
        }
        if !weight.is_finite() || weight < 0.0 {
            return Err(PromptVersionError::InvalidWeight { weight });
        }
        Ok(Self {
            name,
            version,
            content: content.into(),
            weight,
        })
    }
}

/// Invalid weighted-prompt configuration.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum PromptVersionError {
    /// Prompt names must be usable keys.
    #[error("weighted prompt name must not be empty")]
    EmptyName,
    /// Version zero is reserved and invalid.
    #[error("weighted prompt version must be greater than zero")]
    ZeroVersion,
    /// Weights must be finite and non-negative.
    #[error("weighted prompt weight must be finite and non-negative, got {weight}")]
    InvalidWeight {
        /// Rejected weight.
        weight: f64,
    },
    /// The caller's key and the version's embedded name disagree.
    #[error("weighted prompt key {key:?} does not match version name {version_name:?}")]
    NameMismatch {
        /// Store key supplied by the caller.
        key: String,
        /// Name carried by the version.
        version_name: String,
    },
    /// A version is immutable once inserted.
    #[error("weighted prompt {name:?} version {version} already exists")]
    DuplicateVersion {
        /// Prompt name.
        name: String,
        /// Existing version.
        version: u32,
    },
}

// --- Store ---

/// Thread-safe store for versioned prompt templates.
pub struct WeightedPromptStore {
    versions: Mutex<HashMap<String, Vec<WeightedPromptVersion>>>,
}

impl WeightedPromptStore {
    /// Create an empty prompt store.
    pub fn new() -> Self {
        Self {
            versions: Mutex::new(HashMap::new()),
        }
    }

    /// Add a new version under the given `name`. The name stored in the
    /// `WeightedPromptVersion` struct is used as the canonical key.
    pub fn add_version(
        &self,
        name: &str,
        version: WeightedPromptVersion,
    ) -> Result<(), PromptVersionError> {
        if version.name.trim().is_empty() {
            return Err(PromptVersionError::EmptyName);
        }
        if version.version == 0 {
            return Err(PromptVersionError::ZeroVersion);
        }
        if !version.weight.is_finite() || version.weight < 0.0 {
            return Err(PromptVersionError::InvalidWeight {
                weight: version.weight,
            });
        }
        if name != version.name {
            return Err(PromptVersionError::NameMismatch {
                key: name.to_string(),
                version_name: version.name,
            });
        }
        let mut versions = self.versions.lock();
        let stored = versions.entry(name.to_string()).or_default();
        if stored
            .iter()
            .any(|existing| existing.version == version.version)
        {
            return Err(PromptVersionError::DuplicateVersion {
                name: name.to_string(),
                version: version.version,
            });
        }
        stored.push(version);
        Ok(())
    }

    /// Return the version with the highest version number for the given name.
    /// Returns `None` if no versions exist for that name.
    pub fn get_latest(&self, name: &str) -> Option<WeightedPromptVersion> {
        self.versions
            .lock()
            .get(name)
            .and_then(|vs| vs.iter().max_by_key(|v| v.version).cloned())
    }

    /// Select a version by stable weighted cohort assignment (A/B split).
    ///
    /// Returns `None` when no versions exist or all weights are zero.
    /// The same `(name, cohort, salt)` always selects the same version, so
    /// concurrent requests do not correlate on wall-clock state and a caller
    /// remains in one experiment cohort.
    pub fn select_for_cohort(
        &self,
        name: &str,
        cohort: &str,
        salt: &str,
    ) -> Option<WeightedPromptVersion> {
        let guard = self.versions.lock();
        let vs = guard.get(name)?;
        if vs.is_empty() {
            return None;
        }

        let total: f64 = vs.iter().map(|v| v.weight).sum();
        if total <= 0.0 {
            return None;
        }

        let mut digest = Sha256::new();
        for component in [name.as_bytes(), cohort.as_bytes(), salt.as_bytes()] {
            digest.update((component.len() as u64).to_be_bytes());
            digest.update(component);
        }
        let hash = digest.finalize();
        let draw = u64::from_be_bytes(hash[..8].try_into().unwrap_or_default());
        let unit = draw as f64 / (u64::MAX as f64 + 1.0);
        let pick = unit * total;

        let mut cumulative = 0.0;
        for v in vs {
            cumulative += v.weight;
            if pick < cumulative {
                return Some(v.clone());
            }
        }
        vs.last().cloned()
    }

    /// Return all versions stored under `name`, sorted by version number ascending.
    pub fn list_versions(&self, name: &str) -> Vec<WeightedPromptVersion> {
        let mut vs = self.versions.lock().get(name).cloned().unwrap_or_default();
        vs.sort_by_key(|v| v.version);
        vs
    }

    /// Return all prompt names stored in this store.
    pub fn list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.versions.lock().keys().cloned().collect();
        names.sort();
        names
    }
}

impl Default for WeightedPromptStore {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_weights_names_and_duplicate_versions_are_rejected() {
        assert!(WeightedPromptVersion::new("p", 1, "x", f64::NAN).is_err());
        assert!(WeightedPromptVersion::new("p", 1, "x", -1.0).is_err());
        let store = WeightedPromptStore::new();
        let version = WeightedPromptVersion::new("p", 1, "x", 1.0).unwrap();
        assert!(store.add_version("other", version.clone()).is_err());
        store.add_version("p", version.clone()).unwrap();
        assert!(store.add_version("p", version).is_err());

        let bypassed_constructor = WeightedPromptVersion {
            name: "p".to_string(),
            version: 2,
            content: "bad".to_string(),
            weight: f64::NAN,
        };
        assert!(matches!(
            store.add_version("p", bypassed_constructor),
            Err(PromptVersionError::InvalidWeight { .. })
        ));
    }

    fn pv(name: &str, version: u32, weight: f64) -> WeightedPromptVersion {
        WeightedPromptVersion::new(name, version, format!("content-v{version}"), weight).unwrap()
    }

    #[test]
    fn add_and_get_latest_returns_highest_version() {
        let store = WeightedPromptStore::new();
        store.add_version("sys", pv("sys", 1, 1.0)).unwrap();
        store.add_version("sys", pv("sys", 3, 1.0)).unwrap();
        store.add_version("sys", pv("sys", 2, 1.0)).unwrap();
        let latest = store.get_latest("sys").expect("should exist");
        assert_eq!(latest.version, 3);
    }

    #[test]
    fn get_latest_returns_none_for_unknown_name() {
        let store = WeightedPromptStore::new();
        assert!(store.get_latest("missing").is_none());
    }

    #[test]
    fn list_versions_are_sorted_ascending() {
        let store = WeightedPromptStore::new();
        store.add_version("p", pv("p", 3, 1.0)).unwrap();
        store.add_version("p", pv("p", 1, 1.0)).unwrap();
        store.add_version("p", pv("p", 2, 1.0)).unwrap();
        let vs = store.list_versions("p");
        assert_eq!(
            vs.iter().map(|v| v.version).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn list_versions_empty_for_unknown_name() {
        let store = WeightedPromptStore::new();
        assert!(store.list_versions("unknown").is_empty());
    }

    #[test]
    fn select_by_weight_returns_some_when_versions_exist() {
        let store = WeightedPromptStore::new();
        store.add_version("ab", pv("ab", 1, 50.0)).unwrap();
        store.add_version("ab", pv("ab", 2, 50.0)).unwrap();
        let selected = store.select_for_cohort("ab", "customer-1", "experiment-a");
        assert!(selected.is_some());
    }

    #[test]
    fn cohort_selection_is_stable_and_tracks_weights_without_sleeping() {
        let store = WeightedPromptStore::new();
        store.add_version("ab", pv("ab", 1, 90.0)).unwrap();
        store.add_version("ab", pv("ab", 2, 10.0)).unwrap();
        let stable = store
            .select_for_cohort("ab", "customer-42", "rollout-1")
            .unwrap()
            .version;
        for _ in 0..100 {
            assert_eq!(
                store
                    .select_for_cohort("ab", "customer-42", "rollout-1")
                    .unwrap()
                    .version,
                stable
            );
        }
        let selected_v2 = (0..10_000)
            .filter(|index| {
                store
                    .select_for_cohort("ab", &format!("customer-{index}"), "rollout-1")
                    .unwrap()
                    .version
                    == 2
            })
            .count();
        assert!((850..=1_150).contains(&selected_v2), "v2={selected_v2}");
    }

    #[test]
    fn select_by_weight_returns_none_when_all_weights_zero() {
        let store = WeightedPromptStore::new();
        store.add_version("zero", pv("zero", 1, 0.0)).unwrap();
        store.add_version("zero", pv("zero", 2, 0.0)).unwrap();
        assert!(store
            .select_for_cohort("zero", "customer-1", "experiment-a")
            .is_none());
    }

    #[test]
    fn select_by_weight_returns_none_for_missing_name() {
        let store = WeightedPromptStore::new();
        assert!(store
            .select_for_cohort("nope", "customer-1", "experiment-a")
            .is_none());
    }

    #[test]
    fn select_by_weight_single_version_always_returns_it() {
        let store = WeightedPromptStore::new();
        store.add_version("single", pv("single", 1, 100.0)).unwrap();
        let selected = store
            .select_for_cohort("single", "customer-1", "experiment-a")
            .expect("should select");
        assert_eq!(selected.version, 1);
    }

    #[test]
    fn list_names_returns_sorted_names() {
        let store = WeightedPromptStore::new();
        store
            .add_version("z-prompt", pv("z-prompt", 1, 1.0))
            .unwrap();
        store
            .add_version("a-prompt", pv("a-prompt", 1, 1.0))
            .unwrap();
        assert_eq!(store.list_names(), vec!["a-prompt", "z-prompt"]);
    }

    #[test]
    fn prompt_version_content_stored_correctly() {
        let store = WeightedPromptStore::new();
        let pv = WeightedPromptVersion::new("sys", 1, "You are a helpful assistant.", 1.0).unwrap();
        store.add_version("sys", pv).unwrap();
        let latest = store.get_latest("sys").unwrap();
        assert_eq!(latest.content, "You are a helpful assistant.");
    }
}
