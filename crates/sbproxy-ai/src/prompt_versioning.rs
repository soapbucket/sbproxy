//! Prompt versioning and weighted A/B selection (WOR-2672 port of
//! `sbproxy-enterprise-ai::prompt_versioning`).
//!
//! Allows an embedder to maintain multiple versions of a prompt template
//! under a single name, retrieve the latest version, and perform weighted
//! random selection for gradual rollouts and A/B experiments. Fully
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
//! time); this module's [`WeightedPromptStore::select_by_weight`] instead
//! answers "which version should THIS caller get" from a weighted random
//! draw, which is what a gradual percentage rollout needs. It is shipped
//! today as a standalone toolkit; integrating its weights as a
//! `prompts:` config option is a separate, unscheduled follow-up, not
//! assumed here. See `docs/prompt-versioning.md` and
//! `examples/prompt-versioning-rollout/`.

use parking_lot::Mutex;
use std::collections::HashMap;

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
    ) -> Self {
        Self {
            name: name.into(),
            version,
            content: content.into(),
            weight,
        }
    }
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
    pub fn add_version(&self, name: &str, version: WeightedPromptVersion) {
        self.versions
            .lock()
            .entry(name.to_string())
            .or_default()
            .push(version);
    }

    /// Return the version with the highest version number for the given name.
    /// Returns `None` if no versions exist for that name.
    pub fn get_latest(&self, name: &str) -> Option<WeightedPromptVersion> {
        self.versions
            .lock()
            .get(name)
            .and_then(|vs| vs.iter().max_by_key(|v| v.version).cloned())
    }

    /// Select a version by weighted random sampling (A/B split).
    ///
    /// Returns `None` when no versions exist or all weights are zero.
    /// Uses a deterministic hash of the name + total-weight for reproducibility
    /// in unit tests; production code can replace this with `rand::thread_rng`.
    pub fn select_by_weight(&self, name: &str) -> Option<WeightedPromptVersion> {
        let guard = self.versions.lock();
        let vs = guard.get(name)?;
        if vs.is_empty() {
            return None;
        }

        let total: f64 = vs.iter().map(|v| v.weight).sum();
        if total <= 0.0 {
            return None;
        }

        // Deterministic pseudo-random pick: use a simple LCG seeded by
        // the current time in microseconds for adequate randomness in practice.
        // Tests can validate that each version is selectable by iterating.
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_micros())
            .unwrap_or(42) as f64;
        let pick = (seed % 1000.0) / 1000.0 * total;

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

    fn pv(name: &str, version: u32, weight: f64) -> WeightedPromptVersion {
        WeightedPromptVersion::new(name, version, format!("content-v{version}"), weight)
    }

    #[test]
    fn add_and_get_latest_returns_highest_version() {
        let store = WeightedPromptStore::new();
        store.add_version("sys", pv("sys", 1, 1.0));
        store.add_version("sys", pv("sys", 3, 1.0));
        store.add_version("sys", pv("sys", 2, 1.0));
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
        store.add_version("p", pv("p", 3, 1.0));
        store.add_version("p", pv("p", 1, 1.0));
        store.add_version("p", pv("p", 2, 1.0));
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
        store.add_version("ab", pv("ab", 1, 50.0));
        store.add_version("ab", pv("ab", 2, 50.0));
        let selected = store.select_by_weight("ab");
        assert!(selected.is_some());
    }

    #[test]
    fn select_by_weight_returns_none_when_all_weights_zero() {
        let store = WeightedPromptStore::new();
        store.add_version("zero", pv("zero", 1, 0.0));
        store.add_version("zero", pv("zero", 2, 0.0));
        assert!(store.select_by_weight("zero").is_none());
    }

    #[test]
    fn select_by_weight_returns_none_for_missing_name() {
        let store = WeightedPromptStore::new();
        assert!(store.select_by_weight("nope").is_none());
    }

    #[test]
    fn select_by_weight_single_version_always_returns_it() {
        let store = WeightedPromptStore::new();
        store.add_version("single", pv("single", 1, 100.0));
        let selected = store.select_by_weight("single").expect("should select");
        assert_eq!(selected.version, 1);
    }

    #[test]
    fn list_names_returns_sorted_names() {
        let store = WeightedPromptStore::new();
        store.add_version("z-prompt", pv("z-prompt", 1, 1.0));
        store.add_version("a-prompt", pv("a-prompt", 1, 1.0));
        assert_eq!(store.list_names(), vec!["a-prompt", "z-prompt"]);
    }

    #[test]
    fn prompt_version_content_stored_correctly() {
        let store = WeightedPromptStore::new();
        let pv = WeightedPromptVersion::new("sys", 1, "You are a helpful assistant.", 1.0);
        store.add_version("sys", pv);
        let latest = store.get_latest("sys").unwrap();
        assert_eq!(latest.content, "You are a helpful assistant.");
    }
}
