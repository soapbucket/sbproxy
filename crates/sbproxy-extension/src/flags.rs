//! Edge feature flags (F3.24).
//!
//! Flags are evaluated against a per-request context: a flag name plus
//! a sticky bucketing key (user id, tenant id, JWT subject, ...). The
//! evaluator returns `true` or `false` deterministically for the same
//! `(name, key)` pair so a user that lands inside a 25% rollout stays
//! inside it across requests.
//!
//! # Rule grammar
//!
//! Each flag carries a `default` plus an ordered list of rules:
//!
//! - `block_list`: keys in this set always evaluate `false`.
//! - `allow_list`: keys in this set always evaluate `true`.
//! - `rollout_percent`: sticky FNV-1a bucketing on
//!   `fnv1a64(flag_name + "|" + key) % 100`.
//! - `segments`: `true` when the request's segment label matches one
//!   of the configured values.
//!
//! Rules apply in the listed order (block, allow, segment, rollout); the
//! first match wins. When no rule matches, the flag falls back to `default`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Deserialize;

/// Per-flag rules.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FlagRule {
    /// Keys always evaluated as `true`.
    #[serde(default)]
    pub allow_list: HashSet<String>,
    /// Keys always evaluated as `false`.
    #[serde(default)]
    pub block_list: HashSet<String>,
    /// 0 to 100 sticky-bucket cutoff. A request's bucket is
    /// `fnv1a64(flag_name + "|" + key) % 100`. The flag is `true` when
    /// `bucket < rollout_percent`.
    ///
    /// The `|` separator byte is mixed into the hash between the two
    /// strings, so a cohort-preview tool that concatenates them
    /// without it computes a different bucket than the proxy does.
    #[serde(default)]
    pub rollout_percent: u32,
    /// Segment labels that always evaluate `true`.
    #[serde(default)]
    pub segments: HashSet<String>,
}

/// One flag configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct FlagConfig {
    /// Unique flag name.
    pub name: String,
    /// Value when no rule matches.
    #[serde(default)]
    pub default: bool,
    /// Rules applied in order; the first match wins.
    #[serde(default)]
    pub rules: FlagRule,
}

/// Run-time flag store. Reads take a shared lock and writes take an
/// exclusive lock on the underlying map. Config reloads normally replace
/// the process-wide `Arc<FlagStore>` instead of mutating this map in place.
#[derive(Debug, Default)]
pub struct FlagStore {
    inner: RwLock<HashMap<String, FlagConfig>>,
}

impl FlagStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from a config slice.
    pub fn from_configs(flags: impl IntoIterator<Item = FlagConfig>) -> Self {
        let mut map = HashMap::new();
        for flag in flags {
            map.insert(flag.name.clone(), flag);
        }
        Self {
            inner: RwLock::new(map),
        }
    }

    /// Insert or replace a flag.
    pub fn upsert(&self, flag: FlagConfig) {
        self.inner.write().insert(flag.name.clone(), flag);
    }

    /// Remove a flag.
    pub fn remove(&self, name: &str) {
        self.inner.write().remove(name);
    }

    /// True when `key` lands inside the named flag. Unknown flags
    /// evaluate to `false`.
    pub fn enabled(&self, name: &str, key: &str, segment: Option<&str>) -> bool {
        let guard = self.inner.read();
        let Some(flag) = guard.get(name) else {
            return false;
        };
        evaluate(flag, key, segment)
    }

    /// Snapshot of every configured flag. Useful for an admin endpoint.
    pub fn snapshot(&self) -> Vec<FlagConfig> {
        let mut v: Vec<FlagConfig> = self.inner.read().values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

fn evaluate(flag: &FlagConfig, key: &str, segment: Option<&str>) -> bool {
    let r = &flag.rules;
    if !r.block_list.is_empty() && r.block_list.contains(key) {
        return false;
    }
    if !r.allow_list.is_empty() && r.allow_list.contains(key) {
        return true;
    }
    if let Some(seg) = segment {
        if r.segments.contains(seg) {
            return true;
        }
    }
    if r.rollout_percent >= 100 {
        return true;
    }
    if r.rollout_percent == 0 {
        return flag.default;
    }
    let bucket = sticky_bucket(&flag.name, key);
    if bucket < r.rollout_percent {
        true
    } else {
        flag.default
    }
}

/// Map `(flag_name, key)` deterministically into `[0, 100)`. Uses a
/// FNV-1a 64-bit hash over `flag_name`, a `|` separator byte, then
/// `key`, followed by `% 100`, so the same pair always lands in the
/// same bucket regardless of process restart. The separator is what
/// keeps `("ab", "c")` and `("a", "bc")` in different buckets.
fn sticky_bucket(flag_name: &str, key: &str) -> u32 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for b in flag_name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h ^= b'|' as u64;
    h = h.wrapping_mul(FNV_PRIME);
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    (h % 100) as u32
}

/// Process-wide default flag store. The CEL helper reads from this
/// when no per-engine override is supplied.
static GLOBAL_STORE: once_cell::sync::Lazy<Arc<FlagStore>> =
    once_cell::sync::Lazy::new(|| Arc::new(FlagStore::new()));

/// Replace the global store. Returns the previous handle.
pub fn set_global_store(store: Arc<FlagStore>) -> Arc<FlagStore> {
    let mut guard = GLOBAL_HANDLE.write();
    let prev = guard.clone();
    *guard = store;
    prev
}

/// Run `publish` and then replace the global store while CEL readers are
/// excluded from the transition.
///
/// Embedders that publish another snapshot containing the flag configuration
/// use this to keep the two pointer swaps adjacent: a reader that observes the
/// newly published snapshot and calls [`global_store`] blocks until the
/// matching flag store is installed.
pub fn replace_global_store_after<T>(
    store: Arc<FlagStore>,
    publish: impl FnOnce() -> T,
) -> (Arc<FlagStore>, T) {
    let mut guard = GLOBAL_HANDLE.write();
    let result = publish();
    let previous = std::mem::replace(&mut *guard, store);
    (previous, result)
}

/// Snapshot of the live global store handle.
pub fn global_store() -> Arc<FlagStore> {
    GLOBAL_HANDLE.read().clone()
}

static GLOBAL_HANDLE: once_cell::sync::Lazy<RwLock<Arc<FlagStore>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(GLOBAL_STORE.clone()));

#[cfg(test)]
mod tests {
    use super::*;

    fn flag(name: &str, default: bool, rule: FlagRule) -> FlagConfig {
        FlagConfig {
            name: name.to_string(),
            default,
            rules: rule,
        }
    }

    #[test]
    fn unknown_flag_is_false() {
        let store = FlagStore::new();
        assert!(!store.enabled("nope", "alice", None));
    }

    #[test]
    fn allow_list_wins_over_default_false() {
        let store = FlagStore::from_configs(vec![flag(
            "new-ui",
            false,
            FlagRule {
                allow_list: ["alice".to_string()].into_iter().collect(),
                ..FlagRule::default()
            },
        )]);
        assert!(store.enabled("new-ui", "alice", None));
        assert!(!store.enabled("new-ui", "bob", None));
    }

    #[test]
    fn block_list_wins_over_default_true() {
        let store = FlagStore::from_configs(vec![flag(
            "new-ui",
            true,
            FlagRule {
                block_list: ["bob".to_string()].into_iter().collect(),
                ..FlagRule::default()
            },
        )]);
        assert!(store.enabled("new-ui", "alice", None));
        assert!(!store.enabled("new-ui", "bob", None));
    }

    #[test]
    fn block_list_wins_over_allow_list() {
        // Defensive: a key on both lists is rejected. Spelling errors
        // in config should default to safe.
        let store = FlagStore::from_configs(vec![flag(
            "new-ui",
            false,
            FlagRule {
                allow_list: ["alice".to_string()].into_iter().collect(),
                block_list: ["alice".to_string()].into_iter().collect(),
                ..FlagRule::default()
            },
        )]);
        assert!(!store.enabled("new-ui", "alice", None));
    }

    #[test]
    fn segment_match_overrides_default() {
        let store = FlagStore::from_configs(vec![flag(
            "new-ui",
            false,
            FlagRule {
                segments: ["beta".to_string()].into_iter().collect(),
                ..FlagRule::default()
            },
        )]);
        assert!(store.enabled("new-ui", "alice", Some("beta")));
        assert!(!store.enabled("new-ui", "alice", Some("ga")));
        assert!(!store.enabled("new-ui", "alice", None));
    }

    #[test]
    fn rollout_percent_is_sticky_per_key() {
        let store = FlagStore::from_configs(vec![flag(
            "new-ui",
            false,
            FlagRule {
                rollout_percent: 50,
                ..FlagRule::default()
            },
        )]);
        // Same key evaluates to the same answer every time.
        let first = store.enabled("new-ui", "alice", None);
        for _ in 0..10 {
            assert_eq!(first, store.enabled("new-ui", "alice", None));
        }
        // Distribution across many distinct keys is roughly the rollout.
        let mut hits = 0;
        for i in 0..1_000 {
            if store.enabled("new-ui", &format!("user-{i}"), None) {
                hits += 1;
            }
        }
        assert!(
            hits > 400 && hits < 600,
            "50% rollout produced {hits}/1000 hits, expected ~500"
        );
    }

    #[test]
    fn rollout_zero_falls_back_to_default() {
        let true_default = FlagStore::from_configs(vec![flag(
            "f",
            true,
            FlagRule {
                rollout_percent: 0,
                ..FlagRule::default()
            },
        )]);
        let false_default = FlagStore::from_configs(vec![flag(
            "f",
            false,
            FlagRule {
                rollout_percent: 0,
                ..FlagRule::default()
            },
        )]);
        assert!(true_default.enabled("f", "alice", None));
        assert!(!false_default.enabled("f", "alice", None));
    }

    #[test]
    fn rollout_hundred_is_always_true() {
        let store = FlagStore::from_configs(vec![flag(
            "f",
            false,
            FlagRule {
                rollout_percent: 100,
                ..FlagRule::default()
            },
        )]);
        for i in 0..20 {
            assert!(store.enabled("f", &format!("k{i}"), None));
        }
    }

    #[test]
    fn upsert_replaces_existing() {
        let store = FlagStore::from_configs(vec![flag("f", false, FlagRule::default())]);
        assert!(!store.enabled("f", "alice", None));
        store.upsert(flag(
            "f",
            true,
            FlagRule {
                rollout_percent: 100,
                ..FlagRule::default()
            },
        ));
        assert!(store.enabled("f", "alice", None));
    }

    #[test]
    fn remove_clears_flag() {
        let store = FlagStore::from_configs(vec![flag(
            "f",
            true,
            FlagRule {
                rollout_percent: 100,
                ..FlagRule::default()
            },
        )]);
        assert!(store.enabled("f", "alice", None));
        store.remove("f");
        assert!(!store.enabled("f", "alice", None));
    }

    #[test]
    fn replacing_the_global_store_never_exposes_a_partial_flag_set() {
        let previous = global_store();
        let first = Arc::new(FlagStore::from_configs(vec![
            flag("first-a", true, FlagRule::default()),
            flag("first-b", true, FlagRule::default()),
        ]));
        let second = Arc::new(FlagStore::from_configs(vec![
            flag("second-a", true, FlagRule::default()),
            flag("second-b", true, FlagRule::default()),
        ]));
        set_global_store(first.clone());

        let writer = std::thread::spawn(move || {
            for index in 0..2_000 {
                let next = if index % 2 == 0 {
                    second.clone()
                } else {
                    first.clone()
                };
                set_global_store(next);
            }
        });

        for _ in 0..10_000 {
            let names: Vec<String> = global_store()
                .snapshot()
                .into_iter()
                .map(|flag| flag.name)
                .collect();
            assert!(
                names == ["first-a", "first-b"] || names == ["second-a", "second-b"],
                "reader observed a torn flag set: {names:?}"
            );
        }
        writer.join().expect("writer should finish");
        set_global_store(previous);
    }

    /// The documented formula has to be the one the proxy runs.
    ///
    /// `FlagRule::rollout_percent` said `xxhash(flag_name + key) % 100`
    /// while `sticky_bucket` was FNV-1a over `flag_name`, a `|`, then
    /// `key`. An operator pre-warming a canary reproduced the doc and
    /// pre-warmed the wrong cohort. This recomputes the documented
    /// formula independently, the way an external cohort-preview tool
    /// would, and refuses to let the two drift again.
    #[test]
    fn sticky_bucket_matches_the_documented_fnv1a_formula() {
        fn documented_bucket(flag_name: &str, key: &str) -> u32 {
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
            let mut mix = |bytes: &[u8]| {
                for byte in bytes {
                    hash ^= u64::from(*byte);
                    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                }
            };
            mix(flag_name.as_bytes());
            mix(b"|");
            mix(key.as_bytes());
            (hash % 100) as u32
        }

        for (flag_name, key) in [
            ("new-ui", "tenant-7"),
            ("", ""),
            ("a", "bc"),
            ("checkout-v2", "acct_000000000000"),
        ] {
            assert_eq!(
                sticky_bucket(flag_name, key),
                documented_bucket(flag_name, key),
                "{flag_name:?}/{key:?}",
            );
        }
        // Pinned so a change to the hash is a change to this test.
        assert_eq!(sticky_bucket("new-ui", "tenant-7"), 26);
        // The separator is load bearing: without it these two pairs
        // would hash identically.
        assert_ne!(sticky_bucket("ab", "c"), sticky_bucket("a", "bc"));
    }
}
