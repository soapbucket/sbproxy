//! Prompt versioning and weighted A/B selection (WOR-2672 port of
//! `sbproxy-enterprise-ai::prompt_versioning`).
//!
//! Maintains multiple immutable versions of a prompt under one name, retrieves
//! the latest version, and performs stable weighted cohort selection for
//! gradual rollouts and A/B experiments. [`WeightedPromptStore`](crate::prompt_versioning::WeightedPromptStore) is the
//! self-contained in-memory selection primitive and performs no template
//! rendering. The production proxy builds it from
//! `proxy.ai_toolkit.prompt_rollouts`, publishes it with the compiled pipeline
//! generation, exposes dry-run selection through
//! `POST /admin/ai-toolkit/prompts/select` and `sbproxy ai prompt select`, and
//! consults it for a bare prompt name on the live `ai_proxy` request path after
//! the runtime prompt overlay misses.
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
//! time); this module's [`crate::prompt_versioning::WeightedPromptStore::select_for_cohort_typed`] instead
//! answers "which version should THIS caller get" from a weighted random
//! draw, which is what a gradual percentage rollout needs. It is shipped
//! through the supported `sbproxy ai prompt select` command. See
//! `docs/prompt-versioning.md`.

use num_bigint::BigUint;
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
    /// A complete rollout must have a finite, positive aggregate weight.
    #[error("weighted prompt rollout total must be finite and positive, got {total}")]
    InvalidTotalWeight {
        /// Rejected aggregate weight.
        total: f64,
    },
}

/// Typed failure returned when selecting from a weighted prompt rollout.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum PromptSelectionError {
    /// No rollout is installed under the requested name.
    #[error("weighted prompt rollout {name:?} does not exist")]
    MissingRollout {
        /// Missing rollout name.
        name: String,
    },
    /// The installed rollout has a zero or non-finite aggregate weight.
    #[error("weighted prompt rollout {name:?} has invalid total weight {total}")]
    InvalidTotalWeight {
        /// Rollout containing the invalid aggregate.
        name: String,
        /// Rejected aggregate weight.
        total: f64,
    },
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptCallsiteEvent {
    RolloutLookupHash {
        name_bytes: usize,
    },
    CohortHash {
        name_bytes: usize,
        cohort_bytes: usize,
        salt_bytes: usize,
    },
    SelectedContentClone {
        content_bytes: usize,
    },
    RetiredSnapshotDrop {
        versions: usize,
    },
}

#[cfg(test)]
type PromptCallsiteHook = Box<dyn FnMut(PromptCallsiteEvent)>;

#[cfg(test)]
std::thread_local! {
    static PROMPT_CALLSITE_HOOK: std::cell::RefCell<Option<PromptCallsiteHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct PromptCallsiteProbe {
    previous: Option<PromptCallsiteHook>,
    _current_thread_only: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl PromptCallsiteProbe {
    fn install_for_current_thread(hook: impl FnMut(PromptCallsiteEvent) + 'static) -> Self {
        let previous = PROMPT_CALLSITE_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
        Self {
            previous,
            _current_thread_only: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
impl Drop for PromptCallsiteProbe {
    fn drop(&mut self) {
        let previous = self.previous.take();
        PROMPT_CALLSITE_HOOK.with(|slot| {
            let _ = slot.replace(previous);
        });
    }
}

#[cfg(test)]
fn run_prompt_callsite_hook(event: PromptCallsiteEvent) {
    PROMPT_CALLSITE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(event);
        }
    });
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptPublicationOperation {
    AddVersion,
    ReplaceVersions,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptPublicationEvent {
    RolloutBodyCloned {
        versions: usize,
        content_bytes: usize,
    },
    CallerVersionCloned {
        content_bytes: usize,
    },
    StoreSnapshotCloned {
        rollouts: usize,
        name_bytes: usize,
    },
    PublicationNameCloned {
        operation: PromptPublicationOperation,
        name_bytes: usize,
    },
    PublicationAttempt {
        operation: PromptPublicationOperation,
    },
    PublicationRetry {
        operation: PromptPublicationOperation,
    },
}

#[cfg(test)]
type PromptPublicationHook = Box<dyn FnMut(PromptPublicationEvent)>;

#[cfg(test)]
std::thread_local! {
    static PROMPT_PUBLICATION_HOOK: std::cell::RefCell<Option<PromptPublicationHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct PromptPublicationProbe {
    previous: Option<PromptPublicationHook>,
    _current_thread_only: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl PromptPublicationProbe {
    fn install_for_current_thread(hook: impl FnMut(PromptPublicationEvent) + 'static) -> Self {
        let previous = PROMPT_PUBLICATION_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
        Self {
            previous,
            _current_thread_only: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
impl Drop for PromptPublicationProbe {
    fn drop(&mut self) {
        let previous = self.previous.take();
        PROMPT_PUBLICATION_HOOK.with(|slot| {
            let _ = slot.replace(previous);
        });
    }
}

#[cfg(test)]
fn run_prompt_publication_hook(event: PromptPublicationEvent) {
    PROMPT_PUBLICATION_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(event);
        }
    });
}

#[cfg(test)]
std::thread_local! {
    static PROMPT_DRAW_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static PROMPT_UNIT_OBSERVATION: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
struct PromptDrawProbe {
    previous_draw: Option<u64>,
    previous_unit_bits: Option<u64>,
    _current_thread_only: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl PromptDrawProbe {
    fn install_for_current_thread(draw: u64) -> Self {
        let previous_draw = PROMPT_DRAW_OVERRIDE.with(|slot| slot.replace(Some(draw)));
        let previous_unit_bits = PROMPT_UNIT_OBSERVATION.with(|slot| slot.replace(None));
        Self {
            previous_draw,
            previous_unit_bits,
            _current_thread_only: std::marker::PhantomData,
        }
    }

    fn observed_unit(&self) -> Option<f64> {
        PROMPT_UNIT_OBSERVATION.with(|slot| slot.get().map(f64::from_bits))
    }
}

#[cfg(test)]
impl Drop for PromptDrawProbe {
    fn drop(&mut self) {
        PROMPT_DRAW_OVERRIDE.with(|slot| slot.set(self.previous_draw));
        PROMPT_UNIT_OBSERVATION.with(|slot| slot.set(self.previous_unit_bits));
    }
}

// --- Store ---

type PromptRolloutSnapshot = std::sync::Arc<[WeightedPromptVersion]>;
type PromptStoreSnapshot = std::sync::Arc<HashMap<String, PromptRolloutSnapshot>>;

fn exact_weight_units(weight: f64) -> BigUint {
    debug_assert!(weight.is_finite() && weight >= 0.0);
    let bits = weight.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as usize;
    let fraction = bits & ((1u64 << 52) - 1);
    if exponent == 0 {
        BigUint::from(fraction)
    } else {
        BigUint::from((1u64 << 52) | fraction) << (exponent - 1)
    }
}

fn exact_rollout_total<'a>(weights: impl IntoIterator<Item = &'a f64>) -> Result<BigUint, f64> {
    let maximum = exact_weight_units(f64::MAX);
    let mut exact = BigUint::default();
    for weight in weights {
        exact += exact_weight_units(*weight);
        if exact > maximum {
            return Err(f64::INFINITY);
        }
    }
    if exact == BigUint::default() {
        Err(0.0)
    } else {
        Ok(exact)
    }
}

fn clone_rollout_for_publication(
    versions: Option<&PromptRolloutSnapshot>,
) -> Vec<WeightedPromptVersion> {
    versions
        .map(|versions| {
            #[cfg(test)]
            run_prompt_publication_hook(PromptPublicationEvent::RolloutBodyCloned {
                versions: versions.len(),
                content_bytes: versions.iter().fold(0usize, |bytes, version| {
                    bytes.saturating_add(version.content.len())
                }),
            });
            versions.to_vec()
        })
        .unwrap_or_default()
}

fn clone_store_for_publication(
    current: &PromptStoreSnapshot,
) -> HashMap<String, PromptRolloutSnapshot> {
    #[cfg(test)]
    run_prompt_publication_hook(PromptPublicationEvent::StoreSnapshotCloned {
        rollouts: current.len(),
        name_bytes: current
            .keys()
            .fold(0usize, |bytes, name| bytes.saturating_add(name.len())),
    });
    current.as_ref().clone()
}

fn reject_duplicate_version(
    name: &str,
    versions: &[WeightedPromptVersion],
    version: u32,
) -> Result<(), PromptVersionError> {
    if versions.iter().any(|existing| existing.version == version) {
        return Err(PromptVersionError::DuplicateVersion {
            name: name.to_string(),
            version,
        });
    }
    Ok(())
}

fn record_retired_snapshot_drop(retired: &PromptStoreSnapshot) {
    #[cfg(test)]
    run_prompt_callsite_hook(PromptCallsiteEvent::RetiredSnapshotDrop {
        versions: retired.values().fold(0usize, |count, versions| {
            count.saturating_add(versions.len())
        }),
    });
    #[cfg(not(test))]
    let _ = retired;
}

/// Thread-safe store for versioned prompt templates.
pub struct WeightedPromptStore {
    // Readers take only `versions`. Writers acquire `publication` before the
    // brief `versions` pointer swap, so fallback preparation cannot block
    // request-path snapshot reads or race another publication.
    versions: Mutex<PromptStoreSnapshot>,
    publication: Mutex<()>,
}

impl WeightedPromptStore {
    /// Create an empty prompt store.
    pub fn new() -> Self {
        Self {
            versions: Mutex::new(std::sync::Arc::new(HashMap::new())),
            publication: Mutex::new(()),
        }
    }

    fn snapshot(&self) -> PromptStoreSnapshot {
        let current = self.versions.lock();
        std::sync::Arc::clone(&current)
    }

    fn replace_snapshot_if_current(
        &self,
        expected: &PromptStoreSnapshot,
        replacement: PromptStoreSnapshot,
    ) -> Option<PromptStoreSnapshot> {
        let publication = self.publication.lock();
        let mut current = self.versions.lock();
        if !std::sync::Arc::ptr_eq(expected, &current) {
            drop(current);
            drop(publication);
            drop(replacement);
            return None;
        }
        let retired = std::mem::replace(&mut *current, replacement);
        drop(current);
        drop(publication);
        Some(retired)
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
        let current = self.snapshot();
        let mut stored = clone_rollout_for_publication(current.get(name));
        reject_duplicate_version(name, &stored, version.version)?;
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::CallerVersionCloned {
            content_bytes: version.content.len(),
        });
        stored.push(version.clone());
        stored.sort_by_key(|version| version.version);

        let mut replacement = clone_store_for_publication(&current);
        let stored: PromptRolloutSnapshot = stored.into();
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationNameCloned {
            operation: PromptPublicationOperation::AddVersion,
            name_bytes: name.len(),
        });
        replacement.insert(name.to_string(), stored);
        let replacement = std::sync::Arc::new(replacement);
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationAttempt {
            operation: PromptPublicationOperation::AddVersion,
        });
        if let Some(retired) = self.replace_snapshot_if_current(&current, replacement) {
            drop(retired);
            drop(current);
            return Ok(());
        }

        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationRetry {
            operation: PromptPublicationOperation::AddVersion,
        });
        let publication = self.publication.lock();
        let current = self.snapshot();
        let mut stored = clone_rollout_for_publication(current.get(name));
        reject_duplicate_version(name, &stored, version.version)?;
        stored.push(version);
        stored.sort_by_key(|version| version.version);
        let mut replacement = clone_store_for_publication(&current);
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationNameCloned {
            operation: PromptPublicationOperation::AddVersion,
            name_bytes: name.len(),
        });
        replacement.insert(name.to_string(), stored.into());
        let retired = {
            let mut live = self.versions.lock();
            debug_assert!(std::sync::Arc::ptr_eq(&current, &live));
            std::mem::replace(&mut *live, std::sync::Arc::new(replacement))
        };
        drop(publication);
        drop(retired);
        drop(current);
        Ok(())
    }

    /// Atomically replace one rollout with a validated, canonical snapshot.
    ///
    /// Every member is validated before the live store is locked for the
    /// single publication step. Zero-weight members are valid when the
    /// complete rollout still has a finite, positive aggregate weight.
    pub fn replace_versions(
        &self,
        name: &str,
        mut versions: Vec<WeightedPromptVersion>,
    ) -> Result<(), PromptVersionError> {
        if name.trim().is_empty() {
            return Err(PromptVersionError::EmptyName);
        }

        for version in &versions {
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
                    version_name: version.name.clone(),
                });
            }
        }

        versions.sort_by_key(|version| version.version);
        for duplicate in versions.windows(2) {
            if duplicate[0].version == duplicate[1].version {
                return Err(PromptVersionError::DuplicateVersion {
                    name: name.to_string(),
                    version: duplicate[0].version,
                });
            }
        }

        exact_rollout_total(versions.iter().map(|version| &version.weight))
            .map_err(|total| PromptVersionError::InvalidTotalWeight { total })?;

        let rollout: PromptRolloutSnapshot = versions.into();
        let current = self.snapshot();
        let mut replacement = clone_store_for_publication(&current);
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationNameCloned {
            operation: PromptPublicationOperation::ReplaceVersions,
            name_bytes: name.len(),
        });
        replacement.insert(name.to_string(), std::sync::Arc::clone(&rollout));
        let replacement = std::sync::Arc::new(replacement);
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationAttempt {
            operation: PromptPublicationOperation::ReplaceVersions,
        });
        if let Some(retired) = self.replace_snapshot_if_current(&current, replacement) {
            record_retired_snapshot_drop(&retired);
            drop(retired);
            drop(current);
            return Ok(());
        }

        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationRetry {
            operation: PromptPublicationOperation::ReplaceVersions,
        });
        let publication = self.publication.lock();
        let current = self.snapshot();
        let mut replacement = clone_store_for_publication(&current);
        #[cfg(test)]
        run_prompt_publication_hook(PromptPublicationEvent::PublicationNameCloned {
            operation: PromptPublicationOperation::ReplaceVersions,
            name_bytes: name.len(),
        });
        replacement.insert(name.to_string(), rollout);
        let retired = {
            let mut live = self.versions.lock();
            debug_assert!(std::sync::Arc::ptr_eq(&current, &live));
            std::mem::replace(&mut *live, std::sync::Arc::new(replacement))
        };
        drop(publication);
        record_retired_snapshot_drop(&retired);
        drop(retired);
        drop(current);
        Ok(())
    }

    /// Return the version with the highest version number for the given name.
    /// Returns `None` if no versions exist for that name.
    pub fn get_latest(&self, name: &str) -> Option<WeightedPromptVersion> {
        self.snapshot()
            .get(name)
            .and_then(|vs| vs.iter().max_by_key(|v| v.version).cloned())
    }

    /// Select a version by stable weighted cohort assignment (A/B split).
    ///
    /// Returns `None` when no rollout exists or its aggregate weight is zero
    /// or mathematically exceeds the largest finite `f64`.
    /// The same `(name, cohort, salt)` always selects the same version, so
    /// concurrent requests do not correlate on wall-clock state and a caller
    /// remains in one experiment cohort.
    pub fn select_for_cohort(
        &self,
        name: &str,
        cohort: &str,
        salt: &str,
    ) -> Option<WeightedPromptVersion> {
        self.select_for_cohort_typed(name, cohort, salt).ok()
    }

    /// Select a version by stable weighted cohort assignment with typed
    /// missing-rollout and invalid-total errors.
    pub fn select_for_cohort_typed(
        &self,
        name: &str,
        cohort: &str,
        salt: &str,
    ) -> Result<WeightedPromptVersion, PromptSelectionError> {
        let snapshot = self.snapshot();
        #[cfg(test)]
        run_prompt_callsite_hook(PromptCallsiteEvent::RolloutLookupHash {
            name_bytes: name.len(),
        });
        let vs = snapshot
            .get(name)
            .ok_or_else(|| PromptSelectionError::MissingRollout {
                name: name.to_string(),
            })?;

        let total =
            exact_rollout_total(vs.iter().map(|version| &version.weight)).map_err(|total| {
                PromptSelectionError::InvalidTotalWeight {
                    name: name.to_string(),
                    total,
                }
            })?;

        #[cfg(test)]
        run_prompt_callsite_hook(PromptCallsiteEvent::CohortHash {
            name_bytes: name.len(),
            cohort_bytes: cohort.len(),
            salt_bytes: salt.len(),
        });
        let mut digest = Sha256::new();
        for component in [name.as_bytes(), cohort.as_bytes(), salt.as_bytes()] {
            digest.update((component.len() as u64).to_be_bytes());
            digest.update(component);
        }
        let hash = digest.finalize();
        let draw = u64::from_be_bytes(hash[..8].try_into().unwrap_or_default());
        #[cfg(test)]
        let draw = PROMPT_DRAW_OVERRIDE.with(|slot| slot.get().unwrap_or(draw));
        #[cfg(test)]
        let unit = ((draw >> 11) as f64) / 9_007_199_254_740_992.0;
        #[cfg(test)]
        PROMPT_UNIT_OBSERVATION.with(|slot| slot.set(Some(unit.to_bits())));
        let pick = BigUint::from(draw) * &total;

        let mut cumulative = BigUint::default();
        for v in vs.iter() {
            cumulative += exact_weight_units(v.weight);
            if pick < (&cumulative << 64usize) {
                #[cfg(test)]
                run_prompt_callsite_hook(PromptCallsiteEvent::SelectedContentClone {
                    content_bytes: v.content.len(),
                });
                return Ok(v.clone());
            }
        }
        #[cfg(test)]
        if let Some(version) = vs.iter().rev().find(|version| version.weight > 0.0) {
            run_prompt_callsite_hook(PromptCallsiteEvent::SelectedContentClone {
                content_bytes: version.content.len(),
            });
        }
        vs.iter()
            .rev()
            .find(|version| version.weight > 0.0)
            .cloned()
            .ok_or_else(|| PromptSelectionError::InvalidTotalWeight {
                name: name.to_string(),
                total: 0.0,
            })
    }

    /// Return all versions stored under `name`, sorted by version number ascending.
    pub fn list_versions(&self, name: &str) -> Vec<WeightedPromptVersion> {
        let snapshot = self.snapshot();
        let mut vs = snapshot
            .get(name)
            .map(|versions| versions.to_vec())
            .unwrap_or_default();
        vs.sort_by_key(|v| v.version);
        vs
    }

    /// Return all prompt names stored in this store.
    pub fn list_names(&self) -> Vec<String> {
        let snapshot = self.snapshot();
        let mut names: Vec<String> = snapshot.keys().cloned().collect();
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

    fn rollout_batch(name: &str, versions: &[(u32, f64)]) -> Vec<WeightedPromptVersion> {
        versions
            .iter()
            .map(|(version, weight)| pv(name, *version, *weight))
            .collect()
    }

    fn rollout_fingerprint(
        store: &WeightedPromptStore,
        name: &str,
    ) -> Vec<(String, u32, String, u64)> {
        store
            .list_versions(name)
            .into_iter()
            .map(|version| {
                (
                    version.name,
                    version.version,
                    version.content,
                    version.weight.to_bits(),
                )
            })
            .collect()
    }

    type RolloutFingerprint = Vec<(String, u32, String, u64)>;
    type WholeStoreFingerprint = Vec<(String, RolloutFingerprint)>;

    fn whole_store_fingerprint(store: &WeightedPromptStore) -> WholeStoreFingerprint {
        store
            .list_names()
            .into_iter()
            .map(|name| {
                let rollout = rollout_fingerprint(store, &name);
                (name, rollout)
            })
            .collect()
    }

    enum ContendedWriterEvent {
        Publication(PromptPublicationEvent),
        Finished(Result<(), PromptVersionError>),
    }

    struct ContentionTranscript {
        events: Vec<PromptPublicationEvent>,
        forced_conflicts: usize,
        successful_racers: WholeStoreFingerprint,
        result: Option<Result<(), PromptVersionError>>,
        failure: Option<String>,
    }

    fn drive_forced_publication_conflicts(
        store: &std::sync::Arc<WeightedPromptStore>,
        target: &str,
        expected_live: &[(String, u32, String, u64)],
        operation: PromptPublicationOperation,
        event_rx: std::sync::mpsc::Receiver<ContendedWriterEvent>,
        release_tx: std::sync::mpsc::Sender<()>,
    ) -> ContentionTranscript {
        use std::time::{Duration, Instant};

        const CONFLICTS_OFFERED_TO_OPTIMISTIC_WRITER: usize = 3;
        const FAIL_SAFE_DEADLINE: Duration = Duration::from_secs(10);
        const MAX_TRANSCRIPT_EVENTS: usize = 128;

        let operation_label = match operation {
            PromptPublicationOperation::AddVersion => "add",
            PromptPublicationOperation::ReplaceVersions => "replace",
        };
        let mut events = Vec::new();
        let mut forced_conflicts = 0usize;
        let mut successful_racers = Vec::new();
        let mut result = None;
        let mut failure = None;
        let deadline = Instant::now() + FAIL_SAFE_DEADLINE;

        while result.is_none() && failure.is_none() {
            if events.len() >= MAX_TRANSCRIPT_EVENTS {
                failure = Some(format!(
                    "writer exceeded the {MAX_TRANSCRIPT_EVENTS}-event transcript bound"
                ));
                let _ = release_tx.send(());
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                failure = Some("writer exceeded the single absolute deadline".to_string());
                let _ = release_tx.send(());
                break;
            }
            match event_rx.recv_timeout(remaining) {
                Ok(ContendedWriterEvent::Publication(event)) => {
                    let is_target_attempt = matches!(
                        &event,
                        PromptPublicationEvent::PublicationAttempt {
                            operation: observed,
                        } if *observed == operation
                    );
                    events.push(event);
                    if !is_target_attempt {
                        continue;
                    }

                    let before = rollout_fingerprint(store, target);
                    if before != expected_live {
                        failure = Some(format!(
                            "reader saw a partial target before publication: {before:?}"
                        ));
                    }
                    if failure.is_none()
                        && forced_conflicts < CONFLICTS_OFFERED_TO_OPTIMISTIC_WRITER
                    {
                        let racer_name = format!("e3-{operation_label}-racer-{forced_conflicts}");
                        let competitor =
                            store.replace_versions(&racer_name, vec![pv(&racer_name, 1, 1.0)]);
                        if let Err(error) = competitor {
                            failure = Some(format!(
                                "competing publication {forced_conflicts} failed: {error:?}"
                            ));
                        } else {
                            successful_racers.push((
                                racer_name.clone(),
                                vec![(racer_name, 1, "content-v1".to_string(), 1.0f64.to_bits())],
                            ));
                            forced_conflicts += 1;
                        }
                    }
                    let after = rollout_fingerprint(store, target);
                    if failure.is_none() && after != expected_live {
                        failure = Some(format!(
                            "reader saw a partial target during publication: {after:?}"
                        ));
                    }
                    let _ = release_tx.send(());
                }
                Ok(ContendedWriterEvent::Finished(writer_result)) => {
                    result = Some(writer_result);
                }
                Err(error) => {
                    failure = Some(format!("writer rendezvous failed: {error}"));
                    let _ = release_tx.send(());
                }
            }
        }
        drop(release_tx);

        ContentionTranscript {
            events,
            forced_conflicts,
            successful_racers,
            result,
            failure,
        }
    }

    #[test]
    fn rollout_batch_accepts_zero_weight_when_total_is_positive_control() {
        let store = WeightedPromptStore::new();
        let result =
            store.replace_versions("bounded", rollout_batch("bounded", &[(1, 0.0), (2, 1.0)]));
        assert!(result.is_ok(), "[0, 1] rollout must be valid: {result:?}");

        let selection = store.select_for_cohort_typed("bounded", "customer-1", "rollout-1");
        match selection {
            Ok(version) => assert_eq!(version.version, 2),
            Err(error) => panic!("valid rollout was not selectable: {error:?}"),
        }
    }

    #[test]
    fn rollout_batch_rejects_invalid_totals_transactionally() {
        let store = WeightedPromptStore::new();
        let installed = store.replace_versions("atomic", rollout_batch("atomic", &[(9, 1.0)]));
        assert!(
            installed.is_ok(),
            "control rollout must install: {installed:?}"
        );
        let live_before = rollout_fingerprint(&store, "atomic");

        let zero = store.replace_versions("atomic", rollout_batch("atomic", &[(1, 0.0), (2, 0.0)]));
        match zero {
            Err(PromptVersionError::InvalidTotalWeight { total }) => {
                assert_eq!(total, 0.0)
            }
            other => panic!("zero total returned the wrong result: {other:?}"),
        }
        assert_eq!(
            rollout_fingerprint(&store, "atomic"),
            live_before,
            "zero-total replacement mutated the live snapshot"
        );

        let overflow = store.replace_versions(
            "atomic",
            rollout_batch("atomic", &[(1, f64::MAX), (2, f64::MAX)]),
        );
        match overflow {
            Err(PromptVersionError::InvalidTotalWeight { total }) => {
                assert_eq!(total, f64::INFINITY)
            }
            other => panic!("non-finite aggregate returned the wrong result: {other:?}"),
        }
        assert_eq!(
            rollout_fingerprint(&store, "atomic"),
            live_before,
            "non-finite replacement mutated the live snapshot"
        );
    }

    #[test]
    fn rollout_batch_validates_every_member_transactionally() {
        fn assert_unchanged(
            store: &WeightedPromptStore,
            expected: &[(String, u32, String, u64)],
            label: &str,
        ) {
            assert_eq!(
                rollout_fingerprint(store, "atomic"),
                expected,
                "{label} refusal mutated the live snapshot"
            );
        }

        let store = WeightedPromptStore::new();
        let installed = store.replace_versions("atomic", rollout_batch("atomic", &[(9, 1.0)]));
        assert!(
            installed.is_ok(),
            "control rollout must install: {installed:?}"
        );
        let live_before = rollout_fingerprint(&store, "atomic");

        let empty = store.replace_versions("atomic", Vec::new());
        assert!(matches!(
            empty,
            Err(PromptVersionError::InvalidTotalWeight { total }) if total == 0.0
        ));
        assert_unchanged(&store, &live_before, "empty batch");

        let empty_name = store.replace_versions(
            "atomic",
            vec![
                pv("atomic", 1, 0.5),
                WeightedPromptVersion {
                    name: String::new(),
                    version: 2,
                    content: "empty-name".to_string(),
                    weight: 0.5,
                },
            ],
        );
        assert!(matches!(empty_name, Err(PromptVersionError::EmptyName)));
        assert_unchanged(&store, &live_before, "empty member name");

        let mismatch =
            store.replace_versions("atomic", vec![pv("atomic", 1, 0.5), pv("other", 2, 0.5)]);
        assert!(matches!(
            mismatch,
            Err(PromptVersionError::NameMismatch { ref key, ref version_name })
                if key == "atomic" && version_name == "other"
        ));
        assert_unchanged(&store, &live_before, "name mismatch");

        let duplicate =
            store.replace_versions("atomic", rollout_batch("atomic", &[(1, 0.5), (1, 0.5)]));
        assert!(matches!(
            duplicate,
            Err(PromptVersionError::DuplicateVersion { ref name, version })
                if name == "atomic" && version == 1
        ));
        assert_unchanged(&store, &live_before, "duplicate version");

        let zero_version = store.replace_versions(
            "atomic",
            vec![
                pv("atomic", 1, 0.5),
                WeightedPromptVersion {
                    name: "atomic".to_string(),
                    version: 0,
                    content: "zero-version".to_string(),
                    weight: 0.5,
                },
            ],
        );
        assert!(matches!(zero_version, Err(PromptVersionError::ZeroVersion)));
        assert_unchanged(&store, &live_before, "zero version");

        let nan_weight = store.replace_versions(
            "atomic",
            vec![
                pv("atomic", 1, 0.5),
                WeightedPromptVersion {
                    name: "atomic".to_string(),
                    version: 2,
                    content: "nan-weight".to_string(),
                    weight: f64::NAN,
                },
            ],
        );
        assert!(matches!(
            nan_weight,
            Err(PromptVersionError::InvalidWeight { weight }) if weight.is_nan()
        ));
        assert_unchanged(&store, &live_before, "NaN member weight");

        let negative_weight = store.replace_versions(
            "atomic",
            vec![
                pv("atomic", 1, 1.0),
                WeightedPromptVersion {
                    name: "atomic".to_string(),
                    version: 2,
                    content: "negative-weight".to_string(),
                    weight: -0.5,
                },
            ],
        );
        assert!(matches!(
            negative_weight,
            Err(PromptVersionError::InvalidWeight { weight }) if weight == -0.5
        ));
        assert_unchanged(&store, &live_before, "negative member weight");
    }

    #[test]
    fn rollout_batch_publication_exposes_only_complete_snapshots() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Barrier,
        };

        const SNAPSHOT_VERSIONS: u32 = 64;
        const REPLACEMENTS: usize = 129;
        const OLD_CONTENT: &str = "old snapshot prompt body";
        const NEW_CONTENT: &str = "new snapshot prompt body";
        const OLD_WEIGHT: f64 = 1.0;
        const NEW_WEIGHT: f64 = 3.0;

        struct SignalDone(Arc<AtomicBool>);

        impl Drop for SignalDone {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        fn complete_snapshot(first: u32, content: &str, weight: f64) -> Vec<WeightedPromptVersion> {
            (first..first + SNAPSHOT_VERSIONS)
                .map(|version| WeightedPromptVersion {
                    name: "atomic".to_string(),
                    version,
                    content: content.to_string(),
                    weight,
                })
                .collect()
        }

        fn expected_fingerprint(
            first: u32,
            content: &str,
            weight: f64,
        ) -> Vec<(String, u32, String, u64)> {
            (first..first + SNAPSHOT_VERSIONS)
                .map(|version| {
                    (
                        "atomic".to_string(),
                        version,
                        content.to_string(),
                        weight.to_bits(),
                    )
                })
                .collect()
        }

        let store = Arc::new(WeightedPromptStore::new());
        let old_fingerprint = expected_fingerprint(1_000, OLD_CONTENT, OLD_WEIGHT);
        let new_fingerprint = expected_fingerprint(2_000, NEW_CONTENT, NEW_WEIGHT);
        let installed =
            store.replace_versions("atomic", complete_snapshot(1_000, OLD_CONTENT, OLD_WEIGHT));
        assert!(
            installed.is_ok(),
            "old snapshot must install: {installed:?}"
        );

        let barrier = Arc::new(Barrier::new(2));
        let done = Arc::new(AtomicBool::new(false));
        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer_done = Arc::clone(&done);
        let writer = std::thread::spawn(move || {
            let _signal_done = SignalDone(writer_done);
            writer_barrier.wait();
            let mut failure = None;
            for replacement in 0..REPLACEMENTS {
                let (first, content, weight) = if replacement % 2 == 0 {
                    (2_000, NEW_CONTENT, NEW_WEIGHT)
                } else {
                    (1_000, OLD_CONTENT, OLD_WEIGHT)
                };
                let result = writer_store
                    .replace_versions("atomic", complete_snapshot(first, content, weight));
                if let Err(error) = result {
                    failure = Some(format!("replacement {replacement} failed: {error:?}"));
                    break;
                }
                std::thread::yield_now();
            }
            failure
        });

        barrier.wait();
        let mut reads = 0usize;
        let mut partial = None;
        while !done.load(Ordering::Acquire) || reads < 2_048 {
            let observed = rollout_fingerprint(&store, "atomic");
            if observed != old_fingerprint && observed != new_fingerprint {
                partial = Some(observed);
                break;
            }
            reads += 1;
        }
        let writer_failure = match writer.join() {
            Ok(failure) => failure,
            Err(_) => Some("replacement thread panicked".to_string()),
        };
        assert!(
            partial.is_none() && writer_failure.is_none(),
            "reader observed partial publication: partial={partial:?}, writer={writer_failure:?}"
        );
        assert_eq!(
            rollout_fingerprint(&store, "atomic"),
            new_fingerprint,
            "final replacement did not publish the complete new snapshot"
        );
    }

    #[test]
    fn add_version_contention_bounds_deep_clones_and_falls_back() {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc, Arc,
        };

        const INSTALLED_VERSIONS: u32 = 64;
        const CONTENT_BYTES: usize = 32 * 1024;

        let store = Arc::new(WeightedPromptStore::new());
        let target = "contended-add";
        let installed = (1..=INSTALLED_VERSIONS)
            .map(|version| WeightedPromptVersion {
                name: target.to_string(),
                version,
                content: "i".repeat(CONTENT_BYTES),
                weight: 1.0,
            })
            .collect::<Vec<_>>();
        let setup = store.replace_versions(target, installed);
        assert!(setup.is_ok(), "contention control must install: {setup:?}");
        let live_before = rollout_fingerprint(&store, target);

        let added = WeightedPromptVersion {
            name: target.to_string(),
            version: INSTALLED_VERSIONS + 1,
            content: "n".repeat(CONTENT_BYTES),
            weight: 1.0,
        };
        let mut expected_after = live_before.clone();
        expected_after.push((
            target.to_string(),
            INSTALLED_VERSIONS + 1,
            "n".repeat(CONTENT_BYTES),
            1.0f64.to_bits(),
        ));

        let (event_tx, event_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let fallback_reader_lock_checks = Arc::new(AtomicUsize::new(0));
        let all_fallback_reader_locks_available = Arc::new(AtomicBool::new(true));
        let worker_store = Arc::clone(&store);
        let hook_store = Arc::clone(&worker_store);
        let hook_fallback_reader_lock_checks = Arc::clone(&fallback_reader_lock_checks);
        let hook_all_fallback_reader_locks_available =
            Arc::clone(&all_fallback_reader_locks_available);
        let worker = std::thread::spawn(move || {
            let publication_tx = event_tx.clone();
            let mut in_fallback = false;
            let _probe = PromptPublicationProbe::install_for_current_thread(move |event| {
                if matches!(
                    &event,
                    PromptPublicationEvent::PublicationRetry {
                        operation: PromptPublicationOperation::AddVersion,
                    }
                ) {
                    in_fallback = true;
                }
                let observes_fallback_preparation = in_fallback
                    && matches!(
                        &event,
                        PromptPublicationEvent::RolloutBodyCloned { .. }
                            | PromptPublicationEvent::StoreSnapshotCloned { .. }
                            | PromptPublicationEvent::PublicationNameCloned {
                                operation: PromptPublicationOperation::AddVersion,
                                ..
                            }
                    );
                if observes_fallback_preparation {
                    hook_fallback_reader_lock_checks.fetch_add(1, Ordering::SeqCst);
                    if hook_store.versions.try_lock().is_none() {
                        hook_all_fallback_reader_locks_available.store(false, Ordering::SeqCst);
                    }
                }
                let wait = matches!(
                    &event,
                    PromptPublicationEvent::PublicationAttempt {
                        operation: PromptPublicationOperation::AddVersion,
                    }
                );
                if publication_tx
                    .send(ContendedWriterEvent::Publication(event))
                    .is_ok()
                    && wait
                {
                    let _ = release_rx.recv();
                }
            });
            let result = worker_store.add_version(target, added);
            let _ = event_tx.send(ContendedWriterEvent::Finished(result));
        });

        let transcript = drive_forced_publication_conflicts(
            &store,
            target,
            &live_before,
            PromptPublicationOperation::AddVersion,
            event_rx,
            release_tx,
        );
        let completion_signaled = transcript.result.is_some();
        let worker_joined = if completion_signaled {
            worker.join().is_ok()
        } else {
            drop(worker);
            false
        };
        let fallback_reader_lock_checks = fallback_reader_lock_checks.load(Ordering::SeqCst);
        let all_fallback_reader_locks_available =
            all_fallback_reader_locks_available.load(Ordering::SeqCst);
        let rollout_clone_observations = transcript
            .events
            .iter()
            .filter_map(|event| match event {
                PromptPublicationEvent::RolloutBodyCloned {
                    versions,
                    content_bytes,
                } => Some((*versions, *content_bytes)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let caller_clone_bytes = transcript
            .events
            .iter()
            .filter_map(|event| match event {
                PromptPublicationEvent::CallerVersionCloned { content_bytes } => {
                    Some(*content_bytes)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let snapshot_clone_observations = transcript
            .events
            .iter()
            .filter_map(|event| match event {
                PromptPublicationEvent::StoreSnapshotCloned {
                    rollouts,
                    name_bytes,
                } => Some((*rollouts, *name_bytes)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let name_clone_bytes = transcript
            .events
            .iter()
            .filter_map(|event| match event {
                PromptPublicationEvent::PublicationNameCloned {
                    operation: PromptPublicationOperation::AddVersion,
                    name_bytes,
                } => Some(*name_bytes),
                _ => None,
            })
            .collect::<Vec<_>>();
        let retries = transcript
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    PromptPublicationEvent::PublicationRetry {
                        operation: PromptPublicationOperation::AddVersion,
                    }
                )
            })
            .count();
        let attempts = transcript
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    PromptPublicationEvent::PublicationAttempt {
                        operation: PromptPublicationOperation::AddVersion,
                    }
                )
            })
            .count();
        let clone_payloads_valid = rollout_clone_observations.iter().all(|(versions, bytes)| {
            *versions == INSTALLED_VERSIONS as usize
                && *bytes == INSTALLED_VERSIONS as usize * CONTENT_BYTES
        }) && caller_clone_bytes
            .iter()
            .all(|bytes| *bytes == CONTENT_BYTES)
            && snapshot_clone_observations
                .iter()
                .all(|(rollouts, name_bytes)| *rollouts >= 1 && *name_bytes >= target.len())
            && name_clone_bytes.iter().all(|bytes| *bytes == target.len());
        let clone_accounting_non_vacuous = !rollout_clone_observations.is_empty()
            && !caller_clone_bytes.is_empty()
            && !snapshot_clone_observations.is_empty()
            && !name_clone_bytes.is_empty();
        let mut expected_whole_store = transcript.successful_racers.clone();
        expected_whole_store.push((target.to_string(), expected_after.clone()));
        expected_whole_store.sort_by(|left, right| left.0.cmp(&right.0));
        let final_whole_store = whole_store_fingerprint(&store);

        assert!(
            completion_signaled
                && worker_joined
                && transcript.failure.is_none()
                && matches!(&transcript.result, Some(Ok(())))
                && transcript.forced_conflicts == 1
                && transcript.successful_racers.len() == 1
                && (1..=2).contains(&attempts)
                && rollout_clone_observations.len() <= 2
                && caller_clone_bytes.len() <= 2
                && snapshot_clone_observations.len() <= 2
                && name_clone_bytes.len() <= 2
                && retries == 1
                && fallback_reader_lock_checks == 3
                && all_fallback_reader_locks_available
                && clone_accounting_non_vacuous
                && clone_payloads_valid
                && final_whole_store == expected_whole_store,
            "add_version did not preserve racers or bound optimistic work: completion={completion_signaled}, joined={worker_joined}, failure={:?}, result={:?}, forced={}, racers={:?}, attempts={attempts}, rollout_clones={rollout_clone_observations:?}, caller_clones={caller_clone_bytes:?}, snapshot_clones={snapshot_clone_observations:?}, name_clones={name_clone_bytes:?}, retries={retries}, fallback_reader_lock_checks={fallback_reader_lock_checks}, all_fallback_reader_locks_available={all_fallback_reader_locks_available}, clone_accounting={clone_accounting_non_vacuous}, payloads_valid={clone_payloads_valid}, final_store={final_whole_store:?}, expected_store={expected_whole_store:?}",
            transcript.failure,
            transcript.result,
            transcript.forced_conflicts,
            transcript.successful_racers
        );
    }

    #[test]
    fn replace_versions_contention_bounds_snapshot_clones_and_falls_back() {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc, Arc,
        };

        const SNAPSHOT_VERSIONS: u32 = 64;
        const CONTENT_BYTES: usize = 32 * 1024;
        const NAME_BYTES: usize = 64 * 1024;

        let store = Arc::new(WeightedPromptStore::new());
        let target = "t".repeat(NAME_BYTES);
        let installed = (1..=SNAPSHOT_VERSIONS)
            .map(|version| WeightedPromptVersion {
                name: target.clone(),
                version,
                content: "o".repeat(CONTENT_BYTES),
                weight: 1.0,
            })
            .collect::<Vec<_>>();
        let setup = store.replace_versions(&target, installed);
        assert!(setup.is_ok(), "contention control must install: {setup:?}");
        let live_before = rollout_fingerprint(&store, &target);

        let replacement = (1_001..=1_000 + SNAPSHOT_VERSIONS)
            .map(|version| WeightedPromptVersion {
                name: target.clone(),
                version,
                content: "r".repeat(CONTENT_BYTES),
                weight: 2.0,
            })
            .collect::<Vec<_>>();
        let expected_after = replacement
            .iter()
            .map(|version| {
                (
                    version.name.clone(),
                    version.version,
                    version.content.clone(),
                    version.weight.to_bits(),
                )
            })
            .collect::<Vec<_>>();

        let (event_tx, event_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let fallback_reader_lock_checks = Arc::new(AtomicUsize::new(0));
        let all_fallback_reader_locks_available = Arc::new(AtomicBool::new(true));
        let worker_store = Arc::clone(&store);
        let hook_store = Arc::clone(&worker_store);
        let hook_fallback_reader_lock_checks = Arc::clone(&fallback_reader_lock_checks);
        let hook_all_fallback_reader_locks_available =
            Arc::clone(&all_fallback_reader_locks_available);
        let worker_target = target.clone();
        let worker = std::thread::spawn(move || {
            let publication_tx = event_tx.clone();
            let mut in_fallback = false;
            let _probe = PromptPublicationProbe::install_for_current_thread(move |event| {
                if matches!(
                    &event,
                    PromptPublicationEvent::PublicationRetry {
                        operation: PromptPublicationOperation::ReplaceVersions,
                    }
                ) {
                    in_fallback = true;
                }
                let observes_fallback_preparation = in_fallback
                    && matches!(
                        &event,
                        PromptPublicationEvent::StoreSnapshotCloned { .. }
                            | PromptPublicationEvent::PublicationNameCloned {
                                operation: PromptPublicationOperation::ReplaceVersions,
                                ..
                            }
                    );
                if observes_fallback_preparation {
                    hook_fallback_reader_lock_checks.fetch_add(1, Ordering::SeqCst);
                    if hook_store.versions.try_lock().is_none() {
                        hook_all_fallback_reader_locks_available.store(false, Ordering::SeqCst);
                    }
                }
                let wait = matches!(
                    &event,
                    PromptPublicationEvent::PublicationAttempt {
                        operation: PromptPublicationOperation::ReplaceVersions,
                    }
                );
                if publication_tx
                    .send(ContendedWriterEvent::Publication(event))
                    .is_ok()
                    && wait
                {
                    let _ = release_rx.recv();
                }
            });
            let result = worker_store.replace_versions(&worker_target, replacement);
            let _ = event_tx.send(ContendedWriterEvent::Finished(result));
        });

        let transcript = drive_forced_publication_conflicts(
            &store,
            &target,
            &live_before,
            PromptPublicationOperation::ReplaceVersions,
            event_rx,
            release_tx,
        );
        let completion_signaled = transcript.result.is_some();
        let worker_joined = if completion_signaled {
            worker.join().is_ok()
        } else {
            drop(worker);
            false
        };
        let fallback_reader_lock_checks = fallback_reader_lock_checks.load(Ordering::SeqCst);
        let all_fallback_reader_locks_available =
            all_fallback_reader_locks_available.load(Ordering::SeqCst);
        let snapshot_clone_observations = transcript
            .events
            .iter()
            .filter_map(|event| match event {
                PromptPublicationEvent::StoreSnapshotCloned {
                    rollouts,
                    name_bytes,
                } => Some((*rollouts, *name_bytes)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let name_clone_bytes = transcript
            .events
            .iter()
            .filter_map(|event| match event {
                PromptPublicationEvent::PublicationNameCloned {
                    operation: PromptPublicationOperation::ReplaceVersions,
                    name_bytes,
                } => Some(*name_bytes),
                _ => None,
            })
            .collect::<Vec<_>>();
        let retries = transcript
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    PromptPublicationEvent::PublicationRetry {
                        operation: PromptPublicationOperation::ReplaceVersions,
                    }
                )
            })
            .count();
        let attempts = transcript
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    PromptPublicationEvent::PublicationAttempt {
                        operation: PromptPublicationOperation::ReplaceVersions,
                    }
                )
            })
            .count();
        let clone_payloads_valid = snapshot_clone_observations
            .iter()
            .all(|(rollouts, name_bytes)| *rollouts >= 1 && *name_bytes >= target.len())
            && name_clone_bytes.iter().all(|bytes| *bytes == target.len());
        let clone_accounting_non_vacuous =
            !snapshot_clone_observations.is_empty() && !name_clone_bytes.is_empty();
        let mut expected_whole_store = transcript.successful_racers.clone();
        expected_whole_store.push((target.clone(), expected_after.clone()));
        expected_whole_store.sort_by(|left, right| left.0.cmp(&right.0));
        let final_whole_store = whole_store_fingerprint(&store);

        assert!(
            completion_signaled
                && worker_joined
                && transcript.failure.is_none()
                && matches!(&transcript.result, Some(Ok(())))
                && transcript.forced_conflicts == 1
                && transcript.successful_racers.len() == 1
                && (1..=2).contains(&attempts)
                && snapshot_clone_observations.len() <= 2
                && name_clone_bytes.len() <= 2
                && retries == 1
                && fallback_reader_lock_checks == 2
                && all_fallback_reader_locks_available
                && clone_accounting_non_vacuous
                && clone_payloads_valid
                && final_whole_store == expected_whole_store,
            "replace_versions did not preserve racers or bound optimistic work: completion={completion_signaled}, joined={worker_joined}, failure={:?}, result={:?}, forced={}, racers={:?}, attempts={attempts}, snapshot_clones={snapshot_clone_observations:?}, name_clones={name_clone_bytes:?}, retries={retries}, fallback_reader_lock_checks={fallback_reader_lock_checks}, all_fallback_reader_locks_available={all_fallback_reader_locks_available}, clone_accounting={clone_accounting_non_vacuous}, payloads_valid={clone_payloads_valid}, final_store={final_whole_store:?}, expected_store={expected_whole_store:?}",
            transcript.failure,
            transcript.result,
            transcript.forced_conflicts,
            transcript.successful_racers
        );
    }

    #[test]
    fn rollout_selection_releases_global_lock_before_lookup_cohort_hash_and_content_clone() {
        use std::{
            sync::{mpsc, Arc},
            time::Duration,
        };

        const LARGE_INPUT_BYTES: usize = 1024 * 1024 + 1;
        const LARGE_CONTENT_BYTES: usize = 2 * 1024 * 1024 + 1;
        const PROBE_DEADLINE: Duration = Duration::from_secs(10);

        let store = Arc::new(WeightedPromptStore::new());
        let name = "n".repeat(LARGE_INPUT_BYTES);
        let cohort = "c".repeat(LARGE_INPUT_BYTES);
        let salt = "s".repeat(LARGE_INPUT_BYTES);
        let installed = store.replace_versions(
            &name,
            vec![WeightedPromptVersion {
                name: name.clone(),
                version: 1,
                content: "p".repeat(LARGE_CONTENT_BYTES),
                weight: 1.0,
            }],
        );
        assert!(installed.is_ok(), "large control rollout must install");

        let (event_tx, event_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::channel();
        let worker_store = Arc::clone(&store);
        let worker = std::thread::spawn(move || {
            let _probe = PromptCallsiteProbe::install_for_current_thread(move |event| {
                if event_tx.send(event).is_ok() {
                    let _ = release_rx.recv();
                }
            });
            worker_store.select_for_cohort_typed(&name, &cohort, &salt)
        });

        let mut observations = Vec::new();
        let mut receive_failure = None;
        for _ in 0..3 {
            match event_rx.recv_timeout(PROBE_DEADLINE) {
                Ok(event) => {
                    let global_lock_available = store.versions.try_lock().is_some();
                    observations.push((event, global_lock_available));
                    let _ = release_tx.send(());
                }
                Err(error) => {
                    receive_failure = Some(error.to_string());
                    let _ = release_tx.send(());
                    break;
                }
            }
        }
        drop(release_tx);
        let selection = worker.join();
        let expected_events = vec![
            PromptCallsiteEvent::RolloutLookupHash {
                name_bytes: LARGE_INPUT_BYTES,
            },
            PromptCallsiteEvent::CohortHash {
                name_bytes: LARGE_INPUT_BYTES,
                cohort_bytes: LARGE_INPUT_BYTES,
                salt_bytes: LARGE_INPUT_BYTES,
            },
            PromptCallsiteEvent::SelectedContentClone {
                content_bytes: LARGE_CONTENT_BYTES,
            },
        ];
        let observed_events = observations
            .iter()
            .map(|(event, _)| event.clone())
            .collect::<Vec<_>>();
        let every_unbounded_callsite_was_unlocked = observations
            .iter()
            .all(|(_, global_lock_available)| *global_lock_available);
        let selection_ok = matches!(
            &selection,
            Ok(Ok(version)) if version.content.len() == LARGE_CONTENT_BYTES
        );

        assert!(
            receive_failure.is_none()
                && observed_events == expected_events
                && every_unbounded_callsite_was_unlocked
                && selection_ok,
            "selection held the global rollout lock across unbounded work: receive={receive_failure:?}, events={observed_events:?}, locks={observations:?}, selection_ok={selection_ok}"
        );
    }

    #[test]
    fn rollout_replacement_releases_global_lock_before_retired_snapshot_drop() {
        use std::{
            sync::{mpsc, Arc},
            time::Duration,
        };

        const RETIRED_VERSIONS: u32 = 512;
        const RETIRED_CONTENT_BYTES: usize = 4 * 1024;
        const PROBE_DEADLINE: Duration = Duration::from_secs(10);

        let store = Arc::new(WeightedPromptStore::new());
        let retired = (1..=RETIRED_VERSIONS)
            .map(|version| WeightedPromptVersion {
                name: "retired".to_string(),
                version,
                content: "r".repeat(RETIRED_CONTENT_BYTES),
                weight: 1.0,
            })
            .collect::<Vec<_>>();
        let installed = store.replace_versions("retired", retired);
        assert!(installed.is_ok(), "retired control rollout must install");

        let replacement = vec![pv("retired", RETIRED_VERSIONS + 1, 1.0)];
        let (event_tx, event_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::channel();
        let worker_store = Arc::clone(&store);
        let worker = std::thread::spawn(move || {
            let _probe = PromptCallsiteProbe::install_for_current_thread(move |event| {
                if event_tx.send(event).is_ok() {
                    let _ = release_rx.recv();
                }
            });
            worker_store.replace_versions("retired", replacement)
        });

        let event = event_rx.recv_timeout(PROBE_DEADLINE);
        let global_lock_available = store.versions.try_lock().is_some();
        let _ = release_tx.send(());
        drop(release_tx);
        let replacement_result = worker.join();
        let event_ok = matches!(
            &event,
            Ok(PromptCallsiteEvent::RetiredSnapshotDrop { versions })
                if *versions == RETIRED_VERSIONS as usize
        );
        let replacement_ok = matches!(&replacement_result, Ok(Ok(())));

        assert!(
            event_ok && global_lock_available && replacement_ok,
            "retired snapshot dropped while the global rollout lock was held: event={event:?}, lock_available={global_lock_available}, replacement_ok={replacement_ok}"
        );
    }

    #[test]
    fn cohort_mapping_is_invariant_to_batch_input_order() {
        let forward = WeightedPromptStore::new();
        let forward_result = forward.replace_versions(
            "ordered",
            rollout_batch("ordered", &[(1, 1.0), (2, 3.0), (3, 6.0)]),
        );
        assert!(
            forward_result.is_ok(),
            "forward rollout must validate: {forward_result:?}"
        );
        let reversed = WeightedPromptStore::new();
        let reversed_result = reversed.replace_versions(
            "ordered",
            rollout_batch("ordered", &[(3, 6.0), (2, 3.0), (1, 1.0)]),
        );
        assert!(
            reversed_result.is_ok(),
            "reversed rollout must validate: {reversed_result:?}"
        );

        // Frozen independently from the implementation under test for the
        // canonical 1:3:6 rollout and the published length-prefixed SHA-256
        // cohort contract. Keep these as literal oracle values.
        const EXPECTED_SELECTIONS: [(&str, u32); 6] = [
            ("customer-4", 1),
            ("customer-8", 1),
            ("customer-0", 2),
            ("customer-3", 2),
            ("customer-1", 3),
            ("customer-2", 3),
        ];
        let oracle_failures = EXPECTED_SELECTIONS
            .into_iter()
            .filter_map(|(cohort, expected_version)| {
                match forward.select_for_cohort_typed("ordered", cohort, "rollout-1") {
                    Ok(version) if version.version == expected_version => None,
                    other => Some((cohort, expected_version, other)),
                }
            })
            .collect::<Vec<_>>();
        assert!(
            oracle_failures.is_empty(),
            "selector diverged from the independent canonical cohort oracle: {oracle_failures:?}"
        );

        let mut mismatches = Vec::new();
        for index in 0..4_096 {
            let cohort = format!("customer-{index}");
            let forward_version = forward.select_for_cohort_typed("ordered", &cohort, "rollout-1");
            let reversed_version =
                reversed.select_for_cohort_typed("ordered", &cohort, "rollout-1");
            match (forward_version, reversed_version) {
                (Ok(forward), Ok(reversed)) if forward.version == reversed.version => {}
                (forward, reversed) if mismatches.len() < 16 => {
                    mismatches.push((cohort, forward, reversed));
                }
                _ => {}
            }
        }

        assert!(
            mismatches.is_empty(),
            "canonical version ordering must make batch input order irrelevant: {mismatches:?}"
        );
    }

    #[test]
    fn typed_selection_distinguishes_missing_from_corrupt_total() {
        let store = WeightedPromptStore::new();
        let missing = store.select_for_cohort_typed("missing", "customer-1", "rollout-1");
        assert!(matches!(
            missing,
            Err(PromptSelectionError::MissingRollout { ref name }) if name == "missing"
        ));

        let first = store.add_version("corrupt", pv("corrupt", 1, 0.0));
        let second = store.add_version("corrupt", pv("corrupt", 2, 0.0));
        assert!(
            first.is_ok() && second.is_ok(),
            "compatibility builder must still permit zero-weight versions: first={first:?}, second={second:?}"
        );
        let corrupt = store.select_for_cohort_typed("corrupt", "customer-1", "rollout-1");
        assert!(matches!(
            corrupt,
            Err(PromptSelectionError::InvalidTotalWeight { ref name, .. }) if name == "corrupt"
        ));

        let first_max = store.add_version("nonfinite", pv("nonfinite", 1, f64::MAX));
        let second_max = store.add_version("nonfinite", pv("nonfinite", 2, f64::MAX));
        assert!(
            first_max.is_ok() && second_max.is_ok(),
            "compatibility builder setup failed: first={first_max:?}, second={second_max:?}"
        );
        let nonfinite = store.select_for_cohort_typed("nonfinite", "customer-1", "rollout-1");
        assert!(matches!(
            nonfinite,
            Err(PromptSelectionError::InvalidTotalWeight { ref name, .. }) if name == "nonfinite"
        ));
    }

    #[test]
    fn mathematical_weight_overflow_hidden_by_f64_rounding_is_rejected() {
        let store = WeightedPromptStore::new();
        let installed = store.replace_versions("overflow", rollout_batch("overflow", &[(9, 1.0)]));
        assert!(
            installed.is_ok(),
            "overflow control must install: {installed:?}"
        );
        let live_before = rollout_fingerprint(&store, "overflow");

        // Both members are finite, but the exact mathematical sum MAX + 1
        // exceeds the largest representable finite f64. A naïve f64 fold
        // rounds the +1 away and must not be the validation oracle.
        let replacement = store.replace_versions(
            "overflow",
            vec![pv("overflow", 1, f64::MAX), pv("overflow", 2, 1.0)],
        );
        let replacement_rejected = matches!(
            &replacement,
            Err(PromptVersionError::InvalidTotalWeight { .. })
        );
        let replacement_unchanged = rollout_fingerprint(&store, "overflow") == live_before;

        let legacy = WeightedPromptStore::new();
        let first = legacy.add_version("legacy-overflow", pv("legacy-overflow", 1, f64::MAX));
        let second = legacy.add_version("legacy-overflow", pv("legacy-overflow", 2, 1.0));
        let selection =
            legacy.select_for_cohort_typed("legacy-overflow", "customer-1", "rollout-1");
        let defensive_selection_rejected = matches!(
            &selection,
            Err(PromptSelectionError::InvalidTotalWeight { name, .. })
                if name == "legacy-overflow"
        );

        assert!(
            replacement_rejected
                && replacement_unchanged
                && first.is_ok()
                && second.is_ok()
                && defensive_selection_rejected,
            "mathematical MAX+1 overflow was rounded into a valid rollout: replacement={replacement:?}, unchanged={replacement_unchanged}, first={first:?}, second={second:?}, selection={selection:?}"
        );
    }

    #[test]
    fn exact_weight_overflow_reports_a_nonfinite_total() {
        let batch = WeightedPromptStore::new();
        let batch_error = batch
            .replace_versions(
                "batch-overflow-diagnostic",
                vec![
                    pv("batch-overflow-diagnostic", 1, f64::MAX),
                    pv("batch-overflow-diagnostic", 2, 1.0),
                ],
            )
            .expect_err("the exact mathematical total exceeds f64::MAX");
        assert!(matches!(
            batch_error,
            PromptVersionError::InvalidTotalWeight { total }
                if total == f64::INFINITY
        ));

        let legacy = WeightedPromptStore::new();
        legacy
            .add_version(
                "legacy-overflow-diagnostic",
                pv("legacy-overflow-diagnostic", 1, f64::MAX),
            )
            .expect("the compatibility builder accepts finite members");
        legacy
            .add_version(
                "legacy-overflow-diagnostic",
                pv("legacy-overflow-diagnostic", 2, 1.0),
            )
            .expect("the compatibility builder defers aggregate validation");
        let selection_error = legacy
            .select_for_cohort_typed("legacy-overflow-diagnostic", "customer-1", "rollout-1")
            .expect_err("selection defensively validates a compatibility rollout");
        assert!(matches!(
            selection_error,
            PromptSelectionError::InvalidTotalWeight { total, .. }
                if total == f64::INFINITY
        ));
    }

    #[test]
    fn single_f64_max_is_valid_for_batch_and_legacy_selection_control() {
        let batch = WeightedPromptStore::new();
        let batch_install = batch.replace_versions(
            "single-max-batch",
            vec![pv("single-max-batch", 1, f64::MAX)],
        );
        assert!(
            batch_install.is_ok(),
            "a single finite f64::MAX weight must remain a valid batch: {batch_install:?}"
        );
        let batch_selection =
            batch.select_for_cohort_typed("single-max-batch", "customer-1", "rollout-1");
        match batch_selection {
            Ok(version) => {
                assert_eq!(version.version, 1);
                assert_eq!(version.weight.to_bits(), f64::MAX.to_bits());
            }
            Err(error) => panic!("a single finite f64::MAX batch was not selectable: {error:?}"),
        }

        let legacy = WeightedPromptStore::new();
        let legacy_install =
            legacy.add_version("single-max-legacy", pv("single-max-legacy", 1, f64::MAX));
        assert!(
            legacy_install.is_ok(),
            "a single finite f64::MAX weight must remain valid through add_version: {legacy_install:?}"
        );
        let legacy_selection =
            legacy.select_for_cohort_typed("single-max-legacy", "customer-1", "rollout-1");
        match legacy_selection {
            Ok(version) => {
                assert_eq!(version.version, 1);
                assert_eq!(version.weight.to_bits(), f64::MAX.to_bits());
            }
            Err(error) => {
                panic!("a single finite f64::MAX legacy rollout was not selectable: {error:?}")
            }
        }
    }

    #[test]
    fn every_positive_band_survives_a_2pow53_leading_weight() {
        const TWO_POW_53: f64 = 9_007_199_254_740_992.0;
        // Independent exact-integer draw oracles for weights [2^53, 1, 1].
        // These lie strictly inside the second and third raw-u64 bands.
        const BAND_DRAWS: [(u64, u32); 2] = [
            (18_446_744_073_709_548_544, 2),
            (18_446_744_073_709_550_592, 3),
        ];

        let store = WeightedPromptStore::new();
        let installed = store.replace_versions(
            "narrow-bands",
            rollout_batch("narrow-bands", &[(1, TWO_POW_53), (2, 1.0), (3, 1.0)]),
        );
        assert!(
            installed.is_ok(),
            "narrow-band control must install: {installed:?}"
        );

        let failures = BAND_DRAWS
            .into_iter()
            .filter_map(|(draw, expected_version)| {
                let draw_probe = PromptDrawProbe::install_for_current_thread(draw);
                let selected = store.select_for_cohort_typed(
                    "narrow-bands",
                    "ignored-by-draw-seam",
                    "ignored-by-draw-seam",
                );
                drop(draw_probe);
                match selected {
                    Ok(version) if version.version == expected_version => None,
                    other => Some((draw, expected_version, other)),
                }
            })
            .collect::<Vec<_>>();

        assert!(
            failures.is_empty(),
            "positive one-unit bands were erased by f64 total/cumulative math: {failures:?}"
        );
    }

    #[test]
    fn maximum_draw_is_strictly_below_one_and_never_selects_zero_tail() {
        let store = WeightedPromptStore::new();
        let installed =
            store.replace_versions("top-draw", rollout_batch("top-draw", &[(1, 1.0), (2, 0.0)]));
        assert!(
            installed.is_ok(),
            "top-draw control must install: {installed:?}"
        );

        let draw_probe = PromptDrawProbe::install_for_current_thread(u64::MAX);
        let selected = store.select_for_cohort_typed(
            "top-draw",
            "ignored-by-draw-seam",
            "ignored-by-draw-seam",
        );
        let observed_unit = draw_probe.observed_unit();
        drop(draw_probe);
        let selected_positive = matches!(&selected, Ok(version) if version.version == 1);
        let unit_is_half_open = matches!(
            observed_unit,
            Some(unit) if unit.is_finite() && (0.0..1.0).contains(&unit)
        );

        assert!(
            selected_positive && unit_is_half_open,
            "maximum draw escaped [0,1) or selected a zero-weight tail: unit={observed_unit:?}, selected={selected:?}"
        );
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
