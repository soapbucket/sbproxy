// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! VRAM-budget residency (WOR-1654 budget + evict).
//!
//! Decides which models can be co-resident on a GPU and, when a new
//! model does not fit, which idle model to evict. This is the policy
//! layer above the per-engine [`crate::supervisor::Supervisor`]: the
//! supervisor knows how to load and kill one engine; the
//! [`ResidencyManager`] knows how much VRAM the budget allows and
//! turns "load this model" into "evict these first, then load."
//!
//! Pure and deterministic: it tracks a set of resident models with
//! their VRAM cost and a monotonically increasing last-used tick, and
//! its decisions are unit-tested with no GPU. The caller supplies the
//! tick (a logical clock) so tests are reproducible.

use crate::config::EvictionPolicy;

/// A model currently holding VRAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resident {
    /// The advertised model name / catalog id.
    pub model: String,
    /// VRAM it holds, in bytes.
    pub vram_bytes: u64,
    /// Logical last-used tick; higher is more recent.
    pub last_used: u64,
}

/// The outcome of asking to admit a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The model is already resident (its tick is refreshed).
    AlreadyResident,
    /// It fits now; evict these models first (possibly none), then load.
    Admit {
        /// Models to evict (LRU order) to make room.
        evict: Vec<String>,
    },
    /// It cannot be admitted: even evicting every idle model leaves
    /// too little VRAM, or policy forbids eviction.
    Rejected {
        /// Why (for the operator-facing error).
        reason: String,
    },
}

/// Tracks resident models against a VRAM budget.
#[derive(Debug, Clone)]
pub struct ResidencyManager {
    budget_bytes: u64,
    policy: EvictionPolicy,
    resident: Vec<Resident>,
}

impl ResidencyManager {
    /// Create a manager for a GPU with `budget_bytes` of usable VRAM
    /// under `policy`.
    pub fn new(budget_bytes: u64, policy: EvictionPolicy) -> Self {
        Self {
            budget_bytes,
            policy,
            resident: Vec::new(),
        }
    }

    /// Bytes currently held by resident models.
    pub fn used_bytes(&self) -> u64 {
        self.resident.iter().map(|r| r.vram_bytes).sum()
    }

    /// Free bytes against the budget.
    pub fn free_bytes(&self) -> u64 {
        self.budget_bytes.saturating_sub(self.used_bytes())
    }

    /// Currently resident model names.
    pub fn resident_models(&self) -> Vec<String> {
        self.resident.iter().map(|r| r.model.clone()).collect()
    }

    /// Decide how to admit `model` needing `vram_bytes` at logical
    /// time `now`. Does not mutate state; call [`Self::commit_admit`]
    /// (or [`Self::load`]) to apply. Under [`EvictionPolicy::Never`]
    /// no eviction is proposed, so a model that does not fit the free
    /// budget is rejected.
    pub fn plan_admit(&self, model: &str, vram_bytes: u64, _now: u64) -> Admission {
        if self.resident.iter().any(|r| r.model == model) {
            return Admission::AlreadyResident;
        }
        if vram_bytes > self.budget_bytes {
            return Admission::Rejected {
                reason: format!(
                    "model needs {vram_bytes} bytes, more than the whole {} byte budget",
                    self.budget_bytes
                ),
            };
        }
        if vram_bytes <= self.free_bytes() {
            return Admission::Admit { evict: Vec::new() };
        }
        if self.policy == EvictionPolicy::Never {
            return Admission::Rejected {
                reason: "VRAM full and eviction policy is `never`".to_string(),
            };
        }
        // Evict least-recently-used until it fits.
        let mut by_lru: Vec<&Resident> = self.resident.iter().collect();
        by_lru.sort_by_key(|r| r.last_used);
        let mut reclaimed = self.free_bytes();
        let mut evict = Vec::new();
        for r in by_lru {
            if vram_bytes <= reclaimed {
                break;
            }
            evict.push(r.model.clone());
            reclaimed += r.vram_bytes;
        }
        if vram_bytes <= reclaimed {
            Admission::Admit { evict }
        } else {
            Admission::Rejected {
                reason: "cannot free enough VRAM even after evicting all idle models".to_string(),
            }
        }
    }

    /// Apply an admit decision: remove evicted models, add the new
    /// one. Convenience for the common path.
    pub fn commit_admit(&mut self, model: &str, vram_bytes: u64, now: u64, evict: &[String]) {
        self.resident.retain(|r| !evict.contains(&r.model));
        self.resident.push(Resident {
            model: model.to_string(),
            vram_bytes,
            last_used: now,
        });
    }

    /// Plan and apply in one step. Returns the models that were
    /// evicted, or an error string when rejected.
    pub fn load(&mut self, model: &str, vram_bytes: u64, now: u64) -> Result<Vec<String>, String> {
        match self.plan_admit(model, vram_bytes, now) {
            Admission::AlreadyResident => {
                self.touch(model, now);
                Ok(Vec::new())
            }
            Admission::Admit { evict } => {
                self.commit_admit(model, vram_bytes, now, &evict);
                Ok(evict)
            }
            Admission::Rejected { reason } => Err(reason),
        }
    }

    /// Refresh a resident model's last-used tick (on a served request).
    pub fn touch(&mut self, model: &str, now: u64) {
        if let Some(r) = self.resident.iter_mut().find(|r| r.model == model) {
            r.last_used = now;
        }
    }

    /// Drop a model (idle-timeout unload). No-op if not resident.
    pub fn unload(&mut self, model: &str) {
        self.resident.retain(|r| r.model != model);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn fits_without_eviction() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        assert_eq!(m.load("a", 10 * GIB, 1), Ok(vec![]));
        assert_eq!(m.load("b", 10 * GIB, 2), Ok(vec![]));
        assert_eq!(m.used_bytes(), 20 * GIB);
        assert_eq!(m.resident_models().len(), 2);
    }

    #[test]
    fn evicts_lru_to_make_room() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load("a", 10 * GIB, 1).unwrap();
        m.load("b", 10 * GIB, 2).unwrap();
        // Touch a so b is the LRU.
        m.touch("a", 5);
        // c needs 10 GiB; free is 4 GiB, so one model must go. b is LRU.
        let evicted = m.load("c", 10 * GIB, 6).unwrap();
        assert_eq!(evicted, vec!["b".to_string()]);
        let mut names = m.resident_models();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn already_resident_refreshes_tick() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load("a", 10 * GIB, 1).unwrap();
        assert_eq!(m.load("a", 10 * GIB, 9), Ok(vec![]));
        // a is still the only resident, now with tick 9.
        assert_eq!(m.resident_models(), vec!["a".to_string()]);
    }

    #[test]
    fn never_policy_rejects_instead_of_evicting() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Never);
        m.load("a", 20 * GIB, 1).unwrap();
        let err = m.load("b", 10 * GIB, 2).unwrap_err();
        assert!(err.contains("never"), "got: {err}");
        // a stays resident, b did not load.
        assert_eq!(m.resident_models(), vec!["a".to_string()]);
    }

    #[test]
    fn rejects_model_bigger_than_budget() {
        let mut m = ResidencyManager::new(16 * GIB, EvictionPolicy::Lru);
        let err = m.load("huge", 40 * GIB, 1).unwrap_err();
        assert!(err.contains("budget"), "got: {err}");
    }

    #[test]
    fn evicts_multiple_when_needed() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load("a", 6 * GIB, 1).unwrap();
        m.load("b", 6 * GIB, 2).unwrap();
        m.load("c", 6 * GIB, 3).unwrap();
        // free = 6 GiB. d needs 20 GiB, so evict a and b (oldest two)
        // to reclaim 6 + 6 + 6 = 18, +6 free = 24 >= 20.
        let mut evicted = m.load("d", 20 * GIB, 4).unwrap();
        evicted.sort();
        assert_eq!(
            evicted,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn unload_frees_vram() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load("a", 10 * GIB, 1).unwrap();
        m.unload("a");
        assert_eq!(m.used_bytes(), 0);
        assert!(m.resident_models().is_empty());
    }
}
