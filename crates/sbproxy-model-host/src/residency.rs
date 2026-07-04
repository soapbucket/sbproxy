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
    /// Relative cost of reloading this model if evicted (e.g. measured
    /// cold-start milliseconds). A 2026 multi-model-scheduler study
    /// found preemption cost is dominated by weight reload, so the
    /// eviction planner minimizes the reload cost it gives up. `0` for
    /// the plain-LRU path.
    pub reload_cost_ms: u64,
    /// Pinned models are never evicted (the operator wants them always
    /// resident). A pinned co-resident pair is therefore never split.
    pub pinned: bool,
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
        match self.choose_victims(vram_bytes, model) {
            Some(evict) => Admission::Admit { evict },
            None => Admission::Rejected {
                reason: "cannot free enough VRAM even after evicting all idle (non-pinned) models"
                    .to_string(),
            },
        }
    }

    /// Choose the set of resident models to evict to free `needed`
    /// bytes for `incoming`, minimizing the reload cost given up while
    /// protecting pinned models and recently-used ones.
    ///
    /// Cost of evicting a model = its `reload_cost_ms` plus a recency
    /// term weighted to dominate any reload-cost difference, so a
    /// more-recently-used model is always more expensive to evict than
    /// an idle one (LRU behavior), and reload cost only breaks ties
    /// among equally-idle candidates. Pinned models are never
    /// candidates. Returns `None` when no non-pinned subset can free
    /// enough (the caller rejects). With all `reload_cost_ms == 0` this
    /// reduces exactly to least-recently-used eviction.
    fn choose_victims(&self, needed: u64, incoming: &str) -> Option<Vec<String>> {
        let free = self.free_bytes();
        if needed <= free {
            return Some(Vec::new());
        }
        let cands: Vec<&Resident> = self
            .resident
            .iter()
            .filter(|r| r.model != incoming && !r.pinned)
            .collect();
        let reclaimable: u64 = cands.iter().map(|r| r.vram_bytes).sum();
        if free + reclaimable < needed {
            return None; // even evicting every non-pinned model is not enough
        }
        // Recency weight dominates reload-cost differences, so recency
        // is the primary key and reload cost the tiebreaker.
        let recency_w = cands.iter().map(|r| r.reload_cost_ms).max().unwrap_or(0) as u128 + 1;
        let cost = |r: &Resident| r.reload_cost_ms as u128 + recency_w * r.last_used as u128;

        let n = cands.len();
        if n <= 16 {
            // Exhaustive min-cost subset that frees enough.
            let mut best: Option<(u128, usize, Vec<String>)> = None;
            for mask in 1u32..(1u32 << n) {
                let mut freed = free;
                let mut total: u128 = 0;
                let mut count = 0usize;
                let mut set = Vec::new();
                for (idx, r) in cands.iter().enumerate() {
                    if mask & (1 << idx) != 0 {
                        freed += r.vram_bytes;
                        total += cost(r);
                        count += 1;
                        set.push(r.model.clone());
                    }
                }
                if freed >= needed {
                    let key = (total, count);
                    if best.as_ref().is_none_or(|(bc, bn, _)| key < (*bc, *bn)) {
                        best = Some((total, count, set));
                    }
                }
            }
            best.map(|(_, _, set)| set)
        } else {
            // Greedy fallback for large resident sets: evict lowest-cost
            // (most idle, cheapest to reload) first until it fits.
            let mut sorted = cands.clone();
            sorted.sort_by_key(|r| cost(r));
            let mut freed = free;
            let mut set = Vec::new();
            for r in sorted {
                if freed >= needed {
                    break;
                }
                freed += r.vram_bytes;
                set.push(r.model.clone());
            }
            (freed >= needed).then_some(set)
        }
    }

    /// Apply an admit decision: remove evicted models, add the new one
    /// (unpinned, zero reload cost). Convenience for the common path.
    pub fn commit_admit(&mut self, model: &str, vram_bytes: u64, now: u64, evict: &[String]) {
        self.insert(model, vram_bytes, now, 0, false, evict);
    }

    /// Insert a resident, removing any evicted models first.
    fn insert(
        &mut self,
        model: &str,
        vram_bytes: u64,
        now: u64,
        reload_cost_ms: u64,
        pinned: bool,
        evict: &[String],
    ) {
        self.resident.retain(|r| !evict.contains(&r.model));
        self.resident.push(Resident {
            model: model.to_string(),
            vram_bytes,
            last_used: now,
            reload_cost_ms,
            pinned,
        });
    }

    /// Plan and apply in one step. Returns the models that were
    /// evicted, or an error string when rejected. Plain LRU (zero
    /// reload cost, unpinned).
    pub fn load(&mut self, model: &str, vram_bytes: u64, now: u64) -> Result<Vec<String>, String> {
        self.load_managed(model, vram_bytes, now, 0, false)
    }

    /// Plan and apply with a reload cost and a pin flag. Eviction
    /// minimizes reload cost given up and never evicts a pinned model.
    pub fn load_managed(
        &mut self,
        model: &str,
        vram_bytes: u64,
        now: u64,
        reload_cost_ms: u64,
        pinned: bool,
    ) -> Result<Vec<String>, String> {
        match self.plan_admit(model, vram_bytes, now) {
            Admission::AlreadyResident => {
                self.touch(model, now);
                Ok(Vec::new())
            }
            Admission::Admit { evict } => {
                self.insert(model, vram_bytes, now, reload_cost_ms, pinned, &evict);
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

    // --- WOR-1672: reload-cost-aware, pin-protecting eviction ---

    #[test]
    fn reload_cost_breaks_ties_among_equally_idle() {
        // Two idle models with the SAME last_used but different reload
        // cost; freeing room evicts the one cheaper to reload.
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load_managed("cheap", 10 * GIB, 1, 5, false).unwrap();
        m.load_managed("expensive", 10 * GIB, 1, 500, false)
            .unwrap();
        // free = 4 GiB; a 10 GiB model needs one eviction. Same recency,
        // so the cheaper-to-reload model goes.
        let evicted = m.load_managed("new", 10 * GIB, 2, 0, false).unwrap();
        assert_eq!(evicted, vec!["cheap".to_string()]);
    }

    #[test]
    fn evicts_large_idle_not_small_hot() {
        // The design-doc exit case: a small, recently-used model and a
        // large idle one; admitting a third evicts the large idle model.
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load_managed("big-idle", 14 * GIB, 1, 800, false).unwrap();
        m.load_managed("small-hot", 6 * GIB, 2, 50, false).unwrap();
        m.touch("small-hot", 10); // keep it hot
                                  // free = 4 GiB; a 12 GiB model needs room. big-idle is older, so
                                  // recency makes it the cheaper eviction, and it alone frees enough.
        let evicted = m.load_managed("new", 12 * GIB, 11, 0, false).unwrap();
        assert_eq!(evicted, vec!["big-idle".to_string()]);
        assert!(m.resident_models().contains(&"small-hot".to_string()));
    }

    #[test]
    fn pinned_model_is_never_evicted() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        // Pin a small model that is also the oldest (would be LRU victim).
        m.load_managed("pinned", 6 * GIB, 1, 10, true).unwrap();
        m.load_managed("idle", 14 * GIB, 2, 800, false).unwrap();
        // free = 4 GiB; a 12 GiB model needs room. Only "idle" may be
        // evicted; "pinned" stays despite being older.
        let evicted = m.load_managed("new", 12 * GIB, 3, 0, false).unwrap();
        assert_eq!(evicted, vec!["idle".to_string()]);
        assert!(m.resident_models().contains(&"pinned".to_string()));
    }

    #[test]
    fn pinned_pair_is_never_split_and_blocks_when_it_must() {
        let mut m = ResidencyManager::new(24 * GIB, EvictionPolicy::Lru);
        m.load_managed("keep-a", 10 * GIB, 1, 10, true).unwrap();
        m.load_managed("keep-b", 10 * GIB, 2, 10, true).unwrap();
        // free = 4 GiB; a 12 GiB model cannot be admitted because both
        // resident models are pinned. Neither is evicted (pair intact).
        let err = m.load_managed("new", 12 * GIB, 3, 0, false).unwrap_err();
        assert!(err.contains("non-pinned"), "got: {err}");
        let mut names = m.resident_models();
        names.sort();
        assert_eq!(names, vec!["keep-a".to_string(), "keep-b".to_string()]);
    }
}
