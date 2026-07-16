// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-device generation residency and protected eviction planning.
//!
//! A generation occupies one device (single-GPU) or a tensor-parallel group of
//! N identical devices (multi-GPU). Each reservation is stored once and carries
//! its whole device set (`memory.device_indexes`); it reserves the per-device
//! requirement on every device in the set atomically, or on none. Eviction
//! displaces a resident generation as one unit, freeing every device it held,
//! so a multi-device tenant is never left half-resident. That all-or-none rule
//! is what keeps a partial reservation from becoming a deadlock.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AdmissionReason, AdmissionRejection, EvictionPolicy, MemoryEstimate};

/// Lifecycle facts that prevent one resident generation from being evicted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResidencyProtection {
    /// Operator requires the generation to remain resident.
    pub pinned: bool,
    /// At least one request holds an active permit.
    pub active: bool,
    /// At least one live request is queued.
    pub queued: bool,
    /// Generation is acquiring artifacts or starting its engine.
    pub preparing: bool,
    /// Generation is already draining.
    pub draining: bool,
}

impl ResidencyProtection {
    /// Whether policy forbids idle eviction.
    pub const fn is_protected(self) -> bool {
        self.pinned || self.active || self.queued || self.preparing || self.draining
    }
}

/// One generation reserved on one device or a tensor-parallel group of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceReservation {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Process-local deployment generation.
    pub generation: u64,
    /// Complete selected-device memory estimate, including the device set.
    pub memory: MemoryEstimate,
    /// Lifecycle protection facts.
    pub protection: ResidencyProtection,
    /// Monotonic last-used tick.
    pub last_used: u64,
}

/// Successful reservation and deterministic evictions applied before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceReservationResult {
    /// Deployment IDs evicted to make room, in LRU order.
    pub evicted: Vec<String>,
}

/// Host-wide limits applied while placing one generation on a device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceResidencyPolicy {
    /// Maximum generations resident across every device.
    pub max_resident_models: Option<usize>,
    /// Whether an idle resident generation may be displaced.
    pub eviction: EvictionPolicy,
}

impl DeviceResidencyPolicy {
    /// Construct one explicit host-wide residency policy.
    pub const fn new(max_resident_models: Option<usize>, eviction: EvictionPolicy) -> Self {
        Self {
            max_resident_models,
            eviction,
        }
    }
}

/// Residency budgets keyed by worker-local device index, plus the resident
/// generations, each of which may span several devices.
#[derive(Debug, Clone)]
pub struct DeviceResidencySet {
    capacities: BTreeMap<u32, u64>,
    reservations: Vec<DeviceReservation>,
}

impl DeviceResidencySet {
    /// Create independent device budgets. Zero-byte devices reject every load.
    pub fn new(capacities: BTreeMap<u32, u64>) -> Self {
        Self {
            capacities,
            reservations: Vec::new(),
        }
    }

    /// Reserve one generation on its selected device set, evicting only idle
    /// generations, with no host-wide limit.
    pub fn reserve(
        &mut self,
        deployment: &str,
        generation: u64,
        memory: MemoryEstimate,
        protection: ResidencyProtection,
        now: u64,
    ) -> Result<DeviceReservationResult, AdmissionRejection> {
        self.reserve_with_policy(
            deployment,
            generation,
            memory,
            protection,
            now,
            DeviceResidencyPolicy::default(),
        )
    }

    /// Reserve one generation while enforcing the host-wide resident limit and
    /// eviction policy.
    ///
    /// The per-device requirement (`memory.total_bytes`) is reserved on every
    /// device in `memory.device_indexes`, atomically: either every device has
    /// or is cleared to have room, or the reservation is rejected and nothing
    /// changes.
    pub fn reserve_with_policy(
        &mut self,
        deployment: &str,
        generation: u64,
        memory: MemoryEstimate,
        protection: ResidencyProtection,
        now: u64,
        policy: DeviceResidencyPolicy,
    ) -> Result<DeviceReservationResult, AdmissionRejection> {
        if memory.device_indexes.is_empty() {
            return Err(capacity_rejection(format!(
                "deployment {deployment:?} generation {generation} selected no device"
            )));
        }

        // Idempotent re-reservation: the same generation touching its existing
        // residency updates liveness but keeps its immutable memory estimate.
        if let Some(index) = self.reservations.iter().position(|reservation| {
            reservation.deployment == deployment && reservation.generation == generation
        }) {
            let existing = &self.reservations[index];
            if existing.memory.device_indexes != memory.device_indexes {
                return Err(capacity_rejection(format!(
                    "deployment {deployment:?} generation {generation} is already resident on devices {:?}",
                    existing.memory.device_indexes
                )));
            }
            if existing.memory != memory {
                return Err(capacity_rejection(format!(
                    "deployment {deployment:?} generation {generation} changed its immutable memory estimate"
                )));
            }
            self.reservations[index].last_used = now;
            self.reservations[index].protection = protection;
            return Ok(DeviceReservationResult {
                evicted: Vec::new(),
            });
        }

        // Existence + per-device capacity gate.
        for &device_index in &memory.device_indexes {
            let capacity = self.capacities.get(&device_index).ok_or_else(|| {
                capacity_rejection(format!("selected device {device_index} is not present"))
            })?;
            if memory.total_bytes > *capacity {
                return Err(capacity_rejection(format!(
                    "deployment {deployment:?} needs {} bytes on device {device_index}, whose capacity is {capacity} bytes",
                    memory.total_bytes
                )));
            }
        }

        // Bytes that must be reclaimed on each target device to make room.
        let mut needed: BTreeMap<u32, u64> = BTreeMap::new();
        for &device_index in &memory.device_indexes {
            let capacity = self.capacities[&device_index];
            let free = capacity.saturating_sub(self.used_bytes(device_index));
            needed.insert(device_index, memory.total_bytes.saturating_sub(free));
        }

        let count_overflow = policy
            .max_resident_models
            .map(|limit| {
                self.reservations
                    .len()
                    .saturating_add(1)
                    .saturating_sub(limit)
            })
            .unwrap_or(0);

        let any_capacity_needed = needed.values().any(|&bytes| bytes > 0);
        if !any_capacity_needed && count_overflow == 0 {
            self.reservations.push(DeviceReservation {
                deployment: deployment.to_string(),
                generation,
                memory,
                protection,
                last_used: now,
            });
            return Ok(DeviceReservationResult {
                evicted: Vec::new(),
            });
        }

        if policy.eviction == EvictionPolicy::Never {
            return Err(capacity_rejection(format!(
                "deployment {deployment:?} requires displacing a resident generation, but the eviction policy is never"
            )));
        }

        // Greedy LRU eviction. A victim is a whole resident generation; evicting
        // it frees `total_bytes` on every device it occupies at once, which is
        // how a multi-device resident is displaced as a unit.
        let mut candidates = self
            .reservations
            .iter()
            .filter(|reservation| !reservation.protection.is_protected())
            .map(|reservation| {
                (
                    reservation.last_used,
                    reservation.deployment.clone(),
                    reservation.generation,
                    reservation.memory.device_indexes.clone(),
                    reservation.memory.total_bytes,
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            (left.0, left.1.as_str(), left.2).cmp(&(right.0, right.1.as_str(), right.2))
        });

        let mut remaining = needed.clone();
        let mut remaining_count = count_overflow;
        let mut chosen: Vec<(String, u64)> = Vec::new();
        for (_, deployment_id, generation_id, devices, bytes) in candidates {
            let still_short = remaining.values().any(|&n| n > 0);
            if !still_short && remaining_count == 0 {
                break;
            }
            let helps_capacity = devices
                .iter()
                .any(|device| remaining.get(device).copied().unwrap_or(0) > 0);
            if !helps_capacity && remaining_count == 0 {
                continue;
            }
            for device in &devices {
                if let Some(short) = remaining.get_mut(device) {
                    *short = short.saturating_sub(bytes);
                }
            }
            remaining_count = remaining_count.saturating_sub(1);
            chosen.push((deployment_id, generation_id));
        }

        if let Some((device_index, short)) = remaining
            .iter()
            .find(|(_, &short)| short > 0)
            .map(|(d, s)| (*d, *s))
        {
            return Err(capacity_rejection(format!(
                "device {device_index} lacks {short} bytes after protecting active, queued, pinned, preparing, and draining generations"
            )));
        }
        if remaining_count > 0 {
            return Err(capacity_rejection(format!(
                "resident model limit requires {remaining_count} additional evictions after protecting active, queued, pinned, preparing, and draining generations"
            )));
        }

        self.reservations.retain(|reservation| {
            !chosen.iter().any(|(deployment_id, generation_id)| {
                reservation.deployment == *deployment_id && reservation.generation == *generation_id
            })
        });
        let evicted = chosen
            .iter()
            .map(|(deployment_id, _)| deployment_id.clone())
            .collect::<Vec<_>>();
        self.reservations.push(DeviceReservation {
            deployment: deployment.to_string(),
            generation,
            memory,
            protection,
            last_used: now,
        });
        Ok(DeviceReservationResult { evicted })
    }

    /// Apply a new host-wide resident limit to generations that are already
    /// resident.
    pub fn enforce_policy(
        &mut self,
        policy: DeviceResidencyPolicy,
    ) -> Result<DeviceReservationResult, AdmissionRejection> {
        let Some(max_resident_models) = policy.max_resident_models else {
            return Ok(DeviceReservationResult {
                evicted: Vec::new(),
            });
        };
        let overflow = self.reservations.len().saturating_sub(max_resident_models);
        if overflow == 0 {
            return Ok(DeviceReservationResult {
                evicted: Vec::new(),
            });
        }
        if policy.eviction == EvictionPolicy::Never {
            return Err(capacity_rejection(format!(
                "resident model limit requires displacing {overflow} generations, but the eviction policy is never"
            )));
        }

        let mut candidates = self
            .reservations
            .iter()
            .filter(|reservation| !reservation.protection.is_protected())
            .map(|reservation| {
                (
                    reservation.last_used,
                    reservation.deployment.clone(),
                    reservation.generation,
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            (left.0, left.1.as_str(), left.2).cmp(&(right.0, right.1.as_str(), right.2))
        });
        if candidates.len() < overflow {
            return Err(capacity_rejection(format!(
                "resident model limit requires {} additional evictions after protecting active, queued, pinned, preparing, and draining generations",
                overflow.saturating_sub(candidates.len())
            )));
        }
        let chosen = candidates
            .into_iter()
            .take(overflow)
            .map(|(_, deployment, generation)| (deployment, generation))
            .collect::<Vec<_>>();
        self.reservations.retain(|reservation| {
            !chosen.iter().any(|(deployment, generation)| {
                reservation.deployment == *deployment && reservation.generation == *generation
            })
        });
        Ok(DeviceReservationResult {
            evicted: chosen
                .into_iter()
                .map(|(deployment, _)| deployment)
                .collect::<Vec<_>>(),
        })
    }

    /// Protect every current generation while probing overlap capacity for a
    /// rolling launch.
    pub(crate) fn protect_all_for_rollout(&mut self) {
        for reservation in &mut self.reservations {
            reservation.protection.preparing = true;
        }
    }

    /// Keep accounting for a generation that policy selected before its process
    /// stopped.
    pub(crate) fn retain_existing(
        &mut self,
        reservation: DeviceReservation,
    ) -> Result<(), AdmissionRejection> {
        if let Some(existing) = self.reservations.iter_mut().find(|existing| {
            existing.deployment == reservation.deployment
                && existing.generation == reservation.generation
        }) {
            if existing.memory != reservation.memory {
                return Err(capacity_rejection(format!(
                    "deployment {:?} generation {} changed its retained device or memory estimate",
                    reservation.deployment, reservation.generation
                )));
            }
            existing.protection = reservation.protection;
            existing.last_used = reservation.last_used;
            return Ok(());
        }
        for &device_index in &reservation.memory.device_indexes {
            let capacity = self.capacities.get(&device_index).ok_or_else(|| {
                capacity_rejection(format!(
                    "retained deployment {:?} selected missing device {device_index}",
                    reservation.deployment
                ))
            })?;
            let used = self.used_bytes(device_index);
            if used.saturating_add(reservation.memory.total_bytes) > *capacity {
                return Err(capacity_rejection(format!(
                    "retained deployment {:?} generation {} no longer fits on device {device_index}",
                    reservation.deployment, reservation.generation
                )));
            }
        }
        self.reservations.push(reservation);
        Ok(())
    }

    /// Update lifecycle protection without changing capacity accounting.
    ///
    /// `device_index` names one device the generation occupies; the reservation
    /// is a single unit spanning its whole set, so the update applies to the
    /// whole generation.
    pub fn update_protection(
        &mut self,
        device_index: u32,
        deployment: &str,
        generation: u64,
        protection: ResidencyProtection,
    ) {
        if let Some(reservation) = self.reservations.iter_mut().find(|reservation| {
            reservation.deployment == deployment
                && reservation.generation == generation
                && reservation.memory.device_indexes.contains(&device_index)
        }) {
            reservation.protection = protection;
        }
    }

    /// Release one exact generation from every device it held.
    pub fn release(&mut self, device_index: u32, deployment: &str, generation: u64) {
        self.reservations.retain(|reservation| {
            !(reservation.deployment == deployment
                && reservation.generation == generation
                && reservation.memory.device_indexes.contains(&device_index))
        });
    }

    /// Whether one exact generation is resident on the named device.
    pub fn contains(&self, device_index: u32, deployment: &str, generation: u64) -> bool {
        self.reservations.iter().any(|reservation| {
            reservation.deployment == deployment
                && reservation.generation == generation
                && reservation.memory.device_indexes.contains(&device_index)
        })
    }

    /// Used bytes on one device: the per-device requirement of every resident
    /// generation that occupies it.
    pub fn used_bytes(&self, device_index: u32) -> u64 {
        self.reservations
            .iter()
            .filter(|reservation| reservation.memory.device_indexes.contains(&device_index))
            .map(|reservation| reservation.memory.total_bytes)
            .sum()
    }

    /// Deterministic snapshot of every reservation.
    pub fn reservations(&self) -> Vec<DeviceReservation> {
        let mut out = self.reservations.clone();
        out.sort_by(|left, right| {
            (left.deployment.as_str(), left.generation)
                .cmp(&(right.deployment.as_str(), right.generation))
        });
        out
    }
}

fn capacity_rejection(detail: impl AsRef<str>) -> AdmissionRejection {
    AdmissionRejection::new(AdmissionReason::InsufficientCapacity, detail, false, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvictionPolicy;

    fn mem(devices: Vec<u32>, total: u64) -> MemoryEstimate {
        MemoryEstimate {
            device_indexes: devices,
            weight_bytes: total,
            kv_bytes: 0,
            runtime_overhead_bytes: 0,
            safety_margin_bytes: 0,
            total_bytes: total,
        }
    }

    fn active() -> ResidencyProtection {
        ResidencyProtection {
            active: true,
            ..ResidencyProtection::default()
        }
    }

    #[test]
    fn reserving_a_device_set_is_atomic_when_one_device_cannot_clear_room() {
        let mut set = DeviceResidencySet::new(BTreeMap::from([(0, 100), (1, 100)]));
        // Device 1 is full and protected, so it cannot be cleared.
        set.reserve("busy", 1, mem(vec![1], 100), active(), 0)
            .unwrap();

        let result = set.reserve_with_policy(
            "wide",
            1,
            mem(vec![0, 1], 60),
            ResidencyProtection::default(),
            1,
            DeviceResidencyPolicy::new(None, EvictionPolicy::Lru),
        );
        assert!(
            result.is_err(),
            "the reservation must fail when device 1 cannot make room"
        );
        assert_eq!(
            set.used_bytes(0),
            0,
            "device 0 must not be reserved when device 1 fails: no partial reservation"
        );
    }

    #[test]
    fn lru_eviction_displaces_a_multi_device_resident_as_a_unit() {
        let mut set = DeviceResidencySet::new(BTreeMap::from([(0, 100), (1, 100)]));
        // An idle two-device tenant fills both cards.
        set.reserve(
            "old",
            1,
            mem(vec![0, 1], 100),
            ResidencyProtection::default(),
            0,
        )
        .unwrap();
        assert_eq!(set.used_bytes(0), 100);
        assert_eq!(set.used_bytes(1), 100);

        // A new two-device tenant needs both cards; the idle resident is evicted
        // from both, never left half-resident.
        let result = set
            .reserve_with_policy(
                "new",
                1,
                mem(vec![0, 1], 100),
                ResidencyProtection::default(),
                1,
                DeviceResidencyPolicy::new(None, EvictionPolicy::Lru),
            )
            .expect("the new tenant reserves after evicting the idle one");
        assert_eq!(result.evicted, vec!["old".to_string()]);
        assert!(!set.contains(0, "old", 1));
        assert!(!set.contains(1, "old", 1));
        assert!(set.contains(0, "new", 1) && set.contains(1, "new", 1));
    }
}
