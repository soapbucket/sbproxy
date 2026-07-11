// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-device generation residency and protected eviction planning.

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

/// One generation reserved on exactly one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceReservation {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Process-local deployment generation.
    pub generation: u64,
    /// Complete selected-device memory estimate.
    pub memory: MemoryEstimate,
    /// Lifecycle protection facts.
    pub protection: ResidencyProtection,
    /// Monotonic last-used tick.
    pub last_used: u64,
}

/// Successful reservation and deterministic evictions applied before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceReservationResult {
    /// Deployment IDs evicted from the selected device in LRU order.
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

#[derive(Debug, Clone)]
struct DeviceState {
    capacity_bytes: u64,
    reservations: Vec<DeviceReservation>,
}

/// Independent residency budgets keyed by worker-local device index.
#[derive(Debug, Clone)]
pub struct DeviceResidencySet {
    devices: BTreeMap<u32, DeviceState>,
}

impl DeviceResidencySet {
    /// Create independent device budgets. Zero-byte devices reject every load.
    pub fn new(capacities: BTreeMap<u32, u64>) -> Self {
        Self {
            devices: capacities
                .into_iter()
                .map(|(index, capacity_bytes)| {
                    (
                        index,
                        DeviceState {
                            capacity_bytes,
                            reservations: Vec::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Reserve one generation on its selected device, evicting only idle generations there.
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

    /// Reserve one generation while enforcing the host-wide resident limit and eviction policy.
    pub fn reserve_with_policy(
        &mut self,
        deployment: &str,
        generation: u64,
        memory: MemoryEstimate,
        protection: ResidencyProtection,
        now: u64,
        policy: DeviceResidencyPolicy,
    ) -> Result<DeviceReservationResult, AdmissionRejection> {
        let existing_device = self.devices.iter().find_map(|(device_index, device)| {
            device
                .reservations
                .iter()
                .any(|reservation| {
                    reservation.deployment == deployment && reservation.generation == generation
                })
                .then_some(*device_index)
        });
        if let Some(existing_device) = existing_device {
            if existing_device != memory.device_index {
                return Err(capacity_rejection(format!(
                    "deployment {deployment:?} generation {generation} is already resident on device {existing_device}"
                )));
            }
        }
        let device = self.devices.get(&memory.device_index).ok_or_else(|| {
            capacity_rejection(format!(
                "selected device {} is not present",
                memory.device_index
            ))
        })?;
        if let Some(existing) = device.reservations.iter().find(|reservation| {
            reservation.deployment == deployment && reservation.generation == generation
        }) {
            if existing.memory != memory {
                return Err(capacity_rejection(format!(
                    "deployment {deployment:?} generation {generation} changed its immutable memory estimate"
                )));
            }
            let device = self
                .devices
                .get_mut(&memory.device_index)
                .expect("selected device was checked above");
            let existing = device
                .reservations
                .iter_mut()
                .find(|reservation| {
                    reservation.deployment == deployment && reservation.generation == generation
                })
                .expect("existing reservation was checked above");
            existing.last_used = now;
            existing.protection = protection;
            return Ok(DeviceReservationResult {
                evicted: Vec::new(),
            });
        }
        if memory.total_bytes > device.capacity_bytes {
            return Err(capacity_rejection(format!(
                "deployment {deployment:?} needs {} bytes on device {}, whose capacity is {} bytes",
                memory.total_bytes, memory.device_index, device.capacity_bytes
            )));
        }
        let target_capacity = device.capacity_bytes;
        let used = device
            .reservations
            .iter()
            .map(|reservation| reservation.memory.total_bytes)
            .sum::<u64>();
        let free = target_capacity.saturating_sub(used);
        let needed = memory.total_bytes.saturating_sub(free);
        let current_residents = self
            .devices
            .values()
            .map(|device| device.reservations.len())
            .sum::<usize>();
        let count_overflow = policy
            .max_resident_models
            .map(|limit| current_residents.saturating_add(1).saturating_sub(limit))
            .unwrap_or(0);
        if needed == 0 && count_overflow == 0 {
            self.devices
                .get_mut(&memory.device_index)
                .expect("selected device was checked above")
                .reservations
                .push(DeviceReservation {
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

        let mut victims = self
            .devices
            .iter()
            .flat_map(|(device_index, device)| {
                device
                    .reservations
                    .iter()
                    .filter(|reservation| !reservation.protection.is_protected())
                    .map(|reservation| {
                        (
                            reservation.last_used,
                            reservation.deployment.clone(),
                            reservation.generation,
                            *device_index,
                            reservation.memory.total_bytes,
                        )
                    })
            })
            .collect::<Vec<_>>();
        victims.sort_by(|left, right| {
            (left.0, left.1.as_str(), left.2, left.3).cmp(&(
                right.0,
                right.1.as_str(),
                right.2,
                right.3,
            ))
        });
        let mut reclaimed = 0u64;
        let mut selected = Vec::new();
        for victim in victims
            .iter()
            .filter(|victim| victim.3 == memory.device_index)
        {
            if reclaimed >= needed {
                break;
            }
            reclaimed = reclaimed.saturating_add(victim.4);
            selected.push(victim.clone());
        }
        if reclaimed < needed {
            return Err(capacity_rejection(format!(
                "device {} lacks {} bytes after protecting active, queued, pinned, preparing, and draining generations",
                memory.device_index,
                needed.saturating_sub(reclaimed)
            )));
        }
        for victim in victims {
            if selected.len() >= count_overflow {
                break;
            }
            if !selected.iter().any(|selected| {
                selected.1 == victim.1 && selected.2 == victim.2 && selected.3 == victim.3
            }) {
                selected.push(victim);
            }
        }
        if selected.len() < count_overflow {
            return Err(capacity_rejection(format!(
                "resident model limit requires {} additional evictions after protecting active, queued, pinned, preparing, and draining generations",
                count_overflow.saturating_sub(selected.len())
            )));
        }
        selected.sort_by(|left, right| {
            (left.0, left.1.as_str(), left.2, left.3).cmp(&(
                right.0,
                right.1.as_str(),
                right.2,
                right.3,
            ))
        });
        for (device_index, device) in &mut self.devices {
            device.reservations.retain(|reservation| {
                !selected.iter().any(|victim| {
                    victim.3 == *device_index
                        && victim.1 == reservation.deployment
                        && victim.2 == reservation.generation
                })
            });
        }
        let evicted = selected
            .iter()
            .map(|victim| victim.1.clone())
            .collect::<Vec<_>>();
        self.devices
            .get_mut(&memory.device_index)
            .expect("selected device was checked above")
            .reservations
            .push(DeviceReservation {
                deployment: deployment.to_string(),
                generation,
                memory,
                protection,
                last_used: now,
            });
        Ok(DeviceReservationResult { evicted })
    }

    /// Apply a new host-wide resident limit to generations that are already resident.
    pub fn enforce_policy(
        &mut self,
        policy: DeviceResidencyPolicy,
    ) -> Result<DeviceReservationResult, AdmissionRejection> {
        let Some(max_resident_models) = policy.max_resident_models else {
            return Ok(DeviceReservationResult {
                evicted: Vec::new(),
            });
        };
        let resident_count = self
            .devices
            .values()
            .map(|device| device.reservations.len())
            .sum::<usize>();
        let overflow = resident_count.saturating_sub(max_resident_models);
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

        let mut victims = self
            .devices
            .iter()
            .flat_map(|(device_index, device)| {
                device
                    .reservations
                    .iter()
                    .filter(|reservation| !reservation.protection.is_protected())
                    .map(|reservation| {
                        (
                            reservation.last_used,
                            reservation.deployment.clone(),
                            reservation.generation,
                            *device_index,
                        )
                    })
            })
            .collect::<Vec<_>>();
        victims.sort_by(|left, right| {
            (left.0, left.1.as_str(), left.2, left.3).cmp(&(
                right.0,
                right.1.as_str(),
                right.2,
                right.3,
            ))
        });
        if victims.len() < overflow {
            return Err(capacity_rejection(format!(
                "resident model limit requires {} additional evictions after protecting active, queued, pinned, preparing, and draining generations",
                overflow.saturating_sub(victims.len())
            )));
        }
        victims.truncate(overflow);
        for (device_index, device) in &mut self.devices {
            device.reservations.retain(|reservation| {
                !victims.iter().any(|victim| {
                    victim.3 == *device_index
                        && victim.1 == reservation.deployment
                        && victim.2 == reservation.generation
                })
            });
        }
        Ok(DeviceReservationResult {
            evicted: victims
                .into_iter()
                .map(|victim| victim.1)
                .collect::<Vec<_>>(),
        })
    }

    /// Protect every current generation while probing overlap capacity for a rolling launch.
    pub(crate) fn protect_all_for_rollout(&mut self) {
        for device in self.devices.values_mut() {
            for reservation in &mut device.reservations {
                reservation.protection.preparing = true;
            }
        }
    }

    /// Keep accounting for a generation that policy selected before its process stopped.
    pub(crate) fn retain_existing(
        &mut self,
        reservation: DeviceReservation,
    ) -> Result<(), AdmissionRejection> {
        if let Some((device_index, existing)) =
            self.devices.iter_mut().find_map(|(device_index, device)| {
                device
                    .reservations
                    .iter_mut()
                    .find(|existing| {
                        existing.deployment == reservation.deployment
                            && existing.generation == reservation.generation
                    })
                    .map(|existing| (*device_index, existing))
            })
        {
            if device_index != reservation.memory.device_index
                || existing.memory != reservation.memory
            {
                return Err(capacity_rejection(format!(
                    "deployment {:?} generation {} changed its retained device or memory estimate",
                    reservation.deployment, reservation.generation
                )));
            }
            existing.protection = reservation.protection;
            existing.last_used = reservation.last_used;
            return Ok(());
        }
        let device = self
            .devices
            .get_mut(&reservation.memory.device_index)
            .ok_or_else(|| {
                capacity_rejection(format!(
                    "retained deployment {:?} selected missing device {}",
                    reservation.deployment, reservation.memory.device_index
                ))
            })?;
        let used = device
            .reservations
            .iter()
            .map(|existing| existing.memory.total_bytes)
            .sum::<u64>();
        if used.saturating_add(reservation.memory.total_bytes) > device.capacity_bytes {
            return Err(capacity_rejection(format!(
                "retained deployment {:?} generation {} no longer fits on device {}",
                reservation.deployment, reservation.generation, reservation.memory.device_index
            )));
        }
        device.reservations.push(reservation);
        Ok(())
    }

    /// Update lifecycle protection without changing capacity accounting.
    pub fn update_protection(
        &mut self,
        device_index: u32,
        deployment: &str,
        generation: u64,
        protection: ResidencyProtection,
    ) {
        if let Some(reservation) = self.devices.get_mut(&device_index).and_then(|device| {
            device.reservations.iter_mut().find(|reservation| {
                reservation.deployment == deployment && reservation.generation == generation
            })
        }) {
            reservation.protection = protection;
        }
    }

    /// Release one exact generation from its device.
    pub fn release(&mut self, device_index: u32, deployment: &str, generation: u64) {
        if let Some(device) = self.devices.get_mut(&device_index) {
            device.reservations.retain(|reservation| {
                reservation.deployment != deployment || reservation.generation != generation
            });
        }
    }

    /// Whether one exact generation is resident on the selected device.
    pub fn contains(&self, device_index: u32, deployment: &str, generation: u64) -> bool {
        self.devices.get(&device_index).is_some_and(|device| {
            device.reservations.iter().any(|reservation| {
                reservation.deployment == deployment && reservation.generation == generation
            })
        })
    }

    /// Used bytes on one device.
    pub fn used_bytes(&self, device_index: u32) -> u64 {
        self.devices
            .get(&device_index)
            .map(|device| {
                device
                    .reservations
                    .iter()
                    .map(|reservation| reservation.memory.total_bytes)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Deterministic snapshot of every reservation.
    pub fn reservations(&self) -> Vec<DeviceReservation> {
        self.devices
            .values()
            .flat_map(|device| device.reservations.iter().cloned())
            .collect()
    }
}

fn capacity_rejection(detail: impl AsRef<str>) -> AdmissionRejection {
    AdmissionRejection::new(AdmissionReason::InsufficientCapacity, detail, false, None)
}
