// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-device generation residency and protected eviction planning.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AdmissionReason, AdmissionRejection, MemoryEstimate};

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
        let device = self.devices.get_mut(&memory.device_index).ok_or_else(|| {
            capacity_rejection(format!(
                "selected device {} is not present",
                memory.device_index
            ))
        })?;
        if let Some(existing) = device.reservations.iter_mut().find(|reservation| {
            reservation.deployment == deployment && reservation.generation == generation
        }) {
            if existing.memory != memory {
                return Err(capacity_rejection(format!(
                    "deployment {deployment:?} generation {generation} changed its immutable memory estimate"
                )));
            }
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
        let used = device
            .reservations
            .iter()
            .map(|reservation| reservation.memory.total_bytes)
            .sum::<u64>();
        let free = device.capacity_bytes.saturating_sub(used);
        let needed = memory.total_bytes.saturating_sub(free);
        let mut victims = device
            .reservations
            .iter()
            .filter(|reservation| !reservation.protection.is_protected())
            .map(|reservation| {
                (
                    reservation.last_used,
                    reservation.deployment.clone(),
                    reservation.generation,
                    reservation.memory.total_bytes,
                )
            })
            .collect::<Vec<_>>();
        victims.sort_by(|left, right| {
            (left.0, left.1.as_str(), left.2).cmp(&(right.0, right.1.as_str(), right.2))
        });
        let mut reclaimed = 0u64;
        let mut selected = Vec::new();
        for victim in victims {
            if reclaimed >= needed {
                break;
            }
            reclaimed = reclaimed.saturating_add(victim.3);
            selected.push(victim);
        }
        if reclaimed < needed {
            return Err(capacity_rejection(format!(
                "device {} lacks {} bytes after protecting active, queued, pinned, preparing, and draining generations",
                memory.device_index,
                needed.saturating_sub(reclaimed)
            )));
        }
        let selected_keys = selected
            .iter()
            .map(|victim| (victim.1.as_str(), victim.2))
            .collect::<Vec<_>>();
        device.reservations.retain(|reservation| {
            !selected_keys.iter().any(|(deployment, generation)| {
                *deployment == reservation.deployment && *generation == reservation.generation
            })
        });
        let evicted = selected
            .into_iter()
            .map(|victim| victim.1)
            .collect::<Vec<_>>();
        device.reservations.push(DeviceReservation {
            deployment: deployment.to_string(),
            generation,
            memory,
            protection,
            last_used: now,
        });
        Ok(DeviceReservationResult { evicted })
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
