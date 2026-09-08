// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::EngineKind;

/// Whether an engine can run in the detected environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineAvailability {
    /// A compatible engine is installed and ready for use.
    Available,
    /// A compatible, pinned engine can be provisioned automatically.
    Acquirable,
    /// The engine exists but cannot run in this environment or with the artifact.
    Incompatible,
    /// Host policy prevents otherwise supported provisioning or launch.
    Blocked,
}

/// Stable engine detection result shared by control and reconciliation paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineDetection {
    /// Managed engine kind.
    pub kind: EngineKind,
    /// Current availability state.
    pub availability: EngineAvailability,
    /// Detected or pinned version, when known.
    pub version: Option<String>,
    /// Concise operator-safe reason.
    pub reason: String,
    /// Action that makes a non-available engine usable.
    pub remediation: Option<String>,
}
