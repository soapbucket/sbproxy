// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current health of a launched engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineHealth {
    /// Process is alive but its readiness endpoint is not ready yet.
    Starting,
    /// Process is alive and its readiness endpoint is healthy.
    Ready,
    /// Process is alive but its health endpoint reports an error.
    Unhealthy,
    /// Process has exited.
    Stopped,
}
