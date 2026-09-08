// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

/// Static artifact, accelerator, and launch compatibility declared by a driver.
///
/// The artifact and accelerator types are host-owned parameters. This record
/// describes driver compatibility only. It is not a runtime protocol
/// conformance or verification record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineCapabilities<ArtifactFormat, Accelerator> {
    /// Artifact formats the engine can consume.
    pub artifact_formats: Vec<ArtifactFormat>,
    /// Accelerator families supported by this build path.
    pub accelerators: Vec<Accelerator>,
    /// Whether the driver implements isolated container launch.
    pub supports_container: bool,
    /// Whether the driver implements a managed uv environment.
    pub supports_uv: bool,
}
