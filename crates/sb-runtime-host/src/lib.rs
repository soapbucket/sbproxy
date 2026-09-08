// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Runtime-neutral managed engine process and lifecycle host.

mod command;
mod driver;
mod ownership;
mod probe;
mod process;
mod supervisor;
#[cfg(feature = "test-support")]
mod testing;

pub use command::EngineCommand;
pub use driver::{EngineDriver, LaunchRequest, ProvisionRequest, ProvisionedEngine, RunningEngine};
pub use ownership::{
    capture_managed_engine_owner, reap_managed_engines_owned_by_at,
    reap_managed_engines_owned_by_identity_at, reap_stale_managed_engines_at, ManagedEngineOwner,
    ProcessOwnershipStore,
};
pub use probe::{EngineReadinessProbe, LoopbackReadinessProbe};
pub use process::{
    CommandExecutor, CommandOutput, EngineProcess, EngineProcessRunner, TokioCommandExecutor,
};
pub use supervisor::{
    BackoffPolicy, CrashLoopState, EngineSupervisor, SupervisorClock, TokioSupervisorClock,
};
#[cfg(feature = "test-support")]
pub use testing::{
    FakeCommandExecutor, FakeProcess, FakeReadinessProbe, ManualClock, ScriptedDriver,
    ScriptedLaunchRequest, ScriptedProvisionRequest, ScriptedProvisionedEngine,
    ScriptedRunningEngine,
};
