// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Test-only guard for the few tests that must mutate the process
//! environment (WOR-646).
//!
//! `std::env::set_var` / `remove_var` mutate state shared by every
//! thread in this test binary, and a mutation that races any concurrent
//! `getenv` is undefined behavior on POSIX; that race is why Rust 2024
//! makes both functions `unsafe`. The env-mutating tests in this crate
//! are async, so serialization happens through the binary's existing
//! `tokio::sync::Mutex` (holding a `std` mutex guard across an `.await`
//! would trip `clippy::await_holding_lock`). [`EnvVarGuard`] therefore
//! only owns restore-on-drop: acquire the async lock first, then build
//! the guard, and the previous values come back when it drops, panic
//! included. Production code must never call `set_var` / `remove_var`
//! at all; `scripts/check-env-mutation.sh` enforces both rules.

use std::ffi::OsString;

/// RAII restore for process-environment mutation in async tests.
///
/// The caller must already hold the test binary's env serialization
/// lock; this guard captures the previous state of every variable it
/// touches and restores it on drop. Unwinding drops the guard too, so
/// a failing assertion cannot leak its environment into the tests that
/// run after it.
pub(crate) struct EnvVarGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvVarGuard {
    /// Apply `vars` to the process environment: `Some(value)` sets the
    /// variable, `None` removes it. The previous state of every named
    /// variable is captured first and restored on drop.
    pub(crate) fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
        let saved = vars
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect();
        for (name, value) in vars {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (name, previous) in self.saved.drain(..).rev() {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}
