// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Test-only guard for the few tests that must mutate the process
//! environment (WOR-646).
//!
//! `std::env::set_var` / `remove_var` mutate state shared by every
//! thread in this test binary, and a mutation that races any concurrent
//! `getenv` is undefined behavior on POSIX; that race is why Rust 2024
//! makes both functions `unsafe`. Tests whose subject genuinely is the
//! environment (an env-var fallback path, `${VAR}` interpolation) go
//! through [`EnvVarGuard`], which serializes every mutation in this
//! binary behind one lock and restores the previous values when it is
//! dropped, panic included. Production code must never call `set_var` /
//! `remove_var` at all; `scripts/check-env-mutation.sh` enforces both
//! rules.

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, PoisonError};

static ENV_MUTATION: Mutex<()> = Mutex::new(());

/// RAII guard around process-environment mutation in tests.
///
/// Holds the binary-wide mutation lock for its whole lifetime, so
/// env-mutating tests serialize against each other, and restores every
/// variable it touched to its previous state on drop. Unwinding drops
/// the guard too, so a failing assertion cannot leak its environment
/// into the tests that run after it.
pub(crate) struct EnvVarGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    /// Apply `vars` to the process environment: `Some(value)` sets the
    /// variable, `None` removes it. The previous state of every named
    /// variable is captured first and restored on drop.
    pub(crate) fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
        // A panic while a guard is alive poisons the lock only after
        // `Drop` has already restored the environment, so the poison
        // carries no torn state; recover and keep going.
        let lock = ENV_MUTATION.lock().unwrap_or_else(PoisonError::into_inner);
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
        Self { saved, _lock: lock }
    }

    /// Re-set an already-guarded variable to a new value, for tests
    /// that sweep several values of one variable. Panics when `name`
    /// was not part of the guard's construction, because the guard
    /// would then not know how to restore it.
    pub(crate) fn update(&self, name: &'static str, value: &str) {
        assert!(
            self.saved.iter().any(|(saved, _)| *saved == name),
            "EnvVarGuard::update on a variable the guard does not own: {name}"
        );
        std::env::set_var(name, value);
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
