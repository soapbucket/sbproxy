// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Graceful shutdown plumbing.
//!
//! A cloneable signal that resolves once SIGTERM (what Kubernetes sends)
//! or SIGINT (Ctrl-C) arrives. Callers compose it into their own
//! `tokio::select!` arms.
//!
//! The signal and the thing that fires it are separate values, so tests
//! drive shutdown directly instead of raising real process signals at a
//! parallel test runner.

use tokio::sync::watch;

/// Cheaply cloneable shutdown signal.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Resolves once shutdown has been requested. Returns immediately if
    /// it already was.
    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        if *rx.borrow() {
            return;
        }
        // Looped because `changed()` can wake without the value having
        // moved to true.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

/// Fires a [`ShutdownSignal`].
#[derive(Clone, Debug)]
pub struct ShutdownTrigger {
    tx: watch::Sender<bool>,
}

impl ShutdownTrigger {
    /// Request shutdown. Idempotent.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}

/// Build a signal and its trigger.
pub fn channel() -> (ShutdownSignal, ShutdownTrigger) {
    let (tx, rx) = watch::channel(false);
    (ShutdownSignal { rx }, ShutdownTrigger { tx })
}

/// Wait for SIGTERM or SIGINT, then fire `trigger`.
///
/// On non-Unix targets this parks forever: the controller ships in a
/// Linux pod, and a no-op that returned immediately would look like an
/// instant shutdown to whatever awaits it.
pub async fn install_signal_handler(trigger: ShutdownTrigger) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: "k8s_audit", error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: "k8s_audit", error = %e, "failed to install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!(target: "k8s_audit", "SIGTERM received, beginning graceful shutdown");
            }
            _ = sigint.recv() => {
                tracing::info!(target: "k8s_audit", "SIGINT received, beginning graceful shutdown");
            }
        }
        trigger.trigger();
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
        let _ = trigger;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_waiting_task_wakes_on_trigger() {
        let (sig, trig) = channel();
        let waiter = tokio::spawn(async move { sig.wait().await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        trig.trigger();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .is_ok(),
            "the waiter did not wake"
        );
    }

    #[tokio::test]
    async fn waiting_after_the_trigger_returns_immediately() {
        let (sig, trig) = channel();
        trig.trigger();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), sig.wait())
                .await
                .is_ok(),
            "a pre-fired trigger must not block a later waiter"
        );
    }

    #[tokio::test]
    async fn every_clone_sees_the_same_shutdown() {
        let (sig, trig) = channel();
        let clone = sig.clone();
        trig.trigger();
        assert!(tokio::time::timeout(Duration::from_millis(100), sig.wait())
            .await
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), clone.wait())
                .await
                .is_ok()
        );
    }
}
