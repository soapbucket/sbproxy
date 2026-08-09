// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Liveness and readiness answers for the controller pod.
//!
//! `/healthz` is alive-or-not: the process answering at all is the whole
//! signal. `/readyz` stays 503 until the first reconcile pass succeeds,
//! so a rollout does not retire the old replica until the new one has
//! actually rendered a document.

use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);

/// Flip the process-global readiness flag.
pub fn set_ready(ready: bool) {
    READY.store(ready, Ordering::Release);
}

/// Whether the first reconcile pass has succeeded.
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Liveness answer as `(status, body)`. Always 200 while the process runs.
pub fn health_check() -> (u16, &'static str) {
    (200, r#"{"status":"ok"}"#)
}

/// Readiness answer as `(status, body)`. 503 until [`set_ready`] is
/// called with `true`.
pub fn readiness_check() -> (u16, &'static str) {
    if is_ready() {
        (200, r#"{"ready":true}"#)
    } else {
        (503, r#"{"ready":false}"#)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These share one process-global flag, so they are written as a
    // single test rather than several that would race each other under
    // the default parallel test runner.
    #[test]
    fn readiness_tracks_the_flag_and_health_does_not() {
        set_ready(false);
        assert_eq!(readiness_check().0, 503);
        assert!(!is_ready());
        assert_eq!(health_check().0, 200, "liveness ignores readiness");

        set_ready(true);
        assert_eq!(readiness_check().0, 200);
        assert!(is_ready());

        set_ready(false);
        assert_eq!(readiness_check().0, 503);
    }

    #[test]
    fn both_bodies_are_valid_json() {
        let (_, health) = health_check();
        let parsed: serde_json::Value = serde_json::from_str(health).expect("health body is JSON");
        assert_eq!(parsed["status"], "ok");

        let (_, ready) = readiness_check();
        let parsed: serde_json::Value =
            serde_json::from_str(ready).expect("readiness body is JSON");
        assert!(parsed["ready"].is_boolean());
    }
}
