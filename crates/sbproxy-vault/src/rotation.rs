//! Secret rotation with grace period.
//!
//! When a secret is rotated the old value remains valid for a configurable
//! grace period so that in-flight requests using the old credential are not
//! immediately rejected.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::secret_string::SecretString;

// --- internal types ---

struct RotationEntry {
    current: SecretString,
    /// Previous value and the instant it was superseded.
    previous: Option<(SecretString, Instant)>,
}

// --- public API ---

/// Manages secret rotation with a configurable grace period.
///
/// During the grace period both the current **and** the previous value are
/// accepted when calling [`validate`](RotationManager::validate), which
/// allows clients holding the old credential to finish their requests without
/// being forcibly disconnected.
pub struct RotationManager {
    secrets: Mutex<HashMap<String, RotationEntry>>,
    grace_period: Duration,
    re_resolve_interval: Duration,
    last_resolve: Mutex<Instant>,
}

impl RotationManager {
    /// Create a new manager.
    ///
    /// - `grace_period_secs` - how long (seconds) the previous secret value
    ///   remains valid after a rotation.
    /// - `re_resolve_interval_secs` - how often the manager considers it time to
    ///   re-fetch secrets from the vault backend.
    pub fn new(grace_period_secs: u64, re_resolve_interval_secs: u64) -> Self {
        Self {
            secrets: Mutex::new(HashMap::new()),
            grace_period: Duration::from_secs(grace_period_secs),
            re_resolve_interval: Duration::from_secs(re_resolve_interval_secs),
            last_resolve: Mutex::new(Instant::now()),
        }
    }

    /// Update (or insert) the current value for `name`.
    ///
    /// The previous current value, if any, enters the grace period.
    pub fn update(&self, name: &str, new_value: SecretString) {
        let mut map = self.secrets.lock().unwrap();
        let previous = map.remove(name).map(|old| (old.current, Instant::now()));
        map.insert(
            name.to_string(),
            RotationEntry {
                current: new_value,
                previous,
            },
        );
    }

    /// Return `true` if `candidate` matches the **current** value or the
    /// **previous** value still within its grace period.
    pub fn validate(&self, name: &str, candidate: &str) -> bool {
        let map = self.secrets.lock().unwrap();
        let Some(entry) = map.get(name) else {
            return false;
        };
        // Check current value.
        if entry.current == SecretString::new(candidate) {
            return true;
        }
        // Check grace-period previous value.
        if let Some((ref prev, replaced_at)) = entry.previous {
            if replaced_at.elapsed() < self.grace_period && *prev == SecretString::new(candidate) {
                return true;
            }
        }
        false
    }

    /// Return the current value of `name`, or `None` if unknown.
    pub fn get_current(&self, name: &str) -> Option<SecretString> {
        self.secrets
            .lock()
            .unwrap()
            .get(name)
            .map(|e| e.current.clone())
    }

    /// Return `true` when the re-resolve interval has elapsed since the last
    /// call to [`mark_resolved`](RotationManager::mark_resolved).
    pub fn needs_re_resolve(&self) -> bool {
        self.last_resolve.lock().unwrap().elapsed() >= self.re_resolve_interval
    }

    /// Record that secrets have just been re-resolved from the vault, resetting
    /// the re-resolve interval timer.
    pub fn mark_resolved(&self) {
        *self.last_resolve.lock().unwrap() = Instant::now();
    }

    /// Remove grace-period entries that have expired.
    pub fn cleanup_expired(&self) {
        let mut map = self.secrets.lock().unwrap();
        for entry in map.values_mut() {
            if let Some((_, replaced_at)) = &entry.previous {
                if replaced_at.elapsed() >= self.grace_period {
                    entry.previous = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn mgr(grace_secs: u64) -> RotationManager {
        RotationManager::new(grace_secs, 3600)
    }

    // --- update and get_current ---

    #[test]
    fn update_replaces_current_value() {
        let m = mgr(300);
        m.update("key", SecretString::new("v1"));
        m.update("key", SecretString::new("v2"));
        assert_eq!(m.get_current("key").unwrap().expose(), "v2");
    }

    #[test]
    fn get_current_returns_none_for_unknown_key() {
        let m = mgr(300);
        assert!(m.get_current("nonexistent").is_none());
    }

    // --- validate ---

    #[test]
    fn validate_current_value_accepted() {
        let m = mgr(300);
        m.update("token", SecretString::new("current_secret"));
        assert!(m.validate("token", "current_secret"));
    }

    #[test]
    fn validate_old_value_accepted_within_grace_period() {
        let m = mgr(300); // 5 minute grace - definitely not expired in a test
        m.update("token", SecretString::new("old_secret"));
        m.update("token", SecretString::new("new_secret"));
        assert!(
            m.validate("token", "old_secret"),
            "grace period should still be active"
        );
        assert!(m.validate("token", "new_secret"));
    }

    #[test]
    fn validate_wrong_value_rejected() {
        let m = mgr(300);
        m.update("token", SecretString::new("correct"));
        assert!(!m.validate("token", "wrong"));
    }

    #[test]
    fn validate_unknown_key_returns_false() {
        let m = mgr(300);
        assert!(!m.validate("no_such_key", "anything"));
    }

    #[test]
    fn validate_expired_grace_period_rejects_old_value() {
        // Use 0-second grace period so it expires immediately.
        let m = RotationManager::new(0, 3600);
        m.update("token", SecretString::new("old"));
        m.update("token", SecretString::new("new"));
        // Sleep a tiny bit to ensure elapsed > 0.
        thread::sleep(Duration::from_millis(5));
        assert!(
            !m.validate("token", "old"),
            "expired grace period should reject old value"
        );
        assert!(m.validate("token", "new"));
    }

    // --- needs_re_resolve / mark_resolved ---

    #[test]
    fn needs_re_resolve_after_interval_elapsed() {
        // 0-second interval expires immediately.
        let m = RotationManager::new(300, 0);
        thread::sleep(Duration::from_millis(5));
        assert!(m.needs_re_resolve());
    }

    #[test]
    fn needs_re_resolve_false_immediately_after_mark_resolved() {
        let m = RotationManager::new(300, 3600);
        m.mark_resolved();
        assert!(!m.needs_re_resolve());
    }

    // --- cleanup_expired ---

    #[test]
    fn cleanup_removes_expired_previous_entries() {
        let m = RotationManager::new(0, 3600);
        m.update("key", SecretString::new("old"));
        m.update("key", SecretString::new("new"));
        thread::sleep(Duration::from_millis(5));
        m.cleanup_expired();
        // After cleanup the old value should be gone.
        assert!(!m.validate("key", "old"));
        assert!(m.validate("key", "new"));
    }

    #[test]
    fn cleanup_preserves_active_grace_period_entries() {
        let m = RotationManager::new(300, 3600); // 5-min grace
        m.update("key", SecretString::new("old"));
        m.update("key", SecretString::new("new"));
        m.cleanup_expired(); // should not remove still-valid previous
        assert!(
            m.validate("key", "old"),
            "active grace period should survive cleanup"
        );
    }
}
