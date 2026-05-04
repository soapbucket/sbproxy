//! Per-model permissions on virtual API keys.
//!
//! `KeyPermissions` maps virtual key strings to the set of model identifiers
//! they are allowed to invoke.  An empty allowed-set means all models are
//! permitted ("allow all").

use std::collections::{HashMap, HashSet};

/// Tracks which models each virtual key is permitted to use.
pub struct KeyPermissions {
    /// key -> allowed model set (empty = allow all)
    permissions: HashMap<String, HashSet<String>>,
}

impl KeyPermissions {
    /// Create a new, empty `KeyPermissions` store.
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
        }
    }

    /// Set the allowed models for `key`.
    ///
    /// Passing an empty `models` vec means the key is allowed to use all
    /// models (no restriction).
    pub fn set_allowed_models(&mut self, key: &str, models: Vec<String>) {
        self.permissions
            .insert(key.to_string(), models.into_iter().collect());
    }

    /// Return `true` if `model` is allowed for `key`.
    ///
    /// - If the key is unknown, returns `true` (fail open for unknown keys;
    ///   auth middleware is responsible for validating keys exist).
    /// - If the key has an empty allowed set, all models are permitted.
    /// - Otherwise, only models in the allowed set are permitted.
    pub fn is_model_allowed(&self, key: &str, model: &str) -> bool {
        match self.permissions.get(key) {
            None => true,
            Some(set) if set.is_empty() => true,
            Some(set) => set.contains(model),
        }
    }

    /// Return the set of allowed models for `key`, or `None` if the key is
    /// not registered.
    pub fn allowed_models(&self, key: &str) -> Option<&HashSet<String>> {
        self.permissions.get(key)
    }
}

impl Default for KeyPermissions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_allows_all_models() {
        let kp = KeyPermissions::new();
        assert!(kp.is_model_allowed("unknown-key", "gpt-4"));
    }

    #[test]
    fn empty_allowed_set_allows_all_models() {
        let mut kp = KeyPermissions::new();
        kp.set_allowed_models("key1", vec![]);
        assert!(kp.is_model_allowed("key1", "any-model"));
        assert!(kp.is_model_allowed("key1", "gpt-4o"));
    }

    #[test]
    fn specific_model_is_allowed() {
        let mut kp = KeyPermissions::new();
        kp.set_allowed_models(
            "key2",
            vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()],
        );
        assert!(kp.is_model_allowed("key2", "gpt-4"));
        assert!(kp.is_model_allowed("key2", "gpt-3.5-turbo"));
    }

    #[test]
    fn blocked_model_is_rejected() {
        let mut kp = KeyPermissions::new();
        kp.set_allowed_models("key3", vec!["gpt-4".to_string()]);
        assert!(!kp.is_model_allowed("key3", "claude-3-opus"));
    }

    #[test]
    fn allowed_models_returns_registered_set() {
        let mut kp = KeyPermissions::new();
        kp.set_allowed_models("key4", vec!["m1".to_string(), "m2".to_string()]);
        let set = kp.allowed_models("key4").unwrap();
        assert!(set.contains("m1"));
        assert!(set.contains("m2"));
    }

    #[test]
    fn allowed_models_returns_none_for_unknown() {
        let kp = KeyPermissions::new();
        assert!(kp.allowed_models("ghost").is_none());
    }

    #[test]
    fn overwriting_permissions_replaces_old_set() {
        let mut kp = KeyPermissions::new();
        kp.set_allowed_models("key5", vec!["old-model".to_string()]);
        kp.set_allowed_models("key5", vec!["new-model".to_string()]);
        assert!(kp.is_model_allowed("key5", "new-model"));
        assert!(!kp.is_model_allowed("key5", "old-model"));
    }
}
