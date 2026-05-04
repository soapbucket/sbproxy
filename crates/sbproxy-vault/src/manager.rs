//! Multi-vault orchestrator for routing secrets to different backends.

use std::collections::HashMap;

use anyhow::{anyhow, Result};

/// Trait that all vault backends must implement.
pub trait VaultBackend: Send + Sync {
    /// Retrieve a secret by key.
    fn get(&self, key: &str) -> Result<Option<String>>;
    /// Store a secret under the given key.
    fn set(&self, key: &str, value: &str) -> Result<()>;
}

/// Manages multiple named vault backends and routes secret operations
/// to the appropriate backend based on a prefix or explicit backend name.
pub struct VaultManager {
    vaults: HashMap<String, Box<dyn VaultBackend>>,
}

impl VaultManager {
    /// Create an empty vault manager.
    pub fn new() -> Self {
        Self {
            vaults: HashMap::new(),
        }
    }

    /// Register a named vault backend.
    pub fn register(&mut self, name: impl Into<String>, backend: Box<dyn VaultBackend>) {
        self.vaults.insert(name.into(), backend);
    }

    /// Get a secret from a specific named backend.
    pub fn get(&self, backend: &str, key: &str) -> Result<Option<String>> {
        let vault = self
            .vaults
            .get(backend)
            .ok_or_else(|| anyhow!("vault backend not found: {}", backend))?;
        vault.get(key)
    }

    /// Set a secret in a specific named backend.
    pub fn set(&self, backend: &str, key: &str, value: &str) -> Result<()> {
        let vault = self
            .vaults
            .get(backend)
            .ok_or_else(|| anyhow!("vault backend not found: {}", backend))?;
        vault.set(key, value)
    }

    /// List all registered backend names.
    pub fn backends(&self) -> Vec<&str> {
        self.vaults.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for VaultManager {
    fn default() -> Self {
        Self::new()
    }
}

// Implement VaultBackend for LocalVault so it can be used with the manager.
// `get_secret_exposed` returns a plaintext `String` to satisfy the trait
// contract. Callers that want zeroize-on-drop semantics should use
// `LocalVault::get_secret` directly.
impl VaultBackend for crate::local::LocalVault {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.get_secret_exposed(key)
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.set_secret(key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalVault;

    #[test]
    fn test_register_and_get() {
        let mut mgr = VaultManager::new();
        let vault = LocalVault::new();
        vault.set_secret("db_pass", "secret123").unwrap();
        mgr.register("local", Box::new(vault));

        assert_eq!(
            mgr.get("local", "db_pass").unwrap(),
            Some("secret123".to_string())
        );
    }

    #[test]
    fn test_missing_backend_returns_error() {
        let mgr = VaultManager::new();
        assert!(mgr.get("nonexistent", "key").is_err());
    }

    #[test]
    fn test_set_via_manager() {
        let mut mgr = VaultManager::new();
        mgr.register("local", Box::new(LocalVault::new()));
        mgr.set("local", "token", "abc").unwrap();
        assert_eq!(mgr.get("local", "token").unwrap(), Some("abc".to_string()));
    }

    #[test]
    fn test_list_backends() {
        let mut mgr = VaultManager::new();
        mgr.register("local", Box::new(LocalVault::new()));
        mgr.register("remote", Box::new(LocalVault::new()));
        let mut names = mgr.backends();
        names.sort();
        assert_eq!(names, vec!["local", "remote"]);
    }
}
