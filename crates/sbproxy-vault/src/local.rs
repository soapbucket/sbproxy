//! Local in-memory secret store.
//!
//! Stored values are wrapped in [`SecretString`] so that memory is zeroed
//! on drop and accidental `Display`/`Debug` formatting renders `[REDACTED]`
//! instead of the plaintext.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;

use crate::secret_string::SecretString;

/// A simple in-memory secret store.
///
/// Each value is held as a [`SecretString`]; reading via
/// [`LocalVault::get_secret`] returns a fresh `SecretString` (zeroize on
/// drop). For backwards-compatible callers that need a raw `String` use
/// [`LocalVault::get_secret_exposed`] sparingly and avoid logging the
/// returned value.
pub struct LocalVault {
    secrets: Mutex<HashMap<String, SecretString>>,
}

impl LocalVault {
    /// Create a new empty vault.
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieve a secret by key as a [`SecretString`].
    ///
    /// Returns `None` if the key is absent. The returned `SecretString`
    /// zeroizes its backing memory when dropped.
    pub fn get_secret(&self, key: &str) -> Result<Option<SecretString>> {
        Ok(self.secrets.lock().unwrap().get(key).cloned())
    }

    /// Retrieve a secret by key and expose its plaintext as a `String`.
    ///
    /// Provided for callers that interact with APIs requiring a `String`.
    /// Use sparingly and never log the returned value.
    pub fn get_secret_exposed(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .secrets
            .lock()
            .unwrap()
            .get(key)
            .map(|s| s.expose().to_string()))
    }

    /// Store a secret under the given key, overwriting any previous value.
    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        self.secrets
            .lock()
            .unwrap()
            .insert(key.to_string(), SecretString::new(value));
        Ok(())
    }

    /// Delete a secret by key. No-op if the key does not exist.
    pub fn delete_secret(&self, key: &str) -> Result<()> {
        self.secrets.lock().unwrap().remove(key);
        Ok(())
    }

    /// List all secret keys currently stored.
    pub fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self.secrets.lock().unwrap().keys().cloned().collect())
    }
}

impl Default for LocalVault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_secret_returns_secret_string() {
        let vault = LocalVault::new();
        vault.set_secret("api_key", "sk-12345").unwrap();
        let got = vault.get_secret("api_key").unwrap().unwrap();
        assert_eq!(got.expose(), "sk-12345");
    }

    #[test]
    fn test_get_missing_key_returns_none() {
        let vault = LocalVault::new();
        assert!(vault.get_secret("nonexistent").unwrap().is_none());
        assert!(vault.get_secret_exposed("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_get_secret_exposed_returns_plaintext() {
        let vault = LocalVault::new();
        vault.set_secret("api_key", "sk-12345").unwrap();
        assert_eq!(
            vault.get_secret_exposed("api_key").unwrap(),
            Some("sk-12345".to_string())
        );
    }

    #[test]
    fn test_delete_secret() {
        let vault = LocalVault::new();
        vault.set_secret("temp", "value").unwrap();
        vault.delete_secret("temp").unwrap();
        assert!(vault.get_secret("temp").unwrap().is_none());
    }

    #[test]
    fn test_list_keys() {
        let vault = LocalVault::new();
        vault.set_secret("a", "1").unwrap();
        vault.set_secret("b", "2").unwrap();
        let mut keys = vault.list_keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_overwrite_secret() {
        let vault = LocalVault::new();
        vault.set_secret("key", "old").unwrap();
        vault.set_secret("key", "new").unwrap();
        let got = vault.get_secret("key").unwrap().unwrap();
        assert_eq!(got.expose(), "new");
    }

    #[test]
    fn test_secret_string_redacts_on_display() {
        let vault = LocalVault::new();
        vault.set_secret("token", "should-not-leak").unwrap();
        let got = vault.get_secret("token").unwrap().unwrap();
        assert_eq!(format!("{}", got), "[REDACTED]");
        assert_eq!(format!("{:?}", got), "[REDACTED]");
    }
}
