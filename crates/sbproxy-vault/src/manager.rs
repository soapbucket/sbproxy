//! Multi-vault orchestrator for routing secrets to different backends.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};

use crate::vault_ref::{VaultProviderType, VaultRef};

/// Trait that all vault backends must implement.
pub trait VaultBackend: Send + Sync {
    /// Retrieve a secret by key.
    fn get(&self, key: &str) -> Result<Option<String>>;
    /// Retrieve a secret from a parsed provider reference.
    ///
    /// Backends with provider-specific URI query semantics can
    /// override this. The default keeps existing backends on their
    /// path-only lookup behaviour.
    fn get_ref(&self, reference: &VaultRef) -> Result<Option<String>> {
        self.get(&reference.path)
    }
    /// Store a secret under the given key.
    fn set(&self, key: &str, value: &str) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BackendKey {
    provider_type: VaultProviderType,
    name: String,
}

impl BackendKey {
    fn new(provider_type: VaultProviderType, name: impl Into<String>) -> Self {
        Self {
            provider_type,
            name: name.into(),
        }
    }
}

/// Manages named vault backends and routes secret operations by the
/// provider type selected by a parsed URI scheme plus the backend name
/// selected by the URI authority.
pub struct VaultManager {
    vaults: HashMap<BackendKey, Box<dyn VaultBackend>>,
}

impl VaultManager {
    /// Create an empty vault manager.
    pub fn new() -> Self {
        Self {
            vaults: HashMap::new(),
        }
    }

    /// Register a local static secret-map backend under a name.
    ///
    /// This keeps the pre-provider-scheme API source-compatible. New
    /// code should prefer [`Self::register_backend`] so the backend is
    /// registered under its concrete provider type.
    pub fn register(&mut self, name: impl Into<String>, backend: Box<dyn VaultBackend>) {
        self.register_backend(VaultProviderType::LocalSecret, name, backend);
    }

    /// Register a named backend for a concrete provider type.
    pub fn register_backend(
        &mut self,
        provider_type: VaultProviderType,
        name: impl Into<String>,
        backend: Box<dyn VaultBackend>,
    ) {
        self.vaults
            .insert(BackendKey::new(provider_type, name), backend);
    }

    /// Return true when this manager has an exact `(provider type,
    /// backend name)` registration.
    pub fn contains_backend(&self, provider_type: VaultProviderType, name: &str) -> bool {
        self.vaults
            .contains_key(&BackendKey::new(provider_type, name))
    }

    /// Get a secret from a backend by name.
    ///
    /// This compatibility method is only unambiguous when the backend
    /// name exists for exactly one provider type in this manager. New
    /// code should prefer [`Self::get_typed`] or [`Self::get_from_ref`].
    pub fn get(&self, backend: &str, key: &str) -> Result<Option<String>> {
        let provider_type = self.single_provider_for_backend(backend)?;
        self.get_typed(provider_type, backend, key)
    }

    /// Get a secret from a specific provider type and named backend.
    pub fn get_typed(
        &self,
        provider_type: VaultProviderType,
        backend: &str,
        key: &str,
    ) -> Result<Option<String>> {
        self.get_with_metrics(provider_type, backend, |vault| vault.get(key))
    }

    fn get_with_metrics<F>(
        &self,
        provider_type: VaultProviderType,
        backend: &str,
        get: F,
    ) -> Result<Option<String>>
    where
        F: FnOnce(&dyn VaultBackend) -> Result<Option<String>>,
    {
        let start = std::time::Instant::now();
        let outcome = match self.vaults.get(&BackendKey::new(provider_type, backend)) {
            Some(vault) => get(vault.as_ref()),
            None => Err(anyhow!(
                "vault backend not found: {}://{}",
                provider_type.scheme(),
                backend
            )),
        };
        let elapsed = start.elapsed().as_secs_f64();
        let result_label = match &outcome {
            Ok(Some(_)) => "ok",
            Ok(None) => "not_found",
            Err(e) => classify_vault_error(&format!("{e:#}")),
        };
        sbproxy_observe::metrics::record_vault_resolution(
            provider_type.metric_label(),
            result_label,
            elapsed,
        );
        outcome
    }

    /// Resolve a parsed provider-specific reference against this
    /// manager. The backend path is read from [`VaultRef::path`], and a
    /// top-level JSON/map field is extracted when `?key=` is present.
    pub fn get_from_ref(&self, reference: &VaultRef) -> Result<Option<String>> {
        self.get_with_metrics(reference.provider_type, &reference.backend, |vault| {
            vault.get_ref(reference)
        })?
        .map(|secret| apply_key_selector(reference, secret))
        .transpose()
    }

    /// Resolve a parsed reference by walking managers in caller-supplied
    /// scope order, typically origin, then tenant, then proxy.
    ///
    /// The first scope that declares the exact `(provider type, backend
    /// name)` pair owns the reference. A missing secret in that backend
    /// does not fall through to a broader scope.
    pub fn resolve_ref_in_scopes(
        scopes: &[&VaultManager],
        reference: &VaultRef,
    ) -> Result<Option<String>> {
        for scope in scopes {
            if scope.contains_backend(reference.provider_type, &reference.backend) {
                return scope.get_from_ref(reference);
            }
        }
        Err(anyhow!(
            "vault backend not found: {}://{}",
            reference.provider_type.scheme(),
            reference.backend
        ))
    }

    /// Set a secret in a specific named backend.
    ///
    /// This compatibility method is only unambiguous when the backend
    /// name exists for exactly one provider type in this manager. New
    /// code should prefer [`Self::set_typed`].
    pub fn set(&self, backend: &str, key: &str, value: &str) -> Result<()> {
        let provider_type = self.single_provider_for_backend(backend)?;
        self.set_typed(provider_type, backend, key, value)
    }

    /// Set a secret in a specific provider type and named backend.
    pub fn set_typed(
        &self,
        provider_type: VaultProviderType,
        backend: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let vault = self
            .vaults
            .get(&BackendKey::new(provider_type, backend))
            .ok_or_else(|| {
                anyhow!(
                    "vault backend not found: {}://{}",
                    provider_type.scheme(),
                    backend
                )
            })?;
        vault.set(key, value)
    }

    /// List all registered backend names, de-duplicated across provider
    /// types.
    pub fn backends(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.vaults.keys().map(|k| k.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    fn single_provider_for_backend(&self, backend: &str) -> Result<VaultProviderType> {
        let mut matches = self
            .vaults
            .keys()
            .filter(|k| k.name == backend)
            .map(|k| k.provider_type);
        let Some(first) = matches.next() else {
            return Err(anyhow!("vault backend not found: {}", backend));
        };
        if matches.next().is_some() {
            return Err(anyhow!(
                "vault backend name `{backend}` is ambiguous across provider types; use a provider-specific lookup"
            ));
        }
        Ok(first)
    }
}

impl Default for VaultManager {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_key_selector(reference: &VaultRef, secret: String) -> Result<String> {
    let Some(key) = &reference.key else {
        return Ok(secret);
    };

    let value: serde_json::Value = serde_json::from_str(&secret).with_context(|| {
        format!(
            "vault reference {}://{}/{} requested `?key={key}`, but the secret value is not JSON",
            reference.provider_type.scheme(),
            reference.backend,
            reference.path
        )
    })?;
    let selected = value.get(key).ok_or_else(|| {
        anyhow!(
            "vault reference {}://{}/{} requested missing JSON field `{key}`",
            reference.provider_type.scheme(),
            reference.backend,
            reference.path
        )
    })?;
    match selected {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Null => Ok(String::new()),
        other => serde_json::to_string(other).with_context(|| {
            format!(
                "vault reference {}://{}/{} failed to render JSON field `{key}`",
                reference.provider_type.scheme(),
                reference.backend,
                reference.path
            )
        }),
    }
}

/// Map a vault error message (already formatted via `{:#}`) to the
/// closed `result` label set the metrics expose. The classification is
/// heuristic; the goal is to let dashboards split `denied`
/// (authorisation failure) and `not_found` (which the Ok-None arm
/// already covers) out from the catch-all `backend_error` bucket.
fn classify_vault_error(msg: &str) -> &'static str {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("denied") || lower.contains("permission") || lower.contains("forbidden") {
        "denied"
    } else if lower.contains("not found") {
        "not_found"
    } else {
        "backend_error"
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

    fn local_with(key: &str, value: &str) -> Box<dyn VaultBackend> {
        let vault = LocalVault::new();
        vault.set_secret(key, value).unwrap();
        Box::new(vault)
    }

    #[test]
    fn test_register_and_get() {
        let mut mgr = VaultManager::new();
        mgr.register("local", local_with("db_pass", "secret123"));

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
        mgr.register_backend(
            VaultProviderType::HashiCorp,
            "remote",
            Box::new(LocalVault::new()),
        );
        mgr.register_backend(
            VaultProviderType::AwsSecretsManager,
            "remote",
            Box::new(LocalVault::new()),
        );
        let mut names = mgr.backends();
        names.sort();
        assert_eq!(names, vec!["local", "remote"]);
    }

    #[test]
    fn typed_registration_disambiguates_same_backend_name() {
        let mut mgr = VaultManager::new();
        mgr.register_backend(
            VaultProviderType::HashiCorp,
            "primary",
            local_with("secret/data/openai", "hashicorp-value"),
        );
        mgr.register_backend(
            VaultProviderType::AwsSecretsManager,
            "primary",
            local_with("prod/openai", "aws-value"),
        );

        let hashi = VaultRef::parse("vault://primary/secret/data/openai").unwrap();
        let aws = VaultRef::parse("awssm://primary/prod/openai").unwrap();

        assert_eq!(
            mgr.get_from_ref(&hashi).unwrap(),
            Some("hashicorp-value".to_string())
        );
        assert_eq!(
            mgr.get_from_ref(&aws).unwrap(),
            Some("aws-value".to_string())
        );
        assert!(mgr.get("primary", "prod/openai").is_err());
    }

    #[test]
    fn legacy_aws_alias_dispatches_to_aws_backend() {
        let mut mgr = VaultManager::new();
        mgr.register_backend(
            VaultProviderType::AwsSecretsManager,
            "aws",
            local_with("prod/openai", r#"{"api_key":"sk-legacy"}"#),
        );

        let reference = VaultRef::parse("vault://aws/prod/openai?key=api_key").unwrap();
        assert_eq!(
            mgr.get_from_ref(&reference).unwrap(),
            Some("sk-legacy".to_string())
        );
    }

    #[test]
    fn parsed_reference_extracts_json_key() {
        let mut mgr = VaultManager::new();
        mgr.register_backend(
            VaultProviderType::AwsSecretsManager,
            "primary",
            local_with("prod/openai", r#"{"api_key":"sk-test","limit":5}"#),
        );

        let reference = VaultRef::parse("awssm://primary/prod/openai?key=api_key").unwrap();
        assert_eq!(
            mgr.get_from_ref(&reference).unwrap(),
            Some("sk-test".to_string())
        );

        let reference = VaultRef::parse("awssm://primary/prod/openai?key=limit").unwrap();
        assert_eq!(mgr.get_from_ref(&reference).unwrap(), Some("5".to_string()));
    }

    #[test]
    fn scoped_resolution_uses_first_scope_with_matching_type_and_name() {
        let mut proxy = VaultManager::new();
        proxy.register_backend(
            VaultProviderType::HashiCorp,
            "primary",
            local_with("secret/data/openai", "proxy-value"),
        );

        let mut tenant = VaultManager::new();
        tenant.register_backend(
            VaultProviderType::HashiCorp,
            "primary",
            local_with("secret/data/openai", "tenant-value"),
        );

        let mut origin = VaultManager::new();
        origin.register_backend(
            VaultProviderType::AwsSecretsManager,
            "primary",
            local_with("secret/data/openai", "wrong-provider"),
        );

        let reference = VaultRef::parse("vault://primary/secret/data/openai").unwrap();
        assert_eq!(
            VaultManager::resolve_ref_in_scopes(&[&origin, &tenant, &proxy], &reference).unwrap(),
            Some("tenant-value".to_string())
        );
    }

    #[test]
    fn scoped_resolution_does_not_fall_through_after_backend_match() {
        let mut proxy = VaultManager::new();
        proxy.register_backend(
            VaultProviderType::HashiCorp,
            "primary",
            local_with("secret/data/openai", "proxy-value"),
        );

        let mut tenant = VaultManager::new();
        tenant.register_backend(
            VaultProviderType::HashiCorp,
            "primary",
            Box::new(LocalVault::new()),
        );

        let reference = VaultRef::parse("vault://primary/secret/data/openai").unwrap();
        assert_eq!(
            VaultManager::resolve_ref_in_scopes(&[&tenant, &proxy], &reference).unwrap(),
            None
        );
    }
}
