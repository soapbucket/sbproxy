//! Universal secret resolver.
//!
//! Resolves `secret:<name>`, `${ENV_VAR}`, and `file:/path/to/file` patterns
//! embedded in config string values.  Plain strings are passed through unchanged.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};

use crate::manager::{VaultBackend, VaultManager};
use crate::vault_ref::{
    legacy_vault_env_name, legacy_vault_reference_replacement, warn_legacy_vault_reference_once,
    VaultRef,
};

/// Process-wide secret resolver, installed once at binary boot (WOR-1767).
static PROCESS_RESOLVER: OnceLock<Arc<SecretResolver>> = OnceLock::new();

/// Install the process-wide secret resolver used to resolve provider-URI
/// references (`secret://`, `secretfile://`, `vault://`, ...) in config
/// values at handler-build time (WOR-1767). Call once at boot, before the
/// server compiles its config. A second call is ignored.
pub fn install_process_resolver(resolver: Arc<SecretResolver>) {
    let _ = PROCESS_RESOLVER.set(resolver);
}

/// The process-wide secret resolver, if one was installed. Returns `None`
/// in contexts that never reach the wire (the `validate`/`plan`
/// subcommands, unit tests), where secret references are left as-is and
/// caught by plan-time validation instead.
pub fn process_resolver() -> Option<Arc<SecretResolver>> {
    PROCESS_RESOLVER.get().cloned()
}

/// Behaviour when the vault backend is unavailable and a `secret:` reference
/// needs to be resolved.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveFallback {
    /// Reserved for a future caller-managed last-good cache. NOT yet
    /// implemented: the resolver has no backend to populate a cache from
    /// on this path, so selecting `Cache` currently behaves like
    /// [`ResolveFallback::Reject`] (it fails with an error). Do not rely
    /// on it returning a cached value (WOR-1157).
    Cache,
    /// Fail with an error - the safest default.
    Reject,
    /// Try an environment variable whose name matches the vault path.
    Env,
}

/// Resolves secret references from any string value in config.
///
/// Supported reference patterns:
///
/// | Pattern | Resolution |
/// |---------|-----------|
/// | `secret:<name>` | Look up `<name>` in the logical map, then query the vault backend. |
/// | `${VAR_NAME}` | Read the environment variable `VAR_NAME`. |
/// | `file:/some/path` | Read the file at `/some/path` (trimmed). |
/// | anything else | Returned as-is. |
pub struct SecretResolver {
    backend: Option<Arc<dyn VaultBackend>>,
    /// Logical name -> vault path mapping.  Allows stable config names while the
    /// physical vault path can change.
    map: HashMap<String, String>,
    fallback: ResolveFallback,
    /// Provider-scheme backends (`vault://`, `awssm://`, `secretfile://`,
    /// `secret://`, ...). When set, a recognized reference resolves
    /// through here and a miss is a hard error, never passed through
    /// verbatim (WOR-1767).
    manager: Option<Arc<VaultManager>>,
}

impl SecretResolver {
    /// Create a new resolver.
    ///
    /// - `backend` - optional vault backend; when `None` the `fallback` strategy
    ///   is used for `secret:` references.
    /// - `map` - logical name to vault path mapping.
    pub fn new(backend: Option<Arc<dyn VaultBackend>>, map: HashMap<String, String>) -> Self {
        Self {
            backend,
            map,
            fallback: ResolveFallback::Reject,
            manager: None,
        }
    }

    /// Set the fallback strategy used when the vault backend is unavailable.
    pub fn with_fallback(mut self, fallback: ResolveFallback) -> Self {
        self.fallback = fallback;
        self
    }

    /// Attach the provider-scheme backend manager used to resolve
    /// `vault://`, `awssm://`, `secretfile://`, `secret://`, and the other
    /// provider-URI references (WOR-1767).
    pub fn with_manager(mut self, manager: Arc<VaultManager>) -> Self {
        self.manager = Some(manager);
        self
    }

    /// Resolve a config value synchronously.
    ///
    /// Returns the raw value unchanged if it does not match any secret pattern.
    ///
    /// # Blocking I/O
    ///
    /// `file:` references and the `secret:` path of HTTP-backed vault
    /// backends issue blocking I/O. This function is intended for
    /// **synchronous contexts only**: config load on startup, CLI tools,
    /// and tests. From an async runtime, prefer [`Self::resolve_async`]
    /// (which dispatches the work to a blocking thread pool) so the
    /// caller does not stall a Tokio worker.
    pub fn resolve(&self, value: &str) -> Result<String> {
        // Legacy `vault://env/NAME` alias -> env var (compat window). Checked
        // before the provider-URI parse so the alias keeps its env semantics.
        if let Some(var) = legacy_vault_env_name(value) {
            let replacement =
                legacy_vault_reference_replacement(value).unwrap_or_else(|| format!("${{{var}}}"));
            warn_legacy_vault_reference_once(value, &replacement);
            return std::env::var(var).with_context(|| format!("env var {} not set", var));
        }
        // Whole-value `${VAR}` -> env var.
        if value.starts_with("${") && value.ends_with('}') {
            let var = &value[2..value.len() - 1];
            return std::env::var(var).with_context(|| format!("env var {} not set", var));
        }
        // `file:/path` -> file contents.
        if let Some(path) = value.strip_prefix("file:") {
            return std::fs::read_to_string(path)
                .with_context(|| format!("failed to read secret file: {}", path))
                .map(|s| s.trim().to_string());
        }
        // Provider-URI schemes: vault:// awssm:// gcpsm:// k8ssecret://
        // secretfile:// secret://. Resolve through the backend manager.
        // WOR-1767: a recognized reference that cannot be resolved is a HARD
        // ERROR, never passed through verbatim (a literal `vault://...`
        // reaching an upstream as a bearer token is the footgun this closes).
        // Checked before the deprecated `secret:` colon form so `secret://`
        // is routed to the manager, not mis-parsed as a `secret:` name.
        if let Ok(reference) = VaultRef::parse(value) {
            return match &self.manager {
                Some(manager) => manager
                    .get_from_ref(&reference)?
                    .ok_or_else(|| anyhow::anyhow!("secret not found for reference: {value}")),
                None => anyhow::bail!(
                    "no secret backend configured to resolve {value}; declare it under \
                     proxy.secrets.backends"
                ),
            };
        }
        // Deprecated `secret:<name>` (colon) form. Superseded by
        // `secret://<backend>/<name>`; kept for the compat window.
        if let Some(name) = value.strip_prefix("secret:") {
            return self.resolve_secret(name);
        }
        // Plain value: passed through. WOR-1165: only a whole-value `${VAR}`
        // wrapper is expanded; an embedded `${..}` inside a larger string is
        // literal, so warn rather than silently surprise the operator.
        if value.contains("${") {
            tracing::warn!(
                "config value embeds an env-style `${{VAR}}` reference, but only a whole-value \
                 `${{VAR}}` wrapper is expanded; this value is passed through literally"
            );
        }
        Ok(value.to_string())
    }

    /// Async wrapper around [`Self::resolve`] that dispatches the call to
    /// `tokio::task::spawn_blocking`, so file reads and blocking vault HTTP
    /// clients never stall a Tokio worker.
    ///
    /// Requires the resolver to be wrapped in `Arc` so the closure moved
    /// into the blocking pool can outlive the originating future without
    /// borrowing the caller's stack.
    pub async fn resolve_async(self: Arc<Self>, value: String) -> Result<String> {
        tokio::task::spawn_blocking(move || self.resolve(&value))
            .await
            .context("resolve_async blocking task panicked")?
    }

    /// Heuristic warning: return `true` when a plain string looks like it
    /// should be stored in the vault instead of appearing inline in config.
    pub fn check_plain_string_warning(value: &str) -> bool {
        // Well-known secret prefixes.
        if value.starts_with("sk-")
            || value.starts_with("ghp_")
            || value.starts_with("gho_")
            || value.starts_with("AKIA")
        {
            return true;
        }
        // Long alphanumeric strings that look like tokens/keys.
        value.len() > 30
            && value
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    }

    /// Return the logical name to vault path map.
    pub fn map_entries(&self) -> &HashMap<String, String> {
        &self.map
    }

    // --- private ---

    fn resolve_secret(&self, name: &str) -> Result<String> {
        let vault_path = self
            .map
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string());

        match &self.backend {
            Some(backend) => match backend.get(&vault_path)? {
                Some(value) => Ok(value),
                None => anyhow::bail!("secret not found in vault: {} (path: {})", name, vault_path),
            },
            None => match self.fallback {
                ResolveFallback::Env => std::env::var(&vault_path).with_context(|| {
                    format!("no vault backend and env var {} not set", vault_path)
                }),
                ResolveFallback::Reject => {
                    anyhow::bail!("no vault backend configured for secret: {}", name)
                }
                ResolveFallback::Cache => {
                    anyhow::bail!("no cached value for secret: {} (vault unavailable)", name)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalVault;

    /// Serializes the tests that mutate the process-global environment so
    /// `std::env::set_var`/`remove_var` never race a concurrent reader in
    /// this test binary.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn backend_with(key: &str, value: &str) -> Arc<dyn VaultBackend> {
        let vault = LocalVault::new();
        vault.set_secret(key, value).unwrap();
        Arc::new(vault)
    }

    fn resolver_no_backend() -> SecretResolver {
        SecretResolver::new(None, HashMap::new())
    }

    // --- secret: prefix ---

    #[test]
    fn resolve_secret_prefix_found() {
        let resolver =
            SecretResolver::new(Some(backend_with("my_key", "super_secret")), HashMap::new());
        assert_eq!(resolver.resolve("secret:my_key").unwrap(), "super_secret");
    }

    #[test]
    fn resolve_secret_not_found_returns_error() {
        let resolver = SecretResolver::new(Some(backend_with("other", "val")), HashMap::new());
        assert!(resolver.resolve("secret:missing_key").is_err());
    }

    #[test]
    fn resolve_secret_via_logical_map() {
        let mut map = HashMap::new();
        map.insert("token".to_string(), "vault/path/token".to_string());
        let resolver = SecretResolver::new(Some(backend_with("vault/path/token", "abc123")), map);
        assert_eq!(resolver.resolve("secret:token").unwrap(), "abc123");
    }

    #[test]
    fn resolve_secret_no_backend_env_fallback() {
        // Hold the lock for the whole body so no other env-mutating test runs
        // concurrently. SAFETY (for both unsafe blocks below): `set_var` /
        // `remove_var` mutate process-global state; ENV_LOCK excludes the
        // other env tests in this binary, and no vault code reads the
        // environment except through these locked tests, so there is no
        // concurrent environment access.
        let _env = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("TEST_SECRET_ENV_FALLBACK", "from_env") };
        let resolver = resolver_no_backend().with_fallback(ResolveFallback::Env);
        let result = resolver.resolve("secret:TEST_SECRET_ENV_FALLBACK").unwrap();
        assert_eq!(result, "from_env");
        unsafe { std::env::remove_var("TEST_SECRET_ENV_FALLBACK") };
    }

    #[test]
    fn resolve_secret_no_backend_reject_returns_error() {
        let resolver = resolver_no_backend().with_fallback(ResolveFallback::Reject);
        assert!(resolver.resolve("secret:anything").is_err());
    }

    #[test]
    fn resolve_secret_no_backend_cache_returns_error() {
        let resolver = resolver_no_backend().with_fallback(ResolveFallback::Cache);
        assert!(resolver.resolve("secret:anything").is_err());
    }

    // --- ${ENV} ---

    #[test]
    fn resolve_env_var_pattern() {
        // SAFETY (for both unsafe blocks below): ENV_LOCK serializes the
        // env-mutating tests in this binary, so `set_var`/`remove_var` never
        // race a concurrent environment access.
        let _env = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("TEST_RESOLVER_ENV", "from_environment") };
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver.resolve("${TEST_RESOLVER_ENV}").unwrap(),
            "from_environment"
        );
        unsafe { std::env::remove_var("TEST_RESOLVER_ENV") };
    }

    #[test]
    fn resolve_legacy_vault_env_reference() {
        // SAFETY (for both unsafe blocks below): ENV_LOCK serializes the
        // env-mutating tests in this binary, so `set_var`/`remove_var` never
        // race a concurrent environment access.
        let _env = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("TEST_LEGACY_VAULT_ENV", "from_legacy_env") };
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver
                .resolve("vault://env/TEST_LEGACY_VAULT_ENV")
                .unwrap(),
            "from_legacy_env"
        );
        unsafe { std::env::remove_var("TEST_LEGACY_VAULT_ENV") };
    }

    #[test]
    fn resolve_env_var_missing_returns_error() {
        let resolver = resolver_no_backend();
        assert!(resolver.resolve("${DEFINITELY_NOT_SET_VAR_XYZ}").is_err());
    }

    // --- file: ---

    #[test]
    fn resolve_file_prefix() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "  file_secret_value  ").unwrap();
        let path = format!("file:{}", tmp.path().display());
        let resolver = resolver_no_backend();
        assert_eq!(resolver.resolve(&path).unwrap(), "file_secret_value");
    }

    #[test]
    fn resolve_file_missing_returns_error() {
        let resolver = resolver_no_backend();
        assert!(resolver.resolve("file:/does/not/exist/xyzzy").is_err());
    }

    // --- plain string ---

    #[test]
    fn resolve_plain_string_passthrough() {
        let resolver = resolver_no_backend();
        assert_eq!(resolver.resolve("just_a_value").unwrap(), "just_a_value");
        assert_eq!(
            resolver.resolve("http://example.com").unwrap(),
            "http://example.com"
        );
    }

    // --- provider-URI schemes via the manager (WOR-1767) ---

    fn manager_with_local(name: &str, key: &str, value: &str) -> Arc<VaultManager> {
        let vault = LocalVault::new();
        vault.set_secret(key, value).unwrap();
        let mut mgr = VaultManager::new();
        mgr.register(name, Box::new(vault));
        Arc::new(mgr)
    }

    #[test]
    fn resolve_secret_scheme_via_manager() {
        let mgr = manager_with_local("local", "openai", "sk-resolved");
        let resolver = SecretResolver::new(None, HashMap::new()).with_manager(mgr);
        assert_eq!(
            resolver.resolve("secret://local/openai").unwrap(),
            "sk-resolved"
        );
    }

    #[test]
    fn unresolved_provider_uri_errors_not_verbatim() {
        // The footgun this closes: a provider-URI reference must never be
        // passed through verbatim (which would send the literal `vault://...`
        // as a credential). With no backend configured it is a hard error.
        let resolver = resolver_no_backend();
        assert!(resolver
            .resolve("vault://primary/secret/openai?key=api_key")
            .is_err());
        assert!(resolver.resolve("awssm://primary/openai").is_err());
        assert!(resolver.resolve("secret://nope/key").is_err());
    }

    #[test]
    fn plain_url_still_passes_through_not_treated_as_reference() {
        // http:// is not a secret scheme; it must pass through unchanged.
        let resolver = manager_with_local("local", "k", "v");
        let resolver = SecretResolver::new(None, HashMap::new()).with_manager(resolver);
        assert_eq!(
            resolver.resolve("http://example.com").unwrap(),
            "http://example.com"
        );
    }

    // --- check_plain_string_warning ---

    #[test]
    fn warning_detects_openai_key_prefix() {
        assert!(SecretResolver::check_plain_string_warning("sk-proj-abc123"));
    }

    #[test]
    fn warning_detects_github_pat_prefix() {
        assert!(SecretResolver::check_plain_string_warning(
            "ghp_ABCdef1234567890"
        ));
    }

    #[test]
    fn warning_detects_github_oauth_prefix() {
        assert!(SecretResolver::check_plain_string_warning(
            "gho_ABCdef1234567890"
        ));
    }

    #[test]
    fn warning_detects_aws_access_key_prefix() {
        assert!(SecretResolver::check_plain_string_warning(
            "AKIAIOSFODNN7EXAMPLE"
        ));
    }

    #[test]
    fn warning_detects_long_token() {
        // 31-char alphanumeric string should trigger warning.
        assert!(SecretResolver::check_plain_string_warning(
            "abcdefghijklmnopqrstuvwxyz12345"
        ));
    }

    #[test]
    fn no_warning_for_short_plain_value() {
        assert!(!SecretResolver::check_plain_string_warning("hello"));
        assert!(!SecretResolver::check_plain_string_warning("debug"));
    }

    // --- resolve_async ---

    #[test]
    fn resolve_async_reads_file_off_runtime_thread() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "  async_file_secret  ").unwrap();
        let path = format!("file:{}", tmp.path().display());
        let resolver = Arc::new(resolver_no_backend());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(resolver.resolve_async(path)).unwrap();
        assert_eq!(result, "async_file_secret");
    }

    #[test]
    fn resolve_async_passthrough_for_plain_string() {
        let resolver = Arc::new(resolver_no_backend());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(resolver.resolve_async("hello".to_string()))
            .unwrap();
        assert_eq!(result, "hello");
    }
}
