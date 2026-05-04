//! Universal secret resolver.
//!
//! Resolves `secret:<name>`, `${ENV_VAR}`, and `file:/path/to/file` patterns
//! embedded in config string values.  Plain strings are passed through unchanged.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::manager::VaultBackend;

/// Behaviour when the vault backend is unavailable and a `secret:` reference
/// needs to be resolved.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveFallback {
    /// Return the last successfully resolved value from a caller-managed cache.
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
        }
    }

    /// Set the fallback strategy used when the vault backend is unavailable.
    pub fn with_fallback(mut self, fallback: ResolveFallback) -> Self {
        self.fallback = fallback;
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
        if let Some(name) = value.strip_prefix("secret:") {
            self.resolve_secret(name)
        } else if value.starts_with("${") && value.ends_with('}') {
            let var = &value[2..value.len() - 1];
            std::env::var(var).with_context(|| format!("env var {} not set", var))
        } else if let Some(path) = value.strip_prefix("file:") {
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read secret file: {}", path))
                .map(|s| s.trim().to_string())
        } else {
            Ok(value.to_string())
        }
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
        unsafe { std::env::set_var("TEST_RESOLVER_ENV", "from_environment") };
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver.resolve("${TEST_RESOLVER_ENV}").unwrap(),
            "from_environment"
        );
        unsafe { std::env::remove_var("TEST_RESOLVER_ENV") };
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
