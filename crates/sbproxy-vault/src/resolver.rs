//! Universal secret resolver.
//!
//! Resolves provider-URI references (`secret://`, `vault://`, ...),
//! `${ENV_VAR}`, and `file:/path/to/file` patterns embedded in config
//! string values.  Plain strings are passed through unchanged.

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};

use crate::manager::VaultManager;
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

/// Resolves secret references from any string value in config.
///
/// Supported reference patterns:
///
/// | Pattern | Resolution |
/// |---------|-----------|
/// | `secret://`, `vault://`, `awssm://`, ... | Resolve through the provider-scheme backend manager; a miss is a hard error. |
/// | `${VAR_NAME}` | Read the environment variable `VAR_NAME`. |
/// | `file:/some/path` | Read the file at `/some/path` (trimmed). |
/// | anything else | Returned as-is. |
///
/// The Go-era `secret:<name>` (colon) form was removed after its compat
/// window (WOR-1785); `secret://<backend>/<name>` is the replacement.
#[derive(Default)]
pub struct SecretResolver {
    /// Provider-scheme backends (`vault://`, `awssm://`, `secretfile://`,
    /// `secret://`, ...). When set, a recognized reference resolves
    /// through here and a miss is a hard error, never passed through
    /// verbatim (WOR-1767).
    manager: Option<Arc<VaultManager>>,
}

impl SecretResolver {
    /// Create a new resolver. Attach provider-scheme backends with
    /// [`Self::with_manager`]; without one, provider-URI references
    /// fail loud with a pointer at `proxy.secrets.backends`.
    pub fn new() -> Self {
        Self::default()
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
    /// `file:` references and HTTP-backed provider backends issue
    /// blocking I/O. This function is intended for
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
        // The Go-era `secret:<name>` (colon) form is gone (WOR-1785).
        // `VaultRef::parse` above already claimed every `secret://` URI,
        // so a bare `secret:name` here is a stale config; fail with the
        // migration pointer rather than passing it through as a value.
        if let Some(name) = value.strip_prefix("secret:") {
            anyhow::bail!(
                "the `secret:{name}` form was removed; use `secret://<backend>/{name}` \
                 with a backend declared under proxy.secrets.backends (docs/secrets.md)"
            );
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalVault;

    /// Serializes the tests that mutate the process-global environment so
    /// `std::env::set_var`/`remove_var` never race a concurrent reader in
    /// this test binary.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn resolver_no_backend() -> SecretResolver {
        SecretResolver::new()
    }

    // --- removed secret: colon form (WOR-1785) ---

    #[test]
    fn removed_secret_colon_form_errors_with_migration_pointer() {
        let resolver = resolver_no_backend();
        let err = resolver
            .resolve("secret:openai_key")
            .expect_err("the colon form must not resolve or pass through");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("secret://") && msg.contains("proxy.secrets.backends"),
            "error must carry the migration pointer: {msg}"
        );
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
        let resolver = SecretResolver::new().with_manager(mgr);
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
        let resolver = SecretResolver::new().with_manager(resolver);
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
