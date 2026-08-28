//! Universal secret resolver.
//!
//! Resolves provider-URI references (`secret://`, `vault://`, ...),
//! `${ENV_VAR}`, `env:ENV_VAR`, and `file:/path/to/file` patterns
//! embedded in config string values.  Plain strings are passed through
//! unchanged.

use std::io::Read as _;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};

use crate::manager::VaultManager;
use crate::vault_ref::{
    legacy_vault_env_name, legacy_vault_reference_replacement, warn_legacy_vault_reference_once,
    VaultRef,
};

/// Process-wide secret resolver, installed once at binary boot (WOR-1767).
///
/// The `Mutex<Option<..>>` layer (rather than a bare `OnceLock<Arc<..>>`)
/// exists solely so [`reset_process_resolver_for_test`] can clear it; the
/// production `install`/`get` contract below is unchanged by it.
static PROCESS_RESOLVER: OnceLock<Mutex<Option<Arc<SecretResolver>>>> = OnceLock::new();

fn process_resolver_cell() -> &'static Mutex<Option<Arc<SecretResolver>>> {
    PROCESS_RESOLVER.get_or_init(|| Mutex::new(None))
}

/// Install the process-wide secret resolver used to resolve provider-URI
/// references (`secret://`, `secretfile://`, `vault://`, ...) in config
/// values at handler-build time (WOR-1767). Call once at boot, before the
/// server compiles its config. A second call is ignored.
pub fn install_process_resolver(resolver: Arc<SecretResolver>) {
    let mut slot = process_resolver_cell()
        .lock()
        .expect("process resolver mutex");
    if slot.is_none() {
        *slot = Some(resolver);
    }
}

/// The process-wide secret resolver, if one was installed. Returns `None`
/// in contexts that never reach the wire (the `validate`/`plan`
/// subcommands, unit tests), where secret references are left as-is and
/// caught by plan-time validation instead.
pub fn process_resolver() -> Option<Arc<SecretResolver>> {
    process_resolver_cell()
        .lock()
        .expect("process resolver mutex")
        .clone()
}

/// Test-only: clears the installed process resolver.
///
/// `cargo test` (unlike `cargo nextest`) runs every test in a binary in one
/// process, so `install_process_resolver`'s first-wins latch survives past
/// whichever test installed it first (WOR-2298). A test that depends on
/// `process_resolver()` returning `None`, or on installing its own fixture
/// data, must call this first rather than relying on process-per-test
/// isolation it is not guaranteed under every test runner.
#[cfg(any(test, feature = "test-support"))]
pub fn reset_process_resolver_for_test() {
    *process_resolver_cell()
        .lock()
        .expect("process resolver mutex") = None;
}

/// Resolves secret references from any string value in config.
///
/// Supported reference patterns:
///
/// | Pattern | Resolution |
/// |---------|-----------|
/// | `secret://`, `vault://`, `awssm://`, ... | Resolve through the provider-scheme backend manager; a miss is a hard error. |
/// | `${VAR_NAME}` | Read the environment variable `VAR_NAME`. |
/// | `env:VAR_NAME` | Read the environment variable `VAR_NAME`. |
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
        self.resolve_with_limit(value, None)
    }

    /// Resolve a config value while enforcing a whole-value byte ceiling.
    ///
    /// `file:` input is read through a `max_bytes + 1` adapter, so an
    /// oversized file is refused before it can be materialized in memory.
    /// Environment and provider-backed values are checked immediately after
    /// their authoritative resolver returns.
    pub fn resolve_bounded(&self, value: &str, max_bytes: usize) -> Result<String> {
        self.resolve_with_limit(value, Some(max_bytes))
    }

    fn resolve_with_limit(&self, value: &str, max_bytes: Option<usize>) -> Result<String> {
        // Legacy `vault://env/NAME` alias -> env var (compat window). Checked
        // before the provider-URI parse so the alias keeps its env semantics.
        if let Some(var) = legacy_vault_env_name(value) {
            let replacement =
                legacy_vault_reference_replacement(value).unwrap_or_else(|| format!("${{{var}}}"));
            warn_legacy_vault_reference_once(value, &replacement);
            let resolved =
                std::env::var(var).with_context(|| format!("env var {} not set", var))?;
            return enforce_resolved_limit(resolved, max_bytes);
        }
        // Whole-value `${VAR}` -> env var.
        if value.starts_with("${") && value.ends_with('}') {
            let var = &value[2..value.len() - 1];
            let resolved =
                std::env::var(var).with_context(|| format!("env var {} not set", var))?;
            return enforce_resolved_limit(resolved, max_bytes);
        }
        // `env:NAME` -> env var. Same lookup and missing-var error behavior
        // as the `${VAR}` form above, so either spelling fails the same way
        // when the variable is not set.
        if let Some(var) = value.strip_prefix("env:") {
            let resolved =
                std::env::var(var).with_context(|| format!("env var {} not set", var))?;
            return enforce_resolved_limit(resolved, max_bytes);
        }
        // `file:/path` -> file contents.
        if let Some(path) = value.strip_prefix("file:") {
            let resolved = match max_bytes {
                Some(max_bytes) => read_bounded_secret_file(path, max_bytes)?,
                None => std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read secret file: {}", path))?
                    .trim()
                    .to_string(),
            };
            return enforce_resolved_limit(resolved, max_bytes);
        }
        // Provider-URI schemes: vault:// awssm:// gcpsm:// k8ssecret://
        // secretfile:// secret://. Resolve through the backend manager.
        // WOR-1767: a recognized reference that cannot be resolved is a HARD
        // ERROR, never passed through verbatim (a literal `vault://...`
        // reaching an upstream as a bearer token is the footgun this closes).
        // Checked before the deprecated `secret:` colon form so `secret://`
        // is routed to the manager, not mis-parsed as a `secret:` name.
        if let Ok(reference) = VaultRef::parse(value) {
            let resolved = match &self.manager {
                Some(manager) => manager
                    .get_from_ref(&reference)?
                    .ok_or_else(|| anyhow::anyhow!("secret not found for reference: {value}")),
                None => anyhow::bail!(
                    "no secret backend configured to resolve {value}; declare it under \
                     proxy.secrets.backends"
                ),
            }?;
            return enforce_resolved_limit(resolved, max_bytes);
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
        enforce_resolved_limit(value.to_string(), max_bytes)
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

fn enforce_resolved_limit(value: String, max_bytes: Option<usize>) -> Result<String> {
    if let Some(maximum) = max_bytes {
        if value.len() > maximum {
            anyhow::bail!("resolved secret exceeds the {maximum}-byte limit");
        }
    }
    Ok(value)
}

fn read_bounded_secret_file(path: &str, max_bytes: usize) -> Result<String> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to read secret file: {path}"))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read secret file: {path}"))?;
    let value = String::from_utf8(bytes)
        .with_context(|| format!("secret file is not valid UTF-8 text: {path}"))?;
    // `resolve` trims before it measures, so this path has to as well:
    // otherwise `echo "$TOKEN" > token` refuses a secret that is exactly at
    // the limit, for its trailing newline alone, with a message naming the
    // byte count rather than the whitespace.
    //
    // Trimming cannot smuggle an oversized secret through. The read window
    // is one byte past the limit, so only a value that filled it can have
    // been truncated, and truncation moves bytes off the end: trailing
    // whitespace inside a full window means the value already ended. A
    // leading run of whitespace is the one shape that would push real bytes
    // past the window, and that is refused rather than silently shortened.
    let trimmed = value.trim();
    let truncated_by_leading_whitespace =
        value.len() > max_bytes && value.starts_with(char::is_whitespace);
    if trimmed.len() > max_bytes || truncated_by_leading_whitespace {
        anyhow::bail!("resolved secret exceeds the {max_bytes}-byte limit");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalVault;

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
        let _env =
            crate::test_env::EnvVarGuard::set(&[("TEST_RESOLVER_ENV", Some("from_environment"))]);
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver.resolve("${TEST_RESOLVER_ENV}").unwrap(),
            "from_environment"
        );
    }

    #[test]
    fn resolve_legacy_vault_env_reference() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "TEST_LEGACY_VAULT_ENV",
            Some("from_legacy_env"),
        )]);
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver
                .resolve("vault://env/TEST_LEGACY_VAULT_ENV")
                .unwrap(),
            "from_legacy_env"
        );
    }

    #[test]
    fn resolve_env_var_missing_returns_error() {
        let resolver = resolver_no_backend();
        assert!(resolver.resolve("${DEFINITELY_NOT_SET_VAR_XYZ}").is_err());
    }

    // --- env: (WOR-2284) ---

    #[test]
    fn resolve_env_prefix_pattern() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "TEST_RESOLVER_ENV_PREFIX",
            Some("from_env_prefix"),
        )]);
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver.resolve("env:TEST_RESOLVER_ENV_PREFIX").unwrap(),
            "from_env_prefix"
        );
    }

    #[test]
    fn resolve_env_prefix_missing_returns_error() {
        let resolver = resolver_no_backend();
        assert!(resolver.resolve("env:DEFINITELY_NOT_SET_VAR_XYZ").is_err());
    }

    #[test]
    fn resolve_env_prefix_missing_fails_the_same_way_as_dollar_form() {
        // `env:NAME` and `${NAME}` must fail identically for the same
        // missing variable, so operators see one consistent failure mode
        // regardless of which spelling a config uses.
        let resolver = resolver_no_backend();
        let dollar_err = resolver
            .resolve("${DEFINITELY_NOT_SET_VAR_XYZ}")
            .unwrap_err();
        let env_err = resolver
            .resolve("env:DEFINITELY_NOT_SET_VAR_XYZ")
            .unwrap_err();
        assert_eq!(format!("{dollar_err:#}"), format!("{env_err:#}"));
    }

    #[test]
    fn resolve_env_prefix_does_not_affect_other_patterns() {
        // Strictly additive: provider URIs, ${VAR}, file:, and the legacy
        // vault://env/NAME alias all still resolve exactly as before.
        let _env =
            crate::test_env::EnvVarGuard::set(&[("TEST_RESOLVER_ENV", Some("from_environment"))]);
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver.resolve("${TEST_RESOLVER_ENV}").unwrap(),
            "from_environment"
        );
        assert!(resolver
            .resolve("vault://primary/secret/openai?key=api_key")
            .is_err());
        assert!(resolver.resolve("awssm://primary/openai").is_err());
        assert!(resolver.resolve("secret://nope/key").is_err());
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

    #[test]
    fn bounded_file_resolution_accepts_exact_and_refuses_max_plus_one() {
        let exact = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(exact.path(), b"12345678").unwrap();
        let exact_reference = format!("file:{}", exact.path().display());
        let resolver = resolver_no_backend();
        assert_eq!(
            resolver.resolve_bounded(&exact_reference, 8).unwrap(),
            "12345678"
        );

        let oversized = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(oversized.path(), b"123456789").unwrap();
        let oversized_reference = format!("file:{}", oversized.path().display());
        let error = resolver
            .resolve_bounded(&oversized_reference, 8)
            .expect_err("the ninth byte must be refused");
        assert!(error.to_string().contains("8-byte limit"), "{error:#}");
    }

    /// `echo "$TOKEN" > token` writes a trailing newline, so the bounded
    /// path has to measure what it returns, the way `resolve` already does.
    /// Trimming must not turn into a way past the ceiling: a value that
    /// filled the read window behind leading whitespace is refused rather
    /// than handed back silently truncated.
    #[test]
    fn bounded_file_resolution_measures_the_trimmed_value() {
        let resolver = resolver_no_backend();

        let newline_terminated = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(newline_terminated.path(), b"12345678\n").unwrap();
        let reference = format!("file:{}", newline_terminated.path().display());
        assert_eq!(resolver.resolve_bounded(&reference, 8).unwrap(), "12345678");
        assert_eq!(resolver.resolve(&reference).unwrap(), "12345678");

        let leading_whitespace = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(leading_whitespace.path(), b"   123456789012").unwrap();
        let reference = format!("file:{}", leading_whitespace.path().display());
        let error = resolver
            .resolve_bounded(&reference, 8)
            .expect_err("a value the read window truncated must never be returned");
        assert!(error.to_string().contains("8-byte limit"), "{error:#}");
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

    /// WOR-2433. `resolve_with_limit` tests four prefixes before it
    /// reaches the backend manager, and three of them read this host
    /// directly rather than a backend the operator declared. That set is
    /// mirrored, not called, by
    /// `sbproxy_config::types::host_backed_secret_reference`, which the
    /// confined config pass uses to refuse an externally authored
    /// document that reaches for one: `sbproxy-config` does not depend
    /// on this crate and cannot, so the mirror cannot be a call.
    ///
    /// This test is the thing that makes the mirror hold. It pins the
    /// prefix set here, at the enforcer, so adding a new host-backed
    /// prefix to `resolve_with_limit` without adding it there turns this
    /// red with a message saying where to go. Order matters too: the
    /// legacy `vault://env/` alias is checked before the provider-URI
    /// parse, which is why the mirror cannot simply skip every
    /// `scheme://` value.
    #[test]
    fn every_host_backed_prefix_is_mirrored_by_the_confined_pass() {
        // The prefixes `resolve_with_limit` resolves from this host,
        // in the order it tests them.
        const HOST_BACKED: &[&str] = &["vault://env/", "${", "env:", "file:"];
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/resolver.rs"))
                .expect("this file is readable");
        let body = source
            .split_once("fn resolve_with_limit(")
            .expect("resolve_with_limit is still the entry point")
            .1;
        let body = body
            .split_once("\n    }\n")
            .expect("the function has a closing brace")
            .0;
        for prefix in HOST_BACKED {
            assert!(
                body.contains(prefix),
                "resolve_with_limit no longer handles `{prefix}`; \
                 sbproxy_config::types::host_backed_secret_reference mirrors this set and \
                 must be updated with it",
            );
        }
        // Every branch that reads the environment or the filesystem in
        // this function must correspond to one of the prefixes above. A
        // new one shows up as an extra reader.
        let env_reads = body.matches("std::env::var(").count();
        let file_reads = body.matches("read_bounded_secret_file(").count()
            + body.matches("fs::read_to_string(").count();
        assert_eq!(
            env_reads, 3,
            "resolve_with_limit reads the environment from a branch this test does not know \
             about; mirror it in sbproxy_config::types::host_backed_secret_reference",
        );
        assert_eq!(
            file_reads, 2,
            "resolve_with_limit reads the filesystem from a branch this test does not know \
             about; mirror it in sbproxy_config::types::host_backed_secret_reference",
        );
    }
}
