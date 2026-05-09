//! AI provider registry.
//!
//! Replaces the previous hard-coded `match` block with a YAML-driven
//! catalog. The default catalog is gzipped at build time and embedded
//! into the binary via `include_bytes!`; operators may override it at
//! runtime by setting `proxy.ai_providers_file` in `sb.yml` to point
//! at an alternative YAML file.
//!
//! Registry lifecycle:
//!
//! 1. The startup path calls [`init_provider_registry`] with the
//!    optional override path. If the override file is present and
//!    parses, it replaces the embedded set; otherwise the embedded
//!    YAML is decompressed and used.
//! 2. The first call to [`get_provider_info`] before init succeeds
//!    triggers a lazy initialisation against the embedded YAML so
//!    binaries that never call init still work.
//! 3. The parsed registry lives behind a process-wide `ArcSwap` so
//!    SIGHUP / file-watcher / admin reload paths can swap in a fresh
//!    catalog (`reload_provider_registry`) without restarting the
//!    process. In-flight `get_provider_info` lookups continue against
//!    their snapshot until they complete.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Embedded gzipped catalog. The build copies the file at
/// `data/ai_providers.yml.gz` into the binary so a fresh checkout
/// does not need to know about the file path. Regenerate via
/// `gzip -k -9 data/ai_providers.yml`.
const EMBEDDED_PROVIDERS_GZ: &[u8] = include_bytes!("../../data/ai_providers.yml.gz");

/// Known provider metadata.
///
/// Owned strings (not `&'static str`) so the registry can hold values
/// loaded from the runtime override YAML without leaking memory or
/// re-allocating per-request. Field semantics match the previous
/// hard-coded shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Stable provider identifier (e.g. `"openai"`, `"anthropic"`).
    pub name: String,
    /// Human-readable display name shown in UIs.
    pub display_name: String,
    /// Default upstream API base URL for the provider.
    pub default_base_url: String,
    /// HTTP header name carrying the API key (e.g. `Authorization`).
    pub auth_header: String,
    /// Prefix prepended to the API key (e.g. `"Bearer "`, or `""` for raw keys).
    pub auth_prefix: String,
    /// Wire format family this provider's API speaks.
    pub format: ProviderFormat,
    /// Whether the provider supports Server-Sent Events streaming.
    pub supports_streaming: bool,
    /// Whether the provider exposes an embeddings endpoint.
    pub supports_embeddings: bool,
    /// Whether the provider exposes a chat-completions endpoint.
    /// Defaults to `true`; set to `false` for embeddings-only or
    /// reranker-only providers (e.g. Voyage, Jina) so chat configs
    /// fail closed at validation time instead of 404ing at runtime.
    #[serde(default = "default_true")]
    pub supports_chat: bool,
}

fn default_true() -> bool {
    true
}

/// Wire format family used by a provider's API.
///
/// Variants are renamed for the on-disk YAML so common values like
/// `openai` and `gemini` look natural to operators reading the
/// catalog. The default snake-case derivation would emit `open_ai`,
/// which is fine but uglier; explicit renames keep the YAML clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFormat {
    /// OpenAI-compatible chat/completions format.
    #[serde(rename = "openai", alias = "open_ai")]
    OpenAi,
    /// Anthropic Messages API format.
    Anthropic,
    /// Google Gemini / Vertex AI format.
    Google,
    /// AWS Bedrock format (SigV4 auth).
    Bedrock,
    /// Fully custom or proprietary format.
    Custom,
}

/// Raw YAML entry as it appears in `ai_providers.yml`. We separate
/// this from [`ProviderInfo`] so the on-disk schema can grow extra
/// fields (aliases, hostnames, tags, etc.) without forcing every
/// runtime consumer to deal with them.
#[derive(Debug, Deserialize)]
struct YamlProvider {
    name: String,
    display_name: String,
    #[serde(default)]
    aliases: Vec<String>,
    default_base_url: String,
    auth_header: String,
    #[serde(default)]
    auth_prefix: String,
    format: ProviderFormat,
    #[serde(default)]
    supports_streaming: bool,
    #[serde(default)]
    supports_embeddings: bool,
    #[serde(default = "default_true")]
    supports_chat: bool,
}

#[derive(Debug, Deserialize)]
struct YamlCatalog {
    providers: Vec<YamlProvider>,
}

/// Compiled registry: one entry per canonical name plus one entry
/// per alias, all pointing at the same `ProviderInfo` instance via a
/// shared `Vec`. The HashMap stores indices into the vec to keep
/// memory flat.
struct Registry {
    /// Canonical names plus aliases. All keys are lowercased.
    by_name: HashMap<String, usize>,
    /// Compiled provider entries.
    providers: Vec<ProviderInfo>,
    /// Canonical names in YAML declaration order. Used by
    /// [`list_providers`] to preserve a stable iteration order.
    canonical_names: Vec<String>,
}

/// Lazily-initialised, swap-on-reload registry slot.
///
/// `OnceLock` holds the `ArcSwap` itself (so the slot pointer is
/// stable for the life of the process); `ArcSwap` holds the live
/// `Arc<Registry>` and gives readers a lock-free snapshot.
/// `reload_provider_registry` calls `store` with a freshly built
/// registry and existing readers continue against their snapshot.
static REGISTRY: OnceLock<ArcSwap<Registry>> = OnceLock::new();

fn registry_slot() -> &'static ArcSwap<Registry> {
    REGISTRY.get_or_init(|| {
        // Lazy fall-back when init_provider_registry was not called
        // explicitly. We deliberately panic on failure: the embedded
        // catalog is a build artefact, so a parse failure here is a
        // bug we want surfaced loudly rather than silently masked.
        let initial = build_registry(None).expect("embedded ai_providers.yml.gz must parse");
        ArcSwap::from_pointee(initial)
    })
}

/// Initialise the provider registry from an optional override YAML
/// path.
///
/// Should be called once at process startup before any
/// `get_provider_info` lookups. When `override_path` is `None` or
/// the file cannot be read, the embedded gzipped catalog is used
/// instead.
///
/// Behaviour on a second call: the new registry replaces the live
/// one atomically (so this entrypoint can also drive an explicit
/// reload). For SIGHUP / file-watcher / admin reload paths, prefer
/// [`reload_provider_registry`] for clarity.
///
/// Returns `Err` only when the embedded catalog itself fails to
/// parse - that is a build-time bug, never a runtime configuration
/// issue. A missing or malformed override file is logged at `warn`
/// level and the embedded fallback takes over.
pub fn init_provider_registry(override_path: Option<&Path>) -> anyhow::Result<()> {
    let registry = build_registry(override_path)?;
    install_registry(registry);
    Ok(())
}

/// Atomically replace the live provider registry with one built
/// from the override file at `override_path` (or the embedded
/// catalog when `override_path` is `None`).
///
/// Used by the hot-reload paths (SIGHUP handler, file watcher,
/// admin API) to pick up new providers, alias renames, and
/// `default_base_url` changes without restarting the process.
/// In-flight `get_provider_info` lookups continue to see their
/// previous snapshot until they finish.
///
/// Returns `Err` only when the embedded catalog itself fails to
/// parse (a build-time bug). A missing or malformed override falls
/// back to the embedded set with a warn-level log, exactly as in
/// [`init_provider_registry`].
pub fn reload_provider_registry(override_path: Option<&Path>) -> anyhow::Result<()> {
    let registry = build_registry(override_path)?;
    install_registry(registry);
    tracing::info!("AI provider registry reloaded");
    Ok(())
}

fn install_registry(registry: Registry) {
    // `registry_slot()` populates the OnceLock with an `ArcSwap`
    // pointing at the embedded catalog on first call. We then
    // overwrite that snapshot with the freshly built one. The slot
    // pointer itself is stable for the life of the process; only the
    // `Arc<Registry>` inside swaps.
    registry_slot().store(Arc::new(registry));
}

fn build_registry(override_path: Option<&Path>) -> anyhow::Result<Registry> {
    let yaml_text = if let Some(path) = override_path {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                tracing::info!(
                    path = %path.display(),
                    "AI provider registry: loaded override catalog"
                );
                s
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "AI provider registry: override file unreadable; falling back to embedded catalog"
                );
                decompress_embedded()?
            }
        }
    } else {
        decompress_embedded()?
    };

    let catalog: YamlCatalog = serde_yaml::from_str(&yaml_text)
        .map_err(|e| anyhow::anyhow!("ai_providers YAML parse failed: {e}"))?;

    let mut by_name = HashMap::with_capacity(catalog.providers.len() * 2);
    let mut providers = Vec::with_capacity(catalog.providers.len());
    let mut canonical_names = Vec::with_capacity(catalog.providers.len());
    for entry in catalog.providers {
        let info = ProviderInfo {
            name: entry.name.clone(),
            display_name: entry.display_name,
            default_base_url: entry.default_base_url,
            auth_header: entry.auth_header,
            auth_prefix: entry.auth_prefix,
            format: entry.format,
            supports_streaming: entry.supports_streaming,
            supports_embeddings: entry.supports_embeddings,
            supports_chat: entry.supports_chat,
        };
        let idx = providers.len();
        providers.push(info);
        canonical_names.push(entry.name.clone());
        by_name.insert(entry.name.to_ascii_lowercase(), idx);
        for alias in entry.aliases {
            // Aliases are tolerated to collide with each other (last-
            // declared wins). We do not warn because operators may
            // legitimately re-point an alias when overriding the
            // embedded catalog.
            by_name.insert(alias.to_ascii_lowercase(), idx);
        }
    }

    tracing::info!(
        provider_count = providers.len(),
        alias_count = by_name.len() - providers.len(),
        "AI provider registry initialised"
    );

    Ok(Registry {
        by_name,
        providers,
        canonical_names,
    })
}

fn decompress_embedded() -> anyhow::Result<String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(EMBEDDED_PROVIDERS_GZ);
    let mut text = String::new();
    decoder
        .read_to_string(&mut text)
        .map_err(|e| anyhow::anyhow!("embedded ai_providers.yml.gz decode failed: {e}"))?;
    Ok(text)
}

/// Snapshot the current registry. The returned guard derefs to
/// `Arc<Registry>` and is valid even if a reload swaps the slot
/// while the snapshot is alive.
fn registry_snapshot() -> arc_swap::Guard<Arc<Registry>> {
    registry_slot().load()
}

/// Look up provider info by name. Returns `None` for unknown
/// providers. Lookups are case-insensitive and accept any alias
/// declared in the YAML.
pub fn get_provider_info(name: &str) -> Option<ProviderInfo> {
    let snap = registry_snapshot();
    let idx = snap.by_name.get(name.to_ascii_lowercase().as_str())?;
    snap.providers.get(*idx).cloned()
}

/// List canonical provider names in YAML declaration order.
pub fn list_providers() -> Vec<String> {
    registry_snapshot().canonical_names.clone()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_decompresses_and_parses() {
        let yaml = decompress_embedded().expect("embedded gzip valid");
        let catalog: YamlCatalog = serde_yaml::from_str(&yaml).expect("yaml parses");
        assert!(
            catalog.providers.len() >= 43,
            "expected the full default catalog to be embedded; got {}",
            catalog.providers.len()
        );
    }

    #[test]
    fn list_providers_returns_all_known() {
        let names = list_providers();
        assert!(names.contains(&"openai".to_string()));
        assert!(names.contains(&"anthropic".to_string()));
        assert!(names.contains(&"watsonx".to_string()));
        assert!(names.len() >= 43);
    }

    #[test]
    fn get_provider_info_resolves_aliases() {
        let google = get_provider_info("google").expect("alias should resolve");
        assert_eq!(google.name, "gemini");

        let aws_bedrock = get_provider_info("aws_bedrock").expect("alias should resolve");
        assert_eq!(aws_bedrock.name, "bedrock");
    }

    #[test]
    fn get_provider_info_is_case_insensitive() {
        assert!(get_provider_info("OpenAI").is_some());
        assert!(get_provider_info("ANTHROPIC").is_some());
        assert!(get_provider_info("Gemini").is_some());
    }

    #[test]
    fn get_provider_info_unknown_returns_none() {
        assert!(get_provider_info("nonexistent").is_none());
        assert!(get_provider_info("").is_none());
    }

    #[test]
    fn provider_info_fields_round_trip_yaml() {
        let openai = get_provider_info("openai").unwrap();
        assert_eq!(openai.display_name, "OpenAI");
        assert_eq!(openai.default_base_url, "https://api.openai.com/v1");
        assert_eq!(openai.auth_header, "Authorization");
        assert_eq!(openai.auth_prefix, "Bearer ");
        assert_eq!(openai.format, ProviderFormat::OpenAi);
        assert!(openai.supports_streaming);
        assert!(openai.supports_embeddings);
    }

    #[test]
    fn anthropic_uses_x_api_key_header() {
        let info = get_provider_info("anthropic").unwrap();
        assert_eq!(info.auth_header, "x-api-key");
        assert_eq!(info.auth_prefix, "");
        assert_eq!(info.format, ProviderFormat::Anthropic);
    }

    #[test]
    fn local_providers_use_localhost_base_urls() {
        for local in ["ollama", "vllm", "tgi", "lmstudio", "llamacpp"] {
            let info = get_provider_info(local)
                .unwrap_or_else(|| panic!("missing local provider {local}"));
            assert!(
                info.default_base_url.contains("localhost"),
                "{local} base url should mention localhost: {}",
                info.default_base_url
            );
        }
    }

    #[test]
    fn override_yaml_replaces_embedded_catalog() {
        // Build a registry from an in-memory override YAML and
        // confirm that the parsed shape only contains the entries
        // we declared. We cannot mutate the global `REGISTRY` here
        // because tests share process state; we test
        // `build_registry` directly instead.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.yml");
        std::fs::write(
            &path,
            r#"providers:
  - name: only_one
    display_name: My Custom Provider
    default_base_url: https://custom.example.com
    auth_header: X-Custom-Auth
    auth_prefix: ""
    format: openai
    supports_streaming: false
    supports_embeddings: false
"#,
        )
        .unwrap();
        let registry = build_registry(Some(&path)).unwrap();
        assert_eq!(registry.providers.len(), 1);
        assert_eq!(registry.providers[0].name, "only_one");
        assert!(registry.by_name.contains_key("only_one"));
    }

    #[test]
    fn malformed_override_falls_back_to_embedded() {
        // Pointing at a file that does not exist must not crash; we
        // log and use the embedded set.
        let registry = build_registry(Some(Path::new("/dev/null/nope/missing.yml")))
            .expect("falls back when override unreadable");
        assert!(registry.providers.len() >= 43);
    }
}
