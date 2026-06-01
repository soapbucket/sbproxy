//! WOR-800 PR4: redb persistence for the prompt runtime overlay.
//!
//! PR2 shipped the in-process [`sbproxy_ai::prompts::RuntimePromptOverlay`]
//! and PR3 shipped the HTTP mutators that fill it. Both of those
//! are process-lifetime only; a restart loses every runtime add and
//! pin. This module persists overlay mutations to a redb KV store
//! so they survive restart.
//!
//! ## Key schema
//!
//! One key per (host, name) carrying a JSON-serialized
//! [`sbproxy_ai::prompts::NamedPrompt`]:
//!
//! ```text
//! prompts:<host>:<name>  ->  { "default_version": "...", "versions": { ... } }
//! ```
//!
//! Hydration is a single prefix scan at boot. Mutations are a
//! single write per touched (host, name) pair. Hosts are scoped by
//! the colon separator; a hostname containing `:` is supported
//! (the parser splits on the first two colons only).

use anyhow::{anyhow, Context, Result};
use sbproxy_ai::prompts::{NamedPrompt, PromptStore, RuntimePromptOverlay};
use sbproxy_platform::storage::{KVStore, RedbKVStore};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Prefix that scopes all runtime-overlay keys inside the shared KV
/// store. Keeping the prefix narrow lets one redb file host more than
/// just prompts in the future.
const KEY_PREFIX: &str = "prompts:";

/// Persistence handle the admin mutators call after a successful
/// in-memory add or pin. Cheap to clone (it is just an `Arc`).
#[derive(Clone)]
pub struct PromptPersistence {
    store: Arc<dyn KVStore>,
}

impl std::fmt::Debug for PromptPersistence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptPersistence").finish_non_exhaustive()
    }
}

impl PromptPersistence {
    /// Open (or create) the redb file at `path`, hydrate the
    /// process-global runtime overlay from it, and return a handle
    /// the admin mutators use to write through.
    ///
    /// On a fresh file the overlay stays empty; an existing file's
    /// prompts are loaded back into the same `RuntimePromptOverlay`
    /// shape PR3's admin routes mutate.
    pub fn open(path: &Path) -> Result<Self> {
        let path_str = path
            .to_str()
            .ok_or_else(|| anyhow!("prompt persistence path is not valid UTF-8"))?;
        let store: Arc<dyn KVStore> =
            Arc::new(RedbKVStore::new(path_str).context("open prompt persistence redb file")?);
        let overlay = hydrate(&*store).context("hydrate runtime overlay from redb")?;
        sbproxy_ai::prompts::install_runtime_overlay(overlay);
        Ok(Self { store })
    }

    /// Construct directly from an existing KV store. Used by unit
    /// tests so they can swap in an in-memory store without touching
    /// disk; the production caller uses [`Self::open`].
    pub fn from_store(store: Arc<dyn KVStore>) -> Self {
        Self { store }
    }

    /// Persist one named prompt at `prompts:<host>:<name>`. Called
    /// by the admin mutators after the in-memory overlay swap, so
    /// the on-disk file always represents the latest in-memory
    /// state for that (host, name) pair.
    pub fn write_named_prompt(&self, host: &str, name: &str, named: &NamedPrompt) -> Result<()> {
        let key = build_key(host, name);
        let bytes = serde_json::to_vec(named).context("serialize NamedPrompt")?;
        self.store
            .put(key.as_bytes(), &bytes)
            .context("redb put named prompt")?;
        Ok(())
    }
}

/// Scan every `prompts:` key and rebuild a [`RuntimePromptOverlay`].
/// Errors on the first malformed key or undeserializable value so a
/// silently-corrupted redb file does not boot with a partial overlay.
fn hydrate(store: &dyn KVStore) -> Result<RuntimePromptOverlay> {
    let entries = store
        .scan_prefix(KEY_PREFIX.as_bytes())
        .context("scan prompts prefix")?;
    let mut by_host: HashMap<String, PromptStore> = HashMap::new();
    for (key, value) in entries {
        let key_str = std::str::from_utf8(&key).context("prompt persistence key is not UTF-8")?;
        let (host, name) = parse_key(key_str)?;
        let named: NamedPrompt = serde_json::from_slice(&value)
            .with_context(|| format!("deserialize NamedPrompt at key {key_str:?}"))?;
        let entry = by_host.entry(host.to_string()).or_default();
        entry.templates.insert(name.to_string(), named);
    }
    Ok(RuntimePromptOverlay { by_host })
}

/// Build a `prompts:<host>:<name>` key. Hostnames and prompt names
/// pass through verbatim; the colon in `host:port` survives because
/// the parser splits on the first two colons.
fn build_key(host: &str, name: &str) -> String {
    format!("{KEY_PREFIX}{host}:{name}")
}

/// Split a `prompts:<host>:<name>` key. Returns the host and name
/// slices borrowed from the input. Errors when the key does not
/// match the expected shape so a stray key in the table does not
/// silently corrupt the hydrated overlay.
fn parse_key(key: &str) -> Result<(&str, &str)> {
    let rest = key
        .strip_prefix(KEY_PREFIX)
        .ok_or_else(|| anyhow!("key {key:?} lacks expected prompts: prefix"))?;
    let (host, name) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("key {key:?} has no host:name separator"))?;
    if host.is_empty() || name.is_empty() {
        return Err(anyhow!("key {key:?} has empty host or name"));
    }
    Ok((host, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sbproxy_ai::prompts::{install_runtime_overlay, PromptVersion};
    use std::sync::Mutex;

    /// In-memory KVStore used by these tests so the round-trip path
    /// does not touch disk. Mirrors `RedbKVStore` semantics: bytes
    /// in, bytes out, prefix scan.
    #[derive(Default)]
    struct MemStore {
        data: Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
    }

    impl KVStore for MemStore {
        fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
            let g = self.data.lock().unwrap();
            Ok(g.get(key).map(|v| Bytes::copy_from_slice(v)))
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
            let g = self.data.lock().unwrap();
            Ok(g.iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)))
                .collect())
        }
    }

    /// The runtime overlay is process-global; tests that install
    /// into it serialize via the shared lock from `sbproxy_ai`.
    /// Both this module and `admin::tests` mutate the same overlay,
    /// so they must share one mutex or the "reset + mutate + observe"
    /// sequences interleave and flake.
    fn overlay_lock() -> std::sync::MutexGuard<'static, ()> {
        sbproxy_ai::prompts::lock_for_tests()
    }

    fn reset_overlay() {
        install_runtime_overlay(RuntimePromptOverlay::default());
    }

    fn named_v(versions: &[(&str, &str)], default: Option<&str>) -> NamedPrompt {
        let mut map = std::collections::HashMap::new();
        for (v, tpl) in versions {
            map.insert(
                v.to_string(),
                PromptVersion {
                    template: tpl.to_string(),
                    variables: serde_json::Map::new(),
                },
            );
        }
        NamedPrompt {
            default_version: default.map(String::from),
            versions: map,
        }
    }

    #[test]
    fn build_key_round_trips() {
        let key = build_key("example.com", "greet");
        let (h, n) = parse_key(&key).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(n, "greet");
    }

    #[test]
    fn parse_key_supports_host_with_port() {
        let key = build_key("example.com:8080", "greet");
        let (h, n) = parse_key(&key).unwrap();
        // rsplit on `:` keeps the port with the host because the name
        // is split off the rightmost colon.
        assert_eq!(h, "example.com:8080");
        assert_eq!(n, "greet");
    }

    #[test]
    fn parse_key_rejects_missing_prefix() {
        assert!(parse_key("other:example.com:greet").is_err());
    }

    #[test]
    fn parse_key_rejects_empty_segments() {
        assert!(parse_key("prompts::greet").is_err());
        assert!(parse_key("prompts:example.com:").is_err());
    }

    #[test]
    fn write_then_hydrate_round_trips_a_named_prompt() {
        let _g = overlay_lock();
        reset_overlay();
        let store: Arc<dyn KVStore> = Arc::new(MemStore::default());
        let p = PromptPersistence::from_store(store.clone());
        let named = named_v(&[("1", "v1"), ("2", "v2")], Some("2"));
        p.write_named_prompt("example.com", "greet", &named)
            .unwrap();

        // Hydrate from the same store and check the overlay.
        let overlay = hydrate(&*store).unwrap();
        let store_for_host = overlay.by_host.get("example.com").expect("host present");
        let prompt = store_for_host.templates.get("greet").expect("name present");
        assert_eq!(prompt.default_version.as_deref(), Some("2"));
        assert_eq!(prompt.versions.len(), 2);
        assert!(prompt.versions.contains_key("1"));
        assert!(prompt.versions.contains_key("2"));
    }

    #[test]
    fn hydrate_skips_unrelated_keys() {
        let _g = overlay_lock();
        reset_overlay();
        let store: Arc<dyn KVStore> = Arc::new(MemStore::default());
        // Add a key under a different prefix.
        store.put(b"audit:log:1", b"unrelated").unwrap();
        // Add one prompt key.
        let p = PromptPersistence::from_store(store.clone());
        p.write_named_prompt("example.com", "greet", &named_v(&[("1", "v1")], None))
            .unwrap();

        let overlay = hydrate(&*store).unwrap();
        // Only the prompts:* key contributes; the unrelated key is
        // silently ignored.
        assert_eq!(overlay.by_host.len(), 1);
        assert!(overlay.by_host.contains_key("example.com"));
    }

    #[test]
    fn hydrate_returns_error_on_malformed_json() {
        let _g = overlay_lock();
        reset_overlay();
        let store: Arc<dyn KVStore> = Arc::new(MemStore::default());
        // Inject a malformed value under the right prefix shape so the
        // parser passes the key but the JSON decode fails.
        store
            .put(b"prompts:example.com:greet", b"{not json")
            .unwrap();
        let err = hydrate(&*store).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("deserialize NamedPrompt"),
            "expected deserialize error, got: {msg}"
        );
    }

    #[test]
    fn write_overwrites_existing_value_for_same_host_name() {
        let _g = overlay_lock();
        reset_overlay();
        let store: Arc<dyn KVStore> = Arc::new(MemStore::default());
        let p = PromptPersistence::from_store(store.clone());
        p.write_named_prompt("example.com", "greet", &named_v(&[("1", "a")], None))
            .unwrap();
        p.write_named_prompt(
            "example.com",
            "greet",
            &named_v(&[("1", "a"), ("2", "b")], Some("2")),
        )
        .unwrap();
        let overlay = hydrate(&*store).unwrap();
        let prompt = overlay
            .by_host
            .get("example.com")
            .unwrap()
            .templates
            .get("greet")
            .unwrap();
        assert_eq!(prompt.default_version.as_deref(), Some("2"));
        assert_eq!(prompt.versions.len(), 2);
    }
}
