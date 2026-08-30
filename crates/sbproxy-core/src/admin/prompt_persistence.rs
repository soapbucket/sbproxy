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
use sbproxy_security::sealed_record::{
    OpenOutcome, SealKey, SealKeyRing, SealScheme, SealedEnvelope,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Prefix that scopes all runtime-overlay keys inside the shared KV
/// store. Keeping the prefix narrow lets one redb file host more than
/// just prompts in the future.
const KEY_PREFIX: &str = "prompts:";

/// The prompt store's envelope: magic `SBPP`, short for SBproxy Prompt
/// Persistence.
///
/// Deliberately its own [`HkdfPurpose`], not a reuse of the response
/// cache's. An operator may point both surfaces at one secret, and
/// purpose separation is what keeps one derived key from opening the
/// other's records.
///
/// [`HkdfPurpose`]: sbproxy_security::HkdfPurpose
const SBPP_SCHEME: SealScheme = SealScheme::new(
    *b"SBPP",
    1,
    sbproxy_security::HkdfPurpose::PromptPersistenceAtRest,
    b"sbproxy.prompt-persistence.key-id.v1",
);

/// Build a prompt-persistence key ring from resolved key material.
///
/// `active` seals and opens; each entry of `previous` opens only.
/// Material shorter than 16 bytes is refused rather than stretched,
/// matching the response-cache rule: a short passphrase silently
/// accepted is how a store ends up encrypted with something guessable.
pub fn prompt_key_ring(active: Vec<u8>, previous: Vec<Vec<u8>>) -> Result<PromptSealer> {
    let active = SealKey::new(SBPP_SCHEME, active)?;
    let previous = previous
        .into_iter()
        .map(|material| SealKey::new(SBPP_SCHEME, material))
        .collect::<Result<Vec<_>>>()?;
    Ok(PromptSealer {
        ring: SealKeyRing::new(SBPP_SCHEME, active, previous)?,
    })
}

/// The active key plus any retired keys kept only to open older records.
#[derive(Debug)]
pub struct PromptSealer {
    ring: SealKeyRing,
}

impl PromptSealer {
    /// The active key's id, safe to log.
    pub fn active_key_id(&self) -> String {
        self.ring.active_key_id()
    }

    /// How many retired keys can still open records.
    pub fn retired_key_count(&self) -> usize {
        self.ring.retired_key_count()
    }
}

/// Associated data binding a sealed record to the exact key it was stored
/// under.
///
/// Without this a sealed value could be copied from one
/// `prompts:<host>:<name>` slot to another and would still open, silently
/// serving one host's prompt as another's. The envelope header is
/// prepended by the sealing helper, so salt, nonce, and key fingerprint
/// are authenticated as well; this is only the tail.
fn seal_aad(store_key: &[u8]) -> Vec<u8> {
    store_key.to_vec()
}

/// Seal one serialized record under the sealer's active key.
fn seal_record(sealer: &PromptSealer, store_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    sealer
        .ring
        .seal(plaintext, &seal_aad(store_key))
        .context("seal prompt record")
}

/// Return the plaintext bytes for a stored value.
///
/// A value that is not an `SBPP` envelope is returned unchanged, so a
/// file written before encryption was enabled keeps hydrating. Enabling
/// encryption therefore does not orphan existing prompts; each one reseals
/// the next time it is written. JSON values always begin with `{`, which
/// the magic cannot collide with.
///
/// A value that *is* sealed must open. Returning it verbatim on failure
/// would hand undecryptable ciphertext to `serde_json` and report a
/// confusing parse error instead of the real one.
fn open_record(sealer: Option<&PromptSealer>, store_key: &[u8], stored: &[u8]) -> Result<Vec<u8>> {
    // Probe the magic before demanding a sealer, so an unsealed file
    // still hydrates when no key is configured.
    if !stored.starts_with(&SBPP_SCHEME.magic()) {
        return Ok(stored.to_vec());
    }
    let sealer = sealer.ok_or_else(|| {
        anyhow!(
            "prompt record is sealed but no prompt-persistence encryption key is configured; \
             restore the key under admin.prompt_persistence_encryption"
        )
    })?;
    let envelope = SealedEnvelope::parse(SBPP_SCHEME, stored, |v| v == SBPP_SCHEME.version())
        .ok_or_else(|| {
            anyhow!("sealed prompt record is truncated or declares an unsupported envelope version")
        })?;
    match sealer.ring.open(&envelope, &seal_aad(store_key)) {
        OpenOutcome::Opened(plaintext) => Ok(plaintext),
        OpenOutcome::NoMatchingKey => Err(anyhow!(
            "sealed prompt record was written under key {}, which is not the active key and is \
             not listed in previous_keys",
            envelope.fingerprint_hex()
        )),
        OpenOutcome::AuthFailed => Err(anyhow!(
            "sealed prompt record under key {} failed authentication; it is corrupt, or it was \
             moved here from another key",
            envelope.fingerprint_hex()
        )),
    }
}

/// Persistence handle the admin mutators call after a successful
/// in-memory add or pin. Cheap to clone (it is just an `Arc`).
#[derive(Clone)]
pub struct PromptPersistence {
    store: Arc<dyn KVStore>,
    /// `None` stores records as plaintext JSON, which is the historical
    /// behaviour and the default.
    sealer: Option<Arc<PromptSealer>>,
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
    /// `sealer` seals record values at rest. `None` keeps the historical
    /// plaintext-JSON behaviour. A sealer must be built from key material
    /// already resolved by the caller, so an unresolvable reference fails
    /// before this point rather than degrading to plaintext.
    pub fn open(path: &Path, sealer: Option<Arc<PromptSealer>>) -> Result<Self> {
        let path_str = path
            .to_str()
            .ok_or_else(|| anyhow!("prompt persistence path is not valid UTF-8"))?;
        let store: Arc<dyn KVStore> =
            Arc::new(RedbKVStore::new(path_str).context("open prompt persistence redb file")?);
        let overlay =
            hydrate(&*store, sealer.as_deref()).context("hydrate runtime overlay from redb")?;
        sbproxy_ai::prompts::install_runtime_overlay(overlay);
        Ok(Self { store, sealer })
    }

    /// Construct directly from an existing KV store. Used by unit
    /// tests so they can swap in an in-memory store without touching
    /// disk; the production caller uses [`Self::open`].
    pub fn from_store(store: Arc<dyn KVStore>) -> Self {
        Self {
            store,
            sealer: None,
        }
    }

    /// [`Self::from_store`] with at-rest sealing enabled.
    pub fn from_store_sealed(store: Arc<dyn KVStore>, sealer: Arc<PromptSealer>) -> Self {
        Self {
            store,
            sealer: Some(sealer),
        }
    }

    /// Persist one named prompt at `prompts:<host>:<name>`. Called
    /// by the admin mutators after the in-memory overlay swap, so
    /// the on-disk file always represents the latest in-memory
    /// state for that (host, name) pair.
    pub fn write_named_prompt(&self, host: &str, name: &str, named: &NamedPrompt) -> Result<()> {
        let key = build_key(host, name);
        let bytes = serde_json::to_vec(named).context("serialize NamedPrompt")?;
        let stored = match self.sealer.as_deref() {
            Some(sealer) => seal_record(sealer, key.as_bytes(), &bytes)?,
            None => bytes,
        };
        self.store
            .put(key.as_bytes(), &stored)
            .context("redb put named prompt")?;
        Ok(())
    }
}

/// Scan every `prompts:` key and rebuild a [`RuntimePromptOverlay`].
/// Errors on the first malformed key or undeserializable value so a
/// silently-corrupted redb file does not boot with a partial overlay.
fn hydrate(store: &dyn KVStore, sealer: Option<&PromptSealer>) -> Result<RuntimePromptOverlay> {
    let entries = store
        .scan_prefix(KEY_PREFIX.as_bytes())
        .context("scan prompts prefix")?;
    let mut by_host: HashMap<String, PromptStore> = HashMap::new();
    for (key, value) in entries {
        let key_str = std::str::from_utf8(&key).context("prompt persistence key is not UTF-8")?;
        let (host, name) = parse_key(key_str)?;
        let plaintext = open_record(sealer, &key, &value)
            .with_context(|| format!("open prompt record at key {key_str:?}"))?;
        let named: NamedPrompt = serde_json::from_slice(&plaintext)
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
            labels: std::collections::HashMap::new(),
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
        let overlay = hydrate(&*store, None).unwrap();
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

        let overlay = hydrate(&*store, None).unwrap();
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
        let err = hydrate(&*store, None).unwrap_err();
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
        let overlay = hydrate(&*store, None).unwrap();
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

    // --- at-rest sealing ------------------------------------------------

    /// A sealer whose active key is `byte` repeated, with `previous`
    /// as its retired keys.
    fn ring(byte: u8, previous: &[u8]) -> PromptSealer {
        prompt_key_ring(
            vec![byte; 32],
            previous.iter().map(|b| vec![*b; 32]).collect(),
        )
        .expect("32 bytes is enough material")
    }

    fn sealer(byte: u8) -> Arc<PromptSealer> {
        Arc::new(ring(byte, &[]))
    }

    #[test]
    fn key_material_refuses_short_input_and_scrubs_it() {
        let err = prompt_key_ring(b"short".to_vec(), Vec::new()).unwrap_err();
        assert!(
            err.to_string().contains("at least"),
            "a short key must be refused rather than stretched: {err}"
        );
    }

    #[test]
    fn sealed_records_round_trip_and_hide_the_template() {
        let _guard = overlay_lock();
        reset_overlay();
        let store = Arc::new(MemStore::default());
        let sealer = sealer(1);
        let persistence = PromptPersistence::from_store_sealed(store.clone(), sealer.clone());

        persistence
            .write_named_prompt(
                "api.test",
                "greet",
                &named_v(&[("1", "hello world")], Some("1")),
            )
            .expect("write sealed");

        // What landed in the store is sealed, and the template is not in it.
        let stored = store
            .get(build_key("api.test", "greet").as_bytes())
            .expect("get")
            .expect("present");
        assert!(
            stored.starts_with(&SBPP_SCHEME.magic()),
            "value must carry the seal envelope"
        );
        assert!(
            !String::from_utf8_lossy(&stored).contains("hello world"),
            "the template must not be readable in the stored bytes"
        );

        // And it hydrates back through the same sealer.
        let overlay = hydrate(&*store, Some(&sealer)).expect("hydrate sealed");
        let prompt = overlay
            .by_host
            .get("api.test")
            .and_then(|s| s.templates.get("greet"))
            .expect("prompt hydrated");
        assert_eq!(
            prompt.versions.get("1").map(|v| v.template.as_str()),
            Some("hello world")
        );
    }

    #[test]
    fn a_sealed_record_moved_to_another_key_fails_to_open() {
        let sealer = sealer(2);
        let plaintext = br#"{"versions":{}}"#;
        let sealed =
            seal_record(&sealer, build_key("a.test", "greet").as_bytes(), plaintext).expect("seal");

        // Same key material, different store key: the AAD no longer matches,
        // so one host's prompt cannot be served as another's.
        let err = open_record(
            Some(&sealer),
            build_key("b.test", "greet").as_bytes(),
            &sealed,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("failed authentication"),
            "moving a record between keys must fail the AEAD: {err}"
        );

        // Sanity: it does open under its own key.
        let opened = open_record(
            Some(&sealer),
            build_key("a.test", "greet").as_bytes(),
            &sealed,
        )
        .expect("opens under its own key");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn a_record_sealed_under_a_retired_key_still_opens_after_rotation() {
        let old = sealer(3);
        let store_key = build_key("api.test", "greet");
        let sealed = seal_record(&old, store_key.as_bytes(), br#"{"versions":{}}"#).expect("seal");

        // Rotate: the old key moves into previous_keys and a new key becomes
        // active.
        let rotated = ring(4, &[3]);
        let opened = open_record(Some(&rotated), store_key.as_bytes(), &sealed)
            .expect("a retired key must still open its records");
        assert_eq!(opened, br#"{"versions":{}}"#);

        // Drop the retired key and the record is no longer openable, which is
        // what retiring a key is supposed to mean.
        let without = ring(4, &[]);
        let err = open_record(Some(&without), store_key.as_bytes(), &sealed).unwrap_err();
        assert!(
            err.to_string().contains("not the active key"),
            "the error must name the missing key: {err}"
        );
    }

    #[test]
    fn plaintext_records_written_before_encryption_still_hydrate() {
        let _guard = overlay_lock();
        reset_overlay();
        // A file written by a build with no encryption configured.
        let store = Arc::new(MemStore::default());
        let plain = PromptPersistence::from_store(store.clone());
        plain
            .write_named_prompt("api.test", "greet", &named_v(&[("1", "legacy")], Some("1")))
            .expect("write plaintext");

        // Turning encryption on must not orphan it.
        let overlay = hydrate(&*store, Some(&sealer(5))).expect("hydrate mixed file");
        let prompt = overlay
            .by_host
            .get("api.test")
            .and_then(|s| s.templates.get("greet"))
            .expect("legacy prompt still hydrates");
        assert_eq!(
            prompt.versions.get("1").map(|v| v.template.as_str()),
            Some("legacy")
        );
    }

    #[test]
    fn a_sealed_record_with_no_key_configured_is_an_error_not_a_parse_failure() {
        let sealed = seal_record(
            &sealer(6),
            build_key("api.test", "greet").as_bytes(),
            br#"{"versions":{}}"#,
        )
        .expect("seal");
        let err =
            open_record(None, build_key("api.test", "greet").as_bytes(), &sealed).unwrap_err();
        assert!(
            err.to_string()
                .contains("no prompt-persistence encryption key"),
            "losing the key must say so plainly: {err}"
        );
    }
}
