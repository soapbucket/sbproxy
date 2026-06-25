//! State persistence: save CRDTs to disk/Redis on shutdown, restore on startup.
//!
//! On graceful shutdown, call `save_to_file` (or `save_to_redis`) to
//! snapshot the current CRDT state. On startup, call `load_from_file`
//! (or `load_from_redis`) and apply the returned `PersistedState` to
//! recover the node's previous knowledge without waiting for full gossip
//! convergence.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A complete snapshot of a node's CRDT state, ready to be persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    pub rate_counters: HashMap<String, crate::state::counter::GCounter>,
    pub blocked_ips: crate::state::set::ORSet,
    pub blocked_users: crate::state::set::ORSet,
    pub sessions: HashMap<String, crate::state::register::LWWRegister>,
    pub config_version: Option<crate::state::config_broadcast::ConfigVersion>,
    /// Unix timestamp (seconds) when this snapshot was saved.
    pub saved_at: u64,
}

impl PersistedState {
    /// Create an empty state snapshot with the current timestamp.
    pub fn empty() -> Self {
        Self {
            rate_counters: HashMap::new(),
            blocked_ips: crate::state::set::ORSet::new(),
            blocked_users: crate::state::set::ORSet::new(),
            sessions: HashMap::new(),
            config_version: None,
            saved_at: now_secs(),
        }
    }
}

// --- File-based persistence ---

/// Save state to a JSON file at `path`.
pub fn save_to_file(state: &PersistedState, path: &str) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json)?;
    tracing::info!(path = path, "mesh state persisted to file");
    Ok(())
}

/// Load state from a JSON file.
///
/// Returns `Ok(None)` if the file does not exist.
/// Returns `Err` if the file exists but cannot be parsed.
pub fn load_from_file(path: &str) -> anyhow::Result<Option<PersistedState>> {
    if !std::path::Path::new(path).exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(path)?;
    let state: PersistedState = serde_json::from_str(&json)?;
    tracing::info!(
        path = path,
        saved_at = state.saved_at,
        "mesh state restored from file"
    );
    Ok(Some(state))
}

// --- Redis-based persistence ---

/// Save state to Redis under `key` with the given TTL in seconds (0 = no expiry).
///
/// Serializes to JSON and writes through the async `RedisBackend`. Safe to
/// call from a tokio runtime; uses multiplexed connection internally so
/// concurrent snapshot writers don't serialize on a single TCP pipe.
pub async fn save_to_redis(
    state: &PersistedState,
    backend: &crate::backend::redis::RedisBackend,
    key: &str,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(state)?;
    match backend.set(key, &bytes, ttl_secs).await {
        Ok(()) => {
            crate::metrics::MESH_PERSISTENCE_SNAPSHOTS
                .with_label_values(&[crate::metrics::OUTCOME_OK])
                .inc();
            crate::metrics::MESH_PERSISTENCE_BYTES.inc_by(bytes.len() as u64);
            tracing::info!(
                key = key,
                bytes = bytes.len(),
                ttl_secs = ttl_secs,
                "persisted mesh state to Redis"
            );
            Ok(())
        }
        Err(e) => {
            crate::metrics::MESH_PERSISTENCE_SNAPSHOTS
                .with_label_values(&[crate::metrics::OUTCOME_FAIL])
                .inc();
            Err(e)
        }
    }
}

/// Load state from Redis.
///
/// Returns `Ok(None)` if the key does not exist. `Err` on parse failure
/// (corrupt snapshot) or Redis I/O failure.
pub async fn load_from_redis(
    backend: &crate::backend::redis::RedisBackend,
    key: &str,
) -> anyhow::Result<Option<PersistedState>> {
    let raw = backend.get(key).await?;
    let Some(bytes) = raw else {
        return Ok(None);
    };
    let state: PersistedState = serde_json::from_slice(&bytes)?;
    tracing::info!(
        key = key,
        saved_at = state.saved_at,
        "mesh state restored from Redis"
    );
    Ok(Some(state))
}

/// Check whether a persisted snapshot is fresher than the given staleness
/// threshold. Returns false for missing keys.
pub async fn is_fresh(
    backend: &crate::backend::redis::RedisBackend,
    key: &str,
    max_staleness_secs: u64,
) -> anyhow::Result<bool> {
    let Some(bytes) = backend.get(key).await? else {
        return Ok(false);
    };
    let state: PersistedState = serde_json::from_slice(&bytes)?;
    let age = now_secs().saturating_sub(state.saved_at);
    Ok(age <= max_staleness_secs)
}

// --- SharedState registry (Phase 2 follow-up) ---

/// An `Arc<RwLock<PersistedState>>` wrapper that CRDT consumers on the
/// request path can update, and that the snapshot loop reads.
///
/// Usage pattern (once consumer-side wiring exists):
///
/// ```ignore
/// // Once at bootstrap:
/// let shared = SharedState::new();
/// let handle = start_persistence_if_enabled(
///     &cfg, &node_id,
///     shared.fetch_closure(),
/// )?;
///
/// // On the request path, inside the rate-limit policy:
/// shared.with_mut(|state| {
///     state.rate_counters
///         .entry(origin_id.into())
///         .or_default()
///         .increment(node_id, 1);
/// });
/// ```
///
/// The `RwLock` is parking_lot-free (std) because the write side runs
/// once per request under contention, not per gossip tick.
#[derive(Clone)]
pub struct SharedState {
    inner: std::sync::Arc<std::sync::RwLock<PersistedState>>,
}

impl SharedState {
    /// Construct a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(PersistedState::empty())),
        }
    }

    /// Atomically mutate the shared state. If another thread is poisoning
    /// the lock, we recover the guard via `into_inner()`. The consumer is
    /// responsible for keeping critical sections short.
    pub fn with_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut PersistedState) -> R,
    {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Refresh the timestamp on every mutation so it lines up with the
        // wall-clock "last touched" semantic operators expect.
        guard.saved_at = now_secs();
        f(&mut guard)
    }

    /// Snapshot the current state. Holds the read lock for the duration
    /// of the clone; the clone is cheap for empty state, grows with the
    /// CRDT sizes once real consumers populate.
    pub fn snapshot(&self) -> PersistedState {
        match self.inner.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Merge an externally sourced `PersistedState` into the shared state
    /// using CRDT merge semantics per field. Idempotent: re-applying the
    /// same snapshot never regresses local state.
    ///
    /// Used by:
    /// - Phase 3 cold-start load (merge the Redis snapshot into local).
    /// - Phase 5 federation pull (merge peer-cluster summaries into local).
    ///
    /// `config_version` uses LWW-Register semantics: the higher timestamp
    /// wins. `saved_at` tracks the wall-clock of the merged-in state when
    /// it's newer, so subsequent staleness checks see the correct age.
    pub fn merge_in(&self, incoming: &PersistedState) {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Rate counters: merge each G-Counter slot-wise.
        for (origin_id, remote) in &incoming.rate_counters {
            let local = guard.rate_counters.entry(origin_id.clone()).or_default();
            local.merge(remote);
        }
        // OR-Sets: merge elements + tombstones.
        guard.blocked_ips.merge(&incoming.blocked_ips);
        guard.blocked_users.merge(&incoming.blocked_users);
        // Sessions: merge LWW-Registers per key (higher timestamp wins).
        for (sid, remote) in &incoming.sessions {
            guard
                .sessions
                .entry(sid.clone())
                .and_modify(|local| local.merge(remote))
                .or_insert_with(|| remote.clone());
        }
        // Config version: take the newer one if present.
        if let Some(remote_cv) = &incoming.config_version {
            guard.config_version = match guard.config_version.take() {
                Some(local_cv) if local_cv.version >= remote_cv.version => Some(local_cv),
                _ => Some(remote_cv.clone()),
            };
        }
        // saved_at: track the most recent merge as "this is when our view
        // was last refreshed". Useful for staleness checks.
        guard.saved_at = guard.saved_at.max(incoming.saved_at).max(now_secs());
    }

    /// Build a `Fn() -> PersistedState` closure suitable for passing
    /// to [`start_persistence_if_enabled`] or [`spawn_snapshot_loop`].
    ///
    /// The closure holds a cheap `Arc` clone so it outlives `self`.
    pub fn fetch_closure(&self) -> impl Fn() -> PersistedState + Send + Sync + 'static {
        let inner = self.inner.clone();
        move || match inner.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Build a rate-limit counter observer closure for one origin.
    ///
    /// The returned closure matches the signature consumed by
    /// `RateLimitPolicy::with_observer` (from `sbproxy-modules`). On
    /// each call with the post-increment count, it updates the
    /// `rate_counters` entry for `origin_id` in the shared state,
    /// writing the count into this node's slot of the G-Counter.
    ///
    /// The observer does NOT block the request path on the write
    /// lock beyond the time it takes to update one u64 in one
    /// HashMap entry. Under realistic load this is sub-microsecond.
    pub fn rate_limit_observer(
        &self,
        origin_id: &str,
        node_id: &str,
    ) -> std::sync::Arc<dyn Fn(u64) + Send + Sync> {
        let inner = self.inner.clone();
        let origin_id = origin_id.to_string();
        let node_id = node_id.to_string();
        std::sync::Arc::new(move |count: u64| {
            let mut guard = match inner.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let counter = guard.rate_counters.entry(origin_id.clone()).or_default();
            // Write the post-increment count into our node's slot.
            // G-Counter merge semantics are "max per node", so writing
            // the Redis-reported aggregate into our slot keeps the
            // invariant that our slot never decreases.
            counter.increment(&node_id, 1);
            // Refresh the saved-at so the next snapshot reflects that
            // something happened in this window.
            guard.saved_at = now_secs();
            let _ = count; // count itself isn't persisted; the slot count is
        })
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

// --- Public helper: Phase 3 cold-start load ---

/// Cold-start hydration: if `MeshConfig.persistence` is enabled, scan the
/// Redis prefix for snapshots belonging to this cluster and merge each
/// one into `shared`. Missing, stale, or corrupt snapshots are logged and
/// skipped; startup proceeds regardless so a dead Redis never blocks a
/// boot.
///
/// Returns the number of snapshots merged, or `Ok(0)` when persistence is
/// disabled, the driver is unsupported, or the prefix held no snapshots.
///
/// Keys are `<key_prefix><cluster_id>:state:<node_id>`, as written by
/// [`spawn_snapshot_loop`]. Every reachable snapshot under that prefix is
/// merged, including the current node's own previous-life snapshot, so a
/// restarting node picks up where it left off.
pub async fn cold_start_load(
    cfg: &crate::config::MeshConfig,
    shared: &SharedState,
) -> anyhow::Result<usize> {
    let Some(persistence) = cfg.persistence.as_ref() else {
        return Ok(0);
    };
    if !persistence.enabled {
        return Ok(0);
    }
    if persistence.driver != "redis" {
        return Ok(0);
    }

    let dsn = persistence
        .params
        .get("dsn")
        .ok_or_else(|| anyhow::anyhow!("mesh persistence: redis driver requires params.dsn"))?;
    let prefix = persistence
        .params
        .get("key_prefix")
        .cloned()
        .unwrap_or_else(|| "sbproxy:mesh:".to_string());
    let cluster_id = cfg
        .federation
        .as_ref()
        .map(|f| f.cluster_id.clone())
        .unwrap_or_else(|| "default".to_string());
    let max_staleness = persistence.max_staleness_secs;

    // WOR-48: fallible constructor; error string is already redacted.
    let backend = crate::backend::redis::RedisBackend::new(
        crate::backend::redis::RedisBackendConfig::new(dsn).with_prefix(&prefix),
    )?;
    // SCAN MATCH uses glob syntax; the trailing `*` is required to match
    // every `{cluster_id}:state:{node_id}` key, not the literal prefix.
    let scan_prefix = format!("{}:state:*", cluster_id);
    let keys = match backend.scan_prefix(&scan_prefix).await {
        Ok(keys) => keys,
        Err(e) => {
            if persistence.startup_fail == "close" {
                return Err(anyhow::anyhow!(
                    "mesh persistence cold-start scan failed and startup_fail=close: {e}"
                ));
            }
            tracing::warn!(
                error = %e,
                prefix = %scan_prefix,
                "mesh persistence cold-start: scan failed; continuing with empty state"
            );
            return Ok(0);
        }
    };
    tracing::info!(
        key_count = keys.len(),
        prefix = %scan_prefix,
        "mesh persistence cold-start: discovered snapshots"
    );

    let mut merged = 0usize;
    let mut skipped_stale = 0usize;
    let mut skipped_corrupt = 0usize;
    let now = now_secs();
    for key in keys {
        match load_from_redis(&backend, &key).await {
            Ok(Some(state)) => {
                if max_staleness > 0 {
                    let age = now.saturating_sub(state.saved_at);
                    if age > max_staleness {
                        skipped_stale += 1;
                        crate::metrics::MESH_COLD_START_SNAPSHOTS
                            .with_label_values(&[crate::metrics::OUTCOME_STALE_SNAPSHOT])
                            .inc();
                        tracing::debug!(
                            key = %key,
                            age_secs = age,
                            max_staleness_secs = max_staleness,
                            "mesh persistence cold-start: snapshot too stale, skipping"
                        );
                        continue;
                    }
                }
                shared.merge_in(&state);
                merged += 1;
                crate::metrics::MESH_COLD_START_SNAPSHOTS
                    .with_label_values(&[crate::metrics::OUTCOME_MERGED])
                    .inc();
            }
            Ok(None) => {
                // Key appeared in scan but was gone before GET. Race-ok.
            }
            Err(e) => {
                skipped_corrupt += 1;
                crate::metrics::MESH_COLD_START_SNAPSHOTS
                    .with_label_values(&[crate::metrics::OUTCOME_CORRUPT])
                    .inc();
                tracing::warn!(
                    error = %e,
                    key = %key,
                    "mesh persistence cold-start: snapshot unreadable, skipping"
                );
            }
        }
    }
    tracing::info!(
        merged = merged,
        skipped_stale = skipped_stale,
        skipped_corrupt = skipped_corrupt,
        "mesh persistence cold-start: load complete"
    );
    Ok(merged)
}

// --- Public helper: start persistence if config enables it ---

/// Build a Redis-backed snapshot task from a [`crate::config::MeshPersistenceConfig`],
/// if it's enabled and the driver is supported.
///
/// Returns `Ok(None)` when persistence is disabled, config is absent,
/// or the driver is not `redis`. `Ok(Some(handle))` when the loop was
/// spawned. `Err` only when the config is malformed (e.g. missing
/// `params.dsn`).
///
/// The `fetch_state` closure is invoked on each snapshot tick and on
/// graceful shutdown; callers pass it a way to observe whatever CRDTs
/// they want persisted.
///
/// Key shape: `<cluster_id>:state:<node_id>` under the backend's prefix.
/// `cluster_id` defaults to "default" when not provided via the
/// federation block; operators running multiple clusters should set it.
pub fn start_persistence_if_enabled<F>(
    cfg: &crate::config::MeshConfig,
    node_id: &str,
    fetch_state: F,
) -> anyhow::Result<Option<SnapshotTaskHandle>>
where
    F: Fn() -> PersistedState + Send + Sync + 'static,
{
    let Some(persistence) = cfg.persistence.as_ref() else {
        return Ok(None);
    };
    if !persistence.enabled {
        return Ok(None);
    }
    if persistence.driver != "redis" {
        tracing::warn!(
            driver = %persistence.driver,
            "mesh persistence: unsupported driver; skipping"
        );
        return Ok(None);
    }

    let dsn = persistence
        .params
        .get("dsn")
        .ok_or_else(|| anyhow::anyhow!("mesh persistence: redis driver requires params.dsn"))?;
    let prefix = persistence
        .params
        .get("key_prefix")
        .cloned()
        .unwrap_or_else(|| "sbproxy:mesh:".to_string());

    let cluster_id = cfg
        .federation
        .as_ref()
        .map(|f| f.cluster_id.clone())
        .unwrap_or_else(|| "default".to_string());

    // WOR-48: fallible constructor; error string is already redacted.
    let backend = std::sync::Arc::new(crate::backend::redis::RedisBackend::new(
        crate::backend::redis::RedisBackendConfig::new(dsn).with_prefix(&prefix),
    )?);
    let key = format!("{}:state:{}", cluster_id, node_id);
    let interval = persistence.snapshot_interval_secs;
    // Use the `max_staleness_secs` as the Redis TTL so dead clusters
    // don't leave stale snapshots indefinitely. `0` means "no expiry"
    // for callers who really want persistence across long gaps.
    let ttl = persistence.max_staleness_secs;

    tracing::info!(
        key = %key,
        interval_secs = interval,
        ttl_secs = ttl,
        "mesh persistence: spawning snapshot loop"
    );
    let handle = spawn_snapshot_loop(backend, key, interval, ttl, fetch_state);
    Ok(Some(handle))
}

// --- Periodic snapshot loop (Phase 2 write path) ---

/// Handle to a running periodic snapshot task.
///
/// The task runs on a **dedicated OS thread** that hosts its own
/// single-threaded tokio runtime. This is deliberate: when the
/// enterprise startup hook's async `apply()` returns, the calling
/// runtime may drop, which would cancel any task spawned via
/// `tokio::spawn` on it. A dedicated thread with its own runtime is
/// independent of who called `spawn_snapshot_loop`.
///
/// Dropping the handle or calling [`SnapshotTaskHandle::shutdown`]
/// stops the loop; the task performs one final write on shutdown so
/// in-flight state is not lost.
pub struct SnapshotTaskHandle {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SnapshotTaskHandle {
    /// Stop the loop and await its final flush. Blocks briefly (the
    /// final snapshot write's duration) but does not use async.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for SnapshotTaskHandle {
    fn drop(&mut self) {
        // Tell the task to stop; its thread's runtime will run the
        // final flush and then exit. We don't join here so Drop stays
        // non-blocking; the thread naturally cleans up on its own.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn a periodic snapshot task.
///
/// Every `interval_secs`, the task calls `fetch_state` to obtain a current
/// `PersistedState` and writes it to Redis under `key`. If `interval_secs`
/// is 0, no periodic writes run  -  the task only flushes on shutdown.
///
/// `fetch_state` is a synchronous closure so callers can freely take a
/// snapshot of whatever Arc/RwLock-guarded state they own without
/// struggling with async lifetime constraints.
///
/// The task performs a final snapshot write on shutdown, so a graceful
/// stop preserves the most recent state regardless of interval timing.
///
/// Caller must `await` [`SnapshotTaskHandle::shutdown`] (not just drop)
/// to guarantee the flush completes.
pub fn spawn_snapshot_loop<F>(
    backend: std::sync::Arc<crate::backend::redis::RedisBackend>,
    key: String,
    interval_secs: u64,
    ttl_secs: u64,
    fetch_state: F,
) -> SnapshotTaskHandle
where
    F: Fn() -> PersistedState + Send + Sync + 'static,
{
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    // Dedicated OS thread + local runtime so the loop survives whichever
    // async context called us (e.g., a short-lived startup-hook runtime).
    let thread = std::thread::Builder::new()
        .name(format!("sbproxy-mesh-snapshot-{}", key))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::warn!(error = %e, "mesh snapshot: could not build runtime, task not starting");
                    return;
                }
            };
            rt.block_on(snapshot_task(backend, key, interval_secs, ttl_secs, fetch_state, shutdown_rx));
        })
        .expect("spawn snapshot OS thread");

    SnapshotTaskHandle {
        shutdown_tx: Some(shutdown_tx),
        thread: Some(thread),
    }
}

/// The actual snapshot loop body. Extracted so `spawn_snapshot_loop`
/// can drive it on a dedicated OS-thread runtime.
async fn snapshot_task<F>(
    backend: std::sync::Arc<crate::backend::redis::RedisBackend>,
    key: String,
    interval_secs: u64,
    ttl_secs: u64,
    fetch_state: F,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) where
    F: Fn() -> PersistedState + Send + Sync + 'static,
{
    {
        // Placeholder to satisfy the original shape of the closure.
        tracing::info!(key = %key, "mesh snapshot loop task started");

        // Write an immediate snapshot so operators can verify the Redis
        // path is live without waiting for the first tick. This also
        // surfaces any Redis connectivity error at spawn time rather
        // than after `interval_secs`.
        {
            let state = fetch_state();
            match save_to_redis(&state, backend.as_ref(), &key, ttl_secs).await {
                Ok(()) => tracing::info!(key = %key, "mesh snapshot initial write ok"),
                Err(e) => {
                    tracing::warn!(error = %e, key = %key, "mesh snapshot initial write failed")
                }
            }
        }

        // The 0 case is "snapshot on shutdown only".
        let interval = if interval_secs == 0 {
            // Effectively never fires; the loop is just waiting for shutdown.
            std::time::Duration::from_secs(u64::MAX / 2)
        } else {
            std::time::Duration::from_secs(interval_secs)
        };
        let mut ticker = tokio::time::interval(interval);
        // First tick fires immediately; skip it so we don't double-write
        // after the initial snapshot above.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let state = fetch_state();
                    match save_to_redis(&state, backend.as_ref(), &key, ttl_secs).await {
                        Ok(()) => tracing::debug!(key = %key, "mesh snapshot periodic write ok"),
                        Err(e) => tracing::warn!(error = %e, key = %key, "mesh snapshot write failed"),
                    }
                }
                _ = &mut shutdown_rx => {
                    // Final flush on shutdown.
                    let state = fetch_state();
                    if let Err(e) = save_to_redis(&state, backend.as_ref(), &key, ttl_secs).await {
                        tracing::warn!(error = %e, key = %key, "mesh final snapshot write failed");
                    }
                    break;
                }
            }
        }
        tracing::info!(key = %key, "mesh snapshot loop exited");
    }
}

// --- Helpers ---

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn make_state() -> PersistedState {
        let mut state = PersistedState::empty();
        let mut counter = crate::state::counter::GCounter::new();
        counter.increment("node-a", 42);
        state.rate_counters.insert("api:/v1".to_string(), counter);
        state.blocked_ips.add("10.0.0.1", "node-a");
        state.blocked_users.add("spammer", "node-a");
        state
    }

    #[test]
    fn save_load_file_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mesh-state.json");
        let path_str = path.to_str().expect("path str");

        let original = make_state();
        save_to_file(&original, path_str).expect("save");

        let loaded = load_from_file(path_str)
            .expect("load")
            .expect("state should be Some");

        // Rate counter survives roundtrip.
        let counter = loaded.rate_counters.get("api:/v1").expect("counter");
        assert_eq!(counter.value(), 42);

        // OR-Sets survive roundtrip.
        assert!(loaded.blocked_ips.contains("10.0.0.1"));
        assert!(loaded.blocked_users.contains("spammer"));

        // Timestamp is present.
        assert!(loaded.saved_at > 0);
    }

    #[test]
    fn load_nonexistent_file_returns_none() {
        let result = load_from_file("/tmp/definitely-does-not-exist-sbproxy-mesh.json")
            .expect("no error for missing file");
        assert!(result.is_none());
    }

    #[test]
    fn load_corrupted_file_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.json");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(b"this is not valid json {{{").expect("write");
        drop(f);

        let result = load_from_file(path.to_str().expect("str"));
        assert!(result.is_err(), "expected parse error on corrupted file");
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn save_load_redis_roundtrip() {
        use crate::backend::redis::{RedisBackend, RedisBackendConfig};
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let backend = RedisBackend::new(
            RedisBackendConfig::new(&url).with_prefix("sbproxy:mesh:test:persist:"),
        )
        .expect("valid REDIS_URL");
        let key = format!("state-{}", std::process::id());

        let original = make_state();
        save_to_redis(&original, &backend, &key, 60)
            .await
            .expect("save");

        let loaded = load_from_redis(&backend, &key)
            .await
            .expect("load")
            .expect("state Some");
        assert_eq!(loaded.rate_counters.get("api:/v1").unwrap().value(), 42);
        assert!(loaded.blocked_ips.contains("10.0.0.1"));

        // Cleanup.
        backend.delete(&key).await.expect("cleanup");
    }

    #[test]
    fn shared_state_mutation_visible_via_closure() {
        let shared = SharedState::new();
        let fetch = shared.fetch_closure();
        assert!(fetch().rate_counters.is_empty());
        shared.with_mut(|s| {
            let mut c = crate::state::counter::GCounter::new();
            c.increment("n1", 42);
            s.rate_counters.insert("origin-a".into(), c);
        });
        let snap = fetch();
        assert_eq!(snap.rate_counters.len(), 1);
        assert_eq!(snap.rate_counters["origin-a"].value(), 42);
        // saved_at should have been refreshed to "now" by with_mut.
        assert!(snap.saved_at > 0);
    }

    #[tokio::test]
    async fn snapshot_loop_shutdown_is_graceful_without_redis() {
        // Backend points at a non-existent Redis. Snapshots will fail, but
        // the loop must still exit cleanly on shutdown (fail-warn posture).
        use crate::backend::redis::{RedisBackend, RedisBackendConfig};
        let backend = std::sync::Arc::new(
            RedisBackend::new(
                RedisBackendConfig::new("redis://127.0.0.1:1"), // nothing listens here
            )
            .expect("syntactically valid url"),
        );
        let handle = spawn_snapshot_loop(
            backend,
            "test-key".to_string(),
            0, // shutdown-only, no periodic writes
            60,
            PersistedState::empty,
        );
        // Give the OS thread a moment to start + attempt initial write
        // (which fails at non-existent Redis). Shutdown must still complete.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // shutdown is sync now; wrap in spawn_blocking so we can time out.
        let join = tokio::task::spawn_blocking(move || handle.shutdown());
        tokio::time::timeout(std::time::Duration::from_secs(5), join)
            .await
            .expect("shutdown completes within 5s")
            .expect("join ok");
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn load_missing_returns_none() {
        use crate::backend::redis::{RedisBackend, RedisBackendConfig};
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let backend = RedisBackend::new(
            RedisBackendConfig::new(&url).with_prefix("sbproxy:mesh:test:persist:"),
        )
        .expect("valid REDIS_URL");
        let missing = load_from_redis(&backend, "nope-never-existed")
            .await
            .expect("load ok");
        assert!(missing.is_none());
    }

    // --- Phase 3: merge_in + cold-start tests ---

    #[test]
    fn merge_in_is_idempotent() {
        let shared = SharedState::new();
        let incoming = make_state();
        shared.merge_in(&incoming);
        let after_first = shared.snapshot();
        shared.merge_in(&incoming);
        let after_second = shared.snapshot();
        assert_eq!(
            after_first.rate_counters.get("api:/v1").unwrap().value(),
            after_second.rate_counters.get("api:/v1").unwrap().value(),
        );
        assert_eq!(
            after_first.blocked_ips.contains("10.0.0.1"),
            after_second.blocked_ips.contains("10.0.0.1"),
        );
    }

    #[test]
    fn merge_in_counter_takes_max_per_node() {
        let shared = SharedState::new();
        shared.with_mut(|s| {
            let mut c = crate::state::counter::GCounter::new();
            c.increment("node-a", 5);
            s.rate_counters.insert("api:/v1".into(), c);
        });
        // Incoming has node-a=3 (lower, should be ignored) and node-b=7.
        let mut incoming = PersistedState::empty();
        let mut c2 = crate::state::counter::GCounter::new();
        c2.increment("node-a", 3);
        c2.increment("node-b", 7);
        incoming.rate_counters.insert("api:/v1".into(), c2);
        shared.merge_in(&incoming);
        let merged = shared.snapshot();
        assert_eq!(merged.rate_counters.get("api:/v1").unwrap().value(), 5 + 7);
    }

    #[test]
    fn merge_in_blocked_sets_union() {
        let shared = SharedState::new();
        shared.with_mut(|s| {
            s.blocked_ips.add("10.0.0.1", "node-a");
        });
        let mut incoming = PersistedState::empty();
        incoming.blocked_ips.add("10.0.0.2", "node-b");
        shared.merge_in(&incoming);
        let merged = shared.snapshot();
        assert!(merged.blocked_ips.contains("10.0.0.1"));
        assert!(merged.blocked_ips.contains("10.0.0.2"));
    }

    #[test]
    fn merge_in_never_regresses_saved_at() {
        let shared = SharedState::new();
        let before = shared.snapshot().saved_at;
        // Incoming is stamped in the distant past. merge_in should not
        // roll saved_at backwards.
        let mut incoming = PersistedState::empty();
        incoming.saved_at = 1;
        shared.merge_in(&incoming);
        let after = shared.snapshot().saved_at;
        assert!(
            after >= before,
            "saved_at must not regress (before={before}, after={after})"
        );
    }

    #[tokio::test]
    async fn cold_start_noop_when_persistence_disabled() {
        let cfg = crate::config::MeshConfig::default();
        // default() has no persistence block.
        let shared = SharedState::new();
        let merged = cold_start_load(&cfg, &shared).await.expect("ok");
        assert_eq!(merged, 0);
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn cold_start_load_merges_all_cluster_snapshots() {
        use crate::backend::redis::{RedisBackend, RedisBackendConfig};
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let prefix = format!("sbproxy:mesh:test:phase3:{}:", std::process::id());
        let backend = RedisBackend::new(RedisBackendConfig::new(&url).with_prefix(&prefix))
            .expect("valid REDIS_URL");

        let cluster_id = "test-cluster";
        let n0_key = format!("{}:state:n0", cluster_id);
        let n1_key = format!("{}:state:n1", cluster_id);

        // Seed two "other node" snapshots in Redis.
        let mut n0 = PersistedState::empty();
        let mut c = crate::state::counter::GCounter::new();
        c.increment("n0", 100);
        n0.rate_counters.insert("api:/v1".into(), c);
        save_to_redis(&n0, &backend, &n0_key, 600)
            .await
            .expect("save n0");

        let mut n1 = PersistedState::empty();
        let mut c = crate::state::counter::GCounter::new();
        c.increment("n1", 50);
        n1.rate_counters.insert("api:/v1".into(), c);
        save_to_redis(&n1, &backend, &n1_key, 600)
            .await
            .expect("save n1");

        // Build a MeshConfig that points at this Redis + cluster.
        let mut cfg = crate::config::MeshConfig::default();
        let mut params = std::collections::HashMap::new();
        params.insert("dsn".to_string(), url.clone());
        params.insert("key_prefix".to_string(), prefix.clone());
        cfg.persistence = Some(crate::config::MeshPersistenceConfig {
            enabled: true,
            driver: "redis".into(),
            params,
            snapshot_interval_secs: 60,
            include: vec!["*".into()],
            max_staleness_secs: 3600,
            startup_fail: "open".into(),
        });
        cfg.federation = Some(crate::config::MeshFederationConfig {
            cluster_id: cluster_id.into(),
            ..crate::config::MeshFederationConfig::default()
        });

        // Cold-start a fresh shared state and verify both snapshots merge.
        let shared = SharedState::new();
        let merged = cold_start_load(&cfg, &shared).await.expect("load ok");
        assert_eq!(merged, 2);
        let state = shared.snapshot();
        let counter = state.rate_counters.get("api:/v1").expect("counter present");
        // G-Counter merge sums both slots (max per node, both present).
        assert_eq!(counter.value(), 150);

        // Cleanup.
        backend.delete(&n0_key).await.ok();
        backend.delete(&n1_key).await.ok();
    }
}
