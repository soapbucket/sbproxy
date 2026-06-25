//! Cross-cluster federation (Phases 4 + 5).
//!
//! A small number of mesh clusters can share Redis as a bridge to
//! exchange CRDT summaries. Each cluster has one leader that pushes
//! its local state to Redis; every node in every cluster pulls peer
//! cluster summaries and CRDT-merges them into local state.
//!
//! Key schema under the `{key_prefix}` namespace:
//!
//! - `{prefix}fed:clusters`             - SET of cluster_ids in the federation
//! - `{prefix}fed:summary:{cluster_id}` - latest PersistedState from that cluster's leader
//! - `{prefix}fed:heartbeat:{cluster_id}` - unix_ts (string) written by that cluster's leader,
//!   TTL = 3 x sync_interval so dead clusters auto-expire
//!
//! Pull loop skips a peer whose heartbeat is missing or stale (> 3 ×
//! sync_interval old). This is a fail-open model: if Redis or a peer
//! goes away, local state continues serving; updates just stop flowing.
//!
//! See `2026-04-23-mesh-redis-hybrid-design.md` §5.3-§5.5 and
//! `MESH_V1_RESULTS.md` §7.4 for the design rationale.

use crate::backend::redis::{RedisBackend, RedisBackendConfig};
use crate::persistence::{PersistedState, SharedState};
use std::sync::Arc;

/// Flattened runtime config for the federation loop.
///
/// Built from `MeshConfig.federation` + `MeshConfig.persistence` by
/// [`start_federation_if_enabled`]. Kept as its own type so tests can
/// drive the loop without a full `MeshConfig`.
#[derive(Debug, Clone)]
pub struct FederationRuntimeConfig {
    pub cluster_id: String,
    /// If empty, peers are discovered via SMEMBERS(fed:clusters).
    pub peers: Vec<String>,
    pub sync_interval_secs: u64,
    pub read_only: bool,
}

/// Handle to a running federation task.
///
/// Drop the handle to request shutdown (non-blocking) or call
/// [`FederationTaskHandle::shutdown`] to request shutdown and block
/// until the thread exits. Same threading model as the snapshot loop
/// in [`crate::persistence`]: dedicated OS thread + single-threaded
/// tokio runtime so the task survives whichever runtime spawned it.
#[derive(Debug)]
pub struct FederationTaskHandle {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FederationTaskHandle {
    /// Request shutdown and await the thread's exit.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for FederationTaskHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn the federation push + pull loop.
///
/// - `is_leader` is called before every push tick. Only the leader pushes.
/// - `fetch_state` returns a `PersistedState` snapshot for the push.
/// - `shared` receives merged peer summaries on the pull tick.
///
/// Both closures must be cheap to call (O(one Arc clone + one read lock)).
pub fn spawn_federation_loop<F, L>(
    backend: Arc<RedisBackend>,
    config: FederationRuntimeConfig,
    shared: SharedState,
    is_leader: L,
    fetch_state: F,
) -> FederationTaskHandle
where
    F: Fn() -> PersistedState + Send + Sync + 'static,
    L: Fn() -> bool + Send + Sync + 'static,
{
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::Builder::new()
        .name(format!("sbproxy-mesh-federation-{}", config.cluster_id))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::warn!(error = %e, "mesh federation: could not build runtime, not starting");
                    return;
                }
            };
            rt.block_on(federation_task(
                backend,
                config,
                shared,
                is_leader,
                fetch_state,
                shutdown_rx,
            ));
        })
        .expect("spawn federation OS thread");

    FederationTaskHandle {
        shutdown_tx: Some(shutdown_tx),
        thread: Some(thread),
    }
}

/// Build a federation task from a full `MeshConfig`, if enabled.
///
/// Returns `Ok(None)` when federation is disabled, no persistence block
/// to share Redis with, or the local cluster_id is missing. `Err` only
/// when the Redis DSN is malformed.
pub fn start_federation_if_enabled<F, L>(
    cfg: &crate::config::MeshConfig,
    shared: SharedState,
    is_leader: L,
    fetch_state: F,
) -> anyhow::Result<Option<FederationTaskHandle>>
where
    F: Fn() -> PersistedState + Send + Sync + 'static,
    L: Fn() -> bool + Send + Sync + 'static,
{
    let Some(fed) = cfg.federation.as_ref() else {
        return Ok(None);
    };
    if !fed.enabled {
        return Ok(None);
    }
    if fed.cluster_id.is_empty() {
        return Err(anyhow::anyhow!(
            "mesh federation: cluster_id must be set when federation.enabled=true"
        ));
    }

    // Resolve Redis DSN: either share with persistence or use federation.redis.
    let (dsn, prefix) = if fed.share_redis_with_persistence {
        let persistence = cfg.persistence.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "mesh federation: share_redis_with_persistence=true but no persistence block configured"
            )
        })?;
        let dsn = persistence
            .params
            .get("dsn")
            .ok_or_else(|| anyhow::anyhow!("mesh federation: persistence.params.dsn missing"))?
            .clone();
        let prefix = persistence
            .params
            .get("key_prefix")
            .cloned()
            .unwrap_or_else(|| "sbproxy:mesh:".to_string());
        (dsn, prefix)
    } else {
        let params = fed.redis.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "mesh federation: redis block required when share_redis_with_persistence=false"
            )
        })?;
        let dsn = params
            .get("dsn")
            .ok_or_else(|| anyhow::anyhow!("mesh federation: federation.redis.dsn missing"))?
            .clone();
        let prefix = params
            .get("key_prefix")
            .cloned()
            .unwrap_or_else(|| "sbproxy:mesh:".to_string());
        (dsn, prefix)
    };

    // WOR-48: `RedisBackend::new` is fallible. The error message it
    // returns is already redacted (no inline credentials), so it is
    // safe to bubble through `?` straight into operator logs.
    let backend = Arc::new(RedisBackend::new(
        RedisBackendConfig::new(&dsn).with_prefix(&prefix),
    )?);

    let runtime_cfg = FederationRuntimeConfig {
        cluster_id: fed.cluster_id.clone(),
        peers: fed.peers.clone(),
        sync_interval_secs: fed.sync_interval_secs,
        read_only: fed.read_only,
    };

    tracing::info!(
        cluster_id = %runtime_cfg.cluster_id,
        peer_count = runtime_cfg.peers.len(),
        sync_interval_secs = runtime_cfg.sync_interval_secs,
        read_only = runtime_cfg.read_only,
        "mesh federation: spawning loop"
    );
    Ok(Some(spawn_federation_loop(
        backend,
        runtime_cfg,
        shared,
        is_leader,
        fetch_state,
    )))
}

async fn federation_task<F, L>(
    backend: Arc<RedisBackend>,
    config: FederationRuntimeConfig,
    shared: SharedState,
    is_leader: L,
    fetch_state: F,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) where
    F: Fn() -> PersistedState + Send + Sync + 'static,
    L: Fn() -> bool + Send + Sync + 'static,
{
    tracing::info!(
        cluster_id = %config.cluster_id,
        "mesh federation task started"
    );

    // Join the cluster set once on startup (best-effort). The heartbeat
    // loop keeps us discoverable; the set membership is a discovery hint
    // for nodes that didn't have us in their peer list.
    if !config.read_only {
        if let Err(e) = backend.sadd("fed:clusters", &config.cluster_id).await {
            tracing::warn!(error = %e, "mesh federation: failed to SADD fed:clusters; continuing");
        }
    }

    let interval = if config.sync_interval_secs == 0 {
        std::time::Duration::from_secs(10)
    } else {
        std::time::Duration::from_secs(config.sync_interval_secs)
    };
    // TTL on the heartbeat key: 3× sync_interval, so a missed heartbeat
    // becomes visible within one full sync cycle + margin.
    let heartbeat_ttl_secs = 3 * config.sync_interval_secs.max(1);

    let mut ticker = tokio::time::interval(interval);
    // First tick fires immediately. Let it fire so we publish and pull
    // right away instead of waiting one whole sync_interval.

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Push path: leader only.
                if !config.read_only && is_leader() {
                    let state = fetch_state();
                    let summary_res = publish_summary(
                        &backend,
                        &config.cluster_id,
                        &state,
                    ).await;
                    let hb_res = publish_heartbeat(
                        &backend,
                        &config.cluster_id,
                        heartbeat_ttl_secs,
                    ).await;
                    let outcome = if summary_res.is_ok() && hb_res.is_ok() {
                        crate::metrics::OUTCOME_OK
                    } else {
                        crate::metrics::OUTCOME_FAIL
                    };
                    crate::metrics::MESH_FEDERATION_PUSH
                        .with_label_values(&[outcome])
                        .inc();
                    if let Err(e) = summary_res {
                        tracing::warn!(
                            error = %e,
                            cluster_id = %config.cluster_id,
                            "mesh federation: summary push failed"
                        );
                    }
                    if let Err(e) = hb_res {
                        tracing::warn!(
                            error = %e,
                            cluster_id = %config.cluster_id,
                            "mesh federation: heartbeat push failed"
                        );
                    }
                }

                // Pull path: every node. Discover peers if none configured.
                let peers = if config.peers.is_empty() {
                    match backend.smembers("fed:clusters").await {
                        Ok(list) => list,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "mesh federation: fed:clusters discovery failed; skipping pull"
                            );
                            Vec::new()
                        }
                    }
                } else {
                    config.peers.clone()
                };

                let mut merged = 0usize;
                let mut skipped_stale = 0usize;
                let mut failed = 0usize;
                for peer in peers.iter() {
                    if peer == &config.cluster_id {
                        continue;
                    }
                    match pull_peer(&backend, peer, heartbeat_ttl_secs).await {
                        Ok(Some(peer_state)) => {
                            shared.merge_in(&peer_state);
                            merged += 1;
                            crate::metrics::MESH_FEDERATION_PULL
                                .with_label_values(&[crate::metrics::OUTCOME_OK])
                                .inc();
                        }
                        Ok(None) => {
                            skipped_stale += 1;
                            crate::metrics::MESH_FEDERATION_PULL
                                .with_label_values(&[crate::metrics::OUTCOME_STALE])
                                .inc();
                        }
                        Err(e) => {
                            failed += 1;
                            crate::metrics::MESH_FEDERATION_PULL
                                .with_label_values(&[crate::metrics::OUTCOME_FAIL])
                                .inc();
                            tracing::debug!(
                                error = %e,
                                peer = %peer,
                                "mesh federation: pull peer failed"
                            );
                        }
                    }
                }
                // Gauge: live peers minus stale/failed = alive count.
                crate::metrics::MESH_FEDERATION_PEERS
                    .with_label_values(&["alive"])
                    .set(merged as i64);
                crate::metrics::MESH_FEDERATION_PEERS
                    .with_label_values(&["stale"])
                    .set(skipped_stale as i64);
                if merged > 0 || skipped_stale > 0 || failed > 0 {
                    tracing::debug!(
                        merged = merged,
                        skipped_stale = skipped_stale,
                        failed = failed,
                        "mesh federation: pull cycle complete"
                    );
                }
            }
            _ = &mut shutdown_rx => {
                tracing::info!(
                    cluster_id = %config.cluster_id,
                    "mesh federation task shutting down"
                );
                break;
            }
        }
    }
}

/// Write a cluster summary (serialized `PersistedState`) to Redis.
///
/// Used by leader on each sync tick. No TTL: the summary is kept as
/// long as the cluster is alive, and cleaned up when the cluster is
/// torn down (heartbeat TTL signals death).
pub async fn publish_summary(
    backend: &RedisBackend,
    cluster_id: &str,
    state: &PersistedState,
) -> anyhow::Result<()> {
    let key = format!("fed:summary:{}", cluster_id);
    let bytes = serde_json::to_vec(state)?;
    backend.set(&key, &bytes, 0).await?;
    Ok(())
}

/// Write this cluster's leader heartbeat (unix seconds as a string).
/// TTL = `ttl_secs` so stale heartbeats auto-expire.
pub async fn publish_heartbeat(
    backend: &RedisBackend,
    cluster_id: &str,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let key = format!("fed:heartbeat:{}", cluster_id);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = now.to_string().into_bytes();
    backend.set(&key, &payload, ttl_secs).await?;
    Ok(())
}

/// Pull one peer cluster's summary. Returns `Ok(None)` when:
/// - the peer's heartbeat is missing (cluster not publishing or dead),
/// - the peer's heartbeat is stale (older than `max_age_secs`), or
/// - the peer's summary is missing.
///
/// Returns `Err` only on Redis I/O failure or a corrupt summary.
async fn pull_peer(
    backend: &RedisBackend,
    peer_cluster_id: &str,
    max_age_secs: u64,
) -> anyhow::Result<Option<PersistedState>> {
    let hb_key = format!("fed:heartbeat:{}", peer_cluster_id);
    let hb_bytes = match backend.get(&hb_key).await? {
        Some(b) => b,
        None => return Ok(None),
    };
    let hb_str = std::str::from_utf8(&hb_bytes).unwrap_or("0");
    let hb_ts: u64 = hb_str.parse().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(hb_ts) > max_age_secs {
        return Ok(None);
    }

    let sum_key = format!("fed:summary:{}", peer_cluster_id);
    let sum_bytes = match backend.get(&sum_key).await? {
        Some(b) => b,
        None => return Ok(None),
    };
    let state: PersistedState = serde_json::from_slice(&sum_bytes)?;
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MeshConfig, MeshFederationConfig, MeshPersistenceConfig};

    fn persistence_with(dsn: &str, prefix: &str) -> MeshPersistenceConfig {
        let mut params = std::collections::HashMap::new();
        params.insert("dsn".into(), dsn.into());
        params.insert("key_prefix".into(), prefix.into());
        MeshPersistenceConfig {
            enabled: true,
            driver: "redis".into(),
            params,
            snapshot_interval_secs: 60,
            include: vec![],
            max_staleness_secs: 3600,
            startup_fail: "open".into(),
        }
    }

    #[tokio::test]
    async fn start_federation_noop_when_disabled() {
        let cfg = MeshConfig::default();
        let shared = SharedState::new();
        let handle =
            start_federation_if_enabled(&cfg, shared, || true, PersistedState::empty).expect("ok");
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn start_federation_requires_cluster_id() {
        let cfg = MeshConfig {
            persistence: Some(persistence_with("redis://localhost:6379", "t:")),
            federation: Some(MeshFederationConfig {
                cluster_id: String::new(),
                ..MeshFederationConfig::default()
            }),
            ..MeshConfig::default()
        };
        let shared = SharedState::new();
        let err = start_federation_if_enabled(&cfg, shared, || true, PersistedState::empty)
            .expect_err("cluster_id empty must error");
        assert!(err.to_string().contains("cluster_id"));
    }

    #[tokio::test]
    async fn start_federation_requires_redis_when_not_sharing() {
        let cfg = MeshConfig {
            federation: Some(MeshFederationConfig {
                cluster_id: "c1".into(),
                share_redis_with_persistence: false,
                redis: None,
                ..MeshFederationConfig::default()
            }),
            ..MeshConfig::default()
        };
        let shared = SharedState::new();
        let err = start_federation_if_enabled(&cfg, shared, || true, PersistedState::empty)
            .expect_err("redis missing must error");
        assert!(err.to_string().contains("redis"));
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn federation_roundtrip_leader_pushes_follower_pulls() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let prefix = format!("sbproxy:mesh:test:fed:{}:", std::process::id());
        let backend = Arc::new(
            RedisBackend::new(RedisBackendConfig::new(&url).with_prefix(&prefix))
                .expect("valid REDIS_URL"),
        );

        // Seed a peer cluster: write heartbeat + summary as if another
        // cluster's leader had just run.
        let peer_cluster = "peer-cluster";
        let mut peer_state = PersistedState::empty();
        let mut c = crate::state::counter::GCounter::new();
        c.increment("peer-node", 99);
        peer_state.rate_counters.insert("api:/v1".into(), c);
        publish_summary(&backend, peer_cluster, &peer_state)
            .await
            .expect("publish summary");
        publish_heartbeat(&backend, peer_cluster, 60)
            .await
            .expect("publish heartbeat");

        // Spawn a federation loop for THIS cluster ("local-cluster") that
        // pulls peer-cluster.
        let shared = SharedState::new();
        let runtime_cfg = FederationRuntimeConfig {
            cluster_id: "local-cluster".into(),
            peers: vec![peer_cluster.into()],
            sync_interval_secs: 1,
            read_only: true, // don't spam fed:clusters during test
        };
        let handle = spawn_federation_loop(
            backend.clone(),
            runtime_cfg,
            shared.clone(),
            || false, // we're not the leader; doesn't matter since read_only
            PersistedState::empty,
        );

        // Wait up to 5 seconds for the pull to happen.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let local = shared.snapshot();
            if let Some(counter) = local.rate_counters.get("api:/v1") {
                if counter.value() == 99 {
                    handle.shutdown();
                    // Cleanup.
                    backend
                        .delete(&format!("fed:summary:{}", peer_cluster))
                        .await
                        .ok();
                    backend
                        .delete(&format!("fed:heartbeat:{}", peer_cluster))
                        .await
                        .ok();
                    return;
                }
            }
        }
        handle.shutdown();
        panic!("peer summary was not merged within 5s");
    }

    #[tokio::test]
    async fn federation_shutdown_is_graceful_without_redis() {
        // Unreachable Redis; the task should still start, log warnings,
        // and exit cleanly on shutdown request.
        let backend = Arc::new(
            RedisBackend::new(
                RedisBackendConfig::new("redis://127.0.0.1:1").with_prefix("unreachable:"),
            )
            .expect("syntactically valid url"),
        );
        let shared = SharedState::new();
        let handle = spawn_federation_loop(
            backend,
            FederationRuntimeConfig {
                cluster_id: "c".into(),
                peers: vec!["other".into()],
                sync_interval_secs: 1,
                read_only: false,
            },
            shared,
            || true,
            PersistedState::empty,
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        handle.shutdown();
    }
}
