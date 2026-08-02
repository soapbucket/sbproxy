//! Route-scoped semantic cache registry (WOR-2099).
//!
//! [`SemanticCacheRuntimeRegistry`](crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry) parallels [`CompiledPipeline`]'s
//! per-origin vectors the same way `RagRuntimeRegistry` and
//! [`CompressionRuntimeRegistry`](crate::compression_runtime::CompressionRuntimeRegistry)
//! do: one slot per compiled origin action plus one slot per compiled
//! forward-rule action, populated only when that exact action is an
//! `ai_proxy` carrying a `semantic_cache:` block. The registry is built
//! once per pipeline generation and is immutable afterwards, so a hot
//! reload swaps whole registries and never mutates one that in-flight
//! requests have pinned. An old registry, and the Redis or mesh
//! connections it holds, stay alive only while those pinned requests do.
//!
//! Selection is strict: a forward rule without its own `semantic_cache:`
//! block has no runtime, and [`SemanticCacheRuntimeRegistry::get`](crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry::get) never
//! falls back to the origin runtime for it. A forward rule may route to a
//! different model, guardrail set, response shape, or credential policy,
//! so replaying the origin's cached answers there would cross a route
//! boundary an operator drew deliberately.
//!
//! The `backend` field on the action selects memory, Redis, or mesh at
//! runtime. No Cargo feature gates that choice: this crate already links
//! `sbproxy-platform` and `sbproxy-mesh`, so all three adapters compile
//! in every build. A configuration that omits `backend` keeps the
//! historical process-local memory behavior with no external dependency.
//!
//! Construction has two modes. Runtime construction resolves the process
//! cluster handle, verifies the fleet capability, and builds live
//! adapters. Validation construction checks the same configuration shape
//! and dependency declarations but binds stub stores, so validating a
//! candidate config never dials Redis and never speaks to the mesh.
//!
//! [`CompiledPipeline`]: crate::pipeline::CompiledPipeline

/// Thin adapter over the current OSS mesh node and transport, plus the
/// authenticated live-member capability evidence a mesh binding requires.
pub(crate) mod mesh;
/// Async Redis payloads, bounded atomic Lua indexes, health, and purge.
pub(crate) mod redis;

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Context as _;
use futures::StreamExt as _;
use sbproxy_ai::semantic_cache::{
    semantic_origin_route_digest, EmbeddingCache, EmbeddingCacheConfig, EmbeddingSource,
    MemorySemanticCacheStore, SemanticCacheBackend, SemanticCacheStore, SemanticHealthState,
    SemanticPurgeReport, SemanticPurgeScope, SemanticStoreError, SemanticStoreHealth,
    SemanticStoreLookup, SemanticStoreLookupQuery, SemanticStoreStats, SemanticStoreWrite,
};
use sbproxy_mesh::{ClusterHandle, ClusterMode};
use sbproxy_platform::storage::KVStore;

use crate::pipeline::CompiledForwardRule;
use crate::server::ai_support::semantic_static_action_policy_digest;

/// Upper bound on unique stores purged concurrently.
///
/// A `scope: all` purge fans out over every distinct backend adapter. The
/// bound keeps an operator-triggered purge from opening an unbounded
/// number of simultaneous Redis or peer operations on a large
/// configuration.
const MAX_CONCURRENT_PURGES: usize = 16;

/// Fixed inert reason for an enabled block whose provider source has no
/// `embedding:` block.
const INERT_MISSING_EMBEDDING: &str = "semantic_cache.embedding is not configured";
/// Fixed inert reason for an enabled block whose sidecar source has no
/// `sidecar:` block.
const INERT_MISSING_SIDECAR: &str = "semantic_cache.sidecar is not configured";
/// Fixed inert reason for an enabled block whose in-process source has no
/// `inprocess:` block.
const INERT_MISSING_INPROCESS: &str = "semantic_cache.inprocess is not configured";
/// Fixed inert reason for an enabled block whose standalone OpenAI source
/// has no `openai:` block.
const INERT_MISSING_OPENAI: &str = "semantic_cache.openai is not configured";
/// Fixed inert reason for an enabled and source-complete block whose
/// orchestration still declined to build.
///
/// Defensive only: [`semantic_inert_reason`] screens the known
/// source-incomplete shapes before any dependency is collected, so this
/// reason means the canonical cache rejected a configuration this module
/// believed was complete.
const INERT_RUNTIME_UNAVAILABLE: &str = "semantic_cache runtime is unavailable";

/// Immutable semantic caches keyed by origin index and optional
/// forward-rule index.
///
/// Built by `Self::from_process` or `Self::for_validation` after both
/// the main actions and the forward rules of a pipeline are compiled.
/// `Default` yields an empty registry, which is what test pipelines
/// constructed through `CompiledPipeline::default()` carry: every lookup
/// misses and no registration is reported.
#[derive(Default)]
pub struct SemanticCacheRuntimeRegistry {
    /// One slot per compiled origin, parallel to
    /// `CompiledPipeline::actions`.
    by_origin: Vec<SemanticCacheRuntimeSlot>,
    /// Deduplicated backend adapters. Every active binding points at one
    /// entry by index, so a purge visits a shared Redis or mesh adapter
    /// once rather than once per origin that uses it.
    unique_stores: Vec<SemanticStoreRegistration>,
}

/// One deduplicated backend adapter plus the compiled origins bound to it.
struct SemanticStoreRegistration {
    /// The adapter itself. Shared for Redis and mesh, one per active
    /// action for memory.
    store: Arc<dyn SemanticCacheStore>,
    /// Route digests of every compiled origin with an active binding on
    /// this adapter. Scoped purge intersects against this set.
    origin_digests: BTreeSet<[u8; 32]>,
}

/// Bindings for one compiled origin: its main action plus its forward
/// rules, in compiled order.
#[derive(Default)]
struct SemanticCacheRuntimeSlot {
    /// Binding for the origin's main action.
    default: SemanticCacheBinding,
    /// Bindings for the origin's forward-rule actions, parallel to
    /// `CompiledPipeline::forward_rules[origin]`.
    forward_rules: Vec<SemanticCacheBinding>,
}

/// What one compiled action slot resolved to.
#[derive(Default)]
enum SemanticCacheBinding {
    /// The action is not `ai_proxy`, or carries no `semantic_cache:`
    /// block. Reversible PII clears the block during action compilation,
    /// so a redaction policy that can restore the original text lands
    /// here and keeps semantic caching off for that action.
    #[default]
    NotConfigured,
    /// A configured block with `enabled: false`. Admin status keeps
    /// reporting the selected backend; no runtime and no dependency
    /// exists.
    Disabled {
        /// Backend the operator selected, retained for status output.
        backend: SemanticCacheBackend,
    },
    /// An enabled block that cannot build a runtime yet, most often
    /// because the selected embedding source has no matching block.
    /// Historical generated configuration lands here, so this stays a
    /// reported condition rather than a load failure.
    Inert {
        /// Backend the operator selected, retained for status output.
        backend: SemanticCacheBackend,
        /// Fixed, secret-free explanation surfaced through admin status.
        reason: &'static str,
    },
    /// A live cache bound to one backend adapter.
    Active {
        /// Orchestration for this exact action. Each action owns its own
        /// cache and cache-level statistics even when several actions
        /// share one backend adapter.
        cache: Arc<EmbeddingCache>,
        /// Compiled action-policy digest for this exact slot, mixed into
        /// the request-time response-policy digest.
        static_action_policy_digest: [u8; 32],
        /// Index into [`SemanticCacheRuntimeRegistry::unique_stores`].
        store_id: usize,
    },
}

/// One compiled slot as reported to admin status.
///
/// Covers every slot, including unconfigured ones, so status output is
/// parallel to the compiled routing table rather than to the subset that
/// happens to be live.
pub struct SemanticCacheRegistration<'a> {
    /// Compiled origin index this slot belongs to.
    pub origin_idx: usize,
    /// Forward-rule index within that origin, or `None` for the origin's
    /// main action.
    pub forward_rule_idx: Option<usize>,
    /// Whether the action carries a `semantic_cache:` block at all.
    pub configured: bool,
    /// Whether that block is enabled. Always `false` when `configured`
    /// is `false`.
    pub enabled: bool,
    /// Selected backend, when the action configured one.
    pub backend: Option<SemanticCacheBackend>,
    /// Fixed reason an enabled block has no runtime, when it has none.
    pub inert_reason: Option<&'static str>,
    /// Live cache for an active slot.
    pub cache: Option<&'a Arc<EmbeddingCache>>,
    /// Index of the backend adapter an active slot uses. Callers group by
    /// this value to check a shared adapter's health once; it is an
    /// internal detail and must not be serialized.
    pub store_id: Option<usize>,
}

/// What the request path needs to run one semantic cache lookup.
pub struct SemanticCacheSelection<'a> {
    /// Cache orchestration bound to this exact action.
    pub cache: &'a Arc<EmbeddingCache>,
    /// Compiled action-policy digest for this exact slot.
    pub static_action_policy_digest: &'a [u8; 32],
}

/// How the registry resolves backend dependencies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SemanticBuildMode {
    /// Live pipeline construction. Resolves the process cluster handle,
    /// verifies fleet capability, and builds real adapters.
    Runtime,
    /// Validate or plan construction. Checks configuration and declared
    /// dependencies, then binds stub adapters and opens no connection.
    Validation,
}

/// One backend adapter plus the origin digests registered against it,
/// as a test builds them.
#[cfg(test)]
type TestStoreRegistration = (Arc<dyn SemanticCacheStore>, Vec<[u8; 32]>);

impl SemanticCacheRuntimeRegistry {
    /// Bind every enabled and source-complete action to live process
    /// dependencies.
    ///
    /// Scans every main and forward action before creating any adapter,
    /// so a disabled or source-incomplete Redis or mesh block never
    /// forces a Redis connection or a cluster capability preflight. When
    /// at least one binding selects mesh, this publishes the local
    /// capability list once and requires a current authenticated
    /// `semantic_cache_snapshot_v1` declaration from every live member
    /// before the shared mesh adapter exists.
    ///
    /// Errors name the origin index and, where applicable, the
    /// forward-rule index. Backend error text names only the offending
    /// configuration field and a closed failure class, never a DSN,
    /// credential, node ID, or peer address.
    pub(crate) fn from_process(
        server: &sbproxy_config::ProxyServerConfig,
        l2_store: Option<&dyn KVStore>,
        origins: &[sbproxy_config::CompiledOrigin],
        actions: &[sbproxy_modules::Action],
        forward_rules: &[Vec<CompiledForwardRule>],
    ) -> anyhow::Result<Self> {
        Self::build(
            server,
            l2_store,
            origins,
            actions,
            forward_rules,
            SemanticBuildMode::Runtime,
        )
    }

    /// Validate every binding against declared dependencies without using
    /// process-global cluster state and without opening a connection.
    ///
    /// The returned registry is discard-only: its stores refuse every
    /// operation, so a caller that accidentally kept one would observe
    /// misses rather than silently reading a real backend.
    pub(crate) fn for_validation(
        server: &sbproxy_config::ProxyServerConfig,
        l2_store: Option<&dyn KVStore>,
        origins: &[sbproxy_config::CompiledOrigin],
        actions: &[sbproxy_modules::Action],
        forward_rules: &[Vec<CompiledForwardRule>],
    ) -> anyhow::Result<Self> {
        Self::build(
            server,
            l2_store,
            origins,
            actions,
            forward_rules,
            SemanticBuildMode::Validation,
        )
    }

    /// The cache for the action routing selected, if that exact action has
    /// a live semantic cache.
    ///
    /// `forward_rule_idx: None` addresses the origin's main action;
    /// `Some(index)` addresses one of its forward rules. A forward rule
    /// without its own `semantic_cache:` block returns `None` and never
    /// inherits the origin's cache.
    pub fn get(
        &self,
        origin_idx: usize,
        forward_rule_idx: Option<usize>,
    ) -> Option<SemanticCacheSelection<'_>> {
        let slot = self.by_origin.get(origin_idx)?;
        let binding = match forward_rule_idx {
            Some(rule_idx) => slot.forward_rules.get(rule_idx)?,
            None => &slot.default,
        };
        match binding {
            SemanticCacheBinding::Active {
                cache,
                static_action_policy_digest,
                ..
            } => Some(SemanticCacheSelection {
                cache,
                static_action_policy_digest,
            }),
            SemanticCacheBinding::NotConfigured
            | SemanticCacheBinding::Disabled { .. }
            | SemanticCacheBinding::Inert { .. } => None,
        }
    }

    /// Every compiled slot in compiled order: each origin's main action
    /// followed by that origin's forward rules.
    pub fn registrations(&self) -> impl Iterator<Item = SemanticCacheRegistration<'_>> {
        self.by_origin
            .iter()
            .enumerate()
            .flat_map(|(origin_idx, slot)| {
                std::iter::once(registration(origin_idx, None, &slot.default)).chain(
                    slot.forward_rules
                        .iter()
                        .enumerate()
                        .map(move |(rule_idx, binding)| {
                            registration(origin_idx, Some(rule_idx), binding)
                        }),
                )
            })
    }

    /// Purge every backend adapter the scope selects, once each.
    ///
    /// `All` targets every unique adapter. `Origin` targets only the
    /// adapters that carry a binding for that compiled origin. The
    /// namespace and entry scopes derive their origin digest from the
    /// namespace and apply the same filter, so purging one tenant's
    /// namespace never walks a backend that tenant never wrote to.
    ///
    /// One adapter's failure never discards another's result. A store
    /// error becomes a safe failed attempt and the combined report says
    /// `complete: false`, which is what the admin surface reports rather
    /// than claiming success.
    pub async fn purge(&self, scope: &SemanticPurgeScope) -> anyhow::Result<SemanticPurgeReport> {
        let targets = self.purge_targets(scope);
        let mut combined = SemanticPurgeReport {
            removed: 0,
            nodes_attempted: 0,
            nodes_failed: 0,
            complete: true,
        };
        let mut running = futures::stream::iter(
            targets
                .into_iter()
                .map(|registration| registration.store.purge(scope)),
        )
        .buffer_unordered(MAX_CONCURRENT_PURGES);
        while let Some(result) = running.next().await {
            match result {
                Ok(report) => {
                    combined.removed = combined.removed.saturating_add(report.removed);
                    combined.nodes_attempted = combined
                        .nodes_attempted
                        .saturating_add(report.nodes_attempted);
                    combined.nodes_failed =
                        combined.nodes_failed.saturating_add(report.nodes_failed);
                    combined.complete = combined.complete && report.complete;
                }
                // The concrete backend error is deliberately dropped. It
                // can name a DSN, a peer address, or a key, and this
                // report reaches an operator API.
                Err(_) => {
                    combined.nodes_attempted = combined.nodes_attempted.saturating_add(1);
                    combined.nodes_failed = combined.nodes_failed.saturating_add(1);
                    combined.complete = false;
                }
            }
        }
        Ok(combined)
    }

    /// Adapters a purge scope selects, deduplicated by construction.
    fn purge_targets(&self, scope: &SemanticPurgeScope) -> Vec<&SemanticStoreRegistration> {
        match scope {
            SemanticPurgeScope::All => self.unique_stores.iter().collect(),
            SemanticPurgeScope::Origin { origin_digest } => self.stores_for_origin(origin_digest),
            SemanticPurgeScope::Namespace { namespace } => {
                self.stores_for_origin(&namespace.origin_digest())
            }
            SemanticPurgeScope::Entry { namespace, .. } => {
                self.stores_for_origin(&namespace.origin_digest())
            }
        }
    }

    /// Adapters carrying at least one binding for one compiled origin.
    fn stores_for_origin(&self, origin_digest: &[u8; 32]) -> Vec<&SemanticStoreRegistration> {
        self.unique_stores
            .iter()
            .filter(|registration| registration.origin_digests.contains(origin_digest))
            .collect()
    }

    fn build(
        server: &sbproxy_config::ProxyServerConfig,
        l2_store: Option<&dyn KVStore>,
        origins: &[sbproxy_config::CompiledOrigin],
        actions: &[sbproxy_modules::Action],
        forward_rules: &[Vec<CompiledForwardRule>],
        mode: SemanticBuildMode,
    ) -> anyhow::Result<Self> {
        // Pass one classifies every slot without touching a backend, so
        // the dependency scan below sees the final set of active
        // bindings. A disabled or source-incomplete Redis or mesh block
        // must not require Redis, a cluster transport, or a stub.
        let mut plans = Vec::with_capacity(actions.len());
        for (origin_idx, action) in actions.iter().enumerate() {
            let default = plan_action(action).with_context(|| slot_label(origin_idx, None))?;
            let rules: &[CompiledForwardRule] = match forward_rules.get(origin_idx) {
                Some(rules) => rules.as_slice(),
                None => &[],
            };
            let mut per_rule = Vec::with_capacity(rules.len());
            for (rule_idx, rule) in rules.iter().enumerate() {
                per_rule.push(
                    plan_action(&rule.action)
                        .with_context(|| slot_label(origin_idx, Some(rule_idx)))?,
                );
            }
            plans.push((default, per_rule));
        }

        let mut needs_redis = false;
        let mut needs_mesh = false;
        for (default, rules) in &plans {
            for plan in std::iter::once(default).chain(rules.iter()) {
                let SlotPlan::Active { backend, .. } = plan else {
                    continue;
                };
                match backend {
                    SemanticCacheBackend::Redis => needs_redis = true,
                    SemanticCacheBackend::Mesh => needs_mesh = true,
                    SemanticCacheBackend::Memory => {}
                }
            }
        }
        let shared = SharedStores::resolve(server, l2_store, needs_redis, needs_mesh, mode)?;

        let mut builder = RegistryBuilder::new(shared);
        let mut by_origin = Vec::with_capacity(plans.len());
        for (origin_idx, (default, rules)) in plans.into_iter().enumerate() {
            let origin = origins.get(origin_idx).ok_or_else(|| {
                anyhow::anyhow!(
                    "{}: semantic_cache has no compiled origin",
                    slot_label(origin_idx, None)
                )
            })?;
            let origin_digest = semantic_origin_route_digest(origin.hostname.as_str());
            let mut slot = SemanticCacheRuntimeSlot {
                default: builder.bind(default, origin, origin_digest, origin_idx, None)?,
                forward_rules: Vec::with_capacity(rules.len()),
            };
            for (rule_idx, plan) in rules.into_iter().enumerate() {
                slot.forward_rules.push(builder.bind(
                    plan,
                    origin,
                    origin_digest,
                    origin_idx,
                    Some(rule_idx),
                )?);
            }
            by_origin.push(slot);
        }

        Ok(Self {
            by_origin,
            unique_stores: builder.unique_stores,
        })
    }

    /// Build a registry directly from prepared adapters.
    ///
    /// Test seam for the purge fan-out, which depends only on the
    /// deduplicated adapter list and not on any compiled action.
    #[cfg(test)]
    fn from_stores_for_test(stores: Vec<TestStoreRegistration>) -> Self {
        Self {
            by_origin: Vec::new(),
            unique_stores: stores
                .into_iter()
                .map(|(store, origin_digests)| SemanticStoreRegistration {
                    store,
                    origin_digests: origin_digests.into_iter().collect(),
                })
                .collect(),
        }
    }
}

/// Project one binding into its admin-facing registration.
fn registration(
    origin_idx: usize,
    forward_rule_idx: Option<usize>,
    binding: &SemanticCacheBinding,
) -> SemanticCacheRegistration<'_> {
    let base = SemanticCacheRegistration {
        origin_idx,
        forward_rule_idx,
        configured: false,
        enabled: false,
        backend: None,
        inert_reason: None,
        cache: None,
        store_id: None,
    };
    match binding {
        SemanticCacheBinding::NotConfigured => base,
        SemanticCacheBinding::Disabled { backend } => SemanticCacheRegistration {
            configured: true,
            backend: Some(*backend),
            ..base
        },
        SemanticCacheBinding::Inert { backend, reason } => SemanticCacheRegistration {
            configured: true,
            enabled: true,
            backend: Some(*backend),
            inert_reason: Some(*reason),
            ..base
        },
        SemanticCacheBinding::Active {
            cache, store_id, ..
        } => SemanticCacheRegistration {
            configured: true,
            enabled: true,
            backend: Some(cache.backend()),
            cache: Some(cache),
            store_id: Some(*store_id),
            ..base
        },
    }
}

/// What one compiled action slot resolved to before any adapter existed.
enum SlotPlan<'a> {
    /// Not an `ai_proxy`, or no `semantic_cache:` block.
    NotConfigured,
    /// Configured with `enabled: false`.
    Disabled {
        /// Backend the operator selected.
        backend: SemanticCacheBackend,
    },
    /// Enabled but missing the block its embedding source needs.
    Inert {
        /// Backend the operator selected.
        backend: SemanticCacheBackend,
        /// Fixed, secret-free explanation.
        reason: &'static str,
    },
    /// Enabled, source-complete, and eligible for a runtime.
    Active {
        /// Backend the operator selected.
        backend: SemanticCacheBackend,
        /// Validated wire configuration for this exact action.
        config: &'a EmbeddingCacheConfig,
    },
}

/// Classify one compiled action without resolving any dependency.
///
/// Bounds are enforced here, before a runtime is built, so an
/// out-of-range threshold, TTL, entry count, response cap, or LSH
/// parameter fails the candidate pipeline instead of silently clamping.
fn plan_action(action: &sbproxy_modules::Action) -> anyhow::Result<SlotPlan<'_>> {
    let sbproxy_modules::Action::AiProxy(action) = action else {
        return Ok(SlotPlan::NotConfigured);
    };
    let Some(config) = action.config.semantic_cache.as_ref() else {
        return Ok(SlotPlan::NotConfigured);
    };
    config
        .validate()
        .map_err(|error| anyhow::anyhow!("semantic_cache: {error}"))?;
    if !config.enabled {
        return Ok(SlotPlan::Disabled {
            backend: config.backend,
        });
    }
    if let Some(reason) = semantic_inert_reason(config) {
        return Ok(SlotPlan::Inert {
            backend: config.backend,
            reason,
        });
    }
    Ok(SlotPlan::Active {
        backend: config.backend,
        config,
    })
}

/// Why an enabled block still cannot build a runtime, if it cannot.
///
/// The LiteLLM converter emits `semantic_cache: { enabled: true }` with
/// no embedding source block. Turning that generated shape into a load
/// failure would break configurations that work today, so it stays a
/// reported inert slot instead.
fn semantic_inert_reason(config: &EmbeddingCacheConfig) -> Option<&'static str> {
    match config.source {
        EmbeddingSource::Provider if config.embedding.is_none() => Some(INERT_MISSING_EMBEDDING),
        EmbeddingSource::Sidecar if config.sidecar.is_none() => Some(INERT_MISSING_SIDECAR),
        EmbeddingSource::Inprocess if config.inprocess.is_none() => Some(INERT_MISSING_INPROCESS),
        EmbeddingSource::Openai if config.openai.is_none() => Some(INERT_MISSING_OPENAI),
        EmbeddingSource::Provider
        | EmbeddingSource::Sidecar
        | EmbeddingSource::Inprocess
        | EmbeddingSource::Openai => None,
    }
}

/// Operator-facing name for one compiled slot.
fn slot_label(origin_idx: usize, forward_rule_idx: Option<usize>) -> String {
    match forward_rule_idx {
        Some(rule_idx) => format!("origin {origin_idx}: forward rule {rule_idx}"),
        None => format!("origin {origin_idx}"),
    }
}

/// Backend adapters shared by every action that selects them.
///
/// Redis and mesh adapters are safe to share: namespace keys isolate
/// actions from each other and the underlying connection pool and peer
/// transport are built for concurrent use. Memory adapters are not
/// shared, because each action's LRU capacity is its own configuration.
struct SharedStores {
    /// One Redis adapter, present only when an active binding selects it.
    redis: Option<Arc<dyn SemanticCacheStore>>,
    /// One mesh adapter, present only when an active binding selects it.
    mesh: Option<Arc<dyn SemanticCacheStore>>,
}

impl SharedStores {
    fn resolve(
        server: &sbproxy_config::ProxyServerConfig,
        l2_store: Option<&dyn KVStore>,
        needs_redis: bool,
        needs_mesh: bool,
        mode: SemanticBuildMode,
    ) -> anyhow::Result<Self> {
        let redis = if needs_redis {
            Some(resolve_redis_store(l2_store, mode)?)
        } else {
            None
        };
        let mesh = if needs_mesh {
            Some(resolve_mesh_store(server, mode)?)
        } else {
            None
        };
        Ok(Self { redis, mesh })
    }
}

/// Build or validate the shared Redis adapter.
///
/// Both modes run the same connection check, so an operator sees the
/// identical error from `sbproxy validate` and from a live reload.
/// Validation then discards the checked adapter and binds a stub: the
/// constructor opens no socket, but a discarded stub cannot be mistaken
/// for a usable handle by a later caller.
fn resolve_redis_store(
    l2_store: Option<&dyn KVStore>,
    mode: SemanticBuildMode,
) -> anyhow::Result<Arc<dyn SemanticCacheStore>> {
    let store = redis::RedisSemanticCacheStore::from_l2_store(l2_store)?;
    match mode {
        SemanticBuildMode::Runtime => Ok(store as Arc<dyn SemanticCacheStore>),
        SemanticBuildMode::Validation => {
            drop(store);
            Ok(ValidationOnlySemanticStore::arc(
                SemanticCacheBackend::Redis,
            ))
        }
    }
}

/// Build or validate the shared mesh adapter.
///
/// Validation checks only that the operator declared `proxy.cluster`. It
/// never reads the process cluster handle, never publishes a capability
/// announcement, and never contacts a peer, so validating a candidate
/// config on a running node cannot perturb the live fleet view.
fn resolve_mesh_store(
    server: &sbproxy_config::ProxyServerConfig,
    mode: SemanticBuildMode,
) -> anyhow::Result<Arc<dyn SemanticCacheStore>> {
    match mode {
        SemanticBuildMode::Validation => {
            if server.cluster.is_none() {
                anyhow::bail!("semantic_cache.backend mesh requires proxy.cluster");
            }
            Ok(ValidationOnlySemanticStore::arc(SemanticCacheBackend::Mesh))
        }
        SemanticBuildMode::Runtime => {
            let installed = crate::cluster::current_cluster_handle();
            let cluster = distributed_cluster_for_mesh(installed.as_ref())?;
            // One preflight for the whole pipeline, after every enabled
            // and source-complete action has been scanned. It publishes
            // this node's complete capability list, then requires a
            // current authenticated declaration from every live member.
            // A missing, unknown, or changed-membership answer rejects
            // the candidate pipeline before the shared adapter exists and
            // before any mesh binding becomes active, so the previous
            // pipeline stays live.
            let capability = crate::cluster::block_on_cluster(async {
                crate::key_capability::announce_local_capabilities().await;
                mesh::require_semantic_mesh_capability(cluster).await
            })
            .map_err(|error| anyhow::anyhow!("semantic_cache.backend mesh: {error}"))?;
            let store = mesh::MeshSemanticCacheStore::from_cluster(cluster, capability)?;
            Ok(store as Arc<dyn SemanticCacheStore>)
        }
    }
}

/// The installed cluster handle, when it can carry semantic traffic.
///
/// A mesh binding needs a distributed handle with a bound peer transport
/// and a mesh node. A standalone process, a local-only handle, or a
/// distributed handle whose transport failed to bind all reject the
/// candidate pipeline instead of silently degrading to a process-local
/// cache that would answer differently on every replica.
fn distributed_cluster_for_mesh(
    installed: Option<&ClusterHandle>,
) -> anyhow::Result<&ClusterHandle> {
    let cluster = installed
        .ok_or_else(|| anyhow::anyhow!("semantic_cache.backend mesh requires a running cluster"))?;
    if cluster.mode() != ClusterMode::Distributed {
        anyhow::bail!("semantic_cache.backend mesh requires a distributed cluster");
    }
    if !cluster.has_peer_transport() || cluster.mesh_node().is_none() {
        anyhow::bail!("semantic_cache.backend mesh requires a bound cluster transport");
    }
    Ok(cluster)
}

/// Accumulates deduplicated adapters while bindings are attached.
struct RegistryBuilder {
    shared: SharedStores,
    unique_stores: Vec<SemanticStoreRegistration>,
    redis_id: Option<usize>,
    mesh_id: Option<usize>,
}

impl RegistryBuilder {
    fn new(shared: SharedStores) -> Self {
        Self {
            shared,
            unique_stores: Vec::new(),
            redis_id: None,
            mesh_id: None,
        }
    }

    /// Attach one planned slot, creating its adapter registration only
    /// after the cache itself builds.
    fn bind(
        &mut self,
        plan: SlotPlan<'_>,
        origin: &sbproxy_config::CompiledOrigin,
        origin_digest: [u8; 32],
        origin_idx: usize,
        forward_rule_idx: Option<usize>,
    ) -> anyhow::Result<SemanticCacheBinding> {
        let (backend, config) = match plan {
            SlotPlan::NotConfigured => return Ok(SemanticCacheBinding::NotConfigured),
            SlotPlan::Disabled { backend } => {
                return Ok(SemanticCacheBinding::Disabled { backend })
            }
            SlotPlan::Inert { backend, reason } => {
                return Ok(SemanticCacheBinding::Inert { backend, reason })
            }
            SlotPlan::Active { backend, config } => (backend, config),
        };
        let label = slot_label(origin_idx, forward_rule_idx);
        let store = self.store_for(backend, config, &label)?;
        let cache = EmbeddingCache::with_store(config, Arc::clone(&store))
            .with_context(|| format!("{label}: semantic_cache"))?;
        let Some(cache) = cache else {
            return Ok(SemanticCacheBinding::Inert {
                backend,
                reason: INERT_RUNTIME_UNAVAILABLE,
            });
        };
        // The canonical projection excludes the semantic_cache block
        // itself, so changing a threshold does not masquerade as a policy
        // change while changing a guardrail correctly invalidates hits.
        let static_action_policy_digest =
            semantic_static_action_policy_digest(origin, forward_rule_idx)
                .map_err(|error| anyhow::anyhow!("{label}: semantic_cache: {error}"))?;
        let store_id = self.register(backend, store);
        self.unique_stores[store_id]
            .origin_digests
            .insert(origin_digest);
        Ok(SemanticCacheBinding::Active {
            cache: Arc::new(cache),
            static_action_policy_digest,
            store_id,
        })
    }

    /// The adapter one active binding runs on.
    fn store_for(
        &self,
        backend: SemanticCacheBackend,
        config: &EmbeddingCacheConfig,
        label: &str,
    ) -> anyhow::Result<Arc<dyn SemanticCacheStore>> {
        match backend {
            SemanticCacheBackend::Memory => {
                Ok(Arc::new(MemorySemanticCacheStore::new(config.max_entries)))
            }
            SemanticCacheBackend::Redis => self.shared.redis.clone().ok_or_else(|| {
                anyhow::anyhow!("{label}: semantic_cache.backend redis was not prepared")
            }),
            SemanticCacheBackend::Mesh => self.shared.mesh.clone().ok_or_else(|| {
                anyhow::anyhow!("{label}: semantic_cache.backend mesh was not prepared")
            }),
        }
    }

    /// Index of the adapter in the deduplicated list, registering it on
    /// first use.
    fn register(
        &mut self,
        backend: SemanticCacheBackend,
        store: Arc<dyn SemanticCacheStore>,
    ) -> usize {
        match backend {
            SemanticCacheBackend::Memory => self.push(store),
            SemanticCacheBackend::Redis => match self.redis_id {
                Some(id) => id,
                None => {
                    let id = self.push(store);
                    self.redis_id = Some(id);
                    id
                }
            },
            SemanticCacheBackend::Mesh => match self.mesh_id {
                Some(id) => id,
                None => {
                    let id = self.push(store);
                    self.mesh_id = Some(id);
                    id
                }
            },
        }
    }

    fn push(&mut self, store: Arc<dyn SemanticCacheStore>) -> usize {
        self.unique_stores.push(SemanticStoreRegistration {
            store,
            origin_digests: BTreeSet::new(),
        });
        self.unique_stores.len() - 1
    }
}

/// Discard-only adapter bound during validation construction.
///
/// It reports the selected backend so the canonical cache's backend match
/// still holds, and refuses every operation so a validation pipeline that
/// escaped its caller could never read or write a real backend.
struct ValidationOnlySemanticStore {
    backend: SemanticCacheBackend,
}

impl ValidationOnlySemanticStore {
    fn arc(backend: SemanticCacheBackend) -> Arc<dyn SemanticCacheStore> {
        Arc::new(Self { backend })
    }
}

#[async_trait::async_trait]
impl SemanticCacheStore for ValidationOnlySemanticStore {
    fn backend(&self) -> SemanticCacheBackend {
        self.backend
    }

    async fn lookup(
        &self,
        _query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError> {
        Err(SemanticStoreError::Unavailable)
    }

    async fn put(&self, _write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
        Err(SemanticStoreError::Unavailable)
    }

    async fn purge(
        &self,
        _scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError> {
        Err(SemanticStoreError::Unavailable)
    }

    async fn health(&self) -> SemanticStoreHealth {
        SemanticStoreHealth {
            backend: self.backend,
            state: SemanticHealthState::Unavailable,
            reason: Some("validation-only pipeline"),
        }
    }

    fn stats(&self) -> SemanticStoreStats {
        SemanticStoreStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Counting adapter that reports one local purge per call.
    struct CountingStore {
        purges: AtomicU64,
        removed: u64,
        fails: bool,
    }

    impl CountingStore {
        fn arc(removed: u64, fails: bool) -> Arc<Self> {
            Arc::new(Self {
                purges: AtomicU64::new(0),
                removed,
                fails,
            })
        }
    }

    #[async_trait::async_trait]
    impl SemanticCacheStore for CountingStore {
        fn backend(&self) -> SemanticCacheBackend {
            SemanticCacheBackend::Memory
        }

        async fn lookup(
            &self,
            _query: &SemanticStoreLookupQuery,
        ) -> Result<SemanticStoreLookup, SemanticStoreError> {
            Err(SemanticStoreError::Unavailable)
        }

        async fn put(&self, _write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
            Err(SemanticStoreError::Unavailable)
        }

        async fn purge(
            &self,
            _scope: &SemanticPurgeScope,
        ) -> Result<SemanticPurgeReport, SemanticStoreError> {
            self.purges.fetch_add(1, Ordering::SeqCst);
            if self.fails {
                return Err(SemanticStoreError::OperationFailed);
            }
            Ok(SemanticPurgeReport {
                removed: self.removed,
                nodes_attempted: 1,
                nodes_failed: 0,
                complete: true,
            })
        }

        async fn health(&self) -> SemanticStoreHealth {
            SemanticStoreHealth {
                backend: SemanticCacheBackend::Memory,
                state: SemanticHealthState::Healthy,
                reason: None,
            }
        }

        fn stats(&self) -> SemanticStoreStats {
            SemanticStoreStats::default()
        }
    }

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[tokio::test]
    async fn all_purge_invokes_each_unique_store_exactly_once() {
        let shared = CountingStore::arc(3, false);
        let memory = CountingStore::arc(1, false);
        // The shared adapter carries two origins; a scope: all purge must
        // still reach it once, not once per origin.
        let registry = SemanticCacheRuntimeRegistry::from_stores_for_test(vec![
            (
                Arc::clone(&shared) as Arc<dyn SemanticCacheStore>,
                vec![digest(1), digest(2)],
            ),
            (
                Arc::clone(&memory) as Arc<dyn SemanticCacheStore>,
                vec![digest(3)],
            ),
        ]);

        let report = registry
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge");

        assert_eq!(shared.purges.load(Ordering::SeqCst), 1);
        assert_eq!(memory.purges.load(Ordering::SeqCst), 1);
        assert_eq!(report.removed, 4);
        assert_eq!(report.nodes_attempted, 2);
        assert_eq!(report.nodes_failed, 0);
        assert!(report.complete);
    }

    #[tokio::test]
    async fn origin_purge_selects_only_stores_registered_for_that_origin() {
        let shared = CountingStore::arc(2, false);
        let other = CountingStore::arc(5, false);
        let registry = SemanticCacheRuntimeRegistry::from_stores_for_test(vec![
            (
                Arc::clone(&shared) as Arc<dyn SemanticCacheStore>,
                vec![digest(1), digest(2)],
            ),
            (
                Arc::clone(&other) as Arc<dyn SemanticCacheStore>,
                vec![digest(9)],
            ),
        ]);

        let report = registry
            .purge(&SemanticPurgeScope::Origin {
                origin_digest: digest(2),
            })
            .await
            .expect("purge");

        assert_eq!(shared.purges.load(Ordering::SeqCst), 1);
        assert_eq!(
            other.purges.load(Ordering::SeqCst),
            0,
            "an origin purge must not walk a store that origin never wrote to"
        );
        assert_eq!(report.removed, 2);
        assert_eq!(report.nodes_attempted, 1);
        assert!(report.complete);
    }

    #[tokio::test]
    async fn purge_of_an_unregistered_origin_reports_a_complete_no_op() {
        let shared = CountingStore::arc(2, false);
        let registry = SemanticCacheRuntimeRegistry::from_stores_for_test(vec![(
            Arc::clone(&shared) as Arc<dyn SemanticCacheStore>,
            vec![digest(1)],
        )]);

        let report = registry
            .purge(&SemanticPurgeScope::Origin {
                origin_digest: digest(7),
            })
            .await
            .expect("purge");

        assert_eq!(shared.purges.load(Ordering::SeqCst), 0);
        assert_eq!(report.removed, 0);
        assert_eq!(report.nodes_attempted, 0);
        assert!(report.complete);
    }

    #[tokio::test]
    async fn a_failing_store_never_discards_another_stores_report() {
        let healthy = CountingStore::arc(4, false);
        let failing = CountingStore::arc(0, true);
        let registry = SemanticCacheRuntimeRegistry::from_stores_for_test(vec![
            (
                Arc::clone(&healthy) as Arc<dyn SemanticCacheStore>,
                vec![digest(1)],
            ),
            (
                Arc::clone(&failing) as Arc<dyn SemanticCacheStore>,
                vec![digest(1)],
            ),
        ]);

        let report = registry
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("a store error must not become a registry error");

        assert_eq!(healthy.purges.load(Ordering::SeqCst), 1);
        assert_eq!(failing.purges.load(Ordering::SeqCst), 1);
        assert_eq!(report.removed, 4);
        assert_eq!(report.nodes_attempted, 2);
        assert_eq!(report.nodes_failed, 1);
        assert!(!report.complete);
    }

    #[test]
    fn mesh_binding_requires_an_installed_cluster_handle() {
        let error = distributed_cluster_for_mesh(None).expect_err("no cluster installed");
        assert!(
            format!("{error:#}").contains("requires a running cluster"),
            "{error:#}"
        );
    }

    #[test]
    fn mesh_binding_rejects_a_local_only_cluster_handle() {
        let identity = sbproxy_mesh::ClusterIdentity {
            cluster_id: "semantic-test".to_string(),
            node_id: "node-a".to_string(),
            roles: [sbproxy_mesh::ClusterNodeRole::Gateway]
                .into_iter()
                .collect(),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        };
        let handle = sbproxy_mesh::ClusterHandle::local(identity).expect("local handle");

        let error =
            distributed_cluster_for_mesh(Some(&handle)).expect_err("local-only must be rejected");

        assert!(
            format!("{error:#}").contains("requires a distributed cluster"),
            "{error:#}"
        );
    }

    #[test]
    fn validation_stub_reports_its_selected_backend_and_refuses_work() {
        let store = ValidationOnlySemanticStore::arc(SemanticCacheBackend::Mesh);
        assert_eq!(store.backend(), SemanticCacheBackend::Mesh);
        let stats = store.stats();
        assert_eq!(stats.candidate_reads, 0);
        assert_eq!(stats.writes, 0);
    }
}
