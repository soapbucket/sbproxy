// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Compiled semantic-cache registry behavior (WOR-2099).
//!
//! Four contracts are pinned here:
//! * selection is exact. The origin's cache answers `get(origin, None)`,
//!   each forward rule answers only for its own index, and a forward rule
//!   without `semantic_cache:` never inherits the origin's cache,
//! * every slot keeps a status even when it has no runtime, so an
//!   operator can tell "not configured" from "disabled" from "enabled but
//!   inert",
//! * backend selection is a runtime enum, not a Cargo feature. Memory
//!   needs no external dependency, Redis needs the validated
//!   `proxy.l2_cache_settings` connection, and mesh needs a declared
//!   cluster in validation and an installed distributed cluster handle at
//!   runtime,
//! * validation-mode construction opens no Redis or mesh connection, and
//!   a scoped purge visits one shared backend adapter once rather than
//!   once per origin bound to it.
//!
//! The two-node mesh capability contracts (mixed, missing, expired,
//! suspect, and homogeneous fleets) are pinned by the transport-level
//! suite that owns those fixtures; this file covers only what the
//! compiled registry itself decides.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sbproxy_ai::semantic_cache::{
    semantic_origin_route_digest, SemanticCacheBackend, SemanticPurgeScope, SemanticStoreError,
};
use sbproxy_core::pipeline::CompiledPipeline;

/// `Result::expect_err` requires `Debug` on the success value. Several
/// types here deliberately have none: a `CompiledPipeline` would print an
/// entire compiled routing table, and a bound semantic store would print
/// cached prompts and model output. Deriving `Debug` to satisfy a test
/// assertion would put that content one `{:?}` away from a log line, so
/// unwrap the error side explicitly instead.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Accept connections on an ephemeral port, counting each one.
///
/// Returns the bound port and the shared counter. The listener task runs
/// until the test ends.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture listener");
    let port = listener.local_addr().expect("listener addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    hits_task.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
                Err(_) => return,
            }
        }
    });
    (port, hits)
}

/// Give any construction-time dial a generous window to reach a listener
/// before the zero-connection assertions run.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
}

/// One origin whose main action caches in memory, a first forward rule
/// that caches in Redis, and a second forward rule with no
/// `semantic_cache:` block at all.
fn selection_yaml() -> String {
    r#"
proxy:
  http_bind_port: 0
  l2_cache_settings:
    driver: redis
    params:
      dsn: "redis://127.0.0.1:16399"
origins:
  "cache.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: memory
        threshold: 0.9
        ttl_secs: 60
        max_entries: 64
        embedding:
          provider: openai
          model: text-embedding-3-small
    forward_rules:
      - rules:
          - path:
              prefix: /shared/
        origin:
          action:
            type: ai_proxy
            providers: []
            semantic_cache:
              enabled: true
              backend: redis
              threshold: 0.9
              ttl_secs: 60
              max_entries: 64
              embedding:
                provider: openai
                model: text-embedding-3-small
      - rules:
          - path:
              prefix: /plain/
        origin:
          action:
            type: ai_proxy
            providers: []
"#
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_rule_caches_never_fall_back_to_the_origin() {
    // Validation-mode construction so nothing outlives the pipeline;
    // backend selection is identical in both modes.
    let compiled = sbproxy_config::compile_config(&selection_yaml()).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

    let registry = &pipeline.semantic_caches;
    assert_eq!(
        registry
            .get(0, None)
            .expect("origin action cache")
            .cache
            .backend(),
        SemanticCacheBackend::Memory,
    );
    assert_eq!(
        registry
            .get(0, Some(0))
            .expect("forward-rule cache")
            .cache
            .backend(),
        SemanticCacheBackend::Redis,
    );
    assert!(
        registry.get(0, Some(1)).is_none(),
        "a forward rule without semantic_cache: must not inherit the origin cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_length_matches_actions_and_forward_rules() {
    let compiled = sbproxy_config::compile_config(&selection_yaml()).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

    let slots: Vec<_> = pipeline.semantic_caches.registrations().collect();
    // One main action plus two forward rules.
    assert_eq!(slots.len(), 3);
    assert_eq!(slots[0].origin_idx, 0);
    assert_eq!(slots[0].forward_rule_idx, None);
    assert_eq!(slots[1].forward_rule_idx, Some(0));
    assert_eq!(slots[2].forward_rule_idx, Some(1));
    assert!(slots[0].configured);
    assert!(slots[1].configured);
    assert!(
        !slots[2].configured,
        "a forward rule with no block must report an unconfigured slot"
    );
    assert!(slots[2].backend.is_none());
    assert!(slots[2].inert_reason.is_none());
    assert!(slots[2].cache.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn main_and_forward_bindings_carry_different_static_action_policy_digests() {
    let compiled = sbproxy_config::compile_config(&selection_yaml()).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

    let main = pipeline.semantic_caches.get(0, None).expect("origin cache");
    let rule = pipeline
        .semantic_caches
        .get(0, Some(0))
        .expect("forward-rule cache");
    assert_ne!(
        main.static_action_policy_digest, rule.static_action_policy_digest,
        "a forward rule's compiled policy must not digest identically to its origin's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_ai_action_creates_an_empty_slot() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "plain.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
"#;
    let compiled = sbproxy_config::compile_config(yaml).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

    assert!(pipeline.semantic_caches.get(0, None).is_none());
    let slots: Vec<_> = pipeline.semantic_caches.registrations().collect();
    assert_eq!(slots.len(), 1);
    assert!(!slots[0].configured);
    assert!(!slots[0].enabled);
    assert!(slots[0].backend.is_none());
    assert!(slots[0].store_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_semantic_cache_keeps_its_backend_without_a_runtime() {
    // A disabled mesh block must not require a cluster, a transport, or a
    // validation stub. Construction succeeds with no cluster configured.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cache.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: false
        backend: mesh
        embedding:
          provider: openai
          model: text-embedding-3-small
"#;
    let compiled = sbproxy_config::compile_config(yaml).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

    assert!(pipeline.semantic_caches.get(0, None).is_none());
    let slot = pipeline
        .semantic_caches
        .registrations()
        .next()
        .expect("one slot");
    assert!(slot.configured);
    assert!(!slot.enabled);
    assert_eq!(slot.backend, Some(SemanticCacheBackend::Mesh));
    assert!(slot.inert_reason.is_none());
    assert!(slot.cache.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inert_missing_embedding_block_keeps_a_fixed_reason_without_a_runtime() {
    // What the LiteLLM converter emits today: enabled, with no embedding
    // source block. It must stay a reported condition rather than a load
    // failure, and it must not require the selected backend's dependency.
    // This config declares no l2_cache_settings at all.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cache.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: redis
"#;
    let compiled = sbproxy_config::compile_config(yaml).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

    assert!(pipeline.semantic_caches.get(0, None).is_none());
    let slot = pipeline
        .semantic_caches
        .registrations()
        .next()
        .expect("one slot");
    assert!(slot.configured);
    assert!(slot.enabled);
    assert_eq!(slot.backend, Some(SemanticCacheBackend::Redis));
    assert_eq!(
        slot.inert_reason,
        Some("semantic_cache.embedding is not configured")
    );
    assert!(slot.cache.is_none());
    assert!(slot.store_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_backend_needs_no_external_dependency() {
    // No l2_cache_settings, no cluster, and runtime construction. An
    // existing configuration that omits `backend` keeps working exactly
    // as it does today.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cache.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        threshold: 0.9
        ttl_secs: 60
        max_entries: 64
        embedding:
          provider: openai
          model: text-embedding-3-small
"#;
    let compiled = sbproxy_config::compile_config(yaml).expect("compile");
    let pipeline = CompiledPipeline::from_config(compiled).expect("construct");

    assert_eq!(
        pipeline
            .semantic_caches
            .get(0, None)
            .expect("memory cache")
            .cache
            .backend(),
        SemanticCacheBackend::Memory,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_backend_requires_validated_redis_l2_settings() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cache.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: redis
        threshold: 0.9
        ttl_secs: 60
        max_entries: 64
        embedding:
          provider: openai
          model: text-embedding-3-small
"#;
    let compiled = sbproxy_config::compile_config(yaml).expect("compile");
    let error = expect_error(
        CompiledPipeline::from_config_for_validation(compiled),
        "redis backend without l2_cache_settings must not construct",
    );
    let message = format!("{error:#}");
    assert!(message.contains("semantic_cache"), "{message}");
    assert!(message.contains("l2_cache"), "{message}");
}

/// A single-node `cluster:` block. Validation never bootstraps it.
fn cluster_yaml(gossip_port: u16, transport_port: u16) -> String {
    // `state_dir` is required for durable cluster identity and snapshot
    // generations, so a cluster block without one fails to compile before
    // this test can reach the registry it means to exercise. Ported per
    // port pair so two tests cannot share one directory.
    format!(
        r#"  cluster:
    cluster_id: semantic-registry-test
    node_id: node-a
    state_dir: target/test-semantic-registry-{gossip_port}
    roles: [gateway]
    seeds: ["127.0.0.1:{gossip_port}"]
    gossip_port: {gossip_port}
    transport_port: {transport_port}
    advertise_addr: "127.0.0.1:{gossip_port}"
    transport_advertise_addr: "127.0.0.1:{transport_port}"
    security:
      mode: shared_key
      development: true
      shared_key: semantic-registry-development-key
"#
    )
}

/// One mesh-backed AI origin, optionally preceded by a cluster block.
fn mesh_yaml(cluster: &str) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
{cluster}origins:
  "cache.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: mesh
        threshold: 0.9
        ttl_secs: 60
        max_entries: 64
        embedding:
          provider: openai
          model: text-embedding-3-small
"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_backend_requires_proxy_cluster_in_validation_mode() {
    let compiled = sbproxy_config::compile_config(&mesh_yaml("")).expect("compile");
    let error = expect_error(
        CompiledPipeline::from_config_for_validation(compiled),
        "mesh backend without proxy.cluster must not construct",
    );
    let message = format!("{error:#}");
    assert!(message.contains("proxy.cluster"), "{message}");

    let with_cluster = mesh_yaml(&cluster_yaml(17961, 18961));
    let compiled = sbproxy_config::compile_config(&with_cluster).expect("compile");
    let pipeline =
        CompiledPipeline::from_config_for_validation(compiled).expect("declared cluster validates");
    assert_eq!(
        pipeline
            .semantic_caches
            .get(0, None)
            .expect("mesh cache")
            .cache
            .backend(),
        SemanticCacheBackend::Mesh,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_backend_requires_the_installed_distributed_cluster_handle_at_runtime() {
    // Runtime construction in a process with no installed cluster. A
    // local-only handle is rejected by the same guard, which the
    // in-module unit test covers because it can build one directly.
    let yaml = mesh_yaml(&cluster_yaml(17962, 18962));
    let compiled = sbproxy_config::compile_config(&yaml).expect("compile");
    let error = expect_error(
        CompiledPipeline::from_config(compiled),
        "mesh backend must not bind without a running cluster",
    );
    let message = format!("{error:#}");
    assert!(message.contains("semantic_cache.backend mesh"), "{message}");
    assert!(message.contains("cluster"), "{message}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_construction_opens_no_redis_or_mesh_socket() {
    let (redis_port, redis_hits) = counting_listener().await;
    let (gossip_port, gossip_hits) = counting_listener().await;
    let (transport_port, transport_hits) = counting_listener().await;

    let yaml = format!(
        r#"proxy:
  http_bind_port: 0
  l2_cache_settings:
    driver: redis
    params:
      dsn: "redis://127.0.0.1:{redis_port}"
{cluster}origins:
  "redis.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: redis
        embedding:
          provider: openai
          model: text-embedding-3-small
  "mesh.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: mesh
        embedding:
          provider: openai
          model: text-embedding-3-small
"#,
        cluster = cluster_yaml(gossip_port, transport_port),
    );
    let compiled = sbproxy_config::compile_config(&yaml).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");
    drop(pipeline);
    settle().await;

    assert_eq!(
        redis_hits.load(Ordering::SeqCst),
        0,
        "validation-mode construction dialed Redis"
    );
    assert_eq!(
        gossip_hits.load(Ordering::SeqCst),
        0,
        "validation-mode construction contacted a gossip seed"
    );
    assert_eq!(
        transport_hits.load(Ordering::SeqCst),
        0,
        "validation-mode construction contacted a peer transport"
    );
}

/// Two Redis origins sharing one adapter plus a third memory origin.
fn shared_store_yaml() -> String {
    r#"
proxy:
  http_bind_port: 0
  l2_cache_settings:
    driver: redis
    params:
      dsn: "redis://127.0.0.1:16399"
origins:
  "a.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: redis
        embedding:
          provider: openai
          model: text-embedding-3-small
  "b.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: redis
        embedding:
          provider: openai
          model: text-embedding-3-small
  "c.test":
    action:
      type: ai_proxy
      providers: []
      semantic_cache:
        enabled: true
        backend: memory
        embedding:
          provider: openai
          model: text-embedding-3-small
"#
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_shared_store_records_every_origin_that_uses_it() {
    let compiled = sbproxy_config::compile_config(&shared_store_yaml()).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");
    let registry = &pipeline.semantic_caches;

    let mut redis_ids = Vec::new();
    let mut memory_ids = Vec::new();
    for slot in registry.registrations() {
        let Some(store_id) = slot.store_id else {
            continue;
        };
        match slot.backend.expect("an active slot reports its backend") {
            SemanticCacheBackend::Redis => redis_ids.push(store_id),
            SemanticCacheBackend::Memory => memory_ids.push(store_id),
            SemanticCacheBackend::Mesh => panic!("this fixture configures no mesh slot"),
        }
    }
    assert_eq!(redis_ids.len(), 2);
    assert_eq!(
        redis_ids[0], redis_ids[1],
        "both Redis origins must share one adapter"
    );
    assert_eq!(memory_ids.len(), 1);
    assert_ne!(
        redis_ids[0], memory_ids[0],
        "a memory origin must not share the Redis adapter"
    );

    // Both Redis origins reach the one shared adapter, and it is visited
    // once per purge rather than once per origin bound to it.
    for hostname in ["a.test", "b.test"] {
        let report = registry
            .purge(&SemanticPurgeScope::Origin {
                origin_digest: semantic_origin_route_digest(hostname),
            })
            .await
            .expect("purge never turns a store error into a registry error");
        assert_eq!(report.nodes_attempted, 1, "{hostname}");
        // The validation stub refuses every operation, which is exactly
        // how a failed backend must be reported.
        assert_eq!(report.nodes_failed, 1, "{hostname}");
        assert!(!report.complete, "{hostname}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn origin_purge_selects_only_stores_registered_for_that_origin() {
    let compiled = sbproxy_config::compile_config(&shared_store_yaml()).expect("compile");
    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");
    let registry = &pipeline.semantic_caches;

    let memory_only = registry
        .purge(&SemanticPurgeScope::Origin {
            origin_digest: semantic_origin_route_digest("c.test"),
        })
        .await
        .expect("purge");
    assert_eq!(memory_only.nodes_attempted, 1);
    assert_eq!(memory_only.nodes_failed, 0);
    assert!(memory_only.complete);

    let unknown = registry
        .purge(&SemanticPurgeScope::Origin {
            origin_digest: semantic_origin_route_digest("nowhere.test"),
        })
        .await
        .expect("purge");
    assert_eq!(unknown.nodes_attempted, 0);
    assert!(unknown.complete);

    let everything = registry
        .purge(&SemanticPurgeScope::All)
        .await
        .expect("purge");
    assert_eq!(
        everything.nodes_attempted, 2,
        "scope all must visit the shared Redis adapter once, not once per origin"
    );
    assert_eq!(everything.nodes_failed, 1);
    assert!(!everything.complete);
}

/// The closed store-error set stays free of operator values, so a purge
/// or lookup failure can never carry a DSN, host, or key into a report.
#[test]
fn store_error_display_never_carries_an_operator_value() {
    for error in [
        SemanticStoreError::Unavailable,
        SemanticStoreError::InvalidWrite,
        SemanticStoreError::InvalidState,
        SemanticStoreError::OperationFailed,
    ] {
        let rendered = error.to_string();
        assert!(rendered.starts_with("semantic cache"), "{rendered}");
        assert!(!rendered.contains("redis://"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
    }
}
