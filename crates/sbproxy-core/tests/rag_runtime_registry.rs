// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Route-scoped RAG runtime registry behavior (WOR-2098).
//!
//! Three contracts are pinned here:
//! * registry selection is exact: the origin's runtime answers
//!   `get(origin, None)`, each forward rule answers only for its own
//!   index, and a forward rule without `rag:` never inherits the origin
//!   runtime,
//! * validation-mode construction with an installed process resolver
//!   resolves every RAG credential reference exactly once and dials no
//!   embedding, vector-store, or Redis endpoint,
//! * a build without the `rag` feature rejects a configured `rag:` block
//!   loudly instead of silently dropping it.
//!
//! The first two tests compile only with the `rag` feature and are run
//! with `--features rag-full` so every referenced provider adapter is
//! compiled in. The rejection test compiles only without the feature.
//! Gating the two halves per module (rather than a file-level `#![cfg]`)
//! lets one test file cover both build shapes.

#[cfg(feature = "rag")]
mod enabled {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use sbproxy_core::pipeline::CompiledPipeline;

    /// Accept connections on an ephemeral port, counting each one.
    ///
    /// Returns the bound port and the shared counter. The listener task
    /// runs until the test ends.
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

    /// Give any construction-time dial a generous window to reach a
    /// listener before the zero-connection assertions run.
    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    }

    /// One origin whose main action retrieves from Qdrant, a first forward
    /// rule retrieving from Chroma, and a second forward rule with no
    /// `rag:` block at all.
    fn selection_yaml(embedding_port: u16, qdrant_port: u16, chroma_port: u16) -> String {
        format!(
            r#"
proxy:
  http_bind_port: 0
origins:
  "rag.test":
    action:
      type: ai_proxy
      providers: []
      rag:
        embedding:
          provider: compatible
          base_url: "http://127.0.0.1:{embedding_port}/v1"
          model: fixture-embedding
          dimensions: 3
          allow_private_url: true
        vector_store:
          provider: qdrant
          base_url: "http://127.0.0.1:{qdrant_port}"
          collection: support_docs
          allow_private_url: true
    forward_rules:
      - rules:
          - path:
              prefix: /chroma/
        origin:
          action:
            type: ai_proxy
            providers: []
            rag:
              embedding:
                provider: compatible
                base_url: "http://127.0.0.1:{embedding_port}/v1"
                model: fixture-embedding
                dimensions: 3
                allow_private_url: true
              vector_store:
                provider: chroma
                base_url: "http://127.0.0.1:{chroma_port}"
                collection_id: support-docs
                allow_private_url: true
      - rules:
          - path:
              prefix: /plain/
        origin:
          action:
            type: ai_proxy
            providers: []
"#
        )
    }

    /// The selection config with every credential field pointed at the
    /// counting fixture backend, plus a Redis vector store on the forward
    /// rule so the RESP path is covered alongside the HTTP providers.
    fn secret_reference_yaml(embedding_port: u16, qdrant_port: u16, redis_port: u16) -> String {
        format!(
            r#"
proxy:
  http_bind_port: 0
origins:
  "rag.test":
    action:
      type: ai_proxy
      providers: []
      rag:
        embedding:
          provider: compatible
          base_url: "http://127.0.0.1:{embedding_port}/v1"
          model: fixture-embedding
          dimensions: 3
          api_key: "secret://counting-rag/embedding"
          allow_private_url: true
        vector_store:
          provider: qdrant
          base_url: "http://127.0.0.1:{qdrant_port}"
          collection: support_docs
          api_key: "secret://counting-rag/vector"
          allow_private_url: true
    forward_rules:
      - rules:
          - path:
              prefix: /redis/
        origin:
          action:
            type: ai_proxy
            providers: []
            rag:
              embedding:
                provider: compatible
                base_url: "http://127.0.0.1:{embedding_port}/v1"
                model: fixture-embedding
                dimensions: 3
                api_key: "secret://counting-rag/fwd-embedding"
                allow_private_url: true
              vector_store:
                provider: redis
                url: "redis://127.0.0.1:{redis_port}"
                username: "secret://counting-rag/redis-user"
                password: "secret://counting-rag/redis-pass"
                index: support-docs
                vector_field: embedding
                allow_private_url: true
"#
        )
    }

    /// Vault backend that answers every key and counts each lookup, so
    /// the test can assert every reference resolved exactly once.
    struct CountingVault {
        hits: Arc<Mutex<HashMap<String, usize>>>,
    }

    impl sbproxy_vault::VaultBackend for CountingVault {
        fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
            let mut hits = self.hits.lock().expect("hits lock");
            *hits.entry(key.to_string()).or_insert(0) += 1;
            Ok(Some(format!("resolved-{key}")))
        }

        fn set(&self, _key: &str, _value: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forward_rule_runtimes_never_fall_back_to_the_origin() {
        // Validation-mode construction so no background task outlives the
        // pipeline; provider selection is identical in both modes.
        let yaml = selection_yaml(18090, 16333, 18000);
        let compiled = sbproxy_config::compile_config(&yaml).expect("compile");
        let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");

        let registry = &pipeline.rag_runtimes;
        assert_eq!(
            registry
                .get(0, None)
                .expect("origin action runtime")
                .vector_store_provider(),
            "qdrant"
        );
        assert_eq!(
            registry
                .get(0, Some(0))
                .expect("forward-rule runtime")
                .vector_store_provider(),
            "chroma"
        );
        assert!(
            registry.get(0, Some(1)).is_none(),
            "a forward rule without rag: must not inherit the origin runtime"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validation_with_installed_resolver_resolves_rag_refs_without_dial() {
        let hits = Arc::new(Mutex::new(HashMap::new()));
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register(
            "counting-rag",
            Box::new(CountingVault {
                hits: Arc::clone(&hits),
            }),
        );
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));

        let (embedding_port, embedding_hits) = counting_listener().await;
        let (qdrant_port, qdrant_hits) = counting_listener().await;
        let (redis_port, redis_hits) = counting_listener().await;

        let yaml = secret_reference_yaml(embedding_port, qdrant_port, redis_port);
        let compiled = sbproxy_config::compile_config(&yaml).expect("compile");
        let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");
        drop(pipeline);
        settle().await;

        let hits = hits.lock().expect("hits lock");
        for key in [
            "embedding",
            "vector",
            "fwd-embedding",
            "redis-user",
            "redis-pass",
        ] {
            assert_eq!(
                hits.get(key).copied().unwrap_or(0),
                1,
                "rag reference {key} must resolve exactly once: {hits:?}"
            );
        }
        assert_eq!(hits.len(), 5, "unexpected extra resolutions: {hits:?}");

        assert_eq!(
            embedding_hits.load(Ordering::SeqCst),
            0,
            "validation-mode construction dialed the embedding endpoint"
        );
        assert_eq!(
            qdrant_hits.load(Ordering::SeqCst),
            0,
            "validation-mode construction dialed the vector store"
        );
        assert_eq!(
            redis_hits.load(Ordering::SeqCst),
            0,
            "validation-mode construction dialed Redis"
        );
    }
}

#[cfg(not(feature = "rag"))]
mod disabled {
    /// A configured `rag:` block must fail pipeline construction loudly
    /// when the `rag` feature is not compiled in, never be dropped
    /// silently. Run with
    /// `cargo nextest run -p sbproxy-core --no-default-features
    /// configured_rag_is_rejected_without_feature`.
    #[test]
    fn configured_rag_is_rejected_without_feature() {
        let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "rag.test":
    action:
      type: ai_proxy
      providers: []
      rag:
        embedding:
          provider: compatible
          base_url: "http://127.0.0.1:18090/v1"
          model: fixture-embedding
          dimensions: 3
          allow_private_url: true
        vector_store:
          provider: qdrant
          base_url: "http://127.0.0.1:16333"
          collection: support_docs
          allow_private_url: true
"#;
        let compiled = sbproxy_config::compile_config(yaml).expect("compile");
        let error =
            match sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation(compiled) {
                Ok(_) => {
                    panic!("a configured rag: block must not construct without the rag feature")
                }
                Err(error) => error,
            };
        let message = format!("{error:#}");
        assert!(message.contains("rebuild with feature 'rag'"), "{message}");
        assert!(message.contains("origin 0"), "{message}");
    }
}
