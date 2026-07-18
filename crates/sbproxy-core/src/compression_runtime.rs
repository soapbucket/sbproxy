//! Runtime binding for ordered AI context compression.

use crate::compression_store::{
    MeshCompressionStore, MeshCompressionStoreConfig, RedisCompressionStore,
    RedisCompressionStoreConfig,
};
use anyhow::{bail, Context as _};
use async_trait::async_trait;
use sbproxy_ai::compression::{
    CompressionBackend, CompressionLever, CompressionLeverConfig, CompressionPolicy,
    CompressionRequest, CompressionRequestControls, CompressionRun, CompressionRunner,
    CompressionSessionStore, InternalSummarizer, SummarizationOutput, SummarizationRequest,
    SummarizerError, SummaryBufferLever, WindowFitLever,
};
use sbproxy_ai::{AiClient, AiHandlerConfig, ProviderConfig};
use sbproxy_mesh::ClusterHandle;
use sbproxy_platform::storage::{AsyncRedisConfig, AsyncRedisKVStore};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct RuntimeDependencies {
    redis: Option<Arc<AsyncRedisKVStore>>,
    mesh: Option<ClusterHandle>,
    ai_client: Arc<AiClient>,
    writer_node: String,
}

impl RuntimeDependencies {
    fn from_process(server: &sbproxy_config::ProxyServerConfig) -> anyhow::Result<Self> {
        let redis = match server.l2_cache.as_ref() {
            Some(config) if config.driver == "redis" => {
                validate_redis_dsn(&config.params.dsn)?;
                Some(AsyncRedisKVStore::new(AsyncRedisConfig::new(
                    &config.params.dsn,
                )))
            }
            _ => None,
        };
        let cluster = crate::cluster::current_cluster_handle();
        let writer_node = cluster
            .as_ref()
            .map(|handle| handle.identity().node_id.clone())
            .unwrap_or_else(|| "standalone".to_string());
        let mesh = cluster.filter(|handle| handle.mesh_node().is_some());
        Ok(Self {
            redis,
            mesh,
            ai_client: crate::server::ai_client(),
            writer_node,
        })
    }

    #[cfg(test)]
    fn empty_for_test() -> Self {
        Self {
            redis: None,
            mesh: None,
            ai_client: Arc::new(AiClient::new()),
            writer_node: "test-node".to_string(),
        }
    }
}

fn validate_redis_dsn(dsn: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(dsn).context("Redis compression state has an invalid DSN")?;
    if !matches!(parsed.scheme(), "redis" | "rediss") || parsed.host_str().is_none() {
        bail!("Redis compression state has an invalid DSN");
    }
    Ok(())
}

/// Immutable per-origin compression dependencies held by a pipeline snapshot.
pub struct CompressionRuntime {
    policy: CompressionPolicy,
    store: Option<Arc<dyn CompressionSessionStore>>,
    providers: Vec<ProviderConfig>,
    ai_client: Arc<AiClient>,
    writer_node: String,
}

/// Immutable request-specific identity, governance, and message-shape inputs.
pub struct CompressionExecution<'a> {
    /// Effective primary model used for before/after token accounting.
    pub model: &'a str,
    /// Authoritative tenant identity from the resolved request context.
    pub tenant_id: &'a str,
    /// Immutable public credential identifier, never bearer material.
    pub api_key_id: Option<&'a str>,
    /// Stable AI handler origin used for state isolation and budget scope.
    pub origin: &'a str,
    /// Captured caller/session envelope ID bytes, if present.
    pub session_id: Option<[u8; 16]>,
    /// Closed request-shape controls used by stateful eligibility checks.
    pub controls: CompressionRequestControls,
    /// Request-time Unix timestamp in milliseconds.
    pub now_unix_ms: u64,
    /// Provider destinations allowed by the resolved credential policy.
    pub allowed_providers: &'a [String],
    /// Provider destinations denied by the resolved credential policy.
    pub blocked_providers: &'a [String],
    /// Models allowed by the resolved credential policy.
    pub allowed_models: &'a [String],
    /// Models denied by the resolved credential policy.
    pub blocked_models: &'a [String],
    /// Effective origin plus governed-key budget snapshot.
    pub budget: Option<&'a sbproxy_ai::BudgetConfig>,
}

/// Per-origin compression runtimes parallel to a compiled pipeline's actions.
#[derive(Default)]
pub struct CompressionRuntimeRegistry {
    by_origin: Vec<Option<Arc<CompressionRuntime>>>,
}

impl CompressionRuntimeRegistry {
    /// Bind every non-empty effective AI policy to current process dependencies.
    pub fn from_process(
        server: &sbproxy_config::ProxyServerConfig,
        actions: &[sbproxy_modules::Action],
    ) -> anyhow::Result<Self> {
        let dependencies = RuntimeDependencies::from_process(server)?;
        Self::with_dependencies(actions, dependencies)
    }

    fn with_dependencies(
        actions: &[sbproxy_modules::Action],
        dependencies: RuntimeDependencies,
    ) -> anyhow::Result<Self> {
        let mut by_origin = Vec::with_capacity(actions.len());
        for action in actions {
            let sbproxy_modules::Action::AiProxy(action) = action else {
                by_origin.push(None);
                continue;
            };
            let Some(policy) = action.config.effective_compression_policy() else {
                by_origin.push(None);
                continue;
            };
            if policy.levers.is_empty() {
                by_origin.push(None);
                continue;
            }
            let runtime = CompressionRuntime::build(
                policy.into_owned(),
                &action.config,
                dependencies.clone(),
            )
            .context("building AI compression runtime")?;
            by_origin.push(Some(Arc::new(runtime)));
        }
        Ok(Self { by_origin })
    }

    /// Return the runtime pinned to one compiled origin, if enabled.
    pub fn get(&self, origin_idx: usize) -> Option<&Arc<CompressionRuntime>> {
        self.by_origin.get(origin_idx).and_then(Option::as_ref)
    }

    /// Number of origin slots, including disabled/non-AI slots.
    pub fn len(&self) -> usize {
        self.by_origin.len()
    }

    /// Whether this registry has no origin slots.
    pub fn is_empty(&self) -> bool {
        self.by_origin.is_empty()
    }
}

impl fmt::Debug for CompressionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressionRuntime")
            .field("lever_count", &self.policy.levers.len())
            .field("has_state", &self.store.is_some())
            .field("provider_count", &self.providers.len())
            .field("writer_node", &self.writer_node)
            .finish()
    }
}

impl CompressionRuntime {
    fn build(
        policy: CompressionPolicy,
        handler: &AiHandlerConfig,
        dependencies: RuntimeDependencies,
    ) -> anyhow::Result<Self> {
        let summaries = policy
            .levers
            .iter()
            .filter_map(|lever| match lever {
                CompressionLeverConfig::SummaryBuffer(summary) => Some(summary),
                CompressionLeverConfig::WindowFit(_) => None,
            })
            .collect::<Vec<_>>();

        for summary in &summaries {
            let provider = handler
                .providers
                .iter()
                .find(|provider| provider.name.as_str() == summary.summarizer.provider)
                .context("compression summarizer provider is not configured on this AI handler")?;
            if !provider.enabled {
                bail!("compression summarizer provider must be enabled");
            }
            let model = summary.summarizer.model.as_str();
            let provider_declares_model = provider.models.is_empty()
                || provider
                    .models
                    .iter()
                    .any(|candidate| candidate.as_str() == model)
                || provider.model_map.contains_key(model)
                || provider
                    .default_model
                    .as_ref()
                    .is_some_and(|candidate| candidate.as_str() == model);
            if !provider_declares_model {
                bail!("compression summarizer model is not configured on its provider");
            }
            if !handler.is_model_allowed(model) {
                bail!("compression summarizer model is denied by the AI handler policy");
            }
        }

        let store: Option<Arc<dyn CompressionSessionStore>> = if summaries.is_empty() {
            None
        } else {
            let state = policy
                .state
                .as_ref()
                .context("compression state is required for summary_buffer")?;
            let ttl = Duration::from_secs(state.ttl_secs);
            match state.backend {
                CompressionBackend::Redis => {
                    let redis = dependencies.redis.clone().context(
                        "Redis compression state requires proxy.l2_cache_settings.driver: redis",
                    )?;
                    let adapter = RedisCompressionStore::new(
                        redis,
                        RedisCompressionStoreConfig {
                            deletion_fence_ttl: ttl,
                            ..RedisCompressionStoreConfig::default()
                        },
                    )
                    .map_err(|_| {
                        anyhow::anyhow!("Redis compression state configuration is invalid")
                    })?;
                    Some(Arc::new(adapter))
                }
                CompressionBackend::Mesh => {
                    let mesh = dependencies.mesh.clone().context(
                        "mesh compression state requires an active distributed proxy.cluster",
                    )?;
                    let adapter = MeshCompressionStore::new(
                        mesh,
                        MeshCompressionStoreConfig {
                            tombstone_ttl: ttl,
                            ..MeshCompressionStoreConfig::default()
                        },
                    )
                    .map_err(|_| {
                        anyhow::anyhow!("mesh compression state configuration is invalid")
                    })?;
                    Some(Arc::new(adapter))
                }
            }
        };

        Ok(Self {
            policy,
            store,
            providers: handler.providers.clone(),
            ai_client: dependencies.ai_client,
            writer_node: dependencies.writer_node,
        })
    }

    /// Whether this runtime has at least one session-scoped lever.
    pub fn has_stateful_summary(&self) -> bool {
        self.policy
            .levers
            .iter()
            .any(|lever| matches!(lever, CompressionLeverConfig::SummaryBuffer(_)))
    }

    /// External state adapter shared by request and admin operations.
    pub(crate) fn admin_store(&self) -> Option<&Arc<dyn CompressionSessionStore>> {
        self.store.as_ref()
    }

    /// Whether the current handler explicitly permits audited content inspection.
    pub(crate) fn allows_admin_content_inspection(&self) -> bool {
        self.policy.allow_admin_content_inspection
    }

    /// Whether semantic-cache reads and writes must be bypassed for this request.
    pub fn bypasses_semantic_cache(&self, has_captured_session: bool) -> bool {
        has_captured_session && self.has_stateful_summary()
    }

    /// Execute the configured lever sequence against one immutable message list.
    pub async fn run(
        &self,
        execution: CompressionExecution<'_>,
        messages: &[serde_json::Value],
    ) -> CompressionRun {
        let state_ttl = self
            .policy
            .state
            .as_ref()
            .map(|state| Duration::from_secs(state.ttl_secs));
        let mut levers: Vec<Arc<dyn CompressionLever>> =
            Vec::with_capacity(self.policy.levers.len());

        for configured in &self.policy.levers {
            match configured {
                CompressionLeverConfig::WindowFit(config) => {
                    levers.push(Arc::new(WindowFitLever::new(config.clone())));
                }
                CompressionLeverConfig::SummaryBuffer(config) => {
                    let store = self
                        .store
                        .as_ref()
                        .expect("validated summary runtime has a state store")
                        .clone();
                    let provider = self
                        .providers
                        .iter()
                        .find(|provider| provider.name.as_str() == config.summarizer.provider)
                        .expect("validated summary provider remains in pipeline snapshot")
                        .clone();
                    let summarizer = RuntimeInternalSummarizer {
                        ai_client: self.ai_client.clone(),
                        provider,
                        configured_model: config.summarizer.model.clone(),
                        max_input_tokens: sbproxy_ai::context_overflow::model_context_window(
                            &config.summarizer.model,
                        )
                        .unwrap_or(16_384)
                        .saturating_sub(config.target_summary_tokens),
                        origin: execution.origin.to_string(),
                        allowed_providers: execution.allowed_providers.to_vec(),
                        blocked_providers: execution.blocked_providers.to_vec(),
                        allowed_models: execution.allowed_models.to_vec(),
                        blocked_models: execution.blocked_models.to_vec(),
                        budget: execution.budget.cloned(),
                    };
                    levers.push(Arc::new(SummaryBufferLever::new(
                        config.clone(),
                        state_ttl.expect("validated summary runtime has state TTL"),
                        store,
                        Arc::new(summarizer),
                    )));
                }
            }
        }

        let mut request = CompressionRequest::new(execution.model)
            .with_controls(execution.controls)
            .with_clock_and_writer(execution.now_unix_ms, &self.writer_node);
        if let Some(session_id) = execution.session_id {
            request = request.with_session_context(
                execution.tenant_id,
                execution.api_key_id,
                execution.origin,
                session_id,
            );
        }
        CompressionRunner::with_model_counter(levers)
            .run(&request, messages)
            .await
    }
}

struct RuntimeInternalSummarizer {
    ai_client: Arc<AiClient>,
    provider: ProviderConfig,
    configured_model: String,
    max_input_tokens: u64,
    origin: String,
    allowed_providers: Vec<String>,
    blocked_providers: Vec<String>,
    allowed_models: Vec<String>,
    blocked_models: Vec<String>,
    budget: Option<sbproxy_ai::BudgetConfig>,
}

#[async_trait]
impl InternalSummarizer for RuntimeInternalSummarizer {
    fn max_input_tokens(&self, provider: &str, model: &str) -> u64 {
        if provider == self.provider.name.as_str() && model == self.configured_model {
            self.max_input_tokens
        } else {
            0
        }
    }

    async fn summarize(
        &self,
        request: SummarizationRequest<'_>,
    ) -> Result<SummarizationOutput, SummarizerError> {
        if request.provider != self.provider.name.as_str()
            || request.model != self.configured_model
            || !destination_allowed(
                request.provider,
                &self.allowed_providers,
                &self.blocked_providers,
            )
            || !destination_allowed(request.model, &self.allowed_models, &self.blocked_models)
        {
            return Err(SummarizerError::PolicyDenied);
        }

        let budget_keys = if let Some(budget) = self.budget.as_ref() {
            let keys = crate::server::ai_support::budget_scope_keys(
                budget,
                &self.origin,
                request.api_key_id,
                None,
                Some(request.model),
                Some(&self.origin),
                None,
            );
            let shared = crate::server::budget_share::read_shared_for_keys(&keys).await;
            match crate::server::ai_support::budget_preflight(
                budget,
                &keys,
                std::slice::from_ref(&self.provider),
                &shared,
            ) {
                crate::server::ai_support::BudgetGate::Allow => keys,
                crate::server::ai_support::BudgetGate::Block { .. }
                | crate::server::ai_support::BudgetGate::Downgrade { .. } => {
                    return Err(SummarizerError::BudgetDenied);
                }
            }
        } else {
            Vec::new()
        };

        let input_messages = request.input_messages();
        let output = self
            .ai_client
            .summarize_internal(
                &self.provider,
                request.model,
                &input_messages,
                request.target_summary_tokens,
                request.timeout,
            )
            .await?;

        if let Some(budget) = self.budget.as_ref() {
            crate::server::ai_support::record_budget_usage(
                budget,
                &budget_keys,
                request.model,
                output.input_tokens,
                output.output_tokens,
            );
            crate::server::budget_share::record_shared_budget_usage(
                budget,
                &budget_keys,
                request.model,
                output.input_tokens,
                output.output_tokens,
            )
            .await;
        }

        let cost =
            sbproxy_ai::estimate_cost(request.model, output.input_tokens, output.output_tokens);
        sbproxy_ai::ai_metrics::record_ai_request_attributed(
            request.provider,
            request.model,
            "compression_summary",
            request.tenant_id,
            request.api_key_id.unwrap_or(""),
            &sbproxy_ai::attribution::AttributionTags::default(),
            output.input_tokens,
            output.output_tokens,
            0,
            0,
            0,
            cost,
        );
        sbproxy_ai::ai_metrics::record_ai_outcome_attributed(
            request.provider,
            request.model,
            "compression_summary",
            request.tenant_id,
            request.api_key_id.unwrap_or(""),
            "ok",
        );
        Ok(output)
    }
}

fn destination_allowed(value: &str, allowed: &[String], blocked: &[String]) -> bool {
    !blocked.iter().any(|candidate| candidate == value)
        && (allowed.is_empty() || allowed.iter().any(|candidate| candidate == value))
}

#[cfg(test)]
mod tests {
    use super::{CompressionExecution, CompressionRuntime, RuntimeDependencies};
    use async_trait::async_trait;
    use sbproxy_ai::budget::{BudgetLimit, BudgetScope};
    use sbproxy_ai::compression::{
        CommitError, CompressionBackend, CompressionConsistency, CompressionRecordId,
        CompressionRequestControls, CompressionSessionRecord, CompressionSessionStore,
        DeleteResult, FailureReason, LeverOutcome, ListPage, ListRequest, PurgePage, PurgeRequest,
        SkipReason, StoreError, UpdatePermit,
    };
    use sbproxy_ai::{AiHandlerConfig, BudgetConfig, OnExceedAction};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct TestStore {
        record: Mutex<Option<CompressionSessionRecord>>,
        commit_error: Mutex<Option<CommitError>>,
    }

    #[async_trait]
    impl CompressionSessionStore for TestStore {
        fn backend(&self) -> CompressionBackend {
            CompressionBackend::Redis
        }

        fn consistency(&self) -> CompressionConsistency {
            CompressionConsistency::Serialized
        }

        async fn load(
            &self,
            _id: &CompressionRecordId,
        ) -> Result<Option<CompressionSessionRecord>, StoreError> {
            Ok(self.record.lock().unwrap().clone())
        }

        async fn acquire_update(
            &self,
            id: &CompressionRecordId,
            _lease_ttl: Duration,
        ) -> Result<Option<UpdatePermit>, StoreError> {
            Ok(Some(UpdatePermit::new(
                *id,
                CompressionBackend::Redis,
                b"runtime-test".to_vec(),
                1,
            )))
        }

        async fn commit(
            &self,
            _permit: &UpdatePermit,
            _expected_logical_version: Option<u64>,
            record: &CompressionSessionRecord,
            _ttl: Duration,
        ) -> Result<(), CommitError> {
            if let Some(error) = *self.commit_error.lock().unwrap() {
                return Err(error);
            }
            *self.record.lock().unwrap() = Some(record.clone());
            Ok(())
        }

        async fn release(&self, _permit: UpdatePermit) -> Result<(), StoreError> {
            Ok(())
        }

        async fn list(&self, _request: &ListRequest) -> Result<ListPage, StoreError> {
            unreachable!("not used")
        }

        async fn delete(&self, _id: &CompressionRecordId) -> Result<DeleteResult, StoreError> {
            unreachable!("not used")
        }

        async fn purge(&self, _request: &PurgeRequest) -> Result<PurgePage, StoreError> {
            unreachable!("not used")
        }
    }

    async fn serve_summary() -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind summarizer");
        let address = listener.local_addr().expect("summarizer address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept summary request");
            let mut request = Vec::new();
            let total = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read summary request");
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
                let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                break end + 4 + length;
            };
            while request.len() < total {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read summary body");
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
            }
            let body = r#"{"choices":[{"message":{"role":"assistant","content":"bounded historical facts"}}],"usage":{"prompt_tokens":31,"completion_tokens":4}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (format!("http://{address}/v1"), task)
    }

    fn handler_with_base_url(base_url: &str) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "summary-provider",
                "api_key": "test-key",
                "base_url": base_url,
                "allow_private_base_url": true,
                "models": ["summary-model"]
            }],
            "compression": {
                "state": {"backend": "redis", "ttl": "1h"},
                "levers": [{
                    "type": "summary_buffer",
                    "min_tokens": 100,
                    "retain_recent_messages": 1,
                    "target_summary_tokens": 20,
                    "summarizer": {
                        "provider": "summary-provider",
                        "model": "summary-model",
                        "timeout": "2s"
                    }
                }]
            }
        }))
        .expect("handler fixture")
    }

    fn runtime(handler: &AiHandlerConfig, store: Arc<TestStore>) -> CompressionRuntime {
        CompressionRuntime {
            policy: handler
                .effective_compression_policy()
                .expect("compression policy")
                .into_owned(),
            store: Some(store),
            providers: handler.providers.clone(),
            ai_client: Arc::new(sbproxy_ai::AiClient::new()),
            writer_node: "test-node".to_string(),
        }
    }

    fn history() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"role": "user", "content": "old question ".repeat(100)}),
            serde_json::json!({"role": "assistant", "content": "old answer ".repeat(100)}),
            serde_json::json!({"role": "user", "content": "recent question"}),
        ]
    }

    fn execution<'a>(
        api_key_id: Option<&'a str>,
        allowed_providers: &'a [String],
        allowed_models: &'a [String],
        budget: Option<&'a BudgetConfig>,
    ) -> CompressionExecution<'a> {
        CompressionExecution {
            model: "gpt-4",
            tenant_id: "tenant-a",
            api_key_id,
            origin: "ai.example.com",
            session_id: Some([7; 16]),
            controls: CompressionRequestControls::default(),
            now_unix_ms: 10_000,
            allowed_providers,
            blocked_providers: &[],
            allowed_models,
            blocked_models: &[],
            budget,
        }
    }

    fn handler(backend: &str) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "summary-provider",
                "api_key": "test-key",
                "models": ["summary-model"]
            }],
            "compression": {
                "state": {"backend": backend, "ttl": "1h"},
                "levers": [{
                    "type": "summary_buffer",
                    "min_tokens": 100,
                    "retain_recent_messages": 2,
                    "target_summary_tokens": 20,
                    "summarizer": {
                        "provider": "summary-provider",
                        "model": "summary-model",
                        "timeout": "2s"
                    }
                }]
            }
        }))
        .expect("handler fixture")
    }

    #[test]
    fn summary_buffer_requires_selected_redis_runtime() {
        let handler = handler("redis");
        let policy = handler
            .effective_compression_policy()
            .expect("explicit policy")
            .into_owned();

        let error =
            CompressionRuntime::build(policy, &handler, RuntimeDependencies::empty_for_test())
                .expect_err("missing Redis must fail startup");

        assert!(error
            .to_string()
            .contains("Redis compression state requires"));
        assert!(!error.to_string().contains("redis://"));
    }

    #[test]
    fn summary_buffer_requires_distributed_mesh_runtime() {
        let handler = handler("mesh");
        let policy = handler
            .effective_compression_policy()
            .expect("explicit policy")
            .into_owned();

        let error =
            CompressionRuntime::build(policy, &handler, RuntimeDependencies::empty_for_test())
                .expect_err("missing mesh must fail startup");

        assert!(error
            .to_string()
            .contains("mesh compression state requires"));
    }

    #[test]
    fn window_fit_does_not_require_external_state() {
        let handler = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "test-key"}],
            "compression": {
                "levers": [{"type": "window_fit"}]
            }
        }))
        .expect("handler fixture");
        let policy = handler
            .effective_compression_policy()
            .expect("explicit policy")
            .into_owned();

        let runtime =
            CompressionRuntime::build(policy, &handler, RuntimeDependencies::empty_for_test())
                .expect("stateless runtime builds");

        assert!(!runtime.has_stateful_summary());
    }

    #[test]
    fn only_session_scoped_summary_policies_bypass_semantic_cache() {
        let handler = handler("redis");
        let runtime = CompressionRuntime {
            policy: handler
                .effective_compression_policy()
                .expect("explicit policy")
                .into_owned(),
            store: None,
            providers: handler.providers.clone(),
            ai_client: std::sync::Arc::new(sbproxy_ai::AiClient::new()),
            writer_node: "test-node".to_string(),
        };

        assert!(!runtime.bypasses_semantic_cache(false));
        assert!(runtime.bypasses_semantic_cache(true));

        let window_handler = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "test-key"}],
            "compression": {"levers": [{"type": "window_fit"}]}
        }))
        .expect("window handler");
        let window_runtime = CompressionRuntime {
            policy: window_handler
                .effective_compression_policy()
                .expect("explicit policy")
                .into_owned(),
            store: None,
            providers: window_handler.providers.clone(),
            ai_client: std::sync::Arc::new(sbproxy_ai::AiClient::new()),
            writer_node: "test-node".to_string(),
        };
        assert!(!window_runtime.bypasses_semantic_cache(true));
    }

    #[tokio::test]
    async fn runtime_calls_exact_summarizer_and_commits_external_state() {
        let (base_url, request) = serve_summary().await;
        let handler = handler_with_base_url(&base_url);
        let store = Arc::new(TestStore::default());
        let runtime = runtime(&handler, store.clone());

        let run = runtime
            .run(execution(Some("key-a"), &[], &[], None), &history())
            .await;

        assert!(matches!(
            run.lever_results[0].outcome,
            LeverOutcome::Applied
        ));
        assert!(run.tokens_saved > 0);
        let record = store
            .record
            .lock()
            .unwrap()
            .clone()
            .expect("stored summary");
        assert_eq!(record.summary, "bounded historical facts");
        assert_eq!(record.tenant_id, "tenant-a");

        let request = String::from_utf8(request.await.unwrap()).unwrap();
        assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").expect("request body").1).unwrap();
        assert_eq!(body["model"], "summary-model");
        assert_eq!(body["max_tokens"], 20);
    }

    #[tokio::test]
    async fn credential_destination_denial_skips_without_provider_dispatch() {
        let handler = handler_with_base_url("http://127.0.0.1:9/v1");
        let runtime = runtime(&handler, Arc::new(TestStore::default()));
        let allowed_providers = vec!["different-provider".to_string()];

        let run = runtime
            .run(
                execution(Some("key-denied"), &allowed_providers, &[], None),
                &history(),
            )
            .await;

        assert_eq!(
            run.lever_results[0].outcome,
            LeverOutcome::Skipped {
                reason: SkipReason::PolicyDenied
            }
        );
    }

    #[tokio::test]
    async fn summarizer_usage_is_budgeted_before_a_later_commit_failure() {
        let (base_url, request) = serve_summary().await;
        let handler = handler_with_base_url(&base_url);
        let store = Arc::new(TestStore::default());
        *store.commit_error.lock().unwrap() = Some(CommitError::Unavailable);
        let runtime = runtime(&handler, store);
        let budget = BudgetConfig {
            limits: vec![BudgetLimit {
                scope: BudgetScope::ApiKey,
                max_tokens: Some(1),
                max_cost_usd: None,
                period: Some("total".to_string()),
                downgrade_to: None,
            }],
            on_exceed: OnExceedAction::Block,
            soft_landing: None,
        };
        let key_id = "compression-runtime-budget-commit-failure";

        let run = runtime
            .run(execution(Some(key_id), &[], &[], Some(&budget)), &history())
            .await;
        request.await.expect("summarizer was called");

        assert_eq!(
            run.lever_results[0].outcome,
            LeverOutcome::Failed {
                reason: FailureReason::StateUnavailable
            }
        );
        let keys = crate::server::ai_support::budget_scope_keys(
            &budget,
            "ai.example.com",
            Some(key_id),
            None,
            Some("summary-model"),
            Some("ai.example.com"),
            None,
        );
        assert!(matches!(
            crate::server::ai_support::budget_preflight(
                &budget,
                &keys,
                &handler.providers,
                &HashMap::new(),
            ),
            crate::server::ai_support::BudgetGate::Block { .. }
        ));
    }
}
