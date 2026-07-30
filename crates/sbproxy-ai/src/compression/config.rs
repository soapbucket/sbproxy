//! Typed configuration and validation for the compression pipeline.

use crate::provider::ProviderConfig;
use anyhow::bail;
use schemars::schema::{
    InstanceType, NumberValidation, ObjectValidation, Schema, SchemaObject, SubschemaValidation,
};
use schemars::{r#gen::SchemaGenerator, JsonSchema};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Default completion capacity reserved by the legacy window-fit behavior.
pub const DEFAULT_COMPLETION_RESERVE_TOKENS: u64 = 1_024;

/// Default lifetime for omitted state on a stateful compression pipeline.
pub const DEFAULT_COMPRESSION_STATE_TTL_SECS: u64 = 24 * 60 * 60;

/// Maximum request-selectable compression profile name length.
pub const MAX_COMPRESSION_PROFILE_NAME_LEN: usize = 64;

/// Maximum sentence count accepted by one query-selection lever.
pub const MAX_QUERY_SELECT_SENTENCES: usize = 4_096;

/// Maximum target-token budget accepted by one query-selection lever.
pub const MAX_QUERY_SELECT_TARGET_TOKENS: u64 = 1_000_000;

/// Default classifier-sidecar timeout for token pruning.
pub const DEFAULT_TOKEN_PRUNE_TIMEOUT_MS: u64 = 250;

/// Default maximum number of marked chunks sent to token pruning per request.
pub const DEFAULT_TOKEN_PRUNE_MAX_CHUNKS: usize = 64;

/// Maximum bounded chunk fan-out for one token-pruning lever.
pub const MAX_TOKEN_PRUNE_CHUNKS: usize = 256;

/// Maximum absolute token-pruning target.
pub const MAX_TOKEN_PRUNE_TARGET_TOKENS: u32 = 1_000_000;

/// Maximum UTF-8 byte length of one token-pruning model id.
pub const MAX_TOKEN_PRUNE_MODEL_ID_BYTES: usize = 256;

/// Maximum classifier-sidecar timeout accepted from configuration.
pub const MAX_TOKEN_PRUNE_TIMEOUT_MS: u64 = 60_000;

/// Closed request selector for a route-local compression pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CompressionSelector {
    /// Select the route's default compression pipeline.
    On,
    /// Disable compression for this request.
    Off,
    /// Select one declared route-local named profile.
    Profile(String),
}

impl CompressionSelector {
    /// Parse one exact selector token without accepting surrounding whitespace.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        if value != value.trim() {
            bail!("compression selector must not contain surrounding whitespace");
        }
        match value {
            "on" => return Ok(Self::On),
            "off" => return Ok(Self::Off),
            _ => {}
        }
        if value.is_empty() || value.len() > MAX_COMPRESSION_PROFILE_NAME_LEN {
            bail!("compression profile name must contain 1 to 64 bytes");
        }
        let mut bytes = value.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            bail!(
                "compression profile name must start with a lowercase ASCII letter or digit and contain only lowercase ASCII letters, digits, '_' or '-'"
            );
        }
        Ok(Self::Profile(value.to_string()))
    }

    /// Stable selector spelling used by headers, CEL, keys, and logs.
    pub fn as_str(&self) -> &str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Profile(name) => name,
        }
    }
}

impl fmt::Display for CompressionSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Ordered context-compression policy for one AI handler.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionPolicy {
    /// Shared-state backend used by stateful levers.
    #[serde(default)]
    pub state: Option<CompressionStateConfig>,
    /// Permit audited Admin-only summary-content inspection.
    #[serde(default)]
    pub allow_admin_content_inspection: bool,
    /// Compression levers executed in declaration order.
    #[serde(default)]
    pub levers: Vec<CompressionLeverConfig>,
    /// Route-local named pipelines available to governed policy and requests.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, CompressionProfile>,
}

/// One reusable route-local compression pipeline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionProfile {
    /// Shared-state backend used by stateful levers in this profile.
    #[serde(default)]
    pub state: Option<CompressionStateConfig>,
    /// Compression levers executed in declaration order.
    #[serde(default)]
    pub levers: Vec<CompressionLeverConfig>,
}

/// External state selected for stateful compression levers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionStateConfig {
    /// Existing process-wide state subsystem to reuse.
    pub backend: CompressionStateBackend,
    /// Record lifetime, in seconds after deserialization.
    #[serde(
        rename = "ttl",
        deserialize_with = "sbproxy_config::duration::deserialize_secs"
    )]
    #[schemars(with = "DurationSchema")]
    pub ttl_secs: u64,
}

impl Default for CompressionStateConfig {
    fn default() -> Self {
        Self {
            backend: CompressionStateBackend::Local,
            ttl_secs: DEFAULT_COMPRESSION_STATE_TTL_SECS,
        }
    }
}

/// State backends safe to select from public compression configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompressionStateBackend {
    /// Durable lease-serialized state in the process-owned embedded database.
    Local,
    /// Strict Redis lease, fence, and compare-and-set storage.
    Redis,
    /// Replicated mesh storage over the cluster replication substrate.
    /// Requires `proxy.cluster.replication`; conditional writes converge
    /// through causal last-writer-wins merging.
    Mesh,
}

/// Backend identity exposed by store adapters and administrative metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompressionBackend {
    /// Durable lease-serialized state in the process-owned embedded database.
    Local,
    /// Strict Redis lease, fence, and compare-and-set storage.
    Redis,
    /// Eventual last-writer-wins mesh storage.
    Mesh,
}

/// Ranking source used by retrieval-aware compression levers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalRanking {
    /// Select supplied scores when complete, otherwise use lexical ranking.
    #[default]
    Auto,
    /// Require caller-supplied relevance scores.
    Supplied,
    /// Rank marked context with deterministic lexical relevance.
    Lexical,
}

impl RetrievalRanking {
    /// Stable configuration, metric, and log label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Supplied => "supplied",
            Self::Lexical => "lexical",
        }
    }
}

/// One configured compression lever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompressionLeverConfig {
    /// Stateful running-summary compaction.
    SummaryBuffer(SummaryBufferConfig),
    /// Deterministic compatibility trimming to the target model window.
    WindowFit(WindowFitConfig),
    /// Sidecar-backed LLMLingua-2 token pruning over marked text chunks.
    TokenPrune(TokenPruneConfig),
    /// Query-aware sentence selection from marked text chunks.
    QuerySelect(QuerySelectConfig),
    /// Retrieval-aware selection of marked context chunks.
    RagSelect(RagSelectConfig),
    /// Deterministic compact serialization of supported structured content.
    CompactSerialization(CompactSerializationConfig),
    /// Reorder marked context to mitigate lost-in-the-middle effects.
    PositionReorder(PositionReorderConfig),
}

/// Sidecar-backed extractive token-pruning configuration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenPruneConfig {
    /// Minimum target-model tokens across marked text bodies before pruning.
    #[schemars(range(min = 1))]
    pub min_tokens: u64,
    /// Classifier gRPC URI or absolute `unix://` socket path.
    #[schemars(length(min = 1))]
    pub endpoint: String,
    /// Sidecar token-classification model id.
    #[schemars(length(min = 1, max = 256))]
    pub model: String,
    /// Per-RPC timeout in milliseconds.
    #[serde(default = "default_token_prune_timeout_ms")]
    #[schemars(range(min = 1, max = 60_000))]
    pub timeout_ms: u64,
    /// Maximum marked chunks sent to the sidecar in one request.
    #[serde(default = "default_token_prune_max_chunks")]
    #[schemars(range(min = 1, max = 256))]
    pub max_chunks: usize,
    /// Compression target interpreted by the sidecar and rechecked by the gateway.
    pub target: TokenPruneTarget,
}

impl fmt::Debug for TokenPruneConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenPruneConfig")
            .field("min_tokens", &self.min_tokens)
            .field("endpoint", &"<redacted>")
            .field("model", &self.model)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_chunks", &self.max_chunks)
            .field("target", &self.target)
            .finish()
    }
}

/// Exactly one explicit token-pruning target mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum TokenPruneTarget {
    /// Retain a percentage of pruning-tokenizer tokens in each marked chunk.
    RetainRatio {
        /// Percentage retained, from 1 through 99.
        #[schemars(range(min = 1, max = 99))]
        retain_percent: u8,
    },
    /// Retain marked bodies within one target-model token budget.
    TargetTokens {
        /// Aggregate target-model token budget for marked bodies.
        #[schemars(range(min = 1, max = 1_000_000))]
        target_tokens: u32,
    },
}

/// Exactly one bounded budget for query-aware sentence selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum QuerySelectConfig {
    /// Retain at most this many relevant sentences across each retrieval block.
    Sentences {
        /// Maximum relevant sentence count.
        max_sentences: usize,
    },
    /// Retain relevant sentences within this target-model token budget.
    TargetTokens {
        /// Maximum estimated tokens across selected sentence bodies.
        target_tokens: u64,
    },
}

impl<'de> Deserialize<'de> for QuerySelectConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireConfig {
            #[serde(default)]
            max_sentences: Option<usize>,
            #[serde(default)]
            target_tokens: Option<u64>,
        }

        let wire = WireConfig::deserialize(deserializer)?;
        match (wire.max_sentences, wire.target_tokens) {
            (Some(max_sentences), None) => Ok(Self::Sentences { max_sentences }),
            (None, Some(target_tokens)) => Ok(Self::TargetTokens { target_tokens }),
            _ => Err(serde::de::Error::custom(
                "query_select requires exactly one of max_sentences or target_tokens",
            )),
        }
    }
}

impl JsonSchema for QuerySelectConfig {
    fn schema_name() -> String {
        "QuerySelectConfig".to_string()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        let bounded_integer = |format: &str, maximum: f64| {
            SchemaObject {
                instance_type: Some(InstanceType::Integer.into()),
                format: Some(format.to_string()),
                number: Some(Box::new(NumberValidation {
                    minimum: Some(1.0),
                    maximum: Some(maximum),
                    ..NumberValidation::default()
                })),
                ..SchemaObject::default()
            }
            .into()
        };
        let required = |property: &str| {
            SchemaObject {
                object: Some(Box::new(ObjectValidation {
                    required: BTreeSet::from([property.to_string()]),
                    ..ObjectValidation::default()
                })),
                ..SchemaObject::default()
            }
            .into()
        };
        let mut object = ObjectValidation {
            additional_properties: Some(Box::new(false.into())),
            ..ObjectValidation::default()
        };
        object.properties.insert(
            "max_sentences".to_string(),
            bounded_integer("uint", MAX_QUERY_SELECT_SENTENCES as f64),
        );
        object.properties.insert(
            "target_tokens".to_string(),
            bounded_integer("uint64", MAX_QUERY_SELECT_TARGET_TOKENS as f64),
        );

        SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(object)),
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(vec![required("max_sentences"), required("target_tokens")]),
                ..SubschemaValidation::default()
            })),
            ..SchemaObject::default()
        }
        .into()
    }
}

/// Configuration for retrieval-aware marked-context selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RagSelectConfig {
    /// Minimum marked-context tokens before selection is eligible.
    #[schemars(range(min = 1))]
    pub min_tokens: u64,
    /// Ranking source used to compare marked chunks.
    #[serde(default)]
    pub ranking: RetrievalRanking,
    /// Maximum number of marked chunks retained.
    #[schemars(range(min = 1))]
    pub max_chunks: usize,
    /// Minimum accepted relevance percentage, from 0 through 100.
    #[serde(default)]
    #[schemars(range(max = 100))]
    pub min_relevance_percent: u8,
    /// Drop marked chunks whose selected content is empty.
    #[serde(default)]
    pub drop_empty: bool,
}

/// Configuration for deterministic compact serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompactSerializationConfig {
    /// Minimum marked-context tokens before serialization is eligible.
    #[schemars(range(min = 1))]
    pub min_tokens: u64,
    /// Optional tabular compaction rules.
    #[serde(default)]
    #[schemars(schema_with = "conditional_tabular_serialization_schema")]
    pub tabular: TabularSerializationConfig,
}

/// Tabular serialization eligibility controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TabularSerializationConfig {
    /// Enable tabular serialization of supported row collections.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum row count required when tabular serialization is enabled.
    #[serde(default = "default_tabular_min_rows")]
    pub min_rows: usize,
}

impl Default for TabularSerializationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_rows: 8,
        }
    }
}

fn conditional_tabular_serialization_schema(generator: &mut SchemaGenerator) -> Schema {
    let enabled_is_true = SchemaObject {
        const_value: Some(serde_json::Value::Bool(true)),
        ..SchemaObject::default()
    };
    let mut enabled_object = ObjectValidation {
        required: BTreeSet::from(["enabled".to_string()]),
        ..ObjectValidation::default()
    };
    enabled_object
        .properties
        .insert("enabled".to_string(), enabled_is_true.into());
    let enabled_condition = SchemaObject {
        object: Some(Box::new(enabled_object)),
        ..SchemaObject::default()
    };
    let minimum_rows = SchemaObject {
        number: Some(Box::new(NumberValidation {
            minimum: Some(2.0),
            ..NumberValidation::default()
        })),
        ..SchemaObject::default()
    };
    let mut requirement_object = ObjectValidation::default();
    requirement_object
        .properties
        .insert("min_rows".to_string(), minimum_rows.into());
    let enabled_requirement = SchemaObject {
        object: Some(Box::new(requirement_object)),
        ..SchemaObject::default()
    };

    SchemaObject {
        subschemas: Some(Box::new(SubschemaValidation {
            all_of: Some(vec![generator.subschema_for::<TabularSerializationConfig>()]),
            if_schema: Some(Box::new(enabled_condition.into())),
            then_schema: Some(Box::new(enabled_requirement.into())),
            ..SubschemaValidation::default()
        })),
        ..SchemaObject::default()
    }
    .into()
}

/// Configuration for marked-context position reordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionReorderConfig {
    /// Ranking source used to order marked chunks.
    #[serde(default)]
    pub ranking: RetrievalRanking,
}

/// Configuration for the stateful running-summary lever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryBufferConfig {
    /// Minimum request input tokens before summary buffering is eligible.
    pub min_tokens: u64,
    /// Number of most recent messages retained byte-for-byte.
    pub retain_recent_messages: usize,
    /// Maximum tokens requested from the dedicated summarizer.
    pub target_summary_tokens: u64,
    /// Dedicated provider and model used for internal summaries.
    pub summarizer: SummarizerConfig,
}

/// Dedicated internal summarizer selection and timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummarizerConfig {
    /// Provider name from the same AI handler.
    pub provider: String,
    /// Model sent to the selected provider.
    pub model: String,
    /// Hard request timeout, in seconds after deserialization.
    #[serde(
        rename = "timeout",
        deserialize_with = "sbproxy_config::duration::deserialize_secs"
    )]
    #[schemars(with = "DurationSchema")]
    pub timeout_secs: u64,
}

/// Configuration for deterministic model-window fitting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowFitConfig {
    /// Completion capacity excluded from the input-message budget.
    #[serde(default = "default_completion_reserve_tokens")]
    pub completion_reserve_tokens: u64,
    /// Optional hard input-message budget before the target model limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub input_budget_tokens: Option<u64>,
}

impl Default for WindowFitConfig {
    fn default() -> Self {
        Self {
            completion_reserve_tokens: DEFAULT_COMPLETION_RESERVE_TOKENS,
            input_budget_tokens: None,
        }
    }
}

impl CompressionPolicy {
    /// Construct the one-lever policy representing the legacy boolean.
    pub fn legacy_window_fit(completion_reserve_tokens: Option<u64>) -> Self {
        Self {
            state: None,
            allow_admin_content_inspection: false,
            levers: vec![CompressionLeverConfig::WindowFit(WindowFitConfig {
                completion_reserve_tokens: completion_reserve_tokens
                    .unwrap_or(DEFAULT_COMPLETION_RESERVE_TOKENS),
                input_budget_tokens: None,
            })],
            profiles: BTreeMap::new(),
        }
    }

    /// Materialize defaults needed by stateful pipelines after deserialization.
    ///
    /// Route and profile pipelines are independent: a profile with an omitted
    /// state block receives Local state rather than borrowing the route state.
    pub fn apply_state_defaults(&mut self) {
        apply_pipeline_state_default(&mut self.state, &self.levers);
        for profile in self.profiles.values_mut() {
            apply_pipeline_state_default(&mut profile.state, &profile.levers);
        }
    }

    /// Validate policy-local invariants and summarizer provider references.
    pub fn validate(&self, providers: &[ProviderConfig]) -> anyhow::Result<()> {
        validate_pipeline("compression", self.state.as_ref(), &self.levers, providers)?;

        for (name, profile) in &self.profiles {
            if !matches!(
                CompressionSelector::parse(name),
                Ok(CompressionSelector::Profile(_))
            ) {
                bail!(
                    "compression.profiles.{name} is not a valid non-reserved compression profile name"
                );
            }
            validate_pipeline(
                &format!("compression.profiles.{name}"),
                profile.state.as_ref(),
                &profile.levers,
                providers,
            )?;
        }
        Ok(())
    }
}

fn apply_pipeline_state_default(
    state: &mut Option<CompressionStateConfig>,
    levers: &[CompressionLeverConfig],
) {
    if state.is_none()
        && levers
            .iter()
            .any(|lever| matches!(lever, CompressionLeverConfig::SummaryBuffer(_)))
    {
        *state = Some(CompressionStateConfig::default());
    }
}

fn validate_pipeline(
    path: &str,
    state: Option<&CompressionStateConfig>,
    levers: &[CompressionLeverConfig],
    providers: &[ProviderConfig],
) -> anyhow::Result<()> {
    if state.is_some_and(|state| state.ttl_secs == 0) {
        bail!("{path}.state.ttl must be greater than zero");
    }

    for (index, lever) in levers.iter().enumerate() {
        match lever {
            CompressionLeverConfig::SummaryBuffer(summary) => {
                if summary.min_tokens == 0 {
                    bail!("{path}.levers[{index}].min_tokens must be greater than zero");
                }
                if summary.retain_recent_messages == 0 {
                    bail!(
                        "{path}.levers[{index}].retain_recent_messages must be greater than zero"
                    );
                }
                if summary.target_summary_tokens == 0 {
                    bail!("{path}.levers[{index}].target_summary_tokens must be greater than zero");
                }
                if summary.target_summary_tokens >= summary.min_tokens {
                    bail!(
                        "{path}.levers[{index}].target_summary_tokens must be smaller than min_tokens"
                    );
                }
                if summary.summarizer.model.trim().is_empty() {
                    bail!("{path}.levers[{index}].summarizer.model must not be empty");
                }
                if summary.summarizer.timeout_secs == 0 {
                    bail!("{path}.levers[{index}].summarizer.timeout must be greater than zero");
                }
                if !providers
                    .iter()
                    .any(|provider| provider.name.as_str() == summary.summarizer.provider)
                {
                    bail!(
                        "{path}.levers[{index}].summarizer.provider {:?} is not configured on this AI handler",
                        summary.summarizer.provider
                    );
                }
            }
            CompressionLeverConfig::WindowFit(window) => {
                if window.input_budget_tokens == Some(0) {
                    bail!("{path}.levers[{index}].input_budget_tokens must be greater than zero");
                }
            }
            CompressionLeverConfig::TokenPrune(token_prune) => {
                if token_prune.min_tokens == 0 {
                    bail!("{path}.levers[{index}].min_tokens must be greater than zero");
                }
                if token_prune.model.trim().is_empty() {
                    bail!("{path}.levers[{index}].model must not be empty");
                }
                if token_prune.model.len() > MAX_TOKEN_PRUNE_MODEL_ID_BYTES {
                    bail!(
                        "{path}.levers[{index}].model must be at most {MAX_TOKEN_PRUNE_MODEL_ID_BYTES} UTF-8 bytes"
                    );
                }
                if token_prune.endpoint.trim().is_empty() {
                    bail!("{path}.levers[{index}].endpoint must not be empty");
                }
                if let Some(socket_path) = token_prune.endpoint.strip_prefix("unix://") {
                    if !std::path::Path::new(socket_path).is_absolute() {
                        bail!("{path}.levers[{index}].endpoint unix socket path must be absolute");
                    }
                } else {
                    sbproxy_classifier_client::ClassifierClient::validate_endpoint(
                        &token_prune.endpoint,
                    )
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "{path}.levers[{index}].endpoint must be a valid classifier gRPC URI or absolute unix:// path"
                        )
                    })?;
                }
                if token_prune.timeout_ms == 0
                    || token_prune.timeout_ms > MAX_TOKEN_PRUNE_TIMEOUT_MS
                {
                    bail!(
                        "{path}.levers[{index}].timeout_ms must be between 1 and {MAX_TOKEN_PRUNE_TIMEOUT_MS}"
                    );
                }
                if token_prune.max_chunks == 0 || token_prune.max_chunks > MAX_TOKEN_PRUNE_CHUNKS {
                    bail!(
                        "{path}.levers[{index}].max_chunks must be between 1 and {MAX_TOKEN_PRUNE_CHUNKS}"
                    );
                }
                match token_prune.target {
                    TokenPruneTarget::RetainRatio { retain_percent }
                        if !(1..=99).contains(&retain_percent) =>
                    {
                        bail!(
                            "{path}.levers[{index}].target.retain_percent must be between 1 and 99"
                        );
                    }
                    TokenPruneTarget::TargetTokens { target_tokens }
                        if target_tokens == 0 || target_tokens > MAX_TOKEN_PRUNE_TARGET_TOKENS =>
                    {
                        bail!(
                            "{path}.levers[{index}].target.target_tokens must be between 1 and {MAX_TOKEN_PRUNE_TARGET_TOKENS}"
                        );
                    }
                    _ => {}
                }
            }
            CompressionLeverConfig::QuerySelect(query_select) => match query_select {
                QuerySelectConfig::Sentences { max_sentences } => {
                    if *max_sentences == 0 || *max_sentences > MAX_QUERY_SELECT_SENTENCES {
                        bail!(
                            "{path}.levers[{index}].max_sentences must be between 1 and {MAX_QUERY_SELECT_SENTENCES}"
                        );
                    }
                }
                QuerySelectConfig::TargetTokens { target_tokens } => {
                    if *target_tokens == 0 || *target_tokens > MAX_QUERY_SELECT_TARGET_TOKENS {
                        bail!(
                            "{path}.levers[{index}].target_tokens must be between 1 and {MAX_QUERY_SELECT_TARGET_TOKENS}"
                        );
                    }
                }
            },
            CompressionLeverConfig::RagSelect(rag_select) => {
                if rag_select.min_tokens == 0 {
                    bail!("{path}.levers[{index}].min_tokens must be greater than zero");
                }
                if rag_select.max_chunks == 0 {
                    bail!("{path}.levers[{index}].max_chunks must be greater than zero");
                }
                if rag_select.min_relevance_percent > 100 {
                    bail!("{path}.levers[{index}].min_relevance_percent must not exceed 100");
                }
            }
            CompressionLeverConfig::CompactSerialization(compact) => {
                if compact.min_tokens == 0 {
                    bail!("{path}.levers[{index}].min_tokens must be greater than zero");
                }
                if compact.tabular.enabled && compact.tabular.min_rows < 2 {
                    bail!(
                        "{path}.levers[{index}].tabular.min_rows must be at least 2 when tabular.enabled is true"
                    );
                }
            }
            CompressionLeverConfig::PositionReorder(_) => {}
        }
    }
    Ok(())
}

fn default_completion_reserve_tokens() -> u64 {
    DEFAULT_COMPLETION_RESERVE_TOKENS
}

fn default_token_prune_timeout_ms() -> u64 {
    DEFAULT_TOKEN_PRUNE_TIMEOUT_MS
}

fn default_token_prune_max_chunks() -> usize {
    DEFAULT_TOKEN_PRUNE_MAX_CHUNKS
}

fn default_tabular_min_rows() -> usize {
    8
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
enum DurationSchema {
    Seconds(u64),
    Human(String),
}

#[cfg(test)]
mod tests {
    use super::{
        CompressionLeverConfig, CompressionPolicy, CompressionSelector, CompressionStateBackend,
        QuerySelectConfig, RetrievalRanking, TokenPruneConfig, TokenPruneTarget,
    };
    use crate::handler::AiHandlerConfig;
    use jsonschema::JSONSchema;

    fn provider(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "api_key": "test-key",
            "models": ["gpt-test"]
        })
    }

    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "providers": [provider("openai"), provider("anthropic")],
            "compression": {
                "state": {
                    "backend": "redis",
                    "ttl": "24h"
                },
                "levers": [
                    {
                        "type": "summary_buffer",
                        "min_tokens": 12_000,
                        "retain_recent_messages": 8,
                        "target_summary_tokens": 2_048,
                        "summarizer": {
                            "provider": "anthropic",
                            "model": "gpt-test",
                            "timeout": "5s"
                        }
                    },
                    {
                        "type": "window_fit",
                        "completion_reserve_tokens": 1_024
                    }
                ]
            }
        })
    }

    fn config_with_levers(levers: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "providers": [provider("openai")],
            "compression": {"levers": levers}
        })
    }

    fn compression_schema() -> JSONSchema {
        let schema = schemars::schema_for!(CompressionPolicy);
        let value = serde_json::to_value(schema).expect("compression schema serializes");
        JSONSchema::compile(&value).expect("compression schema compiles")
    }

    fn policy_with_lever(lever: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"levers": [lever]})
    }

    #[test]
    fn generated_schema_rejects_runtime_invalid_stateless_bounds() {
        let schema = compression_schema();
        let invalid = [
            serde_json::json!({
                "type": "token_prune",
                "min_tokens": 0,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "target": {"mode": "retain_ratio", "retain_percent": 50}
            }),
            serde_json::json!({
                "type": "token_prune",
                "min_tokens": 1,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "timeout_ms": 60_001,
                "target": {"mode": "retain_ratio", "retain_percent": 50}
            }),
            serde_json::json!({
                "type": "token_prune",
                "min_tokens": 1,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "max_chunks": 257,
                "target": {"mode": "retain_ratio", "retain_percent": 50}
            }),
            serde_json::json!({
                "type": "token_prune",
                "min_tokens": 1,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "target": {"mode": "retain_ratio", "retain_percent": 100}
            }),
            serde_json::json!({
                "type": "token_prune",
                "min_tokens": 1,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "target": {"mode": "target_tokens", "target_tokens": 1_000_001}
            }),
            serde_json::json!({"type": "query_select", "max_sentences": 0}),
            serde_json::json!({"type": "query_select", "max_sentences": 4_097}),
            serde_json::json!({"type": "query_select", "target_tokens": 0}),
            serde_json::json!({"type": "query_select", "target_tokens": 1_000_001}),
            serde_json::json!({"type": "query_select"}),
            serde_json::json!({
                "type": "query_select",
                "max_sentences": 8,
                "target_tokens": 512
            }),
            serde_json::json!({"type": "rag_select", "min_tokens": 0, "max_chunks": 1}),
            serde_json::json!({"type": "rag_select", "min_tokens": 1, "max_chunks": 0}),
            serde_json::json!({
                "type": "rag_select",
                "min_tokens": 1,
                "max_chunks": 1,
                "min_relevance_percent": 101
            }),
            serde_json::json!({"type": "compact_serialization", "min_tokens": 0}),
        ];

        for lever in invalid {
            let instance = policy_with_lever(lever.clone());
            assert!(
                !schema.is_valid(&instance),
                "schema accepted runtime-invalid lever: {lever}"
            );
        }

        let valid = policy_with_lever(serde_json::json!({
            "type": "rag_select",
            "min_tokens": 1,
            "max_chunks": 1,
            "min_relevance_percent": 100
        }));
        assert!(schema.is_valid(&valid));
        assert!(schema.is_valid(&policy_with_lever(serde_json::json!({
            "type": "query_select",
            "max_sentences": 4_096
        }))));
        assert!(schema.is_valid(&policy_with_lever(serde_json::json!({
            "type": "query_select",
            "target_tokens": 1_000_000
        }))));
        assert!(schema.is_valid(&policy_with_lever(serde_json::json!({
            "type": "token_prune",
            "min_tokens": 1,
            "endpoint": "unix:///run/sbproxy/classifier.sock",
            "model": "llmlingua-2",
            "timeout_ms": 60_000,
            "max_chunks": 256,
            "target": {"mode": "retain_ratio", "retain_percent": 99}
        }))));
    }

    #[test]
    fn parses_both_token_pruning_targets_and_defaults() {
        let config = AiHandlerConfig::from_config(config_with_levers(serde_json::json!([
            {
                "type": "token_prune",
                "min_tokens": 1_024,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "target": {"mode": "retain_ratio", "retain_percent": 40}
            },
            {
                "type": "token_prune",
                "min_tokens": 2_048,
                "endpoint": "unix:///run/sbproxy/classifier.sock",
                "model": "llmlingua-2",
                "timeout_ms": 500,
                "max_chunks": 12,
                "target": {"mode": "target_tokens", "target_tokens": 768}
            }
        ])))
        .expect("token-pruning targets parse");
        let levers = &config.compression.expect("compression policy").levers;

        let CompressionLeverConfig::TokenPrune(ratio) = &levers[0] else {
            panic!("expected ratio token-prune config");
        };
        assert_eq!(ratio.timeout_ms, 250);
        assert_eq!(ratio.max_chunks, 64);
        assert_eq!(
            ratio.target,
            TokenPruneTarget::RetainRatio { retain_percent: 40 }
        );
        let CompressionLeverConfig::TokenPrune(tokens) = &levers[1] else {
            panic!("expected absolute token-prune config");
        };
        assert_eq!(tokens.timeout_ms, 500);
        assert_eq!(tokens.max_chunks, 12);
        assert_eq!(
            tokens.target,
            TokenPruneTarget::TargetTokens { target_tokens: 768 }
        );
    }

    #[test]
    fn token_prune_debug_redacts_endpoint_through_enclosing_configs() {
        let sensitive_endpoint = "unix:///private/customer-a/classifier.sock";
        let token_prune = TokenPruneConfig {
            min_tokens: 1_024,
            endpoint: sensitive_endpoint.to_string(),
            model: "llmlingua-2".to_string(),
            timeout_ms: 250,
            max_chunks: 64,
            target: TokenPruneTarget::TargetTokens { target_tokens: 768 },
        };
        let lever = CompressionLeverConfig::TokenPrune(token_prune.clone());
        let policy = CompressionPolicy {
            levers: vec![lever.clone()],
            ..CompressionPolicy::default()
        };

        for debug in [
            format!("{token_prune:?}"),
            format!("{lever:?}"),
            format!("{policy:?}"),
        ] {
            assert!(!debug.contains(sensitive_endpoint), "{debug}");
            assert!(debug.contains("<redacted>"), "{debug}");
            assert!(debug.contains("llmlingua-2"), "{debug}");
        }
    }

    #[test]
    fn schema_rejects_token_prune_model_ids_longer_than_256_characters() {
        let schema = compression_schema();
        let policy = policy_with_lever(serde_json::json!({
            "type": "token_prune",
            "min_tokens": 1_024,
            "endpoint": "http://127.0.0.1:9440",
            "model": "m".repeat(257),
            "target": {"mode": "retain_ratio", "retain_percent": 50}
        }));

        assert!(!schema.is_valid(&policy));
    }

    #[test]
    fn runtime_bounds_token_prune_model_ids_by_utf8_bytes() {
        let exactly_256_bytes = "é".repeat(128);
        let valid = config_with_levers(serde_json::json!([{
            "type": "token_prune",
            "min_tokens": 1_024,
            "endpoint": "http://127.0.0.1:9440",
            "model": exactly_256_bytes,
            "target": {"mode": "retain_ratio", "retain_percent": 50}
        }]));
        AiHandlerConfig::from_config(valid).expect("a 256-byte model id is valid");

        let oversized = format!("{exactly_256_bytes}x");
        let invalid = config_with_levers(serde_json::json!([{
            "type": "token_prune",
            "min_tokens": 1_024,
            "endpoint": "http://127.0.0.1:9440",
            "model": oversized,
            "target": {"mode": "retain_ratio", "retain_percent": 50}
        }]));
        let error = AiHandlerConfig::from_config(invalid)
            .expect_err("a 257-byte model id must fail before runtime")
            .to_string();

        assert!(error.contains("at most 256 UTF-8 bytes"), "{error}");
    }

    #[test]
    fn parses_exactly_one_bounded_query_selection_budget() {
        let config = AiHandlerConfig::from_config(config_with_levers(serde_json::json!([
            {"type": "query_select", "max_sentences": 12},
            {"type": "query_select", "target_tokens": 768}
        ])))
        .expect("query selection budgets parse");
        let levers = &config.compression.expect("compression policy").levers;

        assert_eq!(
            levers[0],
            CompressionLeverConfig::QuerySelect(QuerySelectConfig::Sentences { max_sentences: 12 })
        );
        assert_eq!(
            levers[1],
            CompressionLeverConfig::QuerySelect(QuerySelectConfig::TargetTokens {
                target_tokens: 768
            })
        );

        for invalid in [
            serde_json::json!({"type": "query_select"}),
            serde_json::json!({
                "type": "query_select",
                "max_sentences": 12,
                "target_tokens": 768
            }),
            serde_json::json!({"type": "query_select", "max_sentences": 0}),
            serde_json::json!({"type": "query_select", "max_sentences": 4_097}),
            serde_json::json!({"type": "query_select", "target_tokens": 0}),
            serde_json::json!({"type": "query_select", "target_tokens": 1_000_001}),
        ] {
            assert!(
                AiHandlerConfig::from_config(config_with_levers(serde_json::json!([invalid])))
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_schema_enforces_tabular_min_rows_only_when_enabled() {
        let schema = compression_schema();
        let enabled_too_small = policy_with_lever(serde_json::json!({
            "type": "compact_serialization",
            "min_tokens": 1,
            "tabular": {"enabled": true, "min_rows": 1}
        }));
        let disabled_small = policy_with_lever(serde_json::json!({
            "type": "compact_serialization",
            "min_tokens": 1,
            "tabular": {"enabled": false, "min_rows": 1}
        }));
        let disabled_zero = policy_with_lever(serde_json::json!({
            "type": "compact_serialization",
            "min_tokens": 1,
            "tabular": {"enabled": false, "min_rows": 0}
        }));
        let enabled_boundary = policy_with_lever(serde_json::json!({
            "type": "compact_serialization",
            "min_tokens": 1,
            "tabular": {"enabled": true, "min_rows": 2}
        }));

        assert!(!schema.is_valid(&enabled_too_small));
        assert!(schema.is_valid(&disabled_small));
        assert!(schema.is_valid(&disabled_zero));
        assert!(schema.is_valid(&enabled_boundary));
    }

    #[test]
    fn parses_stateless_lever_defaults_and_closed_rankings() {
        let config = AiHandlerConfig::from_config(config_with_levers(serde_json::json!([
            {
                "type": "rag_select",
                "min_tokens": 1_024,
                "max_chunks": 12
            },
            {
                "type": "compact_serialization",
                "min_tokens": 2_048
            },
            {
                "type": "position_reorder"
            }
        ])))
        .expect("stateless levers parse");
        let levers = &config.compression.expect("compression policy").levers;

        let CompressionLeverConfig::RagSelect(rag_select) = &levers[0] else {
            panic!("expected rag_select");
        };
        assert_eq!(rag_select.min_tokens, 1_024);
        assert_eq!(rag_select.ranking, RetrievalRanking::Auto);
        assert_eq!(rag_select.max_chunks, 12);
        assert_eq!(rag_select.min_relevance_percent, 0);
        assert!(!rag_select.drop_empty);

        let CompressionLeverConfig::CompactSerialization(compact) = &levers[1] else {
            panic!("expected compact_serialization");
        };
        assert_eq!(compact.min_tokens, 2_048);
        assert!(!compact.tabular.enabled);
        assert_eq!(compact.tabular.min_rows, 8);

        let CompressionLeverConfig::PositionReorder(position_reorder) = &levers[2] else {
            panic!("expected position_reorder");
        };
        assert_eq!(position_reorder.ranking, RetrievalRanking::Auto);

        for (value, expected, label) in [
            ("auto", RetrievalRanking::Auto, "auto"),
            ("supplied", RetrievalRanking::Supplied, "supplied"),
            ("lexical", RetrievalRanking::Lexical, "lexical"),
        ] {
            let ranking: RetrievalRanking =
                serde_json::from_value(serde_json::json!(value)).expect("known ranking");
            assert_eq!(ranking, expected);
            assert_eq!(ranking.as_str(), label);
        }
        assert_eq!(RetrievalRanking::default(), RetrievalRanking::Auto);
        assert!(serde_json::from_value::<RetrievalRanking>(serde_json::json!("semantic")).is_err());
    }

    #[test]
    fn rejects_zero_stateless_lever_limits() {
        let cases = [
            (
                serde_json::json!({
                    "type": "rag_select",
                    "min_tokens": 0,
                    "max_chunks": 12
                }),
                "min_tokens must be greater than zero",
            ),
            (
                serde_json::json!({
                    "type": "rag_select",
                    "min_tokens": 1_024,
                    "max_chunks": 0
                }),
                "max_chunks must be greater than zero",
            ),
            (
                serde_json::json!({
                    "type": "compact_serialization",
                    "min_tokens": 0
                }),
                "min_tokens must be greater than zero",
            ),
        ];

        for (lever, expected) in cases {
            let error =
                AiHandlerConfig::from_config(config_with_levers(serde_json::json!([lever])))
                    .unwrap_err()
                    .to_string();
            assert!(
                error.contains(expected),
                "unexpected validation error: {error}"
            );
        }
    }

    #[test]
    fn validates_rag_relevance_percentage_bounds() {
        for accepted in [0, 100] {
            AiHandlerConfig::from_config(config_with_levers(serde_json::json!([{
                "type": "rag_select",
                "min_tokens": 1_024,
                "max_chunks": 12,
                "min_relevance_percent": accepted
            }])))
            .unwrap_or_else(|error| panic!("{accepted} must be accepted: {error}"));
        }

        let error = AiHandlerConfig::from_config(config_with_levers(serde_json::json!([{
            "type": "rag_select",
            "min_tokens": 1_024,
            "max_chunks": 12,
            "min_relevance_percent": 101
        }])))
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("min_relevance_percent must not exceed 100"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn validates_tabular_min_rows_only_when_enabled() {
        for min_rows in [0, 1] {
            AiHandlerConfig::from_config(config_with_levers(serde_json::json!([{
                "type": "compact_serialization",
                "min_tokens": 1_024,
                "tabular": {"enabled": false, "min_rows": min_rows}
            }])))
            .unwrap_or_else(|error| panic!("disabled min_rows={min_rows} must parse: {error}"));

            let error = AiHandlerConfig::from_config(config_with_levers(serde_json::json!([{
                "type": "compact_serialization",
                "min_tokens": 1_024,
                "tabular": {"enabled": true, "min_rows": min_rows}
            }])))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("tabular.min_rows must be at least 2 when tabular.enabled is true"),
                "unexpected validation error: {error}"
            );
        }

        AiHandlerConfig::from_config(config_with_levers(serde_json::json!([{
            "type": "compact_serialization",
            "min_tokens": 1_024,
            "tabular": {"enabled": true, "min_rows": 2}
        }])))
        .expect("enabled tabular serialization accepts two rows");
    }

    #[test]
    fn rejects_unknown_fields_in_every_stateless_config() {
        let cases = [
            serde_json::json!({
                "type": "token_prune",
                "min_tokens": 1_024,
                "endpoint": "http://127.0.0.1:9440",
                "model": "llmlingua-2",
                "target": {"mode": "retain_ratio", "retain_percent": 50},
                "unknown": true
            }),
            serde_json::json!({
                "type": "query_select",
                "max_sentences": 8,
                "unknown": true
            }),
            serde_json::json!({
                "type": "rag_select",
                "min_tokens": 1_024,
                "max_chunks": 12,
                "unknown": true
            }),
            serde_json::json!({
                "type": "compact_serialization",
                "min_tokens": 1_024,
                "unknown": true
            }),
            serde_json::json!({
                "type": "compact_serialization",
                "min_tokens": 1_024,
                "tabular": {"unknown": true}
            }),
            serde_json::json!({
                "type": "position_reorder",
                "unknown": true
            }),
        ];

        for lever in cases {
            let error =
                AiHandlerConfig::from_config(config_with_levers(serde_json::json!([lever])))
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("unknown field"), "unexpected error: {error}");
        }
    }

    #[test]
    fn parses_ordered_policy_and_human_durations() {
        let config = AiHandlerConfig::from_config(valid_config()).expect("compression parses");
        let policy = config.compression.as_ref().expect("explicit policy");

        let state = policy.state.as_ref().expect("state config");
        assert_eq!(state.backend, CompressionStateBackend::Redis);
        assert_eq!(state.ttl_secs, 24 * 60 * 60);
        assert!(!policy.allow_admin_content_inspection);
        assert_eq!(policy.levers.len(), 2);

        match &policy.levers[0] {
            CompressionLeverConfig::SummaryBuffer(summary) => {
                assert_eq!(summary.min_tokens, 12_000);
                assert_eq!(summary.retain_recent_messages, 8);
                assert_eq!(summary.target_summary_tokens, 2_048);
                assert_eq!(summary.summarizer.provider, "anthropic");
                assert_eq!(summary.summarizer.model, "gpt-test");
                assert_eq!(summary.summarizer.timeout_secs, 5);
            }
            other => panic!("expected summary_buffer first, got {other:?}"),
        }
        match &policy.levers[1] {
            CompressionLeverConfig::WindowFit(window) => {
                assert_eq!(window.completion_reserve_tokens, 1_024);
            }
            other => panic!("expected window_fit second, got {other:?}"),
        }
    }

    #[test]
    fn parses_local_and_mesh_as_closed_compression_state_backends_without_changing_redis() {
        let mut local_value = valid_config();
        local_value["compression"]["state"]["backend"] = serde_json::json!("local");
        let local = AiHandlerConfig::from_config(local_value).expect("local backend parses");
        assert_eq!(
            local
                .compression
                .as_ref()
                .and_then(|policy| policy.state.as_ref())
                .expect("state config")
                .backend,
            CompressionStateBackend::Local
        );

        let mut value = valid_config();
        value["compression"]["state"]["backend"] = serde_json::json!("mesh");

        let config = AiHandlerConfig::from_config(value).expect("mesh backend parses");
        let policy = config.compression.as_ref().expect("explicit policy");
        assert_eq!(
            policy.state.as_ref().expect("state config").backend,
            CompressionStateBackend::Mesh
        );

        // The additive variant leaves Redis deserialization untouched.
        let redis = AiHandlerConfig::from_config(valid_config()).expect("redis still parses");
        assert_eq!(
            redis
                .compression
                .as_ref()
                .and_then(|policy| policy.state.as_ref())
                .expect("state config")
                .backend,
            CompressionStateBackend::Redis
        );

        // The backend enum stays closed: unknown names are still rejected.
        let mut unknown = valid_config();
        unknown["compression"]["state"]["backend"] = serde_json::json!("gossip");
        let error = AiHandlerConfig::from_config(unknown)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown variant `gossip`"), "{error}");
    }

    #[test]
    fn summary_buffer_without_state_defaults_to_local_for_default_pipeline() {
        let mut value = valid_config();
        value["compression"]
            .as_object_mut()
            .unwrap()
            .remove("state");

        let config = AiHandlerConfig::from_config(value).expect("omitted state defaults");
        let state = config
            .compression
            .as_ref()
            .and_then(|policy| policy.state.as_ref())
            .expect("summary buffer receives canonical state");
        assert_eq!(state.backend, CompressionStateBackend::Local);
        assert_eq!(state.ttl_secs, 24 * 60 * 60);
    }

    #[test]
    fn stateless_pipeline_without_state_remains_none() {
        let config = AiHandlerConfig::from_config(config_with_levers(serde_json::json!([{
            "type": "window_fit"
        }])))
        .expect("stateless policy compiles");

        assert!(config
            .compression
            .as_ref()
            .expect("compression")
            .state
            .is_none());
    }

    #[test]
    fn rejects_unknown_summarizer_provider() {
        let mut value = valid_config();
        value["compression"]["levers"][0]["summarizer"]["provider"] =
            serde_json::json!("missing-provider");

        let error = AiHandlerConfig::from_config(value).unwrap_err().to_string();
        assert!(error.contains(
            "compression.levers[0].summarizer.provider \"missing-provider\" is not configured"
        ));
    }

    #[test]
    fn rejects_invalid_summary_buffer_numbers() {
        let cases = [
            ("min_tokens", 0, "min_tokens must be greater than zero"),
            (
                "retain_recent_messages",
                0,
                "retain_recent_messages must be greater than zero",
            ),
            (
                "target_summary_tokens",
                0,
                "target_summary_tokens must be greater than zero",
            ),
        ];

        for (field, value, expected) in cases {
            let mut config = valid_config();
            config["compression"]["levers"][0][field] = serde_json::json!(value);
            let error = AiHandlerConfig::from_config(config)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{field}: {error}");
        }
    }

    #[test]
    fn rejects_zero_state_ttl_and_summarizer_timeout() {
        let mut zero_ttl = valid_config();
        zero_ttl["compression"]["state"]["ttl"] = serde_json::json!(0);
        let error = AiHandlerConfig::from_config(zero_ttl)
            .unwrap_err()
            .to_string();
        assert!(error.contains("compression.state.ttl must be greater than zero"));

        let mut zero_timeout = valid_config();
        zero_timeout["compression"]["levers"][0]["summarizer"]["timeout"] = serde_json::json!(0);
        let error = AiHandlerConfig::from_config(zero_timeout)
            .unwrap_err()
            .to_string();
        assert!(error.contains("summarizer.timeout must be greater than zero"));
    }

    #[test]
    fn rejects_empty_model_and_non_reducing_summary_target() {
        let mut empty_model = valid_config();
        empty_model["compression"]["levers"][0]["summarizer"]["model"] = serde_json::json!("  ");
        let error = AiHandlerConfig::from_config(empty_model)
            .unwrap_err()
            .to_string();
        assert!(error.contains("summarizer.model must not be empty"));

        let mut target_too_large = valid_config();
        target_too_large["compression"]["levers"][0]["target_summary_tokens"] =
            serde_json::json!(12_000);
        let error = AiHandlerConfig::from_config(target_too_large)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target_summary_tokens must be smaller than min_tokens"));
    }

    #[test]
    fn missing_compression_preserves_disabled_legacy_behavior() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")]
        }))
        .expect("base config");

        assert!(config.effective_compression_policy().is_none());
    }

    #[test]
    fn legacy_context_compress_maps_to_window_fit() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "resilience": {
                "llm_aware": {
                    "context_compress": true,
                    "completion_reserve_tokens": 2_048
                }
            }
        }))
        .expect("legacy config");

        let effective = config
            .effective_compression_policy()
            .expect("legacy policy");
        assert!(effective.state.is_none());
        assert_eq!(effective.levers.len(), 1);
        match &effective.levers[0] {
            CompressionLeverConfig::WindowFit(window) => {
                assert_eq!(window.completion_reserve_tokens, 2_048);
                assert_eq!(window.input_budget_tokens, None);
            }
            other => panic!("expected legacy window_fit, got {other:?}"),
        }
    }

    #[test]
    fn explicit_empty_policy_wins_over_legacy() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "resilience": {
                "llm_aware": {
                    "context_compress": true,
                    "completion_reserve_tokens": 2_048
                }
            },
            "compression": {
                "levers": []
            }
        }))
        .expect("explicit empty config");

        let effective = config
            .effective_compression_policy()
            .expect("explicit policy remains present");
        assert!(effective.levers.is_empty());
    }

    #[test]
    fn parses_explicit_window_fit_input_budget() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "compression": {
                "levers": [{
                    "type": "window_fit",
                    "completion_reserve_tokens": 512,
                    "input_budget_tokens": 4_096
                }]
            }
        }))
        .expect("explicit input budget parses");

        let policy = config.compression.expect("explicit policy");
        let CompressionLeverConfig::WindowFit(window) = &policy.levers[0] else {
            panic!("expected window_fit");
        };
        assert_eq!(window.completion_reserve_tokens, 512);
        assert_eq!(window.input_budget_tokens, Some(4_096));
    }

    #[test]
    fn rejects_zero_window_fit_input_budget() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "compression": {
                "levers": [{
                    "type": "window_fit",
                    "input_budget_tokens": 0
                }]
            }
        }))
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("compression.levers[0].input_budget_tokens must be greater than zero"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn compression_selector_is_a_bounded_closed_token() {
        assert_eq!(
            CompressionSelector::parse("on").unwrap(),
            CompressionSelector::On
        );
        assert_eq!(
            CompressionSelector::parse("off").unwrap(),
            CompressionSelector::Off
        );
        assert_eq!(
            CompressionSelector::parse("coding-agent").unwrap(),
            CompressionSelector::Profile("coding-agent".to_string())
        );
        assert_eq!(
            CompressionSelector::Profile("lean_2".to_string()).to_string(),
            "lean_2"
        );

        for invalid in [
            "",
            " ON ",
            "Upper",
            "has space",
            "../profile",
            "profile:other",
            "_leading",
        ] {
            assert!(
                CompressionSelector::parse(invalid).is_err(),
                "selector {invalid:?} must be rejected"
            );
        }
        assert!(CompressionSelector::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn parses_and_validates_named_compression_profiles() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "compression": {
                "levers": [],
                "profiles": {
                    "coding-agent": {
                        "levers": [{
                            "type": "window_fit",
                            "input_budget_tokens": 8_192
                        }]
                    },
                    "offload": {
                        "state": {"backend": "redis", "ttl": "1h"},
                        "levers": [{
                            "type": "summary_buffer",
                            "min_tokens": 4_096,
                            "retain_recent_messages": 4,
                            "target_summary_tokens": 512,
                            "summarizer": {
                                "provider": "openai",
                                "model": "gpt-test",
                                "timeout": "5s"
                            }
                        }]
                    }
                }
            }
        }))
        .expect("named profiles compile");

        let profiles = &config.compression.expect("compression").profiles;
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles["coding-agent"].levers.len(), 1);
        assert_eq!(
            profiles["offload"].state.as_ref().unwrap().backend,
            CompressionStateBackend::Redis
        );
    }

    #[test]
    fn rejects_reserved_invalid_and_self_incomplete_profile_names() {
        for invalid in ["on", "off", "Upper", "_leading"] {
            let mut value = serde_json::json!({
                "providers": [provider("openai")],
                "compression": {"profiles": {}}
            });
            value["compression"]["profiles"][invalid] = serde_json::json!({"levers": []});
            let error = AiHandlerConfig::from_config(value).unwrap_err().to_string();
            assert!(error.contains("compression.profiles"), "{invalid}: {error}");
        }

        let missing_state = serde_json::json!({
            "providers": [provider("openai")],
            "compression": {
                "state": {"backend": "redis", "ttl": "1h"},
                "profiles": {
                    "stateful": {
                        "levers": [{
                            "type": "summary_buffer",
                            "min_tokens": 4_096,
                            "retain_recent_messages": 4,
                            "target_summary_tokens": 512,
                            "summarizer": {
                                "provider": "openai",
                                "model": "gpt-test",
                                "timeout": "5s"
                            }
                        }]
                    }
                }
            }
        });
        let config =
            AiHandlerConfig::from_config(missing_state).expect("profile state defaults locally");
        let policy = config.compression.expect("compression");
        assert_eq!(
            policy.state.as_ref().expect("route state").backend,
            CompressionStateBackend::Redis,
            "explicit route state remains unchanged"
        );
        let profile_state = policy.profiles["stateful"]
            .state
            .as_ref()
            .expect("stateful profile receives independent state");
        assert_eq!(profile_state.backend, CompressionStateBackend::Local);
        assert_eq!(profile_state.ttl_secs, 24 * 60 * 60);
    }

    #[test]
    fn configured_keys_may_select_only_declared_profiles() {
        let valid = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "compression": {
                "profiles": {"coding-agent": {"levers": []}}
            },
            "virtual_keys": [{
                "key": "sb_test",
                "compression_profile": "coding-agent"
            }]
        }))
        .expect("declared profile selector");
        assert_eq!(
            valid.virtual_keys[0].compression_profile.as_deref(),
            Some("coding-agent")
        );

        for selector in ["missing", "Bad Name"] {
            let error = AiHandlerConfig::from_config(serde_json::json!({
                "providers": [provider("openai")],
                "compression": {
                    "profiles": {"coding-agent": {"levers": []}}
                },
                "virtual_keys": [{
                    "key": "sb_test",
                    "compression_profile": selector
                }]
            }))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("virtual_keys[0].compression_profile"),
                "{error}"
            );
        }
    }
}
