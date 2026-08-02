//! Sidecar-backed extractive token pruning for explicitly marked context.

use crate::compression::marked_context::{parse_marked_messages, ChunkFormat, MarkedContextError};
use crate::compression::{
    CompressionBackend, CompressionDecision, CompressionLever, CompressionRequest, FailureReason,
    LeverKind, SkipReason, TokenPruneConfig, TokenPruneTarget,
};
use async_trait::async_trait;
use sbproxy_classifier_client::{
    ClassifierClient, ClassifierClientError, CompressionTarget as ClientCompressionTarget,
};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

/// Sanitized output returned by a token-pruning backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPruneOutput {
    /// Extractive text assembled from source spans.
    pub text: String,
    /// Input tokens according to the pruning tokenizer.
    pub original_tokens: u32,
    /// Output tokens according to the pruning tokenizer.
    pub compressed_tokens: u32,
    /// Backend inference latency.
    pub latency_us: u64,
}

/// Closed failures returned by a token-pruning backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPruneBackendError {
    /// The sidecar could not be reached or complete the request.
    Unavailable,
    /// The sidecar response violated the extractive compression contract.
    InvalidOutput,
}

/// Async seam for the production sidecar and deterministic tests.
#[async_trait]
pub trait TokenPruneBackend: Send + Sync {
    /// Compress one marked text body against one explicit target.
    async fn compress(
        &self,
        model: &str,
        text: &str,
        target: TokenPruneTarget,
    ) -> Result<TokenPruneOutput, TokenPruneBackendError>;
}

#[derive(Clone)]
enum SidecarEndpoint {
    Tcp(String),
    Unix(PathBuf),
}

impl std::fmt::Debug for SidecarEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let transport = match self {
            Self::Tcp(_) => "tcp",
            Self::Unix(_) => "unix",
        };
        formatter
            .debug_struct("SidecarEndpoint")
            .field("transport", &transport)
            .field("address", &"<redacted>")
            .finish()
    }
}

/// Lazily connected classifier-sidecar token-pruning backend.
pub struct SidecarTokenPruneBackend {
    endpoint: SidecarEndpoint,
    timeout: Duration,
    client: OnceCell<ClassifierClient>,
}

impl std::fmt::Debug for SidecarTokenPruneBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SidecarTokenPruneBackend")
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .field("client_initialized", &self.client.get().is_some())
            .finish()
    }
}

impl SidecarTokenPruneBackend {
    /// Validate one TCP or `unix://` endpoint without dialing it.
    pub fn new(endpoint: &str, timeout: Duration) -> anyhow::Result<Self> {
        if timeout.is_zero() {
            anyhow::bail!("token-prune sidecar timeout must be greater than zero");
        }
        let endpoint = if let Some(path) = endpoint.strip_prefix("unix://") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                anyhow::bail!("token-prune unix endpoint must contain an absolute path");
            }
            SidecarEndpoint::Unix(path)
        } else {
            ClassifierClient::validate_endpoint(endpoint).map_err(|error| {
                anyhow::anyhow!("invalid token-prune sidecar endpoint: {error}")
            })?;
            SidecarEndpoint::Tcp(endpoint.to_string())
        };
        Ok(Self {
            endpoint,
            timeout,
            client: OnceCell::new(),
        })
    }

    async fn client(&self) -> Result<&ClassifierClient, TokenPruneBackendError> {
        self.client
            .get_or_try_init(|| async {
                match &self.endpoint {
                    SidecarEndpoint::Tcp(endpoint) => {
                        ClassifierClient::connect_lazy(endpoint, self.timeout)
                    }
                    SidecarEndpoint::Unix(path) => {
                        ClassifierClient::connect_uds_lazy(path, self.timeout)
                    }
                }
                .map_err(map_client_error)
            })
            .await
    }
}

#[async_trait]
impl TokenPruneBackend for SidecarTokenPruneBackend {
    async fn compress(
        &self,
        model: &str,
        text: &str,
        target: TokenPruneTarget,
    ) -> Result<TokenPruneOutput, TokenPruneBackendError> {
        let target = match target {
            TokenPruneTarget::RetainRatio { retain_percent } => {
                ClientCompressionTarget::RetainRatio(f64::from(retain_percent) / 100.0)
            }
            TokenPruneTarget::TargetTokens { target_tokens } => {
                ClientCompressionTarget::TargetTokens(target_tokens)
            }
        };
        let response = self
            .client()
            .await?
            .compress(model, text, target)
            .await
            .map_err(map_client_error)?;
        Ok(TokenPruneOutput {
            text: response.text,
            original_tokens: response.original_tokens,
            compressed_tokens: response.compressed_tokens,
            latency_us: response.latency_us,
        })
    }
}

fn map_client_error(error: ClassifierClientError) -> TokenPruneBackendError {
    match error {
        ClassifierClientError::Protocol(_) | ClassifierClientError::InvalidRequest(_) => {
            TokenPruneBackendError::InvalidOutput
        }
        _ => TokenPruneBackendError::Unavailable,
    }
}

/// Stateless extractive pruning over marked text chunks.
pub struct TokenPruneLever {
    config: TokenPruneConfig,
    backend: Arc<dyn TokenPruneBackend>,
}

impl std::fmt::Debug for TokenPruneLever {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenPruneLever")
            .field("min_tokens", &self.config.min_tokens)
            .field("endpoint", &"<redacted>")
            .field("model", &self.config.model)
            .field("timeout_ms", &self.config.timeout_ms)
            .field("max_chunks", &self.config.max_chunks)
            .field("target", &self.config.target)
            .finish_non_exhaustive()
    }
}

impl TokenPruneLever {
    /// Bind validated configuration to one shared backend.
    pub fn new(config: TokenPruneConfig, backend: Arc<dyn TokenPruneBackend>) -> Self {
        Self { config, backend }
    }
}

#[async_trait]
impl CompressionLever for TokenPruneLever {
    fn kind(&self) -> LeverKind {
        LeverKind::TokenPrune
    }

    fn backend(&self) -> Option<CompressionBackend> {
        None
    }

    async fn compress(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionDecision {
        let mut marked = match parse_marked_messages(messages) {
            Ok(Some(marked)) => marked,
            Ok(None) => {
                return CompressionDecision::Skipped {
                    reason: SkipReason::NoMarkedContext,
                };
            }
            Err(MarkedContextError::Malformed) => {
                return CompressionDecision::Skipped {
                    reason: SkipReason::MalformedMarkedContext,
                };
            }
            Err(MarkedContextError::TooLarge) => {
                return CompressionDecision::Skipped {
                    reason: SkipReason::MarkedContextTooLarge,
                };
            }
        };

        let source_chunks = marked
            .blocks_mut()
            .flat_map(|block| block.chunks().iter())
            .cloned()
            .collect::<Vec<_>>();
        if source_chunks
            .iter()
            .any(|chunk| chunk.format() != ChunkFormat::Text)
        {
            return CompressionDecision::Skipped {
                reason: SkipReason::UnsafeStructuredShape,
            };
        }
        if source_chunks.len() > self.config.max_chunks {
            return CompressionDecision::Skipped {
                reason: SkipReason::MarkedContextTooLarge,
            };
        }

        let estimates = source_chunks
            .iter()
            .map(|chunk| crate::token_estimate::estimate_text_tokens(request.model(), chunk.body()))
            .collect::<Vec<_>>();
        let total_tokens = estimates.iter().copied().sum::<u64>();
        if total_tokens < self.config.min_tokens {
            return CompressionDecision::Skipped {
                reason: SkipReason::BelowThreshold,
            };
        }

        let per_chunk_targets = match self.config.target {
            TokenPruneTarget::RetainRatio { .. } => {
                vec![self.config.target; source_chunks.len()]
            }
            TokenPruneTarget::TargetTokens { target_tokens } => {
                if total_tokens <= u64::from(target_tokens) {
                    return CompressionDecision::Skipped {
                        reason: SkipReason::NotNeeded,
                    };
                }
                let Some(allocations) = allocate_target_tokens(&estimates, target_tokens) else {
                    return CompressionDecision::Skipped {
                        reason: SkipReason::NotEligible,
                    };
                };
                allocations
                    .into_iter()
                    .map(|target_tokens| TokenPruneTarget::TargetTokens { target_tokens })
                    .collect()
            }
        };

        let mut outputs = Vec::with_capacity(source_chunks.len());
        for (chunk, target) in source_chunks.iter().zip(per_chunk_targets) {
            let output = match self
                .backend
                .compress(&self.config.model, chunk.body(), target)
                .await
            {
                Ok(output) => output,
                Err(TokenPruneBackendError::Unavailable) => {
                    return CompressionDecision::Failed {
                        reason: FailureReason::TokenPruneUnavailable,
                    };
                }
                Err(TokenPruneBackendError::InvalidOutput) => {
                    return CompressionDecision::Failed {
                        reason: FailureReason::InvalidTokenPruneOutput,
                    };
                }
            };
            if !valid_output(chunk.body(), target, &output) {
                return CompressionDecision::Failed {
                    reason: FailureReason::InvalidTokenPruneOutput,
                };
            }
            outputs.push(output);
        }

        let target_token_counts = outputs
            .iter()
            .map(|output| {
                crate::token_estimate::estimate_text_tokens(request.model(), &output.text)
            })
            .collect::<Vec<_>>();
        let target_budget_is_satisfied = match self.config.target {
            TokenPruneTarget::RetainRatio { retain_percent } => estimates
                .iter()
                .zip(&target_token_counts)
                .all(|(original, compressed)| {
                    *compressed
                        <= original
                            .saturating_mul(u64::from(retain_percent))
                            .div_ceil(100)
                }),
            TokenPruneTarget::TargetTokens { target_tokens } => {
                target_token_counts.iter().copied().sum::<u64>() <= u64::from(target_tokens)
            }
        };
        if !target_budget_is_satisfied {
            return CompressionDecision::Failed {
                reason: FailureReason::InvalidTokenPruneOutput,
            };
        }

        let mut output_index = 0;
        for block in marked.blocks_mut() {
            let transformed = block
                .chunks()
                .iter()
                .map(|chunk| {
                    let output = &outputs[output_index];
                    output_index += 1;
                    chunk.with_body_and_format(output.text.clone(), ChunkFormat::Text)
                })
                .collect::<Vec<_>>();
            block.replace_chunks(transformed);
        }
        let candidate = marked.into_messages();
        if candidate == messages {
            CompressionDecision::Skipped {
                reason: SkipReason::NotNeeded,
            }
        } else {
            CompressionDecision::Candidate {
                messages: candidate,
            }
        }
    }
}

fn valid_output(source: &str, target: TokenPruneTarget, output: &TokenPruneOutput) -> bool {
    if output.text.is_empty()
        || output.original_tokens == 0
        || output.compressed_tokens == 0
        || output.compressed_tokens > output.original_tokens
        || !is_char_subsequence(&output.text, source)
    {
        return false;
    }
    match target {
        TokenPruneTarget::RetainRatio { retain_percent } => {
            let budget = u64::from(output.original_tokens)
                .saturating_mul(u64::from(retain_percent))
                .div_ceil(100);
            u64::from(output.compressed_tokens) <= budget
        }
        TokenPruneTarget::TargetTokens { target_tokens } => {
            output.compressed_tokens <= target_tokens
        }
    }
}

fn is_char_subsequence(candidate: &str, source: &str) -> bool {
    let mut source_chars = source.chars();
    candidate
        .chars()
        .all(|wanted| source_chars.by_ref().any(|found| found == wanted))
}

fn allocate_target_tokens(estimates: &[u64], target_tokens: u32) -> Option<Vec<u32>> {
    if estimates.is_empty() {
        return Some(Vec::new());
    }
    let target = u64::from(target_tokens);
    let count = u64::try_from(estimates.len()).ok()?;
    let total = estimates.iter().copied().sum::<u64>();
    if total == 0 || target < count {
        return None;
    }

    let distributable = target - count;
    let mut allocations = estimates
        .iter()
        .map(|estimate| 1 + distributable.saturating_mul(*estimate) / total)
        .collect::<Vec<_>>();
    let assigned = allocations.iter().copied().sum::<u64>();
    let mut remainders = estimates
        .iter()
        .enumerate()
        .map(|(index, estimate)| (distributable.saturating_mul(*estimate) % total, index))
        .collect::<Vec<_>>();
    remainders.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let unassigned = usize::try_from(target.saturating_sub(assigned)).ok()?;
    for (_, index) in remainders.into_iter().take(unassigned) {
        allocations[index] += 1;
    }
    allocations
        .into_iter()
        .map(u32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::{
        inspect_marked_context, CompressionDecision, CompressionLever, CompressionRequest,
        TokenPruneTarget,
    };
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeBackend {
        calls: Mutex<Vec<(String, String, TokenPruneTarget)>>,
        unavailable: bool,
        output: Option<TokenPruneOutput>,
    }

    #[async_trait]
    impl TokenPruneBackend for FakeBackend {
        async fn compress(
            &self,
            model: &str,
            text: &str,
            target: TokenPruneTarget,
        ) -> Result<TokenPruneOutput, TokenPruneBackendError> {
            self.calls
                .lock()
                .unwrap()
                .push((model.to_string(), text.to_string(), target));
            if self.unavailable {
                return Err(TokenPruneBackendError::Unavailable);
            }
            if let Some(output) = &self.output {
                return Ok(output.clone());
            }
            let text = text
                .split_whitespace()
                .step_by(2)
                .collect::<Vec<_>>()
                .join(" ");
            Ok(TokenPruneOutput {
                text,
                original_tokens: 4,
                compressed_tokens: 2,
                latency_us: 10,
            })
        }
    }

    fn config(target: TokenPruneTarget) -> TokenPruneConfig {
        TokenPruneConfig {
            min_tokens: 1,
            endpoint: "http://127.0.0.1:9440".to_string(),
            model: "llmlingua-2".to_string(),
            timeout_ms: 250,
            max_chunks: 8,
            target,
        }
    }

    fn marked(body: &str, format: &str) -> Vec<Value> {
        vec![json!({
            "role": "user",
            "content": format!(
                "prefix\n<sbproxy-retrieval>\n<sbproxy-query>\nquestion\n</sbproxy-query>\n<sbproxy-chunk id=\"one\" format=\"{format}\">\n{body}\n</sbproxy-chunk>\n</sbproxy-retrieval>\nsuffix"
            )
        })]
    }

    #[tokio::test]
    async fn prunes_only_marked_text_and_preserves_surrounding_contract() {
        let backend = Arc::new(FakeBackend::default());
        let lever = TokenPruneLever::new(
            config(TokenPruneTarget::RetainRatio { retain_percent: 50 }),
            backend.clone(),
        );
        let messages = marked("alpha beta gamma delta", "text");

        let CompressionDecision::Candidate { messages: output } = lever
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await
        else {
            panic!("expected candidate");
        };
        let content = output[0]["content"].as_str().unwrap();
        assert!(content.starts_with("prefix\n<sbproxy-retrieval>"));
        assert!(content.ends_with("</sbproxy-retrieval>\nsuffix"));
        let snapshot = inspect_marked_context(&output).unwrap().unwrap();
        assert_eq!(snapshot.blocks[0].chunks[0].body, "alpha gamma");
        assert_eq!(backend.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn target_token_mode_allocates_and_enforces_the_target_model_budget() {
        let backend = Arc::new(FakeBackend::default());
        let lever = TokenPruneLever::new(
            config(TokenPruneTarget::TargetTokens { target_tokens: 2 }),
            backend.clone(),
        );
        let messages = marked("alpha beta gamma delta", "text");

        let CompressionDecision::Candidate { messages: output } = lever
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await
        else {
            panic!("expected target-token candidate");
        };

        let snapshot = inspect_marked_context(&output).unwrap().unwrap();
        assert_eq!(snapshot.blocks[0].chunks[0].body, "alpha gamma");
        assert!(
            crate::token_estimate::estimate_text_tokens(
                "gpt-4",
                &snapshot.blocks[0].chunks[0].body
            ) <= 2
        );
        assert_eq!(
            backend.calls.lock().unwrap()[0].2,
            TokenPruneTarget::TargetTokens { target_tokens: 2 }
        );
    }

    #[tokio::test]
    async fn below_threshold_and_structured_chunks_never_call_the_sidecar() {
        let backend = Arc::new(FakeBackend::default());
        let mut cfg = config(TokenPruneTarget::RetainRatio { retain_percent: 50 });
        cfg.min_tokens = 10_000;
        let lever = TokenPruneLever::new(cfg, backend.clone());
        assert_eq!(
            lever
                .compress(
                    &CompressionRequest::new("gpt-4"),
                    &marked("alpha beta", "text")
                )
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::BelowThreshold
            }
        );

        let lever = TokenPruneLever::new(
            config(TokenPruneTarget::RetainRatio { retain_percent: 50 }),
            backend.clone(),
        );
        assert_eq!(
            lever
                .compress(
                    &CompressionRequest::new("gpt-4"),
                    &marked(r#"{"alpha":"beta"}"#, "json")
                )
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::UnsafeStructuredShape
            }
        );
        assert!(backend.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sidecar_failure_is_closed_telemetry_but_request_fail_open() {
        let lever = TokenPruneLever::new(
            config(TokenPruneTarget::RetainRatio { retain_percent: 50 }),
            Arc::new(FakeBackend {
                calls: Mutex::new(Vec::new()),
                unavailable: true,
                output: None,
            }),
        );
        assert_eq!(
            lever
                .compress(
                    &CompressionRequest::new("gpt-4"),
                    &marked("alpha beta gamma delta", "text")
                )
                .await,
            CompressionDecision::Failed {
                reason: FailureReason::TokenPruneUnavailable
            }
        );
    }

    #[test]
    fn absolute_budget_allocation_is_total_bounded_and_deterministic() {
        assert_eq!(
            allocate_target_tokens(&[60, 30, 10], 10),
            Some(vec![5, 3, 2])
        );
        assert_eq!(allocate_target_tokens(&[1, 1, 1], 2), None);
    }

    #[test]
    fn endpoint_validation_accepts_tcp_and_absolute_unix_only() {
        assert!(
            SidecarTokenPruneBackend::new("http://127.0.0.1:9440", Duration::from_millis(250))
                .is_ok()
        );
        assert!(SidecarTokenPruneBackend::new(
            "unix:///run/sbproxy/classifier.sock",
            Duration::from_millis(250)
        )
        .is_ok());
        assert!(
            SidecarTokenPruneBackend::new("unix://relative.sock", Duration::from_millis(250))
                .is_err()
        );
    }

    #[test]
    fn debug_output_redacts_sidecar_endpoints() {
        let endpoint = "http://user:secret@classifier.internal:9440/private";
        let backend = SidecarTokenPruneBackend::new(endpoint, Duration::from_millis(250))
            .expect("valid backend");
        let backend_debug = format!("{backend:?}");
        assert!(!backend_debug.contains(endpoint));
        assert!(!backend_debug.contains("classifier.internal"));
        assert!(!backend_debug.contains("secret"));

        let mut cfg = config(TokenPruneTarget::TargetTokens { target_tokens: 8 });
        cfg.endpoint = endpoint.to_string();
        let lever = TokenPruneLever::new(cfg, Arc::new(FakeBackend::default()));
        let lever_debug = format!("{lever:?}");
        assert!(!lever_debug.contains(endpoint));
        assert!(!lever_debug.contains("classifier.internal"));
        assert!(!lever_debug.contains("secret"));
        assert!(backend_debug.contains("<redacted>"));
        assert!(lever_debug.contains("<redacted>"));
    }

    #[tokio::test]
    async fn ratio_mode_is_retokenized_against_the_target_model() {
        let source = "antidisestablishmentarianism a b c";
        let retained = "antidisestablishmentarianism";
        let model = "gpt-4";
        let original_target_tokens = crate::token_estimate::estimate_text_tokens(model, source);
        let retained_target_tokens = crate::token_estimate::estimate_text_tokens(model, retained);
        assert!(
            retained_target_tokens > original_target_tokens.div_ceil(2),
            "fixture must exceed the target-model 50% budget"
        );
        let lever = TokenPruneLever::new(
            config(TokenPruneTarget::RetainRatio { retain_percent: 50 }),
            Arc::new(FakeBackend {
                calls: Mutex::new(Vec::new()),
                unavailable: false,
                output: Some(TokenPruneOutput {
                    text: retained.to_string(),
                    original_tokens: 4,
                    compressed_tokens: 2,
                    latency_us: 10,
                }),
            }),
        );

        assert_eq!(
            lever
                .compress(&CompressionRequest::new(model), &marked(source, "text"))
                .await,
            CompressionDecision::Failed {
                reason: FailureReason::InvalidTokenPruneOutput
            }
        );
    }
}
